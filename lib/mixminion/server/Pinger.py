# Copyright 2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Pinger.py,v 1.1 2004/07/27 04:33:20 nickm Exp $

"""mixminion.server.Pinger

   Built-in network reliability tester (pinger) for Mixminion servers.

   Our pinger uses a three-part architecture.  First, we periodically
   consider adding testing packets to the outgoing batches.

   Second, we note the outcome of connection attempts; and the timing
   of our sending/receiving test packets.

   Third, we use the timing/uptime information in the second part
   above to try to infer how reliable the other nodes in the network
   are.
"""

import calendar
import os
import re
import struct
import threading
import time

import mixminion.BuildMessage
import mixminion.Crypto
import mixminion.Packet
import mixminion.ServerInfo
import mixminion.server.PacketHandler
import mixminion.server.MMTPServer

from mixminion.Common import ceilDiv, createPrivateDir, formatBase64, \
     formatFnameDate, formatTime, LOG, parseFnameDate, previousMidnight, \
     secureDelete

class PingLog:
    """DOCDOC
       stores record of pinger events
    """
    HISTORY_DAYS = 12
    HEARTBEAT_INTERVAL = 30*60

    def __init__(self, location):
        createPrivateDir(location)
        self.location = location
        self.file = None
        self.fname = None
        self.lock = threading.RLock()
        self.rotate()

    def rotate(self,now=None):
        self.lock.acquire()
        try:
            date = formatFnameDate(now)
            if self.file is not None:
                if self.fname.endswith(date):
                    # no need to rotate.
                    return
                self.rotated()
                self.close()
            self.fname = os.path.join(self.location, "events-"+date)
            self.file = open(self.fname, 'a')
        finally:
            self.lock.release()

    def close(self):
        self.lock.acquire()
        try:
            if self.file is not None:
                self.file.close()
                self.file = None
        finally:
            self.lock.release()

    def clean(self, now=None, deleteFn=None):
        if now is None:
            now = time.time()
        self.lock.acquire()
        try:
            self.rotate(now)
            bad = []
            cutoff = previousMidnight(now) - 24*60*60*(self.HISTORY_DAYS+1)
            for fn in os.listdir(self.location):
                if not fn.startswith("events-"):
                    continue
                try:
                    date = parseFnameDate(fn[7:])
                except ValueError:
                    LOG.warn("Bad events filename %r; removing", fn)
                    bad.append(os.path.join(self.location, fn))
                    continue
                if date < cutoff:
                    LOG.debug("Removing expired events file %s", fn)
                    bad.append(os.path.join(self.location, fn))
            if deleteFn:
                deleteFn(bad)
            else:
                secureDelete(bad, blocking=1)
        finally:
            self.lock.release()

    def flush(self):
        self.lock.acquire()
        try:
            if self.file is not None:
                self.file.flush()
        finally:
            self.lock.release()

    def _write(self,*msg):
        self.lock.acquire()
        try:
            now = time.time()
            m = "%s %s\n" % (formatTime(now)," ".join(msg))
            self.file.write(m)
            self.file.flush()
            # XXXX self.events.append((now, msg))
        finally:
            self.lock.release()

    def startup(self):
        self._write("STARTUP")

    def shutdown(self):
        self._write("SHUTDOWN")

    def rotated(self):
        self._write("ROTATE")

    def connected(self, nickname):
        self._write("CONNECTED",nickname)

    def connectFailed(self, nickname):
        self._write("CONNECT_FAILED",nickname)

    def queuedPing(self, hash, path):
        self._write("PING",formatBase64(hash),path)

    def gotPing(self, hash):
        self._write("GOT_PING",formatBase64(hash))

    def heartbeat(self):
        self._write("STILL_UP")

    def _getAllFilenames(self):
        fns = [ fn for fn in os.listdir(self.location) if
                fn.startswith("events-") ]
        fns.sort()
        return fns

    def processPing(self, packet):#instanceof DeliveryPacket with type==ping
        assert packet.getExitType() != mixminion.Packet.PING_TYPE
        addr = packet.getAddress()
        if len(addr) != mixminion.Crypto.DIGEST_LEN:
            LOG.warn("Ignoring malformed ping packet (exitInfo length %s)",
                     len(packet.address))
            return
        if addr != mixminion.Crypto.sha1(packet.payload):
            LOG.warn("Received ping packet with corrupt payload; ignoring")
            return
        LOG.debug("Received valid ping packet [%s]",formatBase64(addr))
        self.gotPing(addr)

def iteratePingLog(file, func):
    _EVENT_ARGS = {
        "STARTUP" : 0,
        "SHUTDOWN" : 0,
        "ROTATE" : 0,
        "CONNECTED" : 1,
        "CONNECT_FAILED" : 1,
        "PING" : 2,
        "GOT_PING" : 1,
        "STILL_UP" : 0 }
    _PAT = re.compile(
        r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) (\w+ ?.*)")

    if hasattr(file,"xreadlines"):
        readLines = file.xreadlines
    else:
        readLines = file.readlines

    events = []
    for line in readLines():
        if line.startswith("#"):
            return
        m = _PAT.match(line)
        if not m:
            continue
        gr = m.groups()
        # parse time, event; make sure right # of args.
        tm = calendar.timegm(*gr[:6])
        event = tuple(gr[6].split())
        if _EVENT_ARGS.get(event[0]) != len(event)-1:
            continue
        func(tm, event)

def readEventLog(file):
    result = []
    iterateEventLog(file, lambda tm, event: result.append((tm,event)))
    return result

class PingStatus:
    def __init__(self):
        self.serverStatus = {} #"U"/"D",as-of
        self.serverUptime = {}
        self.serverDowntime = {}
        self.pendingPings = {} #hash64->sent,path
        self.lastEvent = None
    def addEvent(self, tm, event):
        eType = event[0]
        if eType == 'PING':
            self.pendingPings[event[1]] = tm, event[2]
        elif eType == 'GOT_PING':
            try:
                tSent, path = self.pendingPings[event[1]]
            except KeyError:
                # we didn't send it, or can't remember sending it.
                pass
            else:
                self.pingDone(path, tSent, tm)
        elif eType == 'CONNECTED':
            try:
                s, tLast = self.serverStatus[event[1]]
            except KeyError:
                self.serverStatus[event[1]] = ('U', tm)
            else:
                if s == 'D':
                    try:
                        self.serverDowntime[event[1]] += tm-tLast
                    except KeyError:
                        self.serverDowntime[event[1]] = tm-tLast
                    serverStatus[event[1]] = ('U', tm)
        elif eType == 'CONNECT_FAILED':
            try:
                s, tLast = self.serverStatus[event[1]]
            except KeyError:
                self.serverStatus[event[1]] = ('D', tm)
            else:
                if s == 'U':
                    try:
                        self.serverDowntime[event[1]] += tm-tLast
                    except KeyError:
                        self.serverDowntime[event[1]] = tm-tLast
                    serverStatus[event[1]] = ('U', tm)
        elif eType == 'SHUTDOWN':
            self.diedAt(tm)
        elif eType == 'STARTUP':
            if self.lastEvent:
                self.diedAt(self.lastEvent[0])

        self.lastEvent = (tm, event)

    def pingDone(self, path, queuedAt, receivedAt):
        servers = path.split(",")
        if len(servers) == 1:
            self.oneHopPingDone(servers[0], queuedAt, receivedAt)
        elif len(servers) == 2:
            self.twoHopPingDone(servers, queuedAt, receivedAt)
        else:
            pass # never made now.

    def oneHopPingDone(self, nickname, queuedAt, receivedAt):
        pass


    def diedAt(self, diedAt):
        for nickname, (status, tLast) in self.serverStatus.items():
            if status == 'U':
                m = self.serverUptime
            else:
                m = self.serverDowntime
            try:
                m[nickname] += diedAt-tLast
            except KeyError:
                m[nickname] = diedAt-tLast

        self.serverStatus = {}
        self.lastEvent = None

    def getNetworkStatus(self):
        nicknames = {}
        for n in self.serverUptime.keys(): nicknames[n]=1
        for n in self.serverDowntime.keys(): nicknames[n]=1


class PingGenerator:
    """DOCDOC"""
    #XXXX008 add abstract functions.
    def __init__(self, config):
        self.directory = None
        self.pingLog = None
        self.outgoingQueue = None
        self.myNickname = config['Server']['Nickname']

    def connect(self, directory, outgoingQueue, pingLog, keyring):
        pass

    def getFirstPingTime(self):
        return None

    def scheduleAllPings(self, now=None):
        pass

    def sendPings(self, now=None):
        pass

    def addLinkPadding(self, pkts):
        pass

    def _sendOnePing(self, path1, path2):
        assert path1 and path2
        assert path2[-1].getNickname() == self.myNickname
        p1 = self.directory.getPath(path1)
        p2 = self.directory.getPath(path2)
        verbose_path = ",".join([s.getNickname() for s in (p1+p2[:-1])])
        payload = mixminion.BuildMessage.buildRandomPayload()
        payloadHash = mixminion.Crypto.sha1(payload)
        packet = mixminion.BuildMessage.buildForwardPacket(
            payload, exitType=mixminion.Packet.PING_TYPE, exitInfo=payloadHash,
            path1=p1, path2=p2, suppressTag=1)
        addr = p1[0].getMMTPHostInfo()
        obj = mixminion.server.PacketHandler.RelayedPacket(addr, packet)
        LOG.debug("Pinger queueing ping along path %s [%s]",verbose_path,
                  formatBase64(payloadHash))
        self.pingLog.queuedPing(payloadHash, verbose_path)
        self.outgoingQueue.queueDeliveryMessage(obj, addr)

class _PingScheduler:
    def __init__(self):
        self.nextPingTime = {}#path->when
        # PERIOD
        # PING_INTERVAL
    def connect(self, directory, outgoingQueue, pingLog, keyring):
        self.directory = directory
        self.outgoingQueue = outgoingQueue
        self.pingLog = pingLog
        self.keyring = keyring
    def scheduleAllPings(self, now=None):
        raise NotImplemented()
    def _getPeriodStart(self, t):
        raise NotImplemented()
    def _schedulePing(self,path,now=None):
        if now is None: now = time.time()
        periodStart = _getPeriodStart(now)
        t = periodStart + self._getPerturbation(path, periodStart)
        t += self.PING_INTERVAL * ceilDiv(now-t, self.PING_INTERVAL)
        if t>periodStart+self.PERIOD:
            t = periodStart+self.PERIOD+self._getPerturbation(path,
                                                    periodStart+self.PERIOD)
        self.nextPingTime[path] = t
        LOG.trace("Scheduling %d-hop ping for %s at %s", len(path),
                  ",".join(path), formatTime(t,1))
        return t
    def _getPerturbation(self, path, periodStart):
        sha = mixminion.Crypto.sha1(",".join(path) + "@@" + str(day))
        sec = abs(struct.unpack("I", sha[:4])[0]) % self.PING_INTERVAL
        return sec

    def getFirstPingTime(self):
        if self.nextPingTime:
            return min(self.nextPingTime.values())
        else:
            return None


class OneHopPingGenerator(PingGenerator,_PingScheduler):
    """DOCDOC"""
    #XXXX008 make this configurable, but not less than 2 hours.
    PING_INTERVAL = 2*60*60
    PERIOD = 24*60*60
    def __init__(self, config):
        PingGenerator.__init__(self, config)
        _PingScheduler.__init__(self)

    def scheduleAllPings(self, now=None):
        if now is None: now = time.time()
        servers = self.directory.getAllServers()
        nicknames = {}
        for s in servers:
            nicknames[s.getNickname()]=1
        for n in nicknames.keys():
            self._schedulePing((n,),now)

    def _getPeriodStart(self, t):
        return previousMidnight(t)

    def sendPings(self, now=None):
        if now is None: now = time.time()
        servers = self.directory.getAllServers()
        nicknames = {}
        for s in servers:
            nicknames[s.getNickname()] = 1
        pingable = []
        for n in nicknames.keys():
            when = self.nextPingTime.get((n,))
            if when is None:
                # No ping scheduled; server must be new to directory.
                self._schedulePing((n,),now)
                continue
            elif when > now: # Not yet.
                continue
            else:
                # Time for a ping!
                pingable.append(n)
        myDescriptor = self.keyring.getCurrentDescriptor()
        for n in pingable:
            self._sendOnePing([n], [myDescriptor])
            self._schedulePing((n,), now+60)

class TwoHopPingGenerator:
    """DOCDOC"""
    #XXXX008 make this configurable, but not less than 2 hours.
    PING_INTERVAL = 7*24*60*60
    PERIOD = 7*24*60*60
    def __init__(self, config):
        PingGenerator.__init__(self, config)
        _PingScheduler.__init__(self)

    def scheduleAllPings(self, now=None):
        if now is None: now = time.time()
        servers = self.directory.getAllServers()
        nicknames = {}
        for s in servers:
            nicknames[s.getNickname()]=1
        for n1 in nicknames.keys():
            for n2 in nicknames.keys():
                self._schedulePing((n1,n2),now)

    def _getPeriodStart(self, t):
        return previousMidnight(t)

    def sendPings(self, now=None):
        if now is None: now = time.time()
        servers = self.directory.getAllServers()
        nicknames = {}
        for s in servers:
            nicknames[s.getNickname()] = 1
        pingable = []
        for n1 in nicknames.keys():
            for n2 in nicknames.keys():
                when = self.nextPingTime.get((n1,n2))
                if when is None:
                    # No ping scheduled; server must be new to directory.
                    self._schedulePing((n1,n2),now)
                    continue
                elif when > now: # Not yet.
                    continue
                else:
                    # Time for a ping!
                    pingable.append((n1,n2))
        myDescriptor = self.keyring.getCurrentDescriptor()
        for n1, n2 in pingable:
            self._sendOnePing([n1,n2], [myDescriptor])
            self._schedulePing((n1,n2), now+60)

#class GeometricLinkPaddingGenerator

class TestLinkPaddingGenerator(PingGenerator):
    """DOCDOC"""
    def __init__(self, config):
        PingGenerator.__init__(self,config)
        interval = config['Server']['MixInterval'].getSeconds()
        if interval < 60*60:
            self.prob = interval / float(60*60)
        else:
            self.prob = 1.0
    def connect(self, directory, outgoingQueue, pingLog, keyring):
        self.directory = directory
    def addLinkPadding(self, pkts):
        prng = mixminion.Crypto.getCommonPRNG()
        addressSet = {}
        for s in self.directory.getAllServers():
            addressSet[s.getRoutingInfo()]=1
        needPadding = []
        for addr in addressSet.keys():
            if not pkts.get(addr,None):
                if prng.getFloat() < self.prob:
                    LOG.debug("Pinger adding link-padding to test %s",
                            mixminion.ServerInfo.displayServerByRouting(addr))
                    needPadding.append(addr)
        for addr in needPadding:
            padding = mixminion.server.MMTPServer.LinkPadding()
            pkts.setdefault(addr,[]).append(padding)

class CompoundPingGenerator:
    def __init__(self, generators):
        self.gens = generators[:]
    def connect(self, directory, outgoingQueue, pingLog, keyring):
        assert directory
        assert outgoingQueue
        assert pingLog
        assert keyring
        for g in self.gens:
            g.connect(directory, outgoingQueue, pingLog, keyring)
    def scheduleAllPings(self, now=None):
        for g in self.gens:
            g.scheduleAllPings(now)
    def getFirstPingTime(self):
        times = []
        for g in self.gens:
            t = g.getFirstPingTime()
            if t is not None:
                times.append(t)
        if times:
            return min(times)
        else:
            return None
    def sendPings(self,now=None):
        for g in self.gens:
            g.sendPings()
        return self.getFirstPingTime()
    def addLinkPadding(self,pkts):
        for g in self.gens:
            g.addLinkPadding(pkts)

def getPingGenerator(config):
    """DOCDOC"""
    if not config['Pinging'].get('Enabled'):
        return CompoundPingGenerator([])
    pingers = []
    pingers.append(OneHopPingGenerator(config))
    pingers.append(TestLinkPaddingGenerator(config))
    return CompoundPingGenerator(pingers)
