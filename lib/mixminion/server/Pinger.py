# Copyright 2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Pinger.py,v 1.3 2004/07/27 23:33:18 nickm Exp $

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

import bisect
import calendar
import cPickle
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

from mixminion.Common import MixError, ceilDiv, createPrivateDir, \
     floorDiv, formatBase64, formatFnameDate, formatTime, LOG, parseFnameDate,\
     previousMidnight, readPickled, secureDelete, writePickled

KEEP_HISTORY_DAYS = 15
USE_HISTORY_DAYS = 12
HEARTBEAT_INTERVAL = 30*60
ONE_DAY = 24*60*60

class PingLog:
    """DOCDOC
       stores record of pinger events
    """
    HEARTBEAT_INTERVAL = 30*60
    def __init__(self, location):
        createPrivateDir(location)
        self.location = location
        self.file = None
        self.fname = None
        self.lock = threading.RLock()
        self.rotate()

    def _getDateString(self, now):
        return formatFnameDate(now)

    def rotate(self,now=None):
        self.lock.acquire()
        try:
            date = self._getDateString(now)
            if self.file is not None:
                if self.fname.endswith(date):
                    # no need to rotate.
                    return
                self.rotated()
                self.close()
                self._rotateHook()
            self.fname = os.path.join(self.location, "events-"+date)
            self.file = open(self.fname, 'a')
        finally:
            self.lock.release()

    def _rotateHook(self,fname=None):
        pass

    def close(self):
        self.lock.acquire()
        try:
            if self.file is not None:
                self.file.close()
                self.file = None
        finally:
            self.lock.release()

    def _parseFname(self,fn):
        if not fn.startswith("events-"):
            return None,None
        try:
            date = parseFnameDate(fn[7:15])
        except ValueError:
            return None,None
        tp = fn[15:]
        if tp == "":
            return date,"log"
        elif tp == ".stat.gz":
            return date,"stat"
        elif tp == ".pend.gz":
            return date,"pend"
        else:
            return None,None

    def clean(self, now=None, deleteFn=None):
        if now is None:
            now = time.time()
        self.lock.acquire()
        try:
            self.rotate(now)
            bad = []
            lastPending = None
            cutoff = previousMidnight(now) - ONE_DAY*(KEEP_HISTORY_DAYS)
            filenames = os.listdir(self.location)
            filenames.sort() # consider files in order of time.
            for fn in os.listdir(self.location):
                date,tp = self._parseFname(fn)
                if not date:
                    LOG.warn("Unrecognized events file %s",fn)
                    continue
                elif date < cutoff:
                    LOG.debug("Removing expired events file %s", fn)
                    bad.append(os.path.join(self.location, fn))
                elif tp == "pend":
                    if self.lastPending:
                        LOG.debug("Removing old pending-pings file %s",
                                  lastPending)
                        bad.append(os.path.join(self.location,lastPending))
                        self.lastPending = fn
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

    def _event(self,tm,event):
        pass

    def _write(self,*msg):
        self.lock.acquire()
        try:
            now = time.time()
            m = "%s %s\n" % (formatTime(now)," ".join(msg))
            self.file.write(m)
            self.file.flush()
            self._event(now, msg)
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

    def calculateStatistics(self,now=None):
        pass

    def getLatestStatistics(self):
        return None

class PingStatusLog(PingLog):
    MAX_PING_AGE = 12 * ONE_DAY

    def __init__(self, location):
        PingLog.__init__(self,location)
        self.pingStatus = None
        self.latestStatistics = None
        self._loadDepth=0
        self._loadPingStatus()

    def _event(self,tm,event):
        # lock is held.
        self.pingStatus.addEvent(tm,event)

    def _rotateHook(self,fname=None):
        # hold lock
        if fname is None:
            fname = self.fname
        pr = self.pingStatus.splitResults(_nocopy=1)
        pend = pr.pendingPings
        pr.pendingPings=None
        # separate these for space savings.
        writePickled(fname+".pend.gz",pend,gzipped=1)
        writePickled(fname+".stat.gz",pr,gzipped=1)

    def _rescanImpl(self):
        # hold lock; restore pingStatus.
        fnames = [ fn for fn in os.listdir(self.location) if
                   self._parseFname(fn)[1] == 'log' ]
        fnames.sort() # go by date.

        self.pingStatus = ps = PingStatus()
        for fn in fnames[:-1]:
            f = open(fn, 'r')
            try:
                ps.addFile(f)
            finally:
                f.close()
            if fn != self.fname:
                self._rotateHook(fn)

    def _loadPingStatusImpl(self, binFname, pendFname, logFname):
        # lock is held if any refs to objects are held.
        if binFname:
            results = readPickled(os.path.join(self.location,binFname),gzipped=1)
            if results._version != PeriodResults.MAGIC:
                return 1
            pending = readPickled(os.path.join(self.location,pendFname),gzipped=1)
            results.pendingPings=pending
            ps = PingStatus(results)
        else:
            ps = PingStatus()
        if logFname and os.path.exists(os.path.join(self.location,logFname)):
            f = open(os.path.join(self.location,logFname), 'r')
            ps.addFile(f)
            f.close()
        self.pingStatus = ps
        return 0

    def _loadPingStatus(self):
        # lock is held if any refs to objects are held.
        dateSet = {}
        for fn in os.listdir(self.location):
            date, tp = self._parseFname(fn)
            dateSet.setdefault(date,{})[tp]=fn
        dates = dateSet.keys()
        dates.sort()
        rescan = 0
        # All files but the current one should have stat.  The last stat
        # should have a pend.  Otherwise, rescan.
        lastStat = None
        for d in dates:
            l,s=dateSet[d].get('log'), dateSet[d].get('stat')
            if not l or l == self.fname:
                continue
            if not s:
                rescan = 1
            lastStat = d
        if lastStat and not dateSet[lastStat].has_key('pend'):
            rescan = 1

        if rescan:
            if self._loadDepth:
                raise MixError("Recursive rescan")
            self._rescanImpl()
            self._loadDepth += 1
            try:
                self._loadPingStatus()
            finally:
                self._loadDepth -= 1
            return

        try:
            if lastStat:
                rescan = self._loadPingStatusImpl(dateSet[lastStat]['stat'],
                                                  dateSet[lastStat]['pend'],
                                                  self.fname)
            else:
                rescan = self._loadPingStatusImpl(None,None,self.fname)
        except (cPickle.UnpicklingError, OSError, ValueError):
            rescan = 1

        if rescan:
            #XXXX duplicate code.
            if self._loadDepth:
                raise MixError("Recursive rescan")
            self._rescanImpl()
            self._loadDepth += 1
            try:
                self._loadPingStatus()
            finally:
                self._loadDepth -= 1

    def calculateStatistics(self,now=None):
        if now is None:
            now = time.time()
        self.rotate()
        cutoff = previousMidnight(now)-KEEP_HISTORY_DAYS*ONE_DAY
        stats = []
        for fn in os.listdir(self.location):
            date, tp = self._parseFname(fn)
            if tp != 'stat': continue
            if date < cutoff: continue
            if fn == self.fname: continue
            stats.append((date,
                       readPickled(os.path.join(self.location,fn),gzipped=1)))
        stats.sort()
        stats = [ pr for _,pr in stats ]
        self.lock.acquire()
        try:
            stats.append(self.pingStatus.checkPointResults())
        finally:
            self.lock.release()

        stats = calculatePingResults(stats, now)

        self.lock.acquire()
        try:
            self.latestStatistics = stats
        finally:
            self.lock.release()

        return stats

    def getLatestStatistics(self):
        return self.latestStatistics

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

def readPingLog(file):
    results = []
    iteratePingLog(file, lambda t,e,r=results:r.append(t,e))
    return results

class PeriodResults:
    MAGIC = "PeriodResults-0.0"
    def __init__(self, start, end, liveness, serverUptime,
                 serverDowntime, serverStatus,
                 pings, pendingPings):
        self.start = start
        self.end = end
        self.liveness = liveness
        self.serverUptime = serverUptime # nickname->n_sec.
        self.serverDowntime = serverDowntime # nickname->n_sec.
        self.serverStatus = serverStatus
        self.pings = pings # must be a copy.
        self.pendingPings = pendingPings # must be a copy.
        self._version = self.MAGIC

class PingStatus:
    def __init__(self, lastResults=None):
        if lastResults is not None:
            # must copy
            self.start = lastResults.start
            self.liveness = lastResults.liveness
            self.serverUptime = lastResults.serverUptime
            self.pings = lastResults.pings
            self.pendingPings = lastResults.pendingPings
        else:
            self.start = None
            self.liveness = 0 # n_sec
            self.serverUptime = {} # map from nickname->n_sec
            self.serverDowntime = {} # map from nickname->n_sec
            self.pings = {} # map from path->[(sent,received)...]
            self.pendingPings = {} # map from pinghash->(sent,path)

        self.lastEventTime = None
        self.serverStatus = {} # nickname->"U"/"D", as-of
        self.lastUpdated = None

    def checkpointResults(self, _nocopy=0):
        if self.lastEventTime is None:
            return None
        if _nocopy:
            c = lambda x:x
        else:
            c = lambda x:x.copy()
        self.update(self.lastEventTime)
        return PeriodResults(self.start, self.lastEventTime,
                             self.liveness, c(self.serverUptime),
                             c(self.serverDowntime),
                             c(self.serverStatus),
                             c(self.pings),
                             c(self.pendingPings))

    def splitResults(self, _nocopy=0):
        if self.lastEventTime is None:
            return None
        pr = self.checkpointResults(_nocopy=1)
        if _nocopy:
            c = lambda x:x
        else:
            c = lambda x:x.copy()
        self.serverUptime = {}
        self.serverDowntime = {}
        self.serverStatus = c(self.serverStatus)
        self.pings = {}
        self.pendingPings = c(self.pendingPings)
        return pr

    def expirePings(self, cutoff):
        for h,(sent,path) in self.pendingPings.items():
            if sent<cutoff:
                self.pings[path].setdefault(path,[]).append((sent,None))
                del self.pendingPings[h]

    def addEvent(self, tm, event):
        eType = event[0]
        if eType == 'PING':
            self.pendingPings[event[1]] = tm, event[2]
        elif eType == 'GOT_PING':
            h = event[1]
            try:
                tSent, path = self.pendingPing[h]
            except KeyError:
                # we didn't send it, or can't remember sending it.
                LOG.warn("Received a ping I don't remember sending (%s)",
                         event[1])
            else:
                del self.pendingPings[event[1]]
                self.pings.setdefault(path, []).append((tSent,tm))
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
                    self.serverStatus[event[1]] = ('U', tm)
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
                    self.serverStatus[event[1]] = ('U', tm)
        elif eType == 'SHUTDOWN':
            self.diedAt(tm)
        elif eType == 'STARTUP':
            if self.lastEventTime:
                self.diedAt(self.lastEventTime)

        if self.start is None:
            self.start = tm

        self.lastEventTime = tm

    def addFile(self, file):
        iteratePingLog(file, self.addEvent)

    def update(self, liveAt):
        for nickname, (status, tLast) in self.serverStatus.items():
            if status == 'U':
                m = self.serverUptime
            else:
                m = self.serverDowntime
            if liveAt < tLast: continue
            try:
                m[nickname] += liveAt-tLast
            except KeyError:
                m[nickname] = liveAt-tLast

        if self.lastUpdated is not None and self.lastUpdated < liveAt:
            self.liveness += liveAt-self.last

        self.lastUpdated = liveAt

    def diedAt(self, diedAt):
        self.update(diedAt)

        self.serverStatus = {}
        self.lastEventTime = None

class OneDayPingResults:
    #XXXX008 move to ClientDirectory?
    def __init__(self):
        self.start = 0
        self.end = 0
        self.uptime = {} # nickname->pct
        self.reliability = {} # path->pct
        self.latency = {} # path->avg

class PingResults:
    #XXXX008 move to ClientDirectory?
    def __init__(self, days, summary):
        self.days = days # list of OneDayPingResults
        self.summary = summary

GRACE_PERIOD = ONE_DAY
WEIGHT_AGE = [ 5, 10, 10, 10, 10, 9, 8, 5, 3, 2, 2, 1, 0, 0, 0, 0, 0 ]

def calculatePingResults(periods, endAt):
    startAt = previousMidnight(endAt) - ONE_DAY*(USE_HISTORY_DAYS)

    results = [ OneDayPingResults() for _ in xrange(USE_HISTORY_DAYS+1) ]
    summary = OneDayPingResults()
    summary.start = startAt
    summary.end = endAt
    for idx in xrange(USE_HISTORY_DAYS+1):
        results[idx].start = startAt+(ONE_DAY*idx)
        results[idx].end = startAt+(ONE_DAY*idx) - 1

    pingsByDay = [ {} for _ in xrange(USE_HISTORY_DAYS+1) ]
    allPaths = {}
    for p in periods:
        for path,timings in p.pings.items():
            allPaths[path]=1
            for send,recv in timings:
                day = floorDiv(send-startAt, ONE_DAY)
                if day<0: continue
                pingsByDay[day].setdefault(path,[]).append((send,recv))
    for send,path in periods[-1].values():
        if send+GRACE_PERIOD > endAt:
            continue
        day = floorDiv(send-startAt, ONE_DAY)
        if day<0: continue
        pingsByDay[day].setdefault(path,[]).append((send,None))
        allPaths[path]=1

    maxDelay = {}
    delays = {}
    summary.nSent = {}
    summary.nRcvd = {}
    for path in allPaths.keys():
        maxDelay[path] = 0
        delays[path] = []
        summary.nSent[path]=0
        summary.nRcvd[path]=0
    for idx in xrange(KEEP_HISTORY_DAYS+1):
        for path, pings in pingsByDay[idx].keys():
            nRcvd = 0
            nLost = 0
            totalDelay = 0.0
            for (send,recv) in pings:
                if recv is None:
                    nLost += 1
                    continue
                else:
                    nRcvd += 1
                    delay = recv-send
                    totalDelay += delay
                    if delay > maxDelay[path]:
                        maxDelay[path]=delay
                    delays[path].append(delay)
            results[idx].reliability[path] = float(nRcvd)/(nRcvd+nLost)
            results[idx].latency[path] = totalDelay/nRcvd
            summary.nSent[path] += len(pings)
            summary.nRcvd[path] += nRcvd

    totalWeight = {}
    totalWeightReceived = {}
    for path in allPaths.keys():
        delays[path].sort()
        totalWeight[path] = 0
        totalWeightReceived[path] = 0

    for idx in xrange(USE_HISTORY_DAYS+1):
        weightAge = WEIGHT_AGE[idx]
        for path, pings in pingsByDay[-idx].keys():
            if not delays[path]:
                continue
            d = delays[path]
            for send,recv in pings:
                if recv is not None:
                    totalWeightReceived[path] += weightAge
                    totalWeight[path] += weightAge
                else:
                    fracMax = (endAt-send-15*60) * 0.8
                    weightLatent = (bisect.bisect(d, fracMax)/len(d))
                    totalWeight[path] += weightLatent*weightAge

    for path in allPaths.keys():
        if not totalWeight[path]:
            summary.reliability[path]=None
            continue
        summary.reliability[path] = (
            (float(totalWeightReceived[path])/totalWeight[path]))
        d = delays[path]
        summary.latency[path] = d[floorDiv(len(d),2)]

    allServers = {}
    for p in periods:
        for s in p.serverUptime.keys(): allServers[s]=1
        for s in p.serverDowntime.keys(): allServers[s]=1

    for s in allServers.keys():
        upTotal = 0
        downTotal = 0
        for p in periods:
            day = floorDiv(p.start-startAt, ONE_DAY)
            if day<0: continue
            up = p.serverUptime.get(s,0)
            down = p.serverUptime.get(s,0)
            upTotal += up
            downTotal += down
            if up+down < 60*60:
                continue
            results[day].uptime[s] = float(up)/(up+down)
        if upTotal+downTotal < 60*60: continue
        summary.uptime[s] = float(upTotal)/(upTotal+downTotal)

    return PingResults(results, s)

class PingGenerator:
    """DOCDOC"""
    #XXXX008 add abstract functions.
    def __init__(self, config):
        self.directory = None
        self.pingLog = None
        self.outgoingQueue = None
        self.myNickname = config['Server']['Nickname']
        self.latestStatistics = None

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
    def _getPingInterval(self, path):
        raise NotImplemented()
    def _schedulePing(self,path,now=None):
        if now is None: now = time.time()
        periodStart = self._getPeriodStart(now)
        interval = self._getPingInterval(path)
        t = periodStart + self._getPerturbation(path, periodStart, interval)
        t += interval * ceilDiv(now-t, interval)
        if t>periodStart+self.PERIOD:
            t = periodStart+self.PERIOD+self._getPerturbation(path,
                                                    periodStart+self.PERIOD,
                                                              interval)
        self.nextPingTime[path] = t
        LOG.trace("Scheduling %d-hop ping for %s at %s", len(path),
                  ",".join(path), formatTime(t,1))
        return t
    def _getPerturbation(self, path, periodStart, interval):
        sha = mixminion.Crypto.sha1(",".join(path) + "@@" + str(interval))
        sec = abs(struct.unpack("I", sha[:4])[0]) % interval
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
    PERIOD = ONE_DAY
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

    def _getInterval(self, path):
        return self.PING_INTERVAL

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
    DULL_INTERVAL = 4*ONE_DAY
    INTERESTING_INTERVAL = ONE_DAY
    PERIOD = 8*ONE_DAY
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

    def _getPingInterval(self, path):
        stats = self.pingLog.getLatestStatistics()
        if stats is None:
            return self.DULL_INTERVAL
        pStr = ",".join(path)
        nSent = stats.summary.nSent.get(pStr,0)
        nRcvd = stats.summary.nRcvd.get(pStr,0)
        assert nRcvd <= nSent
        if nSent < 3 and nRcvd < 1:
            return self.INTERESTING_INTERVAL
        try:
            rel1 = stats.summary.reliability[path[0]]
            rel2 = stats.summary.reliability[path[1]]
        except KeyError:
            return self.DULL_INTERVAL

        if float(nRcvd)/nSent <= rel1*rel2*0.3:
            return self.INTERESTING_INTERVAL
        else:
            return self.DULL_INTERVAL

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
    pingers.append(TwoHopPingGenerator(config))
    pingers.append(TestLinkPaddingGenerator(config))
    return CompoundPingGenerator(pingers)
