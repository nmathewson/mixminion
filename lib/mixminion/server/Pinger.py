# Copyright 2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Pinger.py,v 1.8 2004/12/02 23:39:02 nickm Exp $

"""mixminion.server.Pinger

   Built-in network reliability tester (pinger) for Mixminion servers.

   Our pinger uses a three-part architecture.  First, we periodically
   consider adding testing packets to the outgoing batches.

   Second, we note the outcome of connection attempts; and the timing
   of our sending/receiving test packets.

   Third, we use the timing/uptime information in the second part
   above to try to infer how reliable the other nodes in the network
   are.

   This module requires python 2.2 or later, and the sqlite module.
"""

import bisect
import calendar
import cPickle
import os
import re
import string
import struct
import sys
import threading
import time

import mixminion.BuildMessage
import mixminion.Crypto
import mixminion.Packet
import mixminion.ServerInfo
import mixminion.server.PacketHandler
import mixminion.server.MMTPServer

from mixminion.Common import MixError, ceilDiv, createPrivateDir, \
     floorDiv, formatBase64, formatFnameDate, formatTime, IntervalSet, LOG, \
     parseFnameDate, previousMidnight, readPickled, secureDelete, writePickled

try:
    import sqlite
except ImportError:
    sqlite = None

KEEP_HISTORY_DAYS = 15
USE_HISTORY_DAYS = 12
HEARTBEAT_INTERVAL = 30*60
ONE_DAY = 24*60*60

# Map from logical type to type used in (sqlite) database.
REALTYPES = { 'time'    : 'integer',
              'boolean' : 'integer',
              'integer' : 'integer',
              'float'   : 'float',
              'varchar' : 'varchar',
              }


_MERGE_ITERS_CODE = """
_MERGE_DONE = object()
def _wrapNext(next,DONE=_MERGE_DONE):
    def fn():
        try:
            return next()
        except StopIteration:
            return DONE
    return fn
def _mergeIters(iterable1, iterable2):
    DONE = _MERGE_DONE
    n1 = _wrapNext(iter(iterable1).next)
    n2 = _wrapNext(iter(iterable2).next)
    peek1 = n1()
    peek2 = n2()
    while peek1 is not DONE and peek2 is not DONE:
        if peek1 <= peek2:
            yield peek1
            peek1 = n1()
        else:
            yield peek2
            peek2 = n2()
    while peek1 is not DONE:
        yield peek1
        peek1 = n1()
    while peek2 is not DONE:
        yield peek2
        peek2 = n2()
"""

if sys.version_info[:2] >= (2,2):
    exec _MERGE_ITERS_CODE

WEIGHT_AGE_PERIOD = 24*60*60
WEIGHT_AGE = [ 5, 10, 10, 10, 10, 9, 8, 5, 3, 2, 2, 1, 0, 0, 0, 0, 0 ]
UPTIME_GRANULARITY = 24*60*60
PING_GRANULARITY = 24*60*60

class PingLog:
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.cursor()
        self.lock = threading.RLock()
        self.serverNames = {}
        self.serverReliability = {}
        self._createAllTables()

    def _objectExists(self, name, objType):
        # hold lock.
        self.cursor.execute(
            "SELECT * FROM SQLITE_MASTER WHERE type = %s AND name = %s",
            (objType,name))
        rs = self.cursor.fetchall()
        return len(rs) > 0

    def _createTable(self, name, rows):
        # hold lock
        if self._objectExists(name,"table"):
            return

        body = []
        for r in rows:
            if len(r) == 2:
                body.append("%s %s"%(r[0],REALTYPES[r[1]]))
            else:
                assert len(r) == 3
                body.append("%s %s %s"%(r[0],REALTYPES[r[1]],r[2]))

        stmt = "CREATE TABLE %s (%s)" % (name,", ".join(body))
        self.cursor.execute(stmt)
        self.connection.commit()

    def _createIndex(self, name, tablename, columns, unique=0):
        #hold lock
        if self._objectExists(name, "index"):
            return

        if unique:
            u = "UNIQUE "
        else:
            u = ""
        stmt = "CREATE %sINDEX %s ON %s (%s)"%(
            u, name, tablename, ", ".join(columns))
        self.cursor.execute(stmt)
        self.connection.commit()

    def _createAllTables(self):
        cur = self.cursor
        self.lock.acquire()
        try:
            # Raw data
            self._createTable("lifetimes",
                              [("up",       "time", "not null"),
                               ("stillup",  "time"),
                               ("shutdown", "boolean")])
            self._createTable("pings",
                              [("hash",     "varchar", "primary key"),
                               ("path",     "varchar", "not null"),
                               ("sentat",   "time",    "not null"),
                               ("received", "time")])
            self._createTable("connects",
                              [("at",       "time", "not null"),
                               ("server",   "varchar", "not null"),
                               ("success",  "boolean", "not null")])
            self._createTable("servers",
                              [("name", "varchar", "unique not null")])
            # Results
            self._createTable("uptimes",
                              [("start", "time", "not null"),
                               ("end",   "time", "not null"),
                               ("name",  "varchar", "not null"),
                               ("uptime", "float", "not null")])
            self._createTable("echolotOneHops",#XXXX008 NOT RIGHT!
                              [("servername",  "time", "not null"),
                               ("at",          "time", "not null"),
                               ("latency",     "integer", "not null"),
                               ("wreliability","float", "not null")])

            self._createIndex("lifetimesUp", "lifetimes", ["up"])
            self._createIndex("pingsHash",   "pings", ["hash"], unique=1)
            # ???? what else on pings?
            self._createIndex("connectsAt", "connects", ["at"])
        finally:
            self.lock.release()

    def _loadServers(self):
        # hold lock.
        self.serverNames = {}
        cur = self.cursor
        cur.execute("SELECT name FROM servers")
        res = cur.fetchall()
        for name, in res:
            self.serverNames[name] = 1

        cur.execute("SELECT servername, MAX(at), wreliablity FROM"
                    " echolotOneHops")
        res = cur.fetchall()
        for name,_,rel in res:
            self.reliability[name]=rel

    def _addServer(self, name):
        # hold lock.
        name = name.lower()
        if self.serverNames.has_key(name):
            return
        self.cursor.execute("INSERT INTO servers (name) VALUES (%s)", name)
        self.serverNames[name] = 1

    def rotate(self, now=None):
        self.lock.acquire()
        if now is None: now = time.time()
        cutoff = self._time(now - KEEP_HISTORY_DAYS * ONE_DAY)
        cur = self.cursor
        try:
            cur.execute("DELETE FROM lifetimes WHERE stillup < %s", cutoff)
            cur.execute("DELETE FROM pings WHERE sentat < %s", cutoff)
            cur.execute("DELETE FROM connects WHERE at < %s", cutoff)
            self.connection.commit()
        finally:
            self.lock.release()

    def flush(self):
        self.lock.acquire()
        try:
            self.connection.commit()
        finally:
            self.lock.release()

    def close(self):
        self.lock.acquire()
        try:
            self.connection.close()
            del self.connection
        finally:
            self.lock.release()

    def _execute(self, sql, args):
        self.lock.acquire()
        try:
            self.cursor.execute(sql, args)
        finally:
            self.lock.release()

    def _time(self, t=None):
        return long(t or time.time())

    _STARTUP = "INSERT INTO lifetimes (up, stillup, shutdown) VALUES (%s,%s, 0)"
    def startup(self,now=None):
        self._startTime = now = self._time(now)
        self._execute(self._STARTUP, (now,now))

    _SHUTDOWN = "UPDATE lifetimes SET stillup = %s, shutdown = %s WHERE up = %s"
    def shutdown(self, now=None):
        if self._startTime is None: self.startup()
        now = self._time(now)
        self._execute(self._SHUTDOWN, (now, now, self._startTime))

    _HEARTBEAT = "UPDATE lifetimes SET stillup = %s WHERE up = %s"
    def heartbeat(self, now=None):
        if self._startTime is None: self.startup()
        self._execute(self._HEARTBEAT, (self._time(now), self._startTime))

    def rotated(self):
        pass

    _CONNECTED = ("INSERT INTO connects (at, server, success) "
                  "VALUES (%s,%s,%s)")
    def connected(self, nickname, success=1, now=None):
        self.lock.acquire()
        try:
            self._addServer(nickname)
            self._execute(self._CONNECTED,
                      (self._time(now), nickname.lower(), success))
        finally:
            self.lock.release()

    def connectFailed(self, nickname):
        self.connected(nickname, 0)

    _QUEUED_PING = ("INSERT INTO pings (hash, path, sentat, received)"
                    "VALUES (%s,%s,%s,%s)")
    def queuedPing(self, hash, path, now=None):
        assert len(hash) == mixminion.Crypto.DIGEST_LEN
        self.lock.acquire()
        try:
            path = path.lower()
            for s in path.split(","):
                self._addServer(s)
            self._execute(self._QUEUED_PING,
                          (formatBase64(hash), path, self._time(now), 0))
        finally:
            self.lock.release()

    _GOT_PING = "UPDATE pings SET received = %s WHERE hash = %s"
    def gotPing(self, hash, now=None):
        assert len(hash) == mixminion.Crypto.DIGEST_LEN
        n = self._execute(self._GOT_PING, (self._time(now), formatBase64(hash)))
        if n == 0:
            LOG.warn("Received ping with no record of its hash")
        elif n > 1:
            LOG.warn("Received ping with multiple hash entries!")

    def calculateUptimes(self, startTime, endTime):
        cur = self.cursor
        self.lock.acquire()

        try:
            cur.execute("DELETE FROM uptimes WHERE start = %s AND end = %s",
                        startTime, endTime)

            # First, calculate my own uptime.
            self.heartbeat()

            timespan = IntervalSet( [(startTime, endTime)] )

            cur.execute("SELECT up, stillup, shutdown FROM lifetimes WHERE "
                        "up <= %s AND stillup >= %s",
                        self._time(endTime), self._time(startTime))
            myUptime = 0
            myIntervals = IntervalSet([ (start, max(end,shutdown))
                                        for start,end,shutdown in cur ])
            myIntervals *= timespan
            myUptime = myIntervals.spanLength()

            cur.execute("INSERT INTO uptimes (start, end, name, uptime)"
                        " VALUES (%s, %s, '<self>', %s)",
                        (self._time(startTime), self._time(endTime),
                         float(myUptime)/(endTime-startTime)))

            # Okay, now everybody else.
            for s in self.serverNames.keys():
                cur.execute("SELECT at, success FROM connects"
                            " WHERE server = %s AND at >= %s AND at <= %s"
                            " ORDER BY at",
                            s, startTime, endTime)

                lastStatus = None
                lastTime = None
                times = [ 0, 0] # uptime, downtime
                for at, success in cur:
                    assert success in (0,1)
                    upAt, downAt = myIntervals.getIntervalContaining(at)
                    if upAt == None:
                        # Event at edge of interval
                        #XXXX008 warn better?
                        LOG.warn("Event out of bounds")
                        continue
                    if lastTime is None or upAt > lastTime:
                        lastTime = upAt
                        lastStatus = None
                    if lastStatus is not None:
                        t = (at-lastTime)/2.0
                        times[success] += t
                        times[lastStatus] += t

                if times == [0,0]:
                    continue
                fraction = float(times[1])/(times[0]+times[1])
                print "Adding ",name,fraction
                cur.execute("INSERT INTO uptimes (start, end, name, uptime)"
                            " VALUES (%s, %s, %s, %s)",
                            (startTime, endTime, s, fraction))
            self.connection.commit()
        finally:
            self.lock.release()

    def getUptimes(self, startAt, endAt):
        """DODOC: uptimes for all servers overlapping [startAt, endAt],
           as mapping from (start,end) to nickname to fraction.
        """
        result = {}
        cur = self.cursor
        self.lock.acquire()
        try:
            cur.execute("SELECT start, end, name, uptime FROM uptimes "
                        "WHERE %s >= start AND %s <= end",
                        (self._time(startAt), self._time(endAt)))
            for s,e,n,u in cur:
                result.setdefault((s,e), {})[n] = u
            return result
        finally:
            self.lock.release()

    def _calculateOneHopResults(self, serverName, startTime, now=None):
        # hold lock; commit when done.
        cur = self.cursor
        GRANULARITY = PING_GRANULARITY
        if now is None:
            now = time.time()
        nPeriods = ceilDiv(now-startTime, GRANULARITY)
        nSent = [0]*nPeriods
        nReceived = [0]*nPeriods
        totalWeights = 0.0
        totalWeighted = 0.0
        perTotalWeights = [0]*nPeriods
        perTotalWeighted = [0]*nPeriods
        allLatentcies = []
        nPings = 0
        cur.execute("SELECT sentat, received FROM pings WHERE path = %s"
                    " AND sentat >= %s AND sentat <= %s",
                    (serverName, startTime, now ))
        for sent,received in cur:
            nPings += 1
            if received:
                allLatencies.append(received-sent)
        allLatencies.sort()

        cur.execute("SELECT sentat, received FROM pings WHERE path = %s"
                    " AND sentat >= %s AND sentat <= %s",
                    (serverName, startTime, now ))
        for sent,received in cur:
            pIdx = floorDiv(sent-startTime, GRANULARITY)
            nSent[pIdx] += 1
            if received:
                nReceived[pIdx] += 1
                w2 = 1
            else:
                mod_age = (now-sent-15*60)*0.8
                w2 = bisect.bisect_left(allLatencies, mod_age)/float(nPings)

            if pIdx < len(WEIGHT_AGE):
                w1 = WEIGHT_AGE[nPeriods-pIdx-1]
            else:
                w1 = 0

            perTotalWeights[pIdx] += w1*w2
            if received:
                perTotalWeighted[pIdx] += w1*w2

        allLatencies.sort()
        if allLatencies:
            latency = allLatencies[floorDiv(len(allLatencies),2)]
        else:
            latency = 0

        reliability = reduce(operator.add, perTotalWeighted)/float(
            reduce(operator.add, perTotalWeights))

        cur.execute("INSERT INTO echolotOneHops (servername, at, latency,"
                    " wreliability) VALUES (%s, %s, %s, %s)",
                    (serverName, now, latency, reliability))

    def _calculateChainCounts(self, startAt, endAt, path):
        # hold lock.
        cur.execute("SELECT count() FROM pings WHERE path = %s"
                    " AND sent >= %s AND sent <= %s",
                    (path,startAt,endAt))
        nSent, = cur.fetchone()
        cur.execute("SELECT count() FROM pings WHERE path = %s"
                    " AND sent >= %s AND sent <= %s AND received > 0",
                    (path,startAt,endAt))
        nReceived, = cur.fetchone()

        servers = path.split(",")
        try:
            rels = [ self.reliability[s] for s in servers ]
            product = reduce(operator.mul, rels)
        except IndexError:
            product = None

        return nSent, nReceived, product

    def _2chainIsBroken(self, startAt, endAt, path):
        #lock
        nSent, nReceived, product = self._calculateChainCounts()
        frac = float(nReceived)/nSent
        return nSent >= 3 and product is not None and frac <= product*0.3

    def _2chainIsInteresting(self, startAt, endAt, path):
        #lock
        nSent, nReceived, product = self._calculateChainCounts()
        frac = float(nReceived)/nSent
        return (nSent < 3 and nReceived == 0) or (
            product is not None and frac <= product*0.3)

    def calculateDailyResults(self, server):
        #XXXX
        pass

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
        raise NotImplemented
    def _getPeriodStart(self, t):
        raise NotImplemented
    def _getPingInterval(self, path):
        raise NotImplemented
    def _schedulePing(self,path,now=None):
        if now is None: now = int(time.time())
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

class OneHopPingGenerator(_PingScheduler,PingGenerator):
    """DOCDOC"""
    #XXXX008 make this configurable, but not less than 2 hours.
    PING_INTERVAL = 2*60*60
    PERIOD = ONE_DAY
    def __init__(self, config):
        PingGenerator.__init__(self, config)
        _PingScheduler.__init__(self)

    def scheduleAllPings(self, now=None):
        if now is None: now = int(time.time())
        servers = self.directory.getAllServers()
        nicknames = {}
        for s in servers:
            nicknames[s.getNickname()]=1
        for n in nicknames.keys():
            self._schedulePing((n,),now)

    def _getPeriodStart(self, t):
        return previousMidnight(t)

    def _getPingInterval(self, path):
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

class TwoHopPingGenerator(_PingScheduler, PingGenerator):
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
            #XXXX008 we need to reschedule pings when a new directory arrives

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

def canRunPinger():
    """DOCDOC"""
    return sys.version_info[:2] >= (2,2) and sqlite is not None

def openPingLog(location):
    # FFFF eventually, we should maybe support more than pysqlite.  But let's
    # FFFF not generalize until we have a 2nd case.
    return PingLog(sqlite.connect(location))
