# Copyright 2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Pinger.py,v 1.12 2004/12/11 02:48:54 nickm Exp $

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
import operator
import os
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

from mixminion.Common import MixError, AtomicFile, ceilDiv, createPrivateDir, \
     floorDiv, formatBase64, formatFnameDate, formatTime, IntervalSet, LOG, \
     parseFnameDate, previousMidnight, readPickled, secureDelete, \
     succeedingMidnight, writePickled

try:
    import sqlite
except ImportError:
    sqlite = None

KEEP_HISTORY_DAYS = 15
HEARTBEAT_INTERVAL = 30*60
ONE_DAY = 24*60*60

# Map from logical type to type used in (sqlite) database.
REALTYPES = { 'time'    : 'integer',
              'boolean' : 'integer',
              'integer' : 'integer',
              'float'   : 'float',
              'varchar' : 'varchar',
              }

class PingerIntervalSchedule:
    """DOCDOC -- defines a set of intervals in time."""
    def __init__(self):
        pass
    def getIntervalContaining(self, t):
        p = previousMidnight(t)
        return p, succeedingMidnight(p)
    def getIntervals(self, startAt, endAt):
        r = []
        t = previousMidnight(startAt)
        while t < endAt:
            n = succeedingMidnight(t)
            r.append((t, n))
            t = n
        return r

class _SQLiteMixin:
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

    def _time(self, t=None):
        return long(t or time.time())

    def _bool(self, b):
        if b:
            return 1
        else:
            return 0

    def _getInsertOrUpdateFn(self, table, keyCols, valCols):
        update = "UPDATE %s SET %s WHERE %s" % (
            table,
            ", ".join(["%s = %%s" % k for k in valCols]),
            " AND ".join(["%s = %%s" % v for v in keyCols]))
        insert = "INSERT INTO %s (%s, %s) VALUES (%s)" % (
            table,
            ", ".join(keyCols),
            ", ".join(valCols),
            ", ".join(["%s"]*(len(valCols)+len(keyCols))))
        def fn(keyVals, valVals):
            assert len(keyVals) == len(keyCols)
            assert len(valVals) == len(valCols)

            self.cursor.execute(update, (valVals+keyVals))
            if self.cursor.rowcount > 0:
                return

            self.cursor.execute(insert, (keyVals+valVals))
        return fn

class PingLog(_SQLiteMixin):
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.cursor()
        self.lock = threading.RLock()
        self.serverNames = {}
        self.serverReliability = {}
        self.uptimeIntervals = PingerIntervalSchedule()
        self.pingIntervals = PingerIntervalSchedule()
        self.brokenChains = {}
        self.interestingChains = {}
        self._startTime = None
        self._lastRecalculation = 0
        self._createAllTables()
        self._loadServers()

    def _createAllTables(self):
        self.lock.acquire()
        try:
            # FFFF This is terrible DB design.  It's not normalized by
            # FFFF any stretch of the imagination, it doesn't have enough
            # FFFF constraints, etc etc.
            # Raw data
            self._createTable("lifetimes",
                              [("up",       "time", "not null"),
                               ("stillup",  "time"),
                               ("shutdown", "time")])
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
            self._createTable("echolotOneHopResults",
                              [("servername",  "varchar", "not null"),
                               ("startAt",     "time",    "not null"),
                               ("endAt",       "time",    "not null"),
                               ("nSent",       "integer", "not null"),
                               ("nReceived",   "integer", "not null"),
                               ("latency",     "integer", "not null"),
                               ("wsent",       "float",   "not null"),
                               ("wreceived",   "float",   "not null"),
                               ("reliability", "float",   "not null")])
            self._createTable("echolotCurrentOneHopResults",
                              [("servername",  "varchar", "unique not null"),
                               ("at",          "time",    "not null"),
                               ("latency",     "integer", "not null"),
                               ("reliability", "float",   "not null")])
            self._createTable("echolotCurrentTwoHopResults",
                              [("path",        "varchar", "unique not null"),
                               ("at",          "time",    "not null"),
                               ("nSent",       "integer", "not null"),
                               ("nReceived",   "integer", "not null"),
                               ("broken",      "boolean", "not null"),
                               ("interesting", "boolean", "not null")])

            self._createIndex("lifetimesUp", "lifetimes", ["up"])
            self._createIndex("pingsHash",   "pings", ["hash"], unique=1)
            self._createIndex("pingsPathSR", "pings",
                              ["path", "sentat", "received"])
            self._createIndex("connectsAt", "connects", ["at"])
            self._createIndex("uptimesNS", "uptimes", ["name", "start"])
            # indices on echolot*results, uptimes.

            self._setUptime = self._getInsertOrUpdateFn(
                "uptimes", ["start", "end", "name"], ["uptime"])
            self._setOneHop = self._getInsertOrUpdateFn(
                "echolotOneHopResults",
                ["servername", "startAt", "endAt"],
                ["nSent", "nReceived", "latency", "wsent", "wreceived",
                 "reliability"])
            self._setCurOneHop = self._getInsertOrUpdateFn(
                "echolotCurrentOneHopResults",
                ["servername"],
                ["at", "latency", "reliability"])
            self._setTwoHop = self._getInsertOrUpdateFn(
                "echolotCurrentTwoHopResults",
                ["path"],
                ["at", "nSent", "nReceived", "broken", "interesting"])
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

        cur.execute("SELECT servername, reliability FROM "
                    "echolotCurrentOneHopResults")
        res = cur.fetchall()
        for name,rel in res:
            self.serverReliability[name]=rel

        cur.execute("SELECT path, broken, interesting FROM "
                    "echolotCurrentTwoHopResults WHERE interesting OR broken")
        res = cur.fetchall()
        broken = {}
        interesting = {}
        for p, b, i in res:
            if b:
                broken[p]=1
            if i:
                interesting[p]=1
        self.isBroken = broken
        self.isInteresting = interesting

    def updateServers(self, names):
        self.lock.acquire()
        try:
            for n in names:
                self._addServer(n)
        finally:
            self.lock.release()

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

    _STARTUP = "INSERT INTO lifetimes (up, stillup, shutdown) VALUES (%s,%s, 0)"
    def startup(self,now=None):
        self._startTime = now = self._time(now)
        self._execute(self._STARTUP, (now,now))

    _SHUTDOWN = "UPDATE lifetimes SET stillup = %s, shutdown = %s WHERE up = %s"
    def shutdown(self, now=None):
        if self._startTime is None: self.startup()
        now = self._time(now)
        self._execute(self._SHUTDOWN, (now, now, self._startTime))

    _HEARTBEAT = "UPDATE lifetimes SET stillup = %s WHERE up = %s AND stillup < %s"
    def heartbeat(self, now=None):
        if self._startTime is None: self.startup()
        now = self._time(now)
        self._execute(self._HEARTBEAT, (now, self._startTime, now))

    def rotated(self):
        pass

    _CONNECTED = ("INSERT INTO connects (at, server, success) "
                  "VALUES (%s,%s,%s)")
    def connected(self, nickname, success=1, now=None):
        self.lock.acquire()
        try:
            self._addServer(nickname)
            self._execute(self._CONNECTED,
                    (self._time(now), nickname.lower(), self._bool(success)))
        finally:
            self.lock.release()

    def connectFailed(self, nickname, now=None):
        self.connected(nickname, success=0, now=now)

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

    def _calculateUptimes(self, startTime, endTime, now=None):
        cur = self.cursor
        self.lock.acquire()
        try:
            # First, calculate my own uptime.
            if now is None: now = time.time()
            self.heartbeat(now)

            timespan = IntervalSet( [(startTime, endTime)] )

            cur.execute("SELECT up, stillup, shutdown FROM lifetimes WHERE "
                        "up <= %s AND stillup >= %s",
                        self._time(endTime), self._time(startTime))
            myUptime = 0
            myIntervals = IntervalSet([ (start, max(end,shutdown))
                                        for start,end,shutdown in cur ])
            myIntervals *= timespan
            myUptime = myIntervals.spanLength()
            fracUptime = float(myUptime)/(endTime-startTime)
            self._setUptime(
                (self._time(startTime), self._time(endTime), "<self>"),
                (fracUptime,))

            # Okay, now everybody else.
            for s in self.serverNames.keys():
                cur.execute("SELECT at, success FROM connects"
                            " WHERE server = %s AND at >= %s AND at <= %s"
                            " ORDER BY at",
                            s, startTime, endTime)

                lastStatus = None
                lastTime = None
                times = [ 0, 0 ] # uptime, downtime
                for at, success in cur:
                    assert success in (0,1)
                    upAt, downAt = myIntervals.getIntervalContaining(at)
                    if upAt == None:
                        # Event outside edge of interval.
                        continue
                    if lastTime is None or upAt > lastTime:
                        lastTime = upAt
                        lastStatus = None
                    if lastStatus is not None:
                        t = (at-lastTime)/2.0
                        times[success] += t
                        times[lastStatus] += t
                    lastStatus = success
                    lastTime = at

                if times == [0,0]:
                    continue
                fraction = float(times[1])/(times[0]+times[1])
                self._setUptime((startTime, endTime, s), (fraction,))
            self.connection.commit()
        finally:
            self.lock.release()

    def calculateUptimes(self, startAt, endAt, now=None):
        if now is None: now = time.time()
        for s, e in self.uptimeIntervals.getIntervals(startAt, endAt):
            self._calculateUptimes(s, e, now=now)

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

    def _roundLatency(self, latency):
        """Using a median latency can leak the fact that a message was a
           ping. DOCDOC"""
        for cutoff, q in [
            (60, 5), (10*60, 60), (30*60, 2*60),
            (60*60, 5*60), (3*60*60, 10*60), (12*60*60, 20*60),
            (24*60*60, 30*60) ]:
            if latency < cutoff:
                quantum = q
                break
        else:
            quantum = 60*60

        return int( float(latency)/quantum + 0.5 ) * quantum

    _WEIGHT_AGE_PERIOD = 24*60*60
    _WEIGHT_AGE = [ 1, 2, 2, 3, 5, 8, 9, 10, 10, 10, 10, 5 ]
    _PING_GRANULARITY = 24*60*60
    def _calculateOneHopResults(self, serverName, startTime, endTime,
                                now=None, calculateOverallResults=1):
        # hold lock; commit when done.
        cur = self.cursor
        if now is None:
            now = time.time()
        self._addServer(serverName)
        if calculateOverallResults:
            startTime = min(startTime,
                       now - (len(self._WEIGHT_AGE)*self._WEIGHT_AGE_PERIOD))
            endTime = max(endTime, now)
        intervals = self.pingIntervals.getIntervals(startTime, endTime)
        nPeriods = len(intervals)
        startTime = intervals[0][0]
        endTime = intervals[-1][1]

        # 1. Compute latencies and number of pings sent in each period.
        #    We need to learn these first so we can tell the percentile
        #    of each ping's latency.
        dailyLatencies = [[] for _ in xrange(nPeriods)]
        nSent = [0]*nPeriods
        nPings = 0
        cur.execute("SELECT sentat, received FROM pings WHERE path = %s"
                    " AND sentat >= %s AND sentat <= %s",
                    (serverName, startTime, endTime))
        for sent,received in cur:
            pIdx = floorDiv(sent-startTime, self._PING_GRANULARITY)
            nSent[pIdx] += 1
            nPings += 1
            if received:
                dailyLatencies[pIdx].append(received-sent)

        dailyMedianLatency = []
        allLatencies = []
        for d in dailyLatencies:
            d.sort()
            if d:
                dailyMedianLatency.append(d[floorDiv(len(d), 2)])
            else:
                dailyMedianLatency.append(0)
            allLatencies.extend(d)
            del d
        del dailyLatencies
        allLatencies.sort()
        #if allLatencies:
        #    LOG.warn("%s pings in %s intervals. Median latency is %s seconds",
        #             nPings, nPeriods,
        #             allLatencies[floorDiv(len(allLatencies),2)])

        # 2. Compute the number of pings actually received each day,
        #    and the number of pings received each day weighted by
        #    apparent-latency percentile.
        nReceived = [0]*nPeriods
        perTotalWeights = [0]*nPeriods
        perTotalWeighted = [0]*nPeriods
        cur.execute("SELECT sentat, received FROM pings WHERE path = %s"
                    " AND sentat >= %s AND sentat <= %s",
                    (serverName, startTime, endTime))
        for sent,received in cur:
            pIdx = floorDiv(sent-startTime, self._PING_GRANULARITY)
            if received:
                nReceived[pIdx] += 1
                w = 1.0
            else:
                mod_age = (now-sent-15*60)*0.8
                w = bisect.bisect_left(allLatencies, mod_age)/float(nPings)
                #LOG.warn("Percentile is %s.", w)

            perTotalWeights[pIdx] += w
            if received:
                perTotalWeighted[pIdx] += w

        # 2b. Write per-day results into the DB.
        for pIdx in xrange(len(intervals)):
            s, e = intervals[pIdx]
            latent = self._roundLatency(dailyMedianLatency[pIdx])
            sent = nSent[pIdx]
            rcvd = nReceived[pIdx]
            wsent = perTotalWeights[pIdx]
            wrcvd = perTotalWeighted[pIdx]
            if wsent:
                rel = wrcvd / wsent
            else:
                rel = 0.0
            #if sent:
            #    LOG.warn("Of pings sent on day %s, %s/%s were received. "
            #             "rel=%s/%s=%s",
            #             pIdx, rcvd, sent, wrcvd, wsent, rel)
            self._setOneHop(
                (serverName, self._time(s), self._time(e)),
                (sent, rcvd, latent, wsent, wrcvd, rel))

        if not calculateOverallResults:
            return

        # 3. Write current overall results into the DB.
        if allLatencies:
            latent = self._roundLatency(allLatencies[floorDiv(len(allLatencies),2)])
        else:
            latent = 0
        wsent = wrcvd = 0.0
        nPeriods = len(self._WEIGHT_AGE)
        perTotalWeights = perTotalWeights[-nPeriods:]
        perTotalWeighted = perTotalWeighted[-nPeriods:]
        for s, r, w in zip(perTotalWeights, perTotalWeighted, self._WEIGHT_AGE):
            wsent += s*w
            wrcvd += r*w
        if wsent:
            rel = wrcvd / wsent
        else:
            rel = 0.0
        self._setCurOneHop((serverName,), (self._time(now), latent, rel))
        self.serverReliability[serverName] = rel

    def calculateOneHopResults(self, now=None):
        self.lock.acquire()
        try:
            if now is None:
                now = time.time()
            for s in self.serverNames.keys():
                # For now, always calculate overall results.
                self._calculateOneHopResults(s,now,now,now,
                                             calculateOverallResults=1)
            self.connection.commit()
        finally:
            self.lock.release()

    def _calculate2ChainStatus(self, since, path, now=None):
        # hold lock.
        cur = self.cursor
        cur.execute("SELECT count() FROM pings WHERE path = %s"
                    " AND sentat >= %s",
                    (path,self._time(since)))
        nSent, = cur.fetchone()
        cur.execute("SELECT count() FROM pings WHERE path = %s"
                    " AND sentat >= %s AND received > 0",
                    (path,since))
        nReceived, = cur.fetchone()

        servers = path.split(",")
        try:
            rels = [ self.serverReliability[s] for s in servers ]
            product = reduce(operator.mul, rels)
        except KeyError:
            product = None

        if nSent == 0:
            frac = 0.0
        else:
            frac = float(nReceived)/nSent

        isBroken = nSent >= 3 and product and frac <= product*0.3
        isInteresting = ((nSent < 3 and nReceived == 0) or
                         (product and frac <= product*0.3))

        return nSent, nReceived, product, isBroken, isInteresting

    _CHAIN_PING_HORIZON = 12*ONE_DAY
    def calculateChainStatus(self, now=None):
        self.lock.acquire()
        try:
            if now is None:
                now = time.time()
            brokenChains = {}
            interestingChains = {}
            since = now - self._CHAIN_PING_HORIZON

            for s1 in self.serverNames.keys():
                for s2 in self.serverNames.keys():
                    p = "%s,%s" % (s1, s2)

                    nS, nR, prod, isBroken, isInteresting = \
                        self._calculate2ChainStatus(since, p)
                    if isBroken:
                        brokenChains[p] = 1
                    if isInteresting:
                        interestingChains[p] = 1
                    self._setTwoHop((p,),
                           (self._time(now), nS, nR, self._bool(isBroken),
                            self._bool(isInteresting)))

            self.isBroken = isBroken
            self.isInteresting = isInteresting
        finally:
            self.lock.release()

    def dumpAllStatus(self,f,since,now=None):
        self.lock.acquire()
        try:
            if now is None: now = time.time()
            print >>f, "# List of all currently tracked servers."
            print >>f, "KNOWN_SERVERS =",self.serverNames.keys()
            cur = self.cursor

            print >>f, "\n# Map from server to list of (period-start, period-end, fractional uptime"
            print >>f, "SERVER_UPTIMES = {"
            cur.execute("SELECT start,end,name,uptime FROM uptimes "
                        "WHERE start >= %s AND end <= %s"
                        "ORDER BY name, start", (since, now))
            lastServer = "---"
            for s,e,n,u in cur:
                if n != lastServer:
                    if lastServer != '---': print >>f, "   ],"
                    lastServer = n
                    print >>f, "   %r : [" % n
                print >>f, "      (%s,%s,%.04f),"%(s,e,u)
            if lastServer != '---': print >>f, "   ]"
            print >>f, "}"

            print >>f, """
# Map from server name to list of (period-start, period-end, # pings sent,
#      # of those pings received, median latency on those pings (sec),
#      weighted reliability)"""
            print >>f, "SERVER_DAILY_PING_STATUS = {"
            cur.execute("SELECT servername,startAt,endAt,nSent,nReceived,"
                        "  latency,reliability FROM echolotOneHopResults "
                        "WHERE startat >= %s AND endat <= %s"
                        "ORDER BY servername, startat", (since, now))
            lastServer = "---"
            for n,s,e,nS,nR,lat,r in cur:
                if n != lastServer:
                    if lastServer != '---': print >>f, "   ],"
                    lastServer = n
                    print >>f, "   %r : [" % n
                print >>f, "      (%s,%s,%s,%s,%s,%.04f),"%(s,e,nS,nR,lat,r)
            if lastServer != '---': print >>f, "   ]"
            print >>f, "}"

            print >>f, "\n# Map from server-name to current (avg latency, avg reliability)"
            print >>f, "SERVER_CUR_PING_STATUS = {"
            cur.execute("SELECT servername,latency,reliability FROM "
                        "echolotCurrentOneHopResults")
            for n,lat,r in cur:
                print >>f, "   %r : (%s,%.04f)," %(n,lat,r)
            print >>f, "}"

            print >>f, "\n# Chains that we want to know more about"
            print >>f, "INTERESTING_CHAINS = ["
            cur.execute("SELECT path FROM echolotCurrentTwoHopResults "
                        "WHERE interesting = 1")
            for p, in cur:
                print >>f, "   %r,"%p
            print >>f, "]"

            print >>f, "\n# Chains that are more unreliable than we'd expect"
            print >>f, "BROKEN_CHAINS = ["
            cur.execute("SELECT path FROM echolotCurrentTwoHopResults "
                        "WHERE broken = 1")
            for p, in cur:
                print >>f, "   %r,"%p
            print >>f, "]"
            print >>f, "\n"

        finally:
            self.lock.release()

    def calculateAll(self, outFname=None, now=None):
        LOG.info("Computing ping results.")
        LOG.info("Starting to compute server uptimes.")
        self.calculateUptimes(now, now-24*60*60*12)
        LOG.info("Starting to compute one-hop ping results")
        self.calculateOneHopResults(now)
        LOG.info("Starting to compute two-hop chain status")
        self.calculateChainStatus(now)
        if outFname:
            LOG.info("Writing ping results to disk")
            f = AtomicFile(outFname, 'w')
            self.dumpAllStatus(f, now-24*60*60*12, now)
            f.close()
        LOG.info("Done computing ping results")
        self.lastCalculation = now

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
            self._schedulePing((n,), now)

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
        if self.pingLog.isInteresting.get(path, 0):
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
