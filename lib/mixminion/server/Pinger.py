# Copyright 2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Pinger.py,v 1.20 2004/12/20 04:16:21 nickm Exp $

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
import mixminion.ThreadUtils
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

HEARTBEAT_INTERVAL = 30*60
ONE_DAY = 24*60*60

class IntervalSchedule:
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

class SQLiteDatabase:
    #XXXX can only be used from one thread at a time.
    LOCKING_IS_COARSE = 1
    # Map from logical type to type used in (sqlite) database.
    REALTYPES = { 'timestamp' : 'integer',
                  'bool'      : 'integer',
                  'integer'   : 'integer',
                  'float'     : 'float',
                  'varchar'   : 'varchar',
                  'char'      : 'char',
              }

    def __init__(self, location):
        parent = os.path.split(location)[0]
        createPrivateDir(parent)
        self._theConnection = sqlite.connect(location, autocommit=0)
        self._theCursor = self._theConnection.cursor()

    def close(self):
        self._theConnection.close()
        self._theConnection = self._theCursor = None

    def getConnection(self):
        return self._theConnection

    def getCursor(self):
        return self._theCursor

    def lock(self):
        self.dbLock.acquire()

    def unlock(self):
        self.dbLock.release()

    def _objectExists(self, name, objType):
        self._theCursor.execute(
            "SELECT * FROM SQLITE_MASTER WHERE type = %s AND name = %s",
            (objType,name))
        rs = self._theCursor.fetchall()
        return len(rs) > 0

    def createTable(self, name, rows, constraints=()):
        if self._objectExists(name,"table"):
            return

        body = []
        for r in rows:
            cname = r[0]
            ctype = r[1]
            if '(' in ctype:
                idx = ctype.find('(')
                ctype = self.REALTYPES[ctype[:idx]]+ctype[idx:]
            else:
                ctype = self.REALTYPES[ctype]

            if len(r) == 2:
                body.append("%s %s"%(cname, ctype))
            else:
                assert len(r) == 3
                body.append("%s %s %s"%(cname, ctype, r[2]))

        body.extend(constraints)

        stmt = "CREATE TABLE %s (%s)" % (name,", ".join(body))
        self._theCursor.execute(stmt)
        self._theConnection.commit()

    def createIndex(self, name, tablename, columns, unique=0):
        if self._objectExists(name, "index"):
            return

        if unique:
            u = "UNIQUE "
        else:
            u = ""
        stmt = "CREATE %sINDEX %s ON %s (%s)"%(
            u, name, tablename, ", ".join(columns))
        self._theCursor.execute(stmt)
        self._theConnection.commit()

    def time(self, t=None):
        return long(t or time.time())

    def bool(self, b):
        if b:
            return 1
        else:
            return 0

    def getInsertOrUpdateFn(self, table, keyCols, valCols):
##         update = "UPDATE %s SET %s WHERE %s" % (
##             table,
##             ", ".join(["%s = %%s" % k for k in valCols]),
##             " AND ".join(["%s = %%s" % v for v in keyCols]))
##         insert = "INSERT INTO %s (%s, %s) VALUES (%s)" % (
##             table,
##             ", ".join(keyCols),
##             ", ".join(valCols),
##             ", ".join(["%s"]*(len(valCols)+len(keyCols))))
        stmt = "INSERT OR REPLACE INTO %s (%s, %s) VALUES (%s)"% (
            table,
            ", ".join(keyCols),
            ", ".join(valCols),
            ", ".join(["%s"]*(len(valCols)+len(keyCols))))
        def fn(keyVals, valVals):
            assert len(keyVals) == len(keyCols)
            assert len(valVals) == len(valCols)

            self._theCursor.execute(stmt, (keyVals+valVals))
        return fn

class PingLog:
    def __init__(self, db):
        self._db = db
        self._time = self._db.time
        self._bool = self._db.bool
        self._lock = threading.RLock()
        self._serverIDs = {}
        self._intervalIDs = {}
        self._serverReliability = {}
        self._intervals = IntervalSchedule()
        self._brokenChains = {}
        self._interestingChains = {}
        self._startTime = None
        self._lastRecalculation = 0
        self._createAllTables()
        self._loadServers()

    def _createAllTables(self):
        self._lock.acquire()
        try:
            # FFFF There are still a few sucky bits of this DB design.
            # FFFF First, we depend on SQLite's behavior when inserting null
            # FFFF into an integer primary key column. (It picks a new integer
            # FFFF for us, without our having to give a sequence.)
            # FFFF Second, paths probably want to have their own table.

            # Raw data
            self._db.createTable("myLifespan",
                                 [("startup",  "timestamp", "not null"),
                                  ("stillup",  "timestamp", "not null"),
                                  ("shutdown", "timestamp")])
            self._db.createTable("ping",
                                 [("hash",     "char(28)",     "primary key"),
                                  ("path",     "varchar(200)", "not null"),
                                  ("sentat",   "timestamp",    "not null"),
                                  ("received", "timestamp")])
            self._db.createTable("server",
                                 [("id",   "integer",     "primary key"),
                                  ("name", "varchar(32)", "unique not null")])
            self._db.createTable(
                "connectionAttempt",
                [("at",       "timestamp", "not null"),
                 ("server",   "integer",   "not null REFERENCES server(id)"),
                 ("success",  "bool",      "not null")])

            # Results
            self._db.createTable("statsInterval",
                                 [("id",      "integer",   "primary key"),
                                  ("startAt", "timestamp", "not null"),
                                  ("endAt",   "timestamp", "not null")])

            self._db.createTable(
                "uptime",
                [("interval", "integer", "not null REFERENCES statsinterval(id)"),
                 ("server",   "integer", "not null REFERENCES server(id)"),
                 ("uptime",   "float",   "not null")],
                ["PRIMARY KEY (interval, server)"])

            self._db.createTable(
                "echolotOneHopResult",
                  [("server",   "integer", "not null REFERENCES server(id)"),
                   ("interval", "integer", "not null REFERENCES statsInterval(id)"),
                   ("nSent",    "integer", "not null"),
                   ("nReceived","integer", "not null"),
                   ("latency",  "integer", "not null"),
                   ("wsent",    "float",   "not null"),
                   ("wreceived","float",   "not null"),
                   ("reliability", "float",   "not null")],
                ["PRIMARY KEY (server, interval)"])

            self._db.createTable(
                "echolotCurrentOneHopResult",
                [("server",      "integer",
                  "primary key REFERENCES server(id)"),
                 ("at",          "timestamp", "not null"),
                 ("latency",     "integer",   "not null"),
                 ("reliability", "float",     "not null")])

            self._db.createTable(
                "echolotCurrentTwoHopResult",
                [("server1",     "integer",   "not null REFERENCES server(id)"),
                 ("server2",     "integer",   "not null REFERENCES server(id)"),
                 ("at",          "timestamp", "not null"),
                 ("nSent",       "integer",   "not null"),
                 ("nReceived",   "integer",   "not null"),
                 ("broken",      "bool",      "not null"),
                 ("interesting", "bool",      "not null")],
                ["PRIMARY KEY (server1, server2)"])

            self._db.createIndex("serverName", "server", ["name"], unique=1)
            self._db.createIndex("statsIntervalSE", "statsInterval",
                                 ["startAt", "endAt"], unique=1)
            self._db.createIndex("myLifespanStartup", "myLifespan", ["startUp"])
            self._db.createIndex("pingHash",   "ping", ["hash"], unique=1)
            self._db.createIndex("pingPathSR", "ping",
                                 ["path", "sentat", "received"])
            self._db.createIndex("connectionAttemptServerAt",
                                 "connectionAttempt", ["server","at"])

            # indices on echolot*results, uptimes.

            self._setUptime = self._db.getInsertOrUpdateFn(
                "uptime", ["interval", "server"], ["uptime"])
            self._setOneHop = self._db.getInsertOrUpdateFn(
                "echolotOneHopResult",
                ["server", "interval"],
                ["nSent", "nReceived", "latency", "wsent", "wreceived",
                 "reliability"])
            self._setCurOneHop = self._db.getInsertOrUpdateFn(
                "echolotCurrentOneHopResult",
                ["server"],
                ["at", "latency", "reliability"])
            self._setTwoHop = self._db.getInsertOrUpdateFn(
                "echolotCurrentTwoHopResult",
                ["server1", "server2"],
                ["at", "nSent", "nReceived", "broken", "interesting"])
        finally:
            self._lock.release()

    def _loadServers(self):
        # hold lock.
        cur = self._db.getCursor()
        cur.execute("SELECT id, name FROM server")
        res = cur.fetchall()
        serverIDs = {}
        for id,name in res:
            serverIDs[name] = id

        serverReliability = {}
        cur.execute("SELECT name, reliability FROM "
                    "echolotCurrentOneHopResult, server "
                    "WHERE server.id = echolotCurrentOneHopResult.server")
        res = cur.fetchall()
        for name,rel in res:
            serverReliability[name]=rel

        cur.execute("SELECT s1.name, s2.name, broken, interesting FROM "
                    "echolotCurrentTwoHopResult, server as S1, server as S2 "
                    "WHERE (interesting = 1 OR broken = 1) AND "
                    "S1.id = server1 AND S2.id = server2")
        res = cur.fetchall()
        broken = {}
        interesting = {}
        for s1, s2, b, i in res:
            if s1 == '<self>' or s2 == '<self>': continue
            p = "%s,%s"%(s1,s2)
            if b:
                broken[p]=1
            if i:
                interesting[p]=1
        self._serverIDs = serverIDs
        self._serverReliability = serverReliability
        self._brokenChains = broken
        self._interestingChains = interesting

    def updateServers(self, names):
        #XXXX008 call when a new directory arrives.
        self._lock.acquire()
        try:
            for n in names:
                self._getServerID(n)
        finally:
            self._lock.release()

    def _getServerID(self, name):
        # doesn't commit.
        name = name.lower()
        self._lock.acquire()
        try:
            try:
                return self._serverIDs[name]
            except KeyError:
                self._serverIDs[name] = 1
        finally:
            self._lock.release()

        cur = self._db.getCursor()

        cur.execute("INSERT INTO server (name) VALUES (%s)", name)
        cur.execute("SELECT id FROM server WHERE name = %s", name)
        #XXXX catch errors!
        ident, = cur.fetchone()
        self._serverIDs[name]=ident
        return ident

    def _getIntervalID(self, start, end):
        # CACHE THESE? FFFF
        start = self._db.time(start)
        end = self._db.time(end)
        cur = self._db.getCursor()
        cur.execute("SELECT id FROM statsInterval WHERE "
                    "startAt = %s AND endAt = %s", start, end)
        r = cur.fetchall()
        if len(r) == 1:
            return r[0][0]

        cur.execute("INSERT INTO statsInterval (startAt, endAt) "
                    "VALUES (%s, %s)", start, end)
        cur.execute("SELECT id FROM statsInterval WHERE "
                    "startAt = %s AND endAt = %s", start, end)
        r = cur.fetchall()
        assert len(r) == 1
        return r[0][0]

    def rotate(self, dataCutoff, resultsCutoff):
        #if now is None: now = time.time()
        #sec = config['Pinging']
        #dataCutoff = self._time(now - sec['RetainPingData'])
        #resultsCutoff = self._time(now - sec['RetainPingResults'])

        cur = self._db.getCursor()
        cur.execute("DELETE FROM myLifespan WHERE stillup < %s", dataCutoff)
        cur.execute("DELETE FROM ping WHERE sentat < %s", dataCutoff)
        cur.execute("DELETE FROM connectionAttempt WHERE at < %s", dataCutoff)

        cur.execute("DELETE FROM uptime WHERE interval IN "
                    "( SELECT id FROM statsInterval WHERE endAt < %s )",
                    resultsCutoff)
        cur.execute("DELETE FROM echolotOneHopResult WHERE interval IN "
                    "( SELECT id FROM statsInterval WHERE endAt < %s )",
                    resultsCutoff)
        cur.execute("DELETE FROM statsInterval WHERE endAt < %s", resultsCutoff)

        self._db.getConnection().commit()

    def flush(self):
        self._db.getConnection().commit()

    def close(self):
        self._db.close()

    _STARTUP = "INSERT INTO myLifespan (startup, stillup, shutdown) VALUES (%s,%s, 0)"
    def startup(self,now=None):
        self._lock.acquire()
        self._startTime = now = self._time(now)
        self._lock.release()
        self._db.getCursor().execute(self._STARTUP, (now,now))
        self._db.getConnection().commit()

    _SHUTDOWN = "UPDATE myLifespan SET stillup = %s, shutdown = %s WHERE startup = %s"
    def shutdown(self, now=None):
        if self._startTime is None: self.startup()
        now = self._time(now)
        self._db.getCursor().execute(self._SHUTDOWN, (now, now, self._startTime))
        self._db.getConnection().commit()

    _HEARTBEAT = "UPDATE myLifespan SET stillup = %s WHERE startup = %s AND stillup < %s"
    def heartbeat(self, now=None):
        if self._startTime is None: self.startup()
        now = self._time(now)
        self._db.getCursor().execute(self._HEARTBEAT, (now, self._startTime, now))
        self._db.getConnection().commit()

    _CONNECTED = ("INSERT INTO connectionAttempt (at, server, success) "
                  "VALUES (%s,%s,%s)")
    def connected(self, nickname, success=1, now=None):
        serverID = self._getServerID(nickname)
        self._db.getCursor().execute(self._CONNECTED,
                        (self._time(now), serverID, self._bool(success)))
        self._db.getConnection().commit()

    def connectFailed(self, nickname, now=None):
        self.connected(nickname, success=0, now=now)

    _QUEUED_PING = ("INSERT INTO ping (hash, path, sentat, received)"
                    "VALUES (%s,%s,%s,%s)")
    def queuedPing(self, hash, path, now=None):
        assert len(hash) == mixminion.Crypto.DIGEST_LEN
        path = path.lower()
        for s in path.split(","):
            self._getServerID(s)
        self._db.getCursor().execute(self._QUEUED_PING,
                             (formatBase64(hash), path, self._time(now), 0))
        self._db.getConnection().commit()

    _GOT_PING = "UPDATE ping SET received = %s WHERE hash = %s"
    def gotPing(self, hash, now=None):
        assert len(hash) == mixminion.Crypto.DIGEST_LEN
        self._db.getCursor().execute(self._GOT_PING, (self._time(now), formatBase64(hash)))
        n = self._db.getCursor().rowcount
        if n == 0:
            LOG.warn("Received ping with no record of its hash")
        elif n > 1:
            LOG.warn("Received ping with multiple hash entries!")

    def _calculateUptimes(self, serverNames, startTime, endTime, now=None):
        # commit when one done
        cur = self._db.getCursor()
        serverNames.sort()

        # First, calculate my own uptime.
        if now is None: now = time.time()
        self.heartbeat(now)

        timespan = IntervalSet( [(startTime, endTime)] )
        calcIntervals = [ (s,e,self._getIntervalID(s,e)) for s,e in
                          self._intervals.getIntervals(startTime,endTime)]

        cur.execute("SELECT startup, stillup, shutdown FROM myLifespan WHERE "
                    "startup <= %s AND stillup >= %s",
                    self._time(endTime), self._time(startTime))
        myUptime = 0
        myIntervals = IntervalSet([ (start, max(end,shutdown))
                                    for start,end,shutdown in cur ])
        myIntervals *= timespan
        for s, e, i in calcIntervals:
            uptime = (myIntervals * IntervalSet([(s,e)])).spanLength()
            fracUptime = float(uptime)/(e-s)
            self._setUptime((i, self._getServerID("<self>")), (fracUptime,))

        # Okay, now everybody else.
        for s, serverID in self._serverIDs.items():
            if s == '<self>': continue
            cur.execute("SELECT at, success FROM connectionAttempt"
                        " WHERE server = %s AND at >= %s AND at <= %s"
                        " ORDER BY at",
                        serverID, startTime, endTime)

            intervals = [[], []] #uptimes, downtimes
            lastStatus = None
            lastTime = None
            for at, success in cur:
                assert success in (0,1)
                upAt, downAt = myIntervals.getIntervalContaining(at)
                #if upAt == None:
                #    # Event outside edge of interval.  This means that
                #    # it happened after a heartbeat, but we never actually
                #    # shut down.  That's fine.
                #    pass
                if lastTime is None or (upAt and upAt > lastTime):
                    lastTime = upAt
                    lastStatus = None
                if lastStatus is not None:
                    t = (at+lastTime)/2.0
                    intervals[lastStatus].append((lastTime,t))
                    intervals[success].append((t,at))
                lastStatus = success
                lastTime = at
            downIntervals = IntervalSet(intervals[0])
            upIntervals = IntervalSet(intervals[1])
            downIntervals *= myIntervals
            upIntervals *= myIntervals

            for s,e,intervalID in calcIntervals:
                uptime = (upIntervals*IntervalSet([(s,e)])).spanLength()
                downtime = (downIntervals*IntervalSet([(s,e)])).spanLength()
                if s == 'foobart': print uptime, downtime
                if uptime < 1 and downtime < 1:
                    continue
                fraction = float(uptime)/(uptime+downtime)
                self._setUptime((intervalID, serverID), (fraction,))

    def calculateUptimes(self, startAt, endAt, now=None):
        if now is None: now = time.time()
        self._lock.acquire()
        try:
            serverNames = self._serverIDs.keys()
        finally:
            self._lock.release()
        serverNames.sort()
        self._calculateUptimes(serverNames, startAt, endAt, now=now)
        self._db.getConnection().commit()

    def getUptimes(self, startAt, endAt):
        """DODOC: uptimes for all servers overlapping [startAt, endAt],
           as mapping from (start,end) to nickname to fraction.
        """
        result = {}
        cur = self._db.getCursor()
        cur.execute("SELECT startat, endat, name, uptime "
                    "FROM uptime, statsInterval, server "
                    "WHERE statsInterval.id = uptime.interval "
                    "AND server.id = uptime.server "
                    "AND %s >= startat AND %s <= endat",
                    (self._time(startAt), self._time(endAt)))
        for s,e,n,u in cur:
            result.setdefault((s,e), {})[n] = u
        self._db.getConnection().commit()
        return result

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
    def _calculateOneHopResult(self, serverName, startTime, endTime,
                                now=None, calculateOverallResults=1):
        # commit when done; serverName must exist.
        cur = self._db.getCursor()
        if now is None:
            now = time.time()
        if calculateOverallResults:
            startTime = min(startTime,
                       now - (len(self._WEIGHT_AGE)*self._WEIGHT_AGE_PERIOD))
            endTime = max(endTime, now)
        intervals = self._intervals.getIntervals(startTime, endTime)
        nPeriods = len(intervals)
        startTime = intervals[0][0]
        endTime = intervals[-1][1]
        serverID = self._getServerID(serverName)

        # 1. Compute latencies and number of pings sent in each period.
        #    We need to learn these first so we can tell the percentile
        #    of each ping's latency.
        dailyLatencies = [[] for _ in xrange(nPeriods)]
        nSent = [0]*nPeriods
        nPings = 0
        cur.execute("SELECT sentat, received FROM ping WHERE path = %s"
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
        cur.execute("SELECT sentat, received FROM ping WHERE path = %s"
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
            s,e = intervals[pIdx]
            intervalID = self._getIntervalID(s,e)
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
                (serverID, intervalID),
                (sent, rcvd, latent, wsent, wrcvd, rel))

        if not calculateOverallResults:
            return None

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
        self._setCurOneHop((serverID,), (self._time(now), latent, rel))
        return rel

    def calculateOneHopResult(self, now=None):
        self._lock.acquire()
        try:
            serverNames = self._serverIDs.keys()
        finally:
            self._lock.release()

        if now is None:
            now = time.time()
        serverNames.sort()
        reliability = {}
        for s in serverNames:
            if s == '<self>': continue
            # For now, always calculate overall results.
            r = self._calculateOneHopResult(s,now,now,now,
                                             calculateOverallResults=1)
            reliability[s] = r
        self._db.getConnection().commit()
        self._lock.acquire()
        try:
            self._serverReliability.update(reliability)
        finally:
            self._lock.release()

    def _calculate2ChainStatus(self, since, s1, s2, now=None):
        # doesn't commit.
        cur = self._db.getCursor()
        path = "%s,%s"%(s1,s2)
        cur.execute("SELECT count() FROM ping WHERE path = %s"
                    " AND sentat >= %s",
                    (path,self._time(since)))
        nSent, = cur.fetchone()
        cur.execute("SELECT count() FROM ping WHERE path = %s"
                    " AND sentat >= %s AND received > 0",
                    (path,since))
        nReceived, = cur.fetchone()

        try:
            product = self._serverReliability[s1] * self._serverReliability[s2]
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
        self._lock.acquire()
        try:
            serverNames = self._serverIDs.keys()
        finally:
            self._lock.release()

        if now is None:
            now = time.time()

        brokenChains = {}
        interestingChains = {}
        since = now - self._CHAIN_PING_HORIZON
        serverNames.sort()

        for s1 in serverNames:
            if s1 == '<self>': continue
            for s2 in serverNames:
                if s2 == '<self>': continue
                p = "%s,%s"%(s1,s2)
                nS, nR, prod, isBroken, isInteresting = \
                    self._calculate2ChainStatus(since, s1, s2)
                if isBroken:
                    brokenChains[p] = 1
                if isInteresting:
                    interestingChains[p] = 1

                self._setTwoHop(
                    (self._getServerID(s1), self._getServerID(s2)),
                    (self._time(now), nS, nR, self._bool(isBroken),
                     self._bool(isInteresting)))
        self._db.getConnection().commit()

        self._lock.acquire()
        try:
            self._brokenChains = brokenChains
            self._interestingChains = interestingChains
        finally:
            self._lock.release()

    def dumpAllStatus(self,f,since,now=None):
        self._lock.acquire()
        try:
            serverNames = self._serverIDs.keys()
        finally:
            self._lock.release()

        if now is None: now = time.time()
        print >>f, "# List of all currently tracked servers."
        print >>f, "KNOWN_SERVERS =",serverNames
        cur = self._db.getCursor()

        print >>f, "\n# Map from server to list of (period-start, period-end, fractional uptime"
        print >>f, "SERVER_UPTIMES = {"
        cur.execute("SELECT startAt,endAt,name,uptime FROM uptime, server, statsInterval "
                    "WHERE startAt >= %s AND startAt <= %s "
                    "AND uptime.server = server.id "
                    "AND uptime.interval = statsInterval.id "
                    "ORDER BY name, startAt", (since, now))
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
        cur.execute("SELECT name,startAt,endAt,nSent,nReceived,"
                   "  latency,reliability "
                   "FROM echolotOneHopResult, server, statsInterval "
                   "WHERE startat >= %s AND startat <= %s"
                   "AND echolotOneHopResult.server = server.id "
                   "AND echolotOneHopResult.interval = statsInterval.id "
                   "ORDER BY name, startat", (since, now))
        lastServer = "---"
        for n,s,e,nS,nR,lat,r in cur:
            if s == '<self>': continue
            if n != lastServer:
                if lastServer != '---': print >>f, "   ],"
                lastServer = n
                print >>f, "   %r : [" % n
            print >>f, "      (%s,%s,%s,%s,%s,%.04f),"%(s,e,nS,nR,lat,r)
        if lastServer != '---': print >>f, "   ]"
        print >>f, "}"

        print >>f, "\n# Map from server-name to current (avg latency, avg reliability)"
        print >>f, "SERVER_CUR_PING_STATUS = {"
        cur.execute("SELECT name,latency,reliability FROM "
                    "echolotCurrentOneHopResult, server WHERE "
                    "echolotCurrentOneHopResult.server = server.id")
        for n,lat,r in cur:
            if n == '<self>': continue
            print >>f, "   %r : (%s,%.04f)," %(n,lat,r)
        print >>f, "}"

        print >>f, "\n# Chains that we want to know more about"
        print >>f, "INTERESTING_CHAINS = ["
        cur.execute("SELECT S1.name, S2.name FROM echolotCurrentTwoHopResult, "
                    "   server as S1, server as S2 WHERE "
                    "interesting = 1 AND S1.id = server1 AND S2.id = server2")
        for s1,s2 in cur:
            if s1 == '<self>' or s2 == '<self>': continue
            print >>f, "   '%s,%s',"%(s1,s2)
        print >>f, "]"

        print >>f, "\n# Chains that are more unreliable than we'd expect"
        print >>f, "BROKEN_CHAINS = ["
        cur.execute("SELECT S1.name, S2.name FROM echolotCurrentTwoHopResult, "
                    "   server as S1, server as S2 WHERE "
                    "broken = 1 AND S1.id = server1 AND S2.id = server2")
        for s1,s2 in cur:
            if s1 == '<self>' or s2 == '<self>': continue
            print >>f, "   '%s,%s',"%(s1,s2)
        print >>f, "]"
        print >>f, "\n"
        self._db.getConnection().commit()

    def calculateAll(self, outFname=None, now=None):
        if now is None: now=time.time()
        LOG.info("Computing ping results.")
        LOG.info("Starting to compute server uptimes.")
        self.calculateUptimes(now-24*60*60*12, now)
        LOG.info("Starting to compute one-hop ping results")
        self.calculateOneHopResult(now)
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
    def connect(self, directory, outgoingQueue, pingLog, keyring):
        self.directory = directory
        self.outgoingQueue = outgoingQueue
        self.pingLog = pingLog
        self.keyring = keyring
        self.seed = keyring.getPingerSeed()
    def _calcPeriodLen(self, interval):
        period = ONE_DAY
        while period < interval*2:
            period *= 2
        return period
    def scheduleAllPings(self, now=None):
        raise NotImplemented()
    def _getPeriodStart(self, t):
        raise NotImplemented()
    def _getPingInterval(self, path):
        raise NotImplemented()
    def _getPeriodLength(self):
        raise NotImplemented()
    def _schedulePing(self,path,now=None):
        if now is None: now = int(time.time())
        periodStart = self._getPeriodStart(now)
        periodEnd = periodStart + self._period_length

        interval = self._getPingInterval(path)
        t = periodStart + self._getPerturbation(path, periodStart, interval)
        t += interval * ceilDiv(now-t, interval)
        if t>periodEnd:
            t = periodEnd+self._getPerturbation(path,
                                                periodEnd,
                                                interval)
        self.nextPingTime[path] = t
        LOG.trace("Scheduling %d-hop ping for %s at %s", len(path),
                  ",".join(path), formatTime(t,1))
        return t
    def _getPerturbation(self, path, periodStart, interval):
        sha = mixminion.Crypto.sha1("%s@@%s@@%s"%(",".join(path),
                                                  interval,
                                                  self.seed))
        # This modulo calculation biases the result, but less than 0.1 percent,
        # so I don't really care.
        sec = abs(struct.unpack("I", sha[:4])[0]) % interval
        return sec

    def getFirstPingTime(self):
        if self.nextPingTime:
            return min(self.nextPingTime.values())
        else:
            return None

class OneHopPingGenerator(_PingScheduler,PingGenerator):
    """DOCDOC"""
    def __init__(self, config):
        PingGenerator.__init__(self, config)
        _PingScheduler.__init__(self)
        self._ping_interval = config['Pinging']['ServerPingPeriod']
        self._period_length = self._calcPeriodLen(self._pingInterval)

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
        return self._ping_interval

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
    def __init__(self, config):
        PingGenerator.__init__(self, config)
        _PingScheduler.__init__(self)
        self._dull_interval = self['Pinging']['DullChainPingPeriod'].getSeconds()
        self._interesting_interval = self['Pinging']['ChainPingPeriod'].getSeconds()
        self._period_length = self._calcPeriodLen(
            max(self._interesting_interval,self._dull_interval))

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
        if self.pingLog._interestingChains.get(path, 0):
            return self._interesting_interval
        else:
            return self._dull_interval

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
        mixInterval = config['Server']['MixInterval'].getSeconds()
        probeInterval = config['Pinging']['ServerProbePeriod'].getSeconds()
        if mixInterval < probeInterval:
            self.prob = mixInterval / float(probeInterval)
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

DATABASE_CLASSES = { 'sqlite' : SQLiteDatabase }

def openPingLog(config, location=None, databaseThread=None):
    # FFFF eventually, we should maybe support more than pysqlite.  But let's
    # FFFF not generalize until we have a 2nd case.
    database = 'sqlite'

    assert DATABASE_CLASSES.has_key(database)
    if location is None:
        location = os.path.join(config.getWorkDir(), "pinger", "pingdb")
    db = DATABASE_CLASSES[database](location)
    log = PingLog(db)

    if db.LOCKING_IS_COARSE and databaseThread is not None:
        log = mixminion.ThreadUtils.BackgroundingDecorator(databaseThread, log)

    return log
