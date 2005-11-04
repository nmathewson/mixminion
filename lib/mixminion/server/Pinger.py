# Copyright 2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Pinger.py,v 1.29 2005/11/04 16:24:16 nickm Exp $

"""mixminion.server.Pinger

   Built-in network reliability tester (pinger) for Mixminion servers.

   Our pinger uses a three-part architecture.  First, we periodically
   consider adding testing packets to the mix pool, and consider
   adding link padding to outgoing patches.  These functions are
   perfomed by PingGenerator objects.

   Second, we note the outcome of connection attempts, and the timing
   of our sending/receiving test packets.  These functions are
   performed by a PingLog object.

   Third, we use the timing/uptime information in the second part
   above to try to infer how reliable the other nodes in the network
   are.  This is also done by PingLog.

   This module requires Python 2.2 or later, and the sqlite module.
   I'm okay with this, since most servers shouldn't be running a
   pinger anyway.
"""

import binascii
import bisect
import calendar
import cPickle
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
     succeedingMidnight, UIError, writePickled

try:
    import sqlite
except ImportError:
    sqlite = None

# How often should the server store the fact that it is still alive (seconds).
HEARTBEAT_INTERVAL = 30*60
# Number of seconds in a day.
ONE_DAY = 24*60*60

class IntervalSchedule:
    """A partition of time into a series of intervals.  (Currently, only
       days are supported."""
    def __init__(self):
        pass
    def getIntervalContaining(self, t):
        """Return a 2-tuple of the start and the end of the interval containing
           't'.  The bottom of the interval is closed; the top is open."""
        p = previousMidnight(t)
        return p, succeedingMidnight(p)
    def getIntervals(self, startAt, endAt):
        """Return a list of all intervals between the one containing
           startAt and the one containing endAt, inclusive."""
        r = []
        t = previousMidnight(startAt)
        while t < endAt:
            n = succeedingMidnight(t)
            r.append((t, n))
            t = n
        return r

class SQLiteDatabase:
    """Helper class.  Encapsulates the properties of the SQLite
       database implementation.

       SQLite is a very minimal relational databse, and SQLite 2.8
       (the one that PySQLite wraps) is even more minimal.  It only
       has two underlying types: string and number.  It only enforces
       them when doing comparisons.  The locking is very
       coarse-grained.  Foreign key constraints aren't checked.

       On the plus side, SQLite has no administrative overhead.  You
       don't need to run a daemon; you don't need to create users; you
       only need to install a library.
    """
    ## Fields:
    # _theConnection: A SQLite database connection.  Only one thread should
    #    use this connection at a time.
    # _theCursor: A cursor for the connection.
    # Defined to 1: this database should only be used from one thread
    # at a time.
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
        """Create a SQLite database storing its data in the file 'location'."""
        parent = os.path.split(location)[0]
        createPrivateDir(parent)
        self._theConnection = sqlite.connect(location, autocommit=0)
        self._theCursor = self._theConnection.cursor()

    def close(self):
        """Release resources held by this database."""
        self._theConnection.close()
        self._theConnection = self._theCursor = None

    def getConnection(self):
        """Return a database connection object.  You do not need to close it
           when you are done."""
        # If LOCKING_IS_COARSE is true, this should return a singleton
        # connection.  If LOCKING_IS_COARSE is false, this should
        # return a thread-local connection.
        return self._theConnection

    def getCursor(self):
        """Return a database cursor object."""
        return self._theCursor

    def _objectExists(self, name, objType):
        """Helper: Return true iff this database has an object called
           'name' of the specified type.  objType should be one of
           'view', 'table', or 'index'.
        """
        self._theCursor.execute(
            "SELECT * FROM SQLITE_MASTER WHERE type = %s AND name = %s",
            (objType,name))
        rs = self._theCursor.fetchall()
        return len(rs) > 0

    def createTable(self, name, columns, constraints=()):
        """If there is no table called 'name', create it.  Its columns
           are given in 'columns', a list of tuples.  Each tuple is
           either a 2-tuple containing a column name and a type, or a
           3-tuple containing a column name, a type, and a series of
           constraints.  Additional table-level constraints can be
           given in a list as 'constraints'.
        """
        # This is more complicated than just saying "CREATE TABLE
        # foo", but it lets us map types and constraints differently
        # on differently broken databases.

        if self._objectExists(name,"table"):
            return

        body = []
        for c in columns:
            cname = c[0]
            ctype = c[1]
            if '(' in ctype:
                idx = ctype.find('(')
                ctype = self.REALTYPES[ctype[:idx]]+ctype[idx:]
            else:
                ctype = self.REALTYPES[ctype]

            if len(c) == 2:
                body.append("%s %s"%(cname, ctype))
            else:
                assert len(c) == 3
                body.append("%s %s %s"%(cname, ctype, c[2]))

        body.extend(constraints)

        stmt = "CREATE TABLE %s (%s)" % (name,", ".join(body))
        self._theCursor.execute(stmt)
        self._theConnection.commit()

    def createIndex(self, name, tablename, columns, unique=0):
        """If the index 'name', doesn't already exist, create an index
           of that name on the table 'tablename', indexing the columns
           'columns'.  If 'unique', create an index of unique values.
        """
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
        """Convert 't' (a Unix time in seconds since the epoch) into the
           format the database wants for its timestamp fields.  If 't' is None,
           use the current time instead.
        """
        return long(t or time.time())

    def bool(self, b):
        """Convert the boolean 'b' into the format the database wants for its
           boolean fields."""
        if b:
            return 1
        else:
            return 0

    def getInsertOrUpdateFn(self, table, keyCols, valCols):
        """Return a function that takes two arguments: a tuple of
           values for the columns in keyCols, and a tuple of values
           for the columns in valCols.  If some row in 'table' has the
           given values for the key columns, this function will update
           that row and set the values of the value columns.
           Otherwise, the function will insert a new row with the
           given value columns."""
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

    def encodeIdentity(self, identity):
        """DOCDOC"""
        if identity == '<self>':
            return '<self>'
        else:
            assert len(identity) == mixminion.Crypto.DIGEST_LEN
            return binascii.b2a_hex(identity)

    def decodeIdentity(self, hexid):
        """DOCDOC"""
        if hexid == '<self>':
            return '<self>'
        else:
            assert len(hexid) == mixminion.Crypto.DIGEST_LEN*2
            return binascii.a2b_hex(hexid)

class PingLog:
    """A PingLog stores a series of pinging-related events to a
       persistant relational database, and calculates server statistics based
       on those events.
    """
    ## Fields:
    # _db: the underlying database.
    # _lock: an instance of threading.RLock to control access to in-memory
    #    structures.  The databse is responsible for keeping its own structures
    #    consistent.
    # _serverIDs: A map from server identity digest to server ID
    #    used in the database.
    # _intervalIDs: A map from (start,end) to a time interval ID used in the
    #    database
    # _serverReliability: A map from lc server nickname to last computed
    #    server reliability (a float between 0 and 1).
    # _intervals: An instance of IntervalSchedule.
    # _brokenChains, _interestingChains: Maps from comma-separated
    #   lowercase hex ids for servers in chains that we believe to be
    #   broken or "interesting" to 1.
    # _startTime: The 'startup' time for the current myLifespan row.
    # _lastRecalculation: The last time this process recomputed all
    #   the stats, or 0 for 'never'.
    # _set{Uptime|OneHop|CurOneHop|TwoHop}: Functions generated by
    #   getInsertOrUpdateFn.

    # FFFF Maybe refactor this into data storage and stats computation.
    def __init__(self, db):
        """Create a new PingLog, storing events into the databse 'db'."""
        self._db = db
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
        """Helper: check for the existence of all the tables and indices
           we plan to use, and create the missing ones."""
        self._lock.acquire()
        try:
            # FFFF There are still a few sucky bits of this DB design.
            # FFFF First, we depend on SQLite's behavior when inserting null
            # FFFF into an integer primary key column. (It picks a new integer
            # FFFF for us, without our having to give a sequence.)
            # FFFF Second, paths probably want to have their own table.

            #### Tables holding raw data.

            # Holds intervals over which this server was running.  A
            # row in myLifespan means: "This server started running at
            # 'startup', and was still running at 'stillup'. If
            # shutdown is provided, that's when the server shut down."
            self._db.createTable("myLifespan",
                                 [("startup",  "timestamp", "not null"),
                                  ("stillup",  "timestamp", "not null"),
                                  ("shutdown", "timestamp")])

            # Holds information about probe packets sent into the network.  A
            # row in ping means: We send a probe packet along the path 'path'
            # at the time 'sentat'.  The payload of the message we receive
            # will hash to 'hash' (base-64 encoded).  If 'received' is not
            # null, we received the packet again at 'received'.
            self._db.createTable("ping",
                                 [("hash",     "char(28)",     "primary key"),
                                  ("path",     "varchar(200)", "not null"),
                                  ("sentat",   "timestamp",    "not null"),
                                  ("received", "timestamp")])

            # Holds identity digests for all the servers we know about.
            self._db.createTable("server",
                              [("id",   "integer",     "primary key"),
                               ("identity", "varchar(40)", "unique not null")])

            # Holds information about our attempts to launch MMTP connections
            # to other servers.  A row in connectionAttempt means: We tried to
            # connect to 'serever' at the time 'at'.  If 'success', we
            # successfully connected and negotiated a protocol version.
            # Otherwise, we failed before we could negotiate a protocol version.
            self._db.createTable(
                "connectionAttempt",
                [("at",       "timestamp", "not null"),
                 ("server",   "integer",   "not null REFERENCES server(id)"),
                 ("success",  "bool",      "not null")])

            #### Tables holding results.

            # Maps spans of time (currently, days) to identifiers.
            self._db.createTable("statsInterval",
                                 [("id",      "integer",   "primary key"),
                                  ("startAt", "timestamp", "not null"),
                                  ("endAt",   "timestamp", "not null")])

            # Holds estimated server uptimes.  Each row in uptime means:
            # during 'interval', our successful and failed connections to
            # 'server' make us believe that it was running and on the network
            # about 'uptime' fraction of the time.
            self._db.createTable(
                "uptime",
                [("interval", "integer", "not null REFERENCES statsinterval(id)"),
                 ("server",   "integer", "not null REFERENCES server(id)"),
                 ("uptime",   "float",   "not null")],
                ["PRIMARY KEY (interval, server)"])

            # Holds estimates for server latency and reliability for a given
            # interval.  Each row in echolotOneHopResult means: during
            # 'interval', we sent 'nSent' one-hop probe messages to 'server'.
            # We eventually received 'nReceived' of them.  The median latency
            # (rounded off) of those we received was 'latency' seconds.
            # Weighting unreceived probe messages by the fraction we would
            # have expected to see by the time we computed the results times
            # 0.8, and weighting received probes by 1.0, the weighted number
            # of sent and received pings are in 'wsent' and 'wreceived', and
            # the weighted fraction received is 'reliability'.

            # (Yes, Echolot is dark magic.)
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

            # Holds estimates for server latency and reliability over the last
            # several (12) days.  A row in echolotCurrentOneHopResults means:
            # We most recently computed single-hop probe statistics for server
            # at 'at'. Over the last several days, its median latency
            # (rounded) has been 'latency' seconds, and its reliability,
            # weighted by relevance of day, has been 'reliability'.
            self._db.createTable(
                "echolotCurrentOneHopResult",
                [("server",      "integer",
                  "primary key REFERENCES server(id)"),
                 ("at",          "timestamp", "not null"),
                 ("latency",     "integer",   "not null"),
                 ("reliability", "float",     "not null")])

            # Holds estimates for two-hop chain reliability. Each row means:
            # We most recently calculted the reliability for the two-hop chain
            # 'server1,server2' at 'at'.  Over the last several (12) days, we
            # sent nSent probes, and have received nReceieved of them.  Iff
            # 'broken', the fraction received is so much lower that what we'd
            # expect that we have concluded that the chain is probably broken.
            # Iff 'interesting', then there is not enough data to be sure, so
            # we're going to probe this chain a bit more frequently for a
            # while.

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

            #### Indices.

            self._db.createIndex("serverIdentity", "server",
                                 ["identity"], unique=1)
            self._db.createIndex("statsIntervalSE", "statsInterval",
                                 ["startAt", "endAt"], unique=1)
            self._db.createIndex("myLifespanStartup", "myLifespan", ["startUp"])
            self._db.createIndex("pingHash",   "ping", ["hash"], unique=1)
            self._db.createIndex("pingPathSR", "ping",
                                 ["path", "sentat", "received"])
            self._db.createIndex("connectionAttemptServerAt",
                                 "connectionAttempt", ["server","at"])
            self._db.createIndex("echolotOneHopResultSI",
                                 "echolotOneHopResult",
                                 ["server",  "interval"])

            # XXXX008 We should maybe have indices on echolot*results,
            # uptimes.

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
        """Helper function; callers must hold lock.  Load _serverIDs,
           _serverReliability, _brokenChains, and _interestingChains from
           the database.
        """
        cur = self._db.getCursor()
        cur.execute("SELECT id, identity FROM server")
        res = cur.fetchall()
        serverIDs = {}
        for idnum,identity in res:
            serverIDs[self._db.decodeIdentity(identity)] = idnum

        serverReliability = {}
        cur.execute("SELECT identity, reliability FROM "
                    "echolotCurrentOneHopResult, server WHERE "
                    "echolotCurrentOneHopResult.server = server.id")
        res = cur.fetchall()
        for hexid,rel in res:
            serverReliability[self._db.decodeIdentity(hexid)]=rel

        cur.execute("SELECT S1.identity, S2.identity,broken,interesting FROM"
                    " echolotCurrentTwoHopResult,server AS S1,server AS S2 "
                    "WHERE (interesting = 1 OR broken = 1) "
                    " AND S1.id = server1 AND S2.id = server2")
        res = cur.fetchall()
        broken = {}
        interesting = {}
        for s1, s2, b, i in res:
            if s1 == '<self>' or s2 == '<self>': continue
            p = "%s,%s"%(s1,s2)
            assert p == p.lower()
            if b:
                broken[p]=1
            if i:
                interesting[p]=1
        self._serverIDs = serverIDs
        self._serverReliability = serverReliability
        self._brokenChains = broken
        self._interestingChains = interesting

    def updateServers(self, descriptorSource):
        """Add the names 'descriptorSource' to the database, if they
           aren't there already.
        """
        for s in descriptorSource.getServerList():
            self._getServerID(s.getIdentityDigest())
        self._db.getConnection().commit()

    def _getServerID(self, identity):
        """Helper: Return the database ID for the server whose
           identity digest is 'identity'.  If the database doesn't
           know about the server yet, add it.  Does not commit the
           current transaction.
        """
        self._lock.acquire()
        try:
            try:
                return self._serverIDs[identity]
            except KeyError:
                self._serverIDs[identity] = 1
        finally:
            self._lock.release()

        cur = self._db.getCursor()

        hexid = self._db.encodeIdentity(identity)

        cur.execute("INSERT INTO server (identity) VALUES (%s)", hexid)
        cur.execute("SELECT id FROM server WHERE identity = %s", hexid)
        #XXXX catch errors!
        ident, = cur.fetchone()
        self._serverIDs[identity]=ident
        return ident

    def _getIntervalID(self, start, end):
        """Helper: Return the database ID for the interval spanning from
           'start' to 'end'.  If the database doesn't know about the interval
           yet, add it.  Does not commit the current transaction.
        """
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
        """Remove expired entries from the database. Remove any raw data from
           before 'dataCutoff', and any computed statistics from before
           'resultsCutoff'.
        """
        #if now is None: now = time.time()
        #sec = config['Pinging']
        #dataCutoff = self._db.time(now - sec['RetainPingData'])
        #resultsCutoff = self._db.time(now - sec['RetainPingResults'])

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
        """Write any pending information to disk."""
        self._db.getConnection().commit()

    def close(self):
        """Release all resources held by this PingLog and the underlying
           database."""
        self._db.close()

    _STARTUP = "INSERT INTO myLifespan (startup, stillup, shutdown) VALUES (%s,%s, 0)"
    def startup(self,now=None):
        """Called when the server has just started.  Starts tracking a new
           interval of this server's lifetime."""
        self._lock.acquire()
        self._startTime = now = self._db.time(now)
        self._lock.release()
        self._db.getCursor().execute(self._STARTUP, (now,now))
        self._db.getConnection().commit()

    _SHUTDOWN = "UPDATE myLifespan SET stillup = %s, shutdown = %s WHERE startup = %s"
    def shutdown(self, now=None):
        """Called when the server is shutting down. Stops tracking the current
           interval of this server's lifetime."""
        if self._startTime is None: self.startup()
        now = self._db.time(now)
        self._db.getCursor().execute(self._SHUTDOWN, (now, now, self._startTime))
        self._db.getConnection().commit()

    _HEARTBEAT = "UPDATE myLifespan SET stillup = %s WHERE startup = %s AND stillup < %s"
    def heartbeat(self, now=None):
        """Called periodically.  Notes that the server is still running as of
           the time 'now'."""
        if self._startTime is None: self.startup()
        now = self._db.time(now)
        self._db.getCursor().execute(self._HEARTBEAT, (now, self._startTime, now))
        self._db.getConnection().commit()

    _CONNECTED = ("INSERT INTO connectionAttempt (at, server, success) "
                  "VALUES (%s,%s,%s)")
    def connected(self, identity, success=1, now=None):
        """Note that we attempted to connect to the server with 'identity'.
           We successfully negotiated a protocol iff success is true.
        """
        serverID = self._getServerID(identity)
        self._db.getCursor().execute(self._CONNECTED,
                        (self._db.time(now), serverID, self._db.bool(success)))
        self._db.getConnection().commit()

    def connectFailed(self, identity, now=None):
        """Note that we attempted to connect to the server named 'nickname',
           but could not negotiate a protocol.
        """
        self.connected(identity, success=0, now=now)

    _QUEUED_PING = ("INSERT INTO ping (hash, path, sentat, received)"
                    "VALUES (%s,%s,%s,%s)")
    def queuedPing(self, hash, path, now=None):
        """Note that we send a probe message along 'path' (a list of
           server identities, excluding ourself as first and last
           hop), such that the payload, when delivered, will have
           'hash' as its digest.
        """
        assert len(hash) == mixminion.Crypto.DIGEST_LEN
        ids = ",".join([ str(self._getServerID(s)) for s in path ])
        self._db.getCursor().execute(self._QUEUED_PING,
                             (formatBase64(hash), ids, self._db.time(now), 0))
        self._db.getConnection().commit()

    _GOT_PING = "UPDATE ping SET received = %s WHERE hash = %s"
    def gotPing(self, hash, now=None):
        """Note that we have received a probe message whose payload had 'hash'
           as its digest.
        """
        assert len(hash) == mixminion.Crypto.DIGEST_LEN
        self._db.getCursor().execute(self._GOT_PING, (self._db.time(now), formatBase64(hash)))
        n = self._db.getCursor().rowcount
        if n == 0:
            LOG.warn("Received ping with no record of its hash")
        elif n > 1:
            LOG.warn("Received ping with multiple hash entries!")

    def _calculateUptimes(self, serverIdentities, startTime, endTime, now=None):
        """Helper: calculate the uptime results for a set of servers, named in
           serverIdentities, for all intervals between startTime and endTime
           inclusive.  Does not commit the current transaction.
        """
        cur = self._db.getCursor()
        serverIdentities.sort()

        # First, calculate my own uptime.
        if now is None: now = time.time()
        self.heartbeat(now)

        timespan = IntervalSet( [(startTime, endTime)] )
        calcIntervals = [ (s,e,self._getIntervalID(s,e)) for s,e in
                          self._intervals.getIntervals(startTime,endTime)]

        cur.execute("SELECT startup, stillup, shutdown FROM myLifespan WHERE "
                    "startup <= %s AND stillup >= %s",
                    self._db.time(endTime), self._db.time(startTime))
        myIntervals = IntervalSet([ (start, max(end,shutdown))
                                    for start,end,shutdown in cur ])
        myIntervals *= timespan
        for s, e, i in calcIntervals:
            uptime = (myIntervals * IntervalSet([(s,e)])).spanLength()
            fracUptime = float(uptime)/(e-s)
            self._setUptime((i, self._getServerID("<self>")), (fracUptime,))

        # Okay, now everybody else.
        for (identity, serverID) in self._serverIDs.items():
            if s in ('<self>','<unknown>'): continue
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
                if uptime < 1 and downtime < 1:
                    continue
                fraction = float(uptime)/(uptime+downtime)
                self._setUptime((intervalID, serverID), (fraction,))

    def calculateUptimes(self, startAt, endAt, now=None):
        """Calculate the uptimes for all servers for all intervals between
           startAt and endAt, inclusive."""
        if now is None: now = time.time()
        self._lock.acquire()
        try:
            serverIdentities = self._serverIDs.keys()
        finally:
            self._lock.release()
        serverIdentities.sort()
        self._calculateUptimes(serverIdentities, startAt, endAt, now=now)
        self._db.getConnection().commit()

    def getUptimes(self, startAt, endAt):
        """Return uptimes for all servers overlapping [startAt, endAt],
           as mapping from (start,end) to identity to fraction.
        """
        result = {}
        cur = self._db.getCursor()
        cur.execute("SELECT startat, endat, identity, uptime "
                    "FROM uptime, statsInterval, server "
                    "WHERE statsInterval.id = uptime.interval "
                    "AND server.id = uptime.server "
                    "AND %s >= startat AND %s <= endat",
                    (self._db.time(startAt), self._db.time(endAt)))
        for s,e,i,u in cur:
            result.setdefault((s,e), {})[self._db.decodeIdentity(i)] = u
        self._db.getConnection().commit()
        return result

    def _roundLatency(self, latency):
        """Return 'latency', rounded to an even unit of time.  Revealing
           median lancency directly can leak the fact that a message was a
           ping.
        """
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
    def _calculateOneHopResult(self, serverIdentity, startTime, endTime,
                                now=None, calculateOverallResults=1):
        """Calculate the latency and reliablity for a given server on
           intervals between startTime and endTime, inclusive.  If
           calculateOverallResults is true, also compute the current overall
           results for that server.
        """
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
        serverID = self._getServerID(serverIdentity)

        # 1. Compute latencies and number of pings sent in each period.
        #    We need to learn these first so we can tell the percentile
        #    of each ping's latency.
        dailyLatencies = [[] for _ in xrange(nPeriods)]
        nSent = [0]*nPeriods
        nPings = 0
        cur.execute("SELECT sentat, received FROM ping WHERE path = %s"
                    " AND sentat >= %s AND sentat <= %s",
                    (serverID, startTime, endTime))
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
                    (serverID, startTime, endTime))
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
        self._setCurOneHop((serverID,), (self._db.time(now), latent, rel))
        return rel

    def calculateOneHopResult(self, now=None):
        """Calculate latency and reliability for all servers.
        """
        self._lock.acquire()
        try:
            serverIdentities = self._serverIDs.keys()
        finally:
            self._lock.release()

        if now is None:
            now = time.time()
        serverIdentities.sort()
        reliability = {}
        for s in serverIdentities:
            if s in ('<self>','<unknown>'): continue
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
        """Helper: Calculate the status (broken/interesting/both/neither) for
           a chain of the servers 's1' and 's2' (given as identity digests),
           considering pings sent since 'since'.  Return a tuple of (number of
           pings sent, number of those pings received, is-broken,
           is-interesting).  Does not commit the current transaction.
        """
        # doesn't commit.
        cur = self._db.getCursor()
        path = "%s,%s"%(self._getServerID(s1),self._getServerID(s2))
        cur.execute("SELECT count() FROM ping WHERE path = %s"
                    " AND sentat >= %s",
                    (path,self._db.time(since)))
        nSent, = cur.fetchone()
        cur.execute("SELECT count() FROM ping WHERE path = %s"
                    " AND sentat >= %s AND received > 0",
                    (path,since))
        nReceived, = cur.fetchone()
        cur.execute("SELECT SUM(r1.reliability * r2.reliability) "
                   "FROM ping, echolotOneHopResult as r1, "
                   "   echolotOneHopResult as r2, statsInterval "
                   "WHERE ping.path = %s AND ping.sentAt >= %s "
                   "AND statsInterval.startAt <= ping.sentAt "
                   "AND statsInterval.endAt >= ping.sentAt "
                   "AND r1.server = %s "
                   "AND r1.interval = statsInterval.id "
                   "AND r2.server = %s "
                   "AND r2.interval = statsInterval.id ",
                    (path, self._db.time(since),
                     self._getServerID(s1), self._getServerID(s2)))

        nExpected, = cur.fetchone()

        isBroken = nSent >= 3 and nExpected and nReceived <= nExpected*0.3

        isInteresting = ((nSent < 3 and nReceived == 0) or
                         (nExpected and nReceived <= nExpected*0.3))
        if 0:
            if isInteresting:
                if nSent < 3 and nReceived == 0:
                    LOG.trace("%s,%s is interesting because %d were sent and %d were received",
                              s1,s2, nSent, nReceived)
                elif nExpected and nReceived <= nExpected*0.3:
                    LOG.trace("%s,%s is interesting because we expected %s and got %s", s1, s2, nExpected, nReceived)
                else:
                    LOG.trace("I have no idea why %s,%s is interesting.",s1,s2)

        return nSent, nReceived, isBroken, isInteresting

    _CHAIN_PING_HORIZON = 12*ONE_DAY
    def calculateChainStatus(self, now=None):
        """Calculate the status of all two-hop chains."""
        self._lock.acquire()
        try:
            serverIdentities = self._serverIDs.keys()
        finally:
            self._lock.release()

        if now is None:
            now = time.time()

        brokenChains = {}
        interestingChains = {}
        since = now - self._CHAIN_PING_HORIZON
        serverIdentities.sort()

        for s1 in serverIdentities:
            if s1 in ('<self>','<unknown>'): continue
            for s2 in serverIdentities:
                if s2 == ('<self>','<unknown>'): continue
                p = "%s,%s"%(s1,s2)
                nS, nR, isBroken, isInteresting = \
                    self._calculate2ChainStatus(since, s1, s2)
                if isBroken:
                    brokenChains[p] = 1
                if isInteresting:
                    interestingChains[p] = 1

                self._setTwoHop(
                    (self._getServerID(s1), self._getServerID(s2)),
                    (self._db.time(now), nS, nR, self._db.bool(isBroken),
                     self._db.bool(isInteresting)))
        self._db.getConnection().commit()

        self._lock.acquire()
        try:
            self._brokenChains = brokenChains
            self._interestingChains = interestingChains
        finally:
            self._lock.release()

    def dumpAllStatus(self,f,since,now=None):
        """Write statistics into the file object 'f' for all intervals since
           'since', inclusive."""
        self._lock.acquire()
        try:
            serverIdentities = self._serverIDs.keys()
        finally:
            self._lock.release()

        if now is None: now = time.time()
        print >>f, "# List of all currently tracked servers."
        print >>f, "KNOWN_SERVERS =", [
            self._db.encodeIdentity(i) for i in serverIdentities]
        cur = self._db.getCursor()

        print >>f, "\n# Map from server to list of (period-start, period-end, fractional uptime"
        print >>f, "SERVER_UPTIMES = {"
        cur.execute("SELECT startAt,endAt,identity,uptime FROM uptime, server, statsInterval "
                    "WHERE startAt >= %s AND startAt <= %s "
                    "AND uptime.server = server.id "
                    "AND uptime.interval = statsInterval.id "
                    "ORDER BY identity, startAt", (since, now))
        lastServer = "---"
        for s,e,i,u in cur:
            if i != lastServer:
                if lastServer != '---': print >>f, "   ],"
                lastServer = i
                print >>f, "   %r : [" % i
            print >>f, "      (%s,%s,%.04f),"%(s,e,u)
        if lastServer != '---': print >>f, "   ]"
        print >>f, "}"

        print >>f, """
# Map from server name to list of (period-start, period-end, # pings sent,
#      # of those pings received, median latency on those pings (sec),
#      weighted reliability)"""
        print >>f, "SERVER_DAILY_PING_STATUS = {"
        cur.execute("SELECT identity,startAt,endAt,nSent,nReceived,"
                   "  latency,reliability "
                   "FROM echolotOneHopResult, statsInterval, server "
                   "WHERE startat >= %s AND startat <= %s"
                   "AND echolotOneHopResult.server = server.id "
                   "AND echolotOneHopResult.interval = statsInterval.id "
                   "ORDER BY identity, startat", (since, now))
        lastServer = "---"
        for i,s,e,nS,nR,lat,r in cur:
            if s == '<self>': continue
            if i != lastServer:
                if lastServer != '---': print >>f, "   ],"
                lastServer = i
                print >>f, "   (%r) : [" % i
            print >>f, "      (%s,%s,%s,%s,%s,%.04f),"%(s,e,nS,nR,lat,r)
        if lastServer != '---': print >>f, "   ]"
        print >>f, "}"

        print >>f, "\n# Map from server identity to current (avg latency, avg reliability)"
        print >>f, "SERVER_CUR_PING_STATUS = {"
        cur.execute("SELECT identity,latency,reliability FROM "
                    "echolotCurrentOneHopResult, server WHERE "
                    "echolotCurrentOneHopResult.server = server.id")
        for i,lat,r in cur:
            if i == '<self>': continue
            print >>f, "   %r : (%s,%.04f)," %(i,lat,r)
        print >>f, "}"

        print >>f, "\n# Chains that we want to know more about"
        print >>f, "INTERESTING_CHAINS = ["
        cur.execute("SELECT S1.identity, S2.identity "
                    "FROM echolotCurrentTwoHopResult, "
                    "   server as S1, server as S2 WHERE "
                    "interesting = 1 AND S1.id = server1 AND S2.id = server2")
        for s1,s2 in cur:
            if s1 == '<self>' or s2 == '<self>': continue
            print >>f, "   '%s,%s',"%(s1,s2)
        print >>f, "]"

        print >>f, "\n# Chains that are more unreliable than we'd expect"
        print >>f, "BROKEN_CHAINS = ["
        cur.execute("SELECT S1.identity, S2.identity "
                    "FROM echolotCurrentTwoHopResult, "
                    "   server as S1, server as S2 WHERE "
                    "broken = 1 AND S1.id = server1 AND S2.id = server2")
        for s1,s2 in cur:
            if s1 == '<self>' or s2 == '<self>': continue
            print >>f, "   '%s,%s',"%(s1,s2)
        print >>f, "]"
        print >>f, "\n"
        self._db.getConnection().commit()

    def calculateAll(self, outFname=None, now=None):
        """Recalculate all statistics, writing the results into a file called
           'outFname'.  If 'outFname' is None, only save the results into the
           database.
        """
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
    """Abstract class: A PingGenerator periodically sends traffic into the
       network, or adds link padding to outgoing connections.
    """
    ## Fields:
    # directory: an instance of ClientDirectory
    # pingLog: an instance of PingLog
    # outgoingQueue: an instance of outgoingQueue, if we're going to send
    #   pings
    def __init__(self, config):
        """Create a new PingGenerator with a given configuration"""
        self.directory = None
        self.pingLog = None
        self.outgoingQueue = None

    def connect(self, directory, outgoingQueue, pingLog, keyring):
        """Use the provided directory/queue/pingLog/keyring as needed.
           This will be called before other methods of this generator."""
        pass

    def directoryUpdated(self):
        """Called when the directory has changed."""
        pass

    def getFirstPingTime(self):
        """Return the next time when we want sendPings() to be called.  Valid
           once scheduleAllPings has been called."""
        return None

    def scheduleAllPings(self, now=None):
        """Figure out when we want to ping what."""
        pass

    def sendPings(self, now=None):
        """Send all pings that are currently pending by adding them to the
           outgoing queue we were connected to.
        """
        pass

    def addLinkPadding(self, pkts):
        """Given a map from addesses (MMTPHostInfo) to lists of
           DeliverableMessage, add link padding objects
           (mixminion.server.MMTPServer.LinkPadding) as desired.  This will be
           called on all outgoing message batches.
        """
        pass

    def _sendOnePing(self, path1, path2):
        """Helper called by subclasses.  Add a ping down a two-stage path;
           queue the ping in self.outgoingQueue, and log the event in
           self.pingLog.  Path1 and path2 are lists of ServerInfo objects, or
           nicknames to be resolved by self.directory.getPath.

           self.path2 must end with self.keyring.getCurrentDescriptor().
           NOTE: Don't use self.myNickname in path1 or path2; we may not
           be in the directory.

           Return 1 if we are able to queue the ping, 0 otherwise.
        """
        assert path1 and path2
        assert (path2[-1].getIdentityDigest() ==
                self.keyring.getIdentityKeyDigest())
        try:
            p1 = self.directory.getPath(path1)
            p2 = self.directory.getPath(path2)
        except UIError, e:
            LOG.info("Not sending scheduled ping: %s",e)
            return 0
        verbose_path = ",".join([s.getNickname() for s in (p1+p2[:-1])])
        identity_list = [ s.getIdentityDigest() for s in p1+p2[:-1] ]
        payload = mixminion.BuildMessage.buildRandomPayload()
        payloadHash = mixminion.Crypto.sha1(payload)
        packet = mixminion.BuildMessage.buildForwardPacket(
            payload, exitType=mixminion.Packet.PING_TYPE, exitInfo=payloadHash,
            path1=p1, path2=p2, suppressTag=1)
        addr = p1[0].getMMTPHostInfo()
        obj = mixminion.server.PacketHandler.RelayedPacket(addr, packet)
        LOG.debug("Pinger queueing ping along path %s [%s]",verbose_path,
                  formatBase64(payloadHash))
        self.pingLog.queuedPing(payloadHash, identity_list)
        self.outgoingQueue.queueDeliveryMessage(obj, addr)
        return 1

class _PingScheduler:
    """Helper class: use an echolot-like approach to schedule pings.

       We divide time into a series of 'periods'.  Within each 'period', we
       ping servers at regular 'intervals', with the first interval offset
       from the start of the period by a random-looking amount.
    """
    ## Fields:
    # nextPingTime: map from path (list of IDs) to the next time we plan to
    #      ping it.
    # seed: a secret random value used to computer perturbations.
    def __init__(self):
        self.nextPingTime = {}#path->when
    def connect(self, directory, outgoingQueue, pingLog, keyring):
        self.directory = directory
        self.outgoingQueue = outgoingQueue
        self.pingLog = pingLog
        self.keyring = keyring
        self.seed = keyring.getPingerSeed()
    def _calcPeriodLen(self, interval):
        """Helper: Given a period length, return the interval length we'll
           use.
        """
        period = ONE_DAY
        while period < interval*2:
            period *= 2
        return period
    def scheduleAllPings(self, now=None):
        # Subclasses should override this to call _schedulePing on all paths.
        raise NotImplemented()
    def _getPeriodStart(self, t):
        """Return the start of the period containing the time t."""
        return floorDiv(t, self._period_length)*self._period_length
    def _getPingInterval(self, path):
        """Abstract: Return the interval of pings for the path 'path'."""
        raise NotImplemented()
    def _getPeriodLength(self):
        """Abstract: Return the length of the period."""
        raise NotImplemented()
    def _schedulePing(self,path,now=None):
        """Helper: schedule a single ping along the path 'path', adding
           it to self.nextPingTime.
        """
        if now is None: now = int(time.time())
        periodStart = self._getPeriodStart(now)
        periodEnd = periodStart + self._period_length
        path = tuple([ p.lower() for p in path ])

        interval = self._getPingInterval(path)
        perturbation = self._getPerturbation(path, periodStart, interval)
        t = periodStart + perturbation
        t += interval * ceilDiv(now-t, interval)
        if t>periodEnd:
            periodStart = periodEnd
            perturbation = self._getPerturbation(path,
                                                 periodStart,
                                                 interval)
            t = periodStart+perturbation

        oldTime = self.nextPingTime.get(path, None)
        self.nextPingTime[path] = t
        if oldTime != t:
            LOG.trace("Scheduling %d-hop ping for %s at %s", len(path),
                      ",".join([binascii.b2a_hex(p) for p in path]),
                      formatTime(t,1))
            #LOG.trace("(Period starts at %s; period is %s days; interval is %s sec; perturbation is %s sec)",
            #          formatTime(periodStart,1), self._period_length/ONE_DAY, interval, perturbation)
        return t
    def _getPerturbation(self, path, periodStart, interval):
        """Return the offset to be used for the ping intervals for 'path'
           of interval 'interval' within the period starting at 'periodStart'.
        """
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
    """A OneHopPingGenerator uses the Echolot ping algorithm to schedule
       single-hop pings all known servers."""
    def __init__(self, config):
        PingGenerator.__init__(self, config)
        _PingScheduler.__init__(self)
        sec = config['Pinging']
        self._ping_interval = sec['ServerPingPeriod'].getSeconds()
        self._period_length = self._calcPeriodLen(self._ping_interval)

    def directoryUpdated(self):
        self.scheduleAllPings()

    def scheduleAllPings(self, now=None):
        if now is None: now = int(time.time())
        servers = self.directory.getAllServers()
        identities = {}
        for s in servers:
            identities[s.getIdentityDigest()]=1
        for (i,) in self.nextPingTime.keys():
            if not identities.has_key(i):
                LOG.trace("Unscheduling 1-hop ping for %s",
                          binascii.b2a_hex(i))
                del self.nextPingTime[(i,)]
        for i in identities.keys():
            self._schedulePing((i,), now)

    def _getPingInterval(self, path):
        return self._ping_interval

    def sendPings(self, now=None):
        if now is None: now = time.time()
        servers = self.directory.getAllServers()
        identities = {}
        for s in servers:
            identities[s.getIdentityDigest()] = s
        pingable = []
        for i in identities.keys():
            when = self.nextPingTime.get((i,))
            if when is None:
                # No ping scheduled; server must be new to directory.
                self._schedulePing((i,),now)
                continue
            elif when > now: # Not yet.
                continue
            else:
                # Time for a ping!
                pingable.append(i)
        myDescriptor = self.keyring.getCurrentDescriptor()
        for i in pingable:
            s = identities[i]
            if self._sendOnePing([s], [myDescriptor]):
                self._schedulePing((i,), now+60)
            else:
                del self.nextPingTime[(i,)]

class TwoHopPingGenerator(_PingScheduler, PingGenerator):
    """A TwoHopPingGenerator uses the Echolot ping algorithm to schedule
       two-hop pings to all known pairs of servers.

       If we conclude that a chain of servers is 'interesting' (possibly
       broken, or too little data to tell), we ping it more frequently.
    """
    def __init__(self, config):
        PingGenerator.__init__(self, config)
        _PingScheduler.__init__(self)
        sec = config['Pinging']
        self._dull_interval = sec['DullChainPingPeriod'].getSeconds()
        self._interesting_interval = sec['ChainPingPeriod'].getSeconds()
        self._period_length = self._calcPeriodLen(
            max(self._interesting_interval,self._dull_interval))

    def directoryUpdated(self):
        self.scheduleAllPings()

    def scheduleAllPings(self, now=None):
        if now is None: now = time.time()
        servers = self.directory.getAllServers()
        identities = {}
        for s in servers:
            identities[s.getIdentityDigest()]=1
        for id1,id2 in self.nextPingTime.keys():
            if not (identities.has_key(id1) and identities.has_key(id2)):
                LOG.trace("Unscheduling 2-hop ping for %s,%s",id1,id2)
                del self.nextPingTime[(id1,id2)]
        for id1 in identities.keys():
            for id2 in identities.keys():
                self._schedulePing((id1,id2),now)

    def _getPingInterval(self, path):
        p = ",".join([self.pingLog._db.encodeIdentity(i) for i in path])
        if self.pingLog._interestingChains.get(p, 0):
            #LOG.trace("While scheduling, I decided that %s was interesting",p)
            return self._interesting_interval
        else:
            #LOG.trace("While scheduling, I decided that %s was dull",p)
            return self._dull_interval

    def sendPings(self, now=None):
        if now is None: now = time.time()
        servers = self.directory.getAllServers()
        identities = {}
        for s in servers:
            identities[s.getIdentityDigest()]=s
        pingable = []
        for id1 in identities.keys():
            for id2 in identities.keys():
                when = self.nextPingTime.get((id1,id2))
                if when is None:
                    # No ping scheduled; server must be new to directory.
                    self._schedulePing((id1,id2),now)
                    continue
                elif when > now: # Not yet.
                    continue
                else:
                    # Time for a ping!
                    pingable.append((id1,id2))
        myDescriptor = self.keyring.getCurrentDescriptor()
        for id1, id2 in pingable:
            s1 = identities[id1]
            s2 = identities[id2]
            if self._sendOnePing([s1,s2], [myDescriptor]):
                self._schedulePing((id1,id2), now+60)
            else:
                del self.nextPingTime[(id1,id2)]

class TestLinkPaddingGenerator(PingGenerator):
    """A PingGenerator to ensure that we randomly probe all known server
       addresses for liveness, from time to time."""
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
    """A CompoundPingGenerator wraps several PingGenerators as a single
       PingGenerator object."""
    def __init__(self, generators):
        self.gens = generators[:]
    def connect(self, directory, outgoingQueue, pingLog, keyring):
        assert directory
        assert outgoingQueue
        assert pingLog
        assert keyring
        for g in self.gens:
            g.connect(directory, outgoingQueue, pingLog, keyring)
    def directoryUpdated(self):
        for g in self.gens:
            g.directoryUpdated()
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
    """Return the PingGenerator (if any) requested in config."""
    #XXXX008 make it possible to turn off some of the components.
    if not config['Pinging'].get('Enabled') or not canRunPinger():
        return CompoundPingGenerator([])
    pingers = []
    pingers.append(OneHopPingGenerator(config))
    pingers.append(TwoHopPingGenerator(config))
    pingers.append(TestLinkPaddingGenerator(config))
    return CompoundPingGenerator(pingers)

def canRunPinger():
    """Return true iff we have the required libraries installed to run a pinger.
    """
    return sys.version_info[:2] >= (2,2) and sqlite is not None

# Map from database type name to databae implementation class.
DATABASE_CLASSES = { 'sqlite' : SQLiteDatabase }

def openPingLog(config, location=None, databaseThread=None):
    """Open a ping log based on the ServerConfig 'config'.  If 'location' is
       provided, store the files in 'location'; otherwise, deduce where to
       store the files from 'config'.  If databaseThread is provided and the
       databse does not do well with multithreading (either no locking, or
       locking too coarse-grained to use), then background all calls to
       PingLog in databaseThread.
    """

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
