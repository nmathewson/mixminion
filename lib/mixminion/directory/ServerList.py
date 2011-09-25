# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.

"""mixminion.directory.ServerList

   Implements a store of serverinfos for a directory, as well as functions
   to generate and sign directories.

   FFFF Right now, this is about maximally slow.  There are a lot of tricks
   FFFF we could do to speed it up: not revalidating servers in our cache;
   FFFF pickling serverinfo objects for easy access, and so on.  But
   FFFF really, we'd need to get 1000 servers before any of these tricks made
   FFFF more than a 10-second difference in directory generation time, so
   FFFF let's leave it simple for now.
   """

__all__ = [ 'ServerList' ]

import os
import time
import threading

import mixminion
import mixminion.Config
import mixminion.Filestore
import mixminion.directory.Directory

from mixminion.Crypto import pk_decode_public_key, pk_encode_public_key, \
     pk_same_public_key
from mixminion.Common import IntervalSet, LOG, MixError, MixFatalError, \
     UIError, createPrivateDir, formatBase64, formatDate, formatFnameTime, \
     formatTime, iterFileLines, Lockfile, openUnique, previousMidnight, readFile,\
     readPickled, readPossiblyGzippedFile, stringContains, writeFile, \
     writePickled
from mixminion.Config import ConfigError
from mixminion.ServerInfo import ServerDirectory, ServerInfo, \
     _getDirectoryDigestImpl

"""
Redesign notes:

  We need to store a pile of descriptors.  They aren't always ones we
  believe in.  They can be:
     - expired (archive these)
     - superseded (archive these)
     - reliable or not
     - trusted or not

  Our workflow looks like this:
    1. On node publish: serverdesc stored into an inbox by DirCGI.
       Minimal validation performed: check for another server with same nick,
       different identity; check for expired/far-future.
    2. Regularly: copy servers from inbox into main store, revalidating them.
        - Move bogus servers into reject (Bogus==can't validate; have validated
          different ID with that nick; etc.).
        - Move dead/superseded servers into archive.
        - Make current-raw-servers.gz
        [ENTRY]
    3. Regularly: Pull other directories' current-raw-servers.gz and find
         out if there are any new servers. [ENTRY]
    4. Regularly: if there are any servers neither trusted nor distrusted,
         email the administrator. [ENTRY]
    5. Daily:
         - Generate a vote directory. [ENTRY]
         - Download all other vote directories. [ENTRY]
         - Generate consensus directory [ENTRY]
         - Pull down sigs from other consensus directories; attach them
           to consensus directory. [ENTRY]
LATER:
         - Incorporate information from pinger.  Make sure probationary
           servers get pinged.

"""

class DescriptorStatus:
    def __init__(self, digest, published, validAfter, validUntil, nickname,
                 identityDigest):
        self._digest = digest
        self._published = published
        self._validAfter = validAfter
        self._validUntil = validUntil
        self._nickname = nickname
        self._identityDigest = identityDigest

    def isSupersededBy(self, others):
        valid = IntervalSet([(self._validAfter, self._validUntil)])
        for o in others:
            if (o._published > self._published and
                o._identityDigest == self._identityDigest):
                valid -= o.getIntervalSet()
        return valid.isEmpty()

class ServerStore:
    KEY_LENGTH=29
    def __init__(self, location, dbLocation, insertOnly=0):
        self._loc = location
        self._dbLoc = dbLocation
        if not insertOnly:
            self.clean()
            self._statusDB = mixminion.Filestore.WritethroughDict(
                self._dbLoc, "server cache")
        else:
            self._statusDB = None
        createPrivateDir(location)

    def close(self):
        self._statusDB.close()

    def sync(self):
        self._statusDB.sync()

    def hasServer(self, server):
        key = self._getKey(server.getDigest())
        if self._statusDB is None:
            return os.path.exists(os.path.join(self._loc,key))
        else:
            return self._statusDB.has_key(key)

    def addServer(self, server, contents=None):
        # returns key
        if contents is None:
            assert server._originalContents
            contents = server._originalContents
        key = self._getKey(server.getDigest())
        f = AtomicFile(os.path.join(self._loc,key))
        try:
            f.write(contents)
            f.close()
        except:
            f.discard()
            raise

        if self._statusDB is not None:
            self._updateCache(key, server)
        return key

    def delServer(self, key):
        if self._statusDB is not None:
            try:
                del self._statusDB[key]
            except KeyError:
                pass
        try:
            os.unlink(os.path.join(self._loc, key))
        except OSError:
            pass

    def rescan(self):
        self._statusDB.close()
        os.path.unlink(self._dbLoc)
        self.clean()
        self._statusDB = mixminion.Filestore.WritethroughDict(
            self._dbLoc, "server cache")
        for key in os.listdir(self._loc):
            fn = os.path.join(self._loc, key)
            try:
                #XXXX digest-cache
                server = ServerInfo(fname=fn)
            except (OSError, MixError, ConfigError), e:
                LOG.warn("Deleting invalid server %s: %s", key, e)
                os.unlink(fn)
                server = None
            if server is None: continue

            k2 = self._getKey(server.getDigest())
            if k2 != key:
                LOG.info("Renaming server in %s to correct file %s",key,k2)
                os.rename(fn, os.path.join(self._loc, k2))
                key = k2
            self._updateCache(key, server)

        self.flush()

    def archiveServers(self, archiveLocation, now=None):
        if now is not None:
            now = time.time()

        archive = {}
        byIdentity = {}
        for key, status in self._statusDB.items():
            if status._validUntil < now:
                archive[key] = 1
                continue
            byIdentity.setdefault(status._identityDigest, []).append(status)

        for ident, servers in byIdentity.items():
            for s in servers:
                if s.isSupersededBy(servers):
                    archive[self._getKey(s._digest)] = 1

        for key in archive.keys():
            self.moveServer(key,archiveLocation)

    def moveServer(self, key, location):
        os.rename(os.path.join(self._loc, key),
                  os.path.join(location, key))
        try:
            del self._statusDB[key]
        except KeyError:
            pass

    def loadServer(self, key, keepContents=0, assumeValid=1):
        #XXXX008 digest-cache
        return ServerInfo(fname=os.path.join(self._loc,key),
                          assumeValid=assumeValid,
                          _keepContents=keepContents)

    def listKeys(self):
        if self._statusDB is not None:
            return self._statusDB.keys()
        else:
            return [ f for f in os.path.listdir(self._loc)
                     if not f.endswith(".tmp") ]

    def getByNickname(self, nickname):
        return [ key for key,status in self._statusDB.items()
                 if status._nickname == nickname ]

    def getByIdentityDigest(self, digest):
        return [ key for key,status in self._statusDB.items()
                 if status._identityDigest == identityDigest ]

    def getByLiveness(self, startAt, endAt):
        return [ key for key,status in self._statusDB.items()
                 if (endAt > status._validAfter and
                     startAt < status._validUntil) ]

    def _updateCache(self, key, server):
        assert key == self._getKey(server.getDigest())

        sec = server['Server']

        status = DescriptorStatus(sec['Digest'],
                                  sec['Published'],
                                  sec['Valid-After'],
                                  sec['Valid-Until'],
                                  sec['Nickname'],
                                  server.getKeyDigest())
        self._statusDB[key] = status

    def _getKey(self, digest):
        k = formatBase64(digest).replace("/","-").replace("=","")
        assert len(k) == self.KEY_LENGTH
        return k

    def clean(self):
        for fn in os.listdir(self._loc):
            if len(fn) > self.KEY_LENGTH and stringContains(fn, ".tmp"):
                os.unlink(os.path.join(self._loc,fn))

    def _repOK(self):
        self.clean()
        keys = self._statusDB.keys()
        fnames = os.listdir(self._loc)
        keys.sort()
        fnames.sort()
        if keys != fnames: return 0

        for f in fnames:
            status = self._statusDB[f]
            try:
                #XXXX digest-cache
                server = ServerInfo(fname=os.path.join(self._loc, f))
            except:
                return 0
            if status._digest != server.getDigest(): return 0
            if status._published != server['Server']['Published']: return 0
            if status._validAfter != server['Server']['Valid-After']: return 0
            if status._validUntil != server['Server']['Valid-Until']: return 0
            if status._nickname != server['Server']['Nickname']: return 0
            if status._identityDigest != server.getKeyStatus(): return 0

        return 1

class LiveServerList:
    def __init__(self, store):
        self.store = store

    def clean(self, voteList, archiveLocation, now=None):
        self.store.flush()
        self.store.clean()
        self.store.archiveServers(archiveLocation, now=now)
        rejectKeys = [ k for k,status in self.store._statusDB.items()
                  if voteList.status[status._identityDigest][0] == 'ignore']
        for k in rejectKeys:
            self.store.moveServer(k, archiveLocation)

    def generateRawServerList(self, voteList, archiveLocation, outFile,
                              now=None):
        if now is None:
            now = time.time()
        self.store.clean(voteList, archiveLocation, now=now)
        # add 2 extra days for margin-of-error.
        for k in self.store.getByLiveness(now, now+24*60*60*32):
            f = open(os.path.join(self.store._loc, k), 'r')
            outFile.write(f.read())
            f.close()

    def addServersFromInbox(self, inbox):
        self.inbox.moveEntriesToStore(self)

    def _addOneFromRawDirLines(self, lines):
        s = "".join(lines)
        #XXXX digest-cache
        si = ServerInfo(s,assumeValid=0,keepContents=1)
        if not self.store.hasServer(si):
            self.store.addServer(si)

    def addServersFromRawDirectoryFile(self, file):
        curLines = []
        for line in iterFileLines(file):
            if line == '[Server]\n' and curLines:
                self._addOneFromRawLines(curLines)
                del curLines[:]
        if curLines:
            self._addOneFromRawLines(curLines)

