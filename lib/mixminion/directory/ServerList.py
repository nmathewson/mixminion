# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerList.py,v 1.52 2004/03/23 05:15:17 nickm Exp $

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
import mixminion.directory.Directory

from mixminion.Crypto import pk_decode_public_key, pk_encode_public_key, \
     pk_same_public_key
from mixminion.Common import IntervalSet, LOG, MixError, MixFatalError, \
     UIError, createPrivateDir, formatBase64, formatDate, formatFnameTime, \
     formatTime, Lockfile, openUnique, previousMidnight, readFile, \
     readPickled, readPossiblyGzippedFile, stringContains, writeFile, \
     writePickled
from mixminion.Config import ConfigError
from mixminion.ServerInfo import ServerDirectory, ServerInfo, \
     _getDirectoryDigestImpl

ACCEPTABLE_CLIENT_VERSIONS = "0.0.6.2 0.0.7rc1"
ACCEPTABLE_SERVER_VERSIONS = "0.0.6.1 0.0.6.2 0.0.7rc1"

# Make sure that the VERSIONS variables above are parseable.
for vl in (ACCEPTABLE_CLIENT_VERSIONS.split(),
           ACCEPTABLE_SERVER_VERSIONS.split()):
    for v in vl:
        mixminion.parse_version_string(v)
del v
del vl

class ServerList:
    """A ServerList holds a set of server descriptors for use in generating
       directories.  It checks new descriptors for consistency with old ones
       as they are inserted.  It will reject any server if:
          -- it is expired (Valid-Until in the past)
          -- it is superseded (For all time it is valid, a more-recently-
             published descriptor is also valid.)
          -- it is inconsistent (We already know a descriptor for this
             nickname, with a different identity key.)
             [FFFF This check will become stricter in the future.]

       This implementation isn't terribly optimized, but there's no need to
       optimize it until we have far more descriptors to worry about.
    """
    ##Fields:
    #  baseDir: Base directory of this list
    #  serverDir: Directory where we store active descriptors.
    #  rejectDir: Directory where we store invalid descriptors.
    #  archiveDir: Directory where we store old descriptors
    #  servers: Map from filename within <serverDir> to ServerInfo objects.
    #  serversByNickname: A map from lowercased server nickname to
    #       lists of filenames within <serverDir>
    #  idCache: an instance of Directory.IDCache
    ##Layout:
    #  basedir
    #     server-ids/
    #          nickname-dateinserted
    #               (Pickled: ("V0", (nickname, encoded public key)))
    #     incoming/new/
    #          nickname-dateinserted.N ...
    #     incoming/updates/
    #          nickname-dateinserted.N ...
    #     servers/
    #          nickname-dateinserted.N ...
    #     archive/
    #          nickname-dateinserted.N ...
    #     reject/
    #          nickname-dateinserted.N ...
    #     directory
    #     dirArchive/
    #          dir-dategenerated.N ...
    #     identity
    #     .lock

    def __init__(self, baseDir, idCache=None):
        """Initialize a ServerList to store servers under baseDir/servers,
           creating directories as needed.
        """
        self.baseDir = baseDir
        if idCache is None:
            idCache = mixminion.directory.Directory.IDCache(
                os.path.join(baseDir, "xx_idcache"))
        self.idCache = idCache

        self.serverIDDir = os.path.join(self.baseDir, "server-ids")
        self.serverDir = os.path.join(self.baseDir, "servers")
        self.rejectDir = os.path.join(self.baseDir, "reject")
        self.archiveDir = os.path.join(self.baseDir, "archive")
        self.dirArchiveDir = os.path.join(self.baseDir, "dirArchive")
        self.lockfile = Lockfile(os.path.join(self.baseDir, ".lock"))
        self.rlock = threading.RLock()
        self.servers = {}
        self.serversByNickname = {}
        createPrivateDir(self.serverIDDir)
        createPrivateDir(self.serverDir)
        createPrivateDir(self.rejectDir)
        createPrivateDir(self.archiveDir)
        createPrivateDir(self.dirArchiveDir)
        self.rescan()

    def isServerKnown(self, server):
        """Return true iff the current server descriptor is known.  Raises
           MixError if we have a server descriptor with this name, but
           a different key."""
        try:
            self._lock()
            try:
                return self.idCache.containsServer(server)
            except mixminion.directory.Directory.MismatchedID:
                raise UIError(("Already know a server named "
                               "%r with different identity key.")
                              % server.getNickname())
        finally:
            self._unlock()

    def rebuildIDCache(self):
        for fn in os.listdir(self.serverIDDir):
            fname = os.path.join(self.serverIDDir, fn)
            tp,val = readPickled(fname)
            if tp != "V0":
                LOG.warn("Weird file version %s on %s",tp,fname)
                continue
            nickname, ident = val
            ID = mixminion.Crypto.sha1(ident)
            self.idCache.insertID(nickname, ID)

    def learnServerID(self, server):
        """Mark the ID for a server descriptor as the canonical
           identity key associated with that server's nickname."""
        try:
            self._lock()
            ident = server.getIdentity()
            nickname = server.getNickname()
            try:
                if self.idCache.containsServer(server):
                    LOG.warn("Server %s already known", nickname)
            except mixminion.directory.MismatchedID:
                raise MixFatalError("Mismatched ID for server %s" % nickname)

            LOG.info("Learning identity for new server %s", nickname)
            self.idCache.insertServer(server)
            writePickled(os.path.join(self.serverIDDir,
                                      nickname+"-"+formatFnameTime()),
                         ("V0", (nickname, pk_encode_public_key(ident))))
            self.idCache.save()
        finally:
            self._unlock()

    def importServerInfo(self, contents, knownOnly=0, server=None):
        """Insert a ServerInfo into the list.  If the server is expired, or
           superseded, or inconsistent, raise a MixError.

           contents -- a string containing the descriptor, or the name of a
               file containing the descriptor (possibly gzip'd)
           knownOnly -- if true, raise MixError is we don't already have
               a descriptor with this nickname.
           server -- If provided, a parsed ServerInfo corresponding to
               'contents'.
        """
        # Raises ConfigError, MixError,

        if not server:
            contents, server = _readServer(contents)
        try:
            self._lock()

            nickname = server.getNickname()
            lcnickname = nickname.lower()

            known = self.isServerKnown(server)
            if knownOnly and not known:
                raise UIError("Unknown server %s: use import-new."%nickname)

            # Is the server already invalid?
            if server.isExpiredAt(time.time()):
                raise UIError("Descriptor has already expired")

            # Is there already a server with the same nickname?
            if self.serversByNickname.has_key(lcnickname):
                # Okay -- make sure we don't have this same descriptor.
                for fn in self.serversByNickname[lcnickname]:
                    oldServer = self.servers[fn]
                    if oldServer['Server']['Digest'] == \
                           server['Server']['Digest']:
                        raise UIError("Server descriptor already inserted.")
                # Okay -- make sure that this server isn't superseded.
                if server.isSupersededBy(
                    [ self.servers[fn] for fn in
                                 self.serversByNickname[lcnickname]]):
                    raise UIError("Server descriptor is superseded")

            if not known:
                # Is the identity new to us?
                self.learnServerID(server)

            newFile = _writeServer(self.serverDir, contents, nickname)

            # Now update the internal structure
            self.servers[newFile] = server
            self.serversByNickname.setdefault(lcnickname, []).append(newFile)
        finally:
            self._unlock()

    def expungeServersByNickname(self, nickname):
        """Forcibly remove all servers named <nickname>"""
        try:
            self._lock()
            LOG.info("Removing all servers named %s", nickname)
            lcnickname = nickname.lower()
            if not self.serversByNickname.has_key(lcnickname):
                LOG.info("  (No such servers exist)")
                return
            servers = self.serversByNickname[lcnickname]
            for fn in servers:
                LOG.info("  Removing %s", fn)
                _moveServer(self.serverDir, self.archiveDir, fn)
                del self.servers[fn]
            del self.serversByNickname[lcnickname]
            LOG.info("  (%s servers removed)", len(servers))
        finally:
            self._unlock()

    def generateDirectory(self,
                          startAt, endAt, extraTime,
                          identityKey,
                          publicationTime=None,
                          badServers=(),
                          excludeServers=()):
        """Generate and sign a new directory, to be effective from <startAt>
           through <endAt>.  It includes all servers that are valid at
           any time between <startAt> and <endAt>+<extraTime>.  The directory
           is signed with <identityKey>.

           Any servers whose nicknames appear in 'badServers' are marked as
           not recommended; any servers whose nicknames appear in
           'excludeServers' are left off the directory entirely.
        """
        try:
            self._lock()
            self.clean()
            if publicationTime is None:
                publicationTime = time.time()
            if previousMidnight(startAt) >= previousMidnight(endAt):
                raise MixError("Validity range does not contain a full day.")

            excludeServers = [ nickname.lower() for nickname in excludeServers]

            # First, sort all servers by nickname.
            includedByNickname =  {}
            for fn, s in self.servers.items():
                nickname = s.getNickname().lower()
                if nickname in excludeServers: continue
                includedByNickname.setdefault(nickname, []).append((s, fn))

            # Second, find all servers that are valid for part of the period,
            # and that aren't superseded for the whole period.
            timeRange = IntervalSet([(previousMidnight(startAt),
                                      endAt+extraTime)])

            for nickname, ss in includedByNickname.items():
                # We prefer the most-recently-published descriptor.  If two
                # are published at the same time, we prefer the one that
                # expires last.
                ss = [ (s['Server']['Published'],
                        s['Server']['Valid-Until'],
                        s, fn) for s,fn in ss]
                ss.sort()
                ss.reverse()
                uncovered = timeRange.copy()
                included = []
                for _, _, s, fn in ss:
                    valid = s.getIntervalSet()
                    if (uncovered * valid):
                        included.append((s, fn))
                        uncovered -= valid
                includedByNickname[nickname] = included

            # Now sort the remaining servers by nickname, then by valid-after.
            included = []
            for ss in includedByNickname.values():
                for s,fn in ss:
                    nickname = s.getNickname()
                    validAfter = s['Server']['Valid-After']
                    included.append((nickname, validAfter, fn))
            included.sort()

            # FFFF We should probably not do all of this in RAM, but
            # FFFF what the hey.  It will only matter if we have many, many
            # FFFF servers in the system.
            contents = [ ]
            for _, _, fn in included:
                txt = readFile(os.path.join(self.serverDir, fn))
                contents.append(txt)

            goodServers = [n for n,_,_ in included if n not in badServers]
            g = {}
            for n in goodServers: g[n]=1
            goodServers = g.keys()
            goodServers.sort()
            goodServers = ", ".join(goodServers)

            #FFFF Support for multiple signatures
            header = """\
            [Directory]
            Version: 0.2
            Published: %s
            Valid-After: %s
            Valid-Until: %s
            Recommended-Servers: %s
            [Signature]
            DirectoryIdentity: %s
            DirectoryDigest:
            DirectorySignature:
            [Recommended-Software]
            MixminionClient: %s
            MixminionServer: %s
            """ % (formatTime(publicationTime),
                   formatDate(startAt),
                   formatDate(endAt),
                   goodServers,
                   formatBase64(pk_encode_public_key(identityKey)),
                   ACCEPTABLE_CLIENT_VERSIONS,
                   ACCEPTABLE_SERVER_VERSIONS)

            directory = header+"".join(contents)
            directory = _getDirectoryDigestImpl(directory, identityKey)

            # Make sure that the directory checks out
            # FFFF remove this once we are _very_ confident.
            if 1:
                parsed = ServerDirectory(string=directory)
                includedDigests = {}
                for _, _, fn in included:
                    includedDigests[self.servers[fn]['Server']['Digest']] = 1
                foundDigests = {}
                for s in parsed.getAllServers():
                    foundDigests[s['Server']['Digest']] = 1
                assert foundDigests == includedDigests

            writeFile(os.path.join(self.baseDir, "directory"),
                      directory,
                      mode=0644)

            f, _ = openUnique(os.path.join(self.dirArchiveDir,
                                            "dir-"+formatFnameTime()))
            f.write(directory)
            f.close()
        finally:
            self._unlock()

    def getDirectoryFilename(self):
        """Return the filename of the most recently generated directory"""
        return os.path.join(self.baseDir, "directory")

    def clean(self, now=None):
        """Remove all expired or superseded servers from the active directory.
        """
        # This algorithm is inefficient: O(N_descs * N_descs_per_nickname).
        # We're just going to ignore that.
        if now is None:
            now = time.time()

        try:
            self._lock()
            removed = {} # Map from filename->whyRemoved
            # Find all superseded servers
            for servers in self.serversByNickname.values():
                servers = [ (self.servers[fn]['Server']['Published'],
                            fn, self.servers[fn]) for fn in servers ]
                servers.sort()
                fns = [ fn for _, fn, _ in servers]
                servers = [ s for _, _, s  in servers ]
                for idx in range(len(servers)):
                    if servers[idx].isSupersededBy(servers[idx+1:]):
                        removed[fns[idx]] = "superseded"

            # Find all expired servers.
            for fn, s in self.servers.items():
                if removed.has_key(fn):
                    continue
                if s.isExpiredAt(now-6000):
                    # The descriptor is expired.
                    removed[fn] = "expired"

            # Now, do the actual removing.
            for fn, why in removed.items():
                LOG.info("Removing %s descriptor %s", why, fn)
                _moveServer(self.serverDir, self.archiveDir, fn)
                del self.servers[fn]

            self.__buildNicknameMap()
        finally:
            self._unlock()

    def rescan(self):
        """Reconstruct this ServerList object's internal state."""
        try:
            self._lock()
            # First, build self.servers
            self.servers = {}
            for filename in os.listdir(self.serverDir):
                path = os.path.join(self.serverDir, filename)
                try:
                    self.servers[filename] = ServerInfo(fname=path)
                except ConfigError, e:
                    LOG.warn("Somehow, a bad server named %s got in our store",
                             filename)
                    LOG.warn(" (Error was: %s)", str(e))
                    _moveServer(self.serverDir, self.rejectDir, filename)

            # Next, rebuild self.serverIDs:
            self.serverIDs = {}
            for filename in os.listdir(self.serverIDDir):
                path = os.path.join(self.serverIDDir, filename)
                t = readPickled(path)
                if t[0] != 'V0':
                    LOG.warn("Skipping confusing stored key in file %s",
                             filename)
                    continue
                nickname, key = t[1]
                key = pk_decode_public_key(key)
                if self.serverIDs.has_key(nickname.lower()):
                    LOG.warn("Eeek! Multiple entries for %s", nickname)
                    if not pk_same_public_key(self.serverIDs[nickname.lower()],
                                              key):
                        raise MixFatalError(
                            "Multiple conflicting entries for %s"%nickname)
                self.serverIDs[nickname.lower()] = key

            # (check for consistency)
            for s in self.servers.values():
                lcn = s.getNickname().lower()
                try:
                    ident = self.serverIDs[lcn]
                except KeyError:
                    raise UIError("No stored key for server %s" %
                                  s.getNickname())

                if not pk_same_public_key(ident, s.getIdentity()):
                    raise UIError("Inconsistent stored key for server %s" %
                                  s.getNickname())

            # Then, rebuild self.serversByNickname
            self.__buildNicknameMap()
        finally:
            self._unlock()

    def __buildNicknameMap(self):
        """Helper method. Regenerate self.serversByNickname from
           self.servers

           Caller must hold lock."""
        self.serversByNickname = {}
        for fn, server in self.servers.items():
            nickname = server.getNickname()
            self.serversByNickname.setdefault(nickname.lower(), []).append(fn)

    def _lock(self):
        self.rlock.acquire()
        self.lockfile.acquire(blocking=1)

    def _unlock(self):
        self.lockfile.release()
        self.rlock.release()

def _moveServer(directory1, directory2, fname):
    """Move a server contained in directory1/fname into directory2, chosing
       a new name for it as needed, and avoiding duplicates."""
    fname1 = os.path.join(directory1, fname)
    if "-" in fname:
        nn = fname[:fname.find("-")]
    else:
        nn = "UNKNOWN"
    s = readPossiblyGzippedFile(fname1)
    _writeServer(directory2, s, nn)
    os.unlink(fname1)

def _writeServer(directory, contents, nickname, mode=0600):
    """Write a server descriptor in 'contents' into a new file in
       'directory'.  The file will have permissions 'mode', and a name
       of the form nickname-YYYYMMDDHHMMSS.n
    """
    newFile = nickname+"-"+formatFnameTime()
    f, newFile = openUnique(os.path.join(directory, newFile), 'w', mode)
    newFile = os.path.split(newFile)[1]
    f.write(contents)
    f.close()
    return newFile

def _readServer(contents):
    """Read a ServerInfo from the string 'contents', which is either a
       server descriptor or the name of a file holding a descriptor.
       Raise MixError on failure."""
    if stringContains(contents, "[Server]"):
        pass
    else:
        contents = readPossiblyGzippedFile(contents)

    # May raise ConfigError, MixError
    return contents, ServerInfo(string=contents, assumeValid=0)
