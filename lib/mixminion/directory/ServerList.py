# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerList.py,v 1.16 2003/05/23 07:54:11 nickm Exp $

"""mixminion.directory.ServerList

   Implements a store of serverinfos for a directory.

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

from mixminion.Crypto import pk_decode_public_key, pk_encode_public_key, \
     pk_same_public_key
from mixminion.Common import IntervalSet, LOG, MixError, UIError, \
     createPrivateDir, \
     formatBase64, formatDate, formatFnameTime, formatTime, Lockfile, \
     openUnique, \
     previousMidnight, readPickled, readPossiblyGzippedFile, stringContains, \
     writePickled
from mixminion.Config import ConfigError
from mixminion.ServerInfo import ServerDirectory, ServerInfo, \
     _getDirectoryDigestImpl

ACCEPTABLE_CLIENT_VERSIONS = "0.0.3"
ACCEPTABLE_SERVER_VERSIONS = "0.0.3"

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
    #  serverIDs: Map from lowercased server nickname to serverID.
    #  serversByNickname: A map from lowercased server nickname to
    #       lists of filenames within <serverDir>
    ##Layout:
    #  basedir
    #     server-ids/
    #          nickname-dateinserted
    #               (Pickled: ("V0", (nickname, encoded public key)))
    #     incoming/
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
    def __init__(self, baseDir):
        """Initialize a ServerList to store servers under baseDir/servers,
           creating directories as needed.
        """
        self.baseDir = baseDir
        self.serverIDDir = os.path.join(self.baseDir, "server-ids")
        self.serverDir = os.path.join(self.baseDir, "servers")
        self.incomingDir = os.path.join(self.baseDir, "incoming")
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
            nickname = server.getNickname()
            lcnickname = nickname.lower()
            try:
                oldIdentity = self.serverIDs[lcnickname]
            except KeyError:
                return 0

            newIdentity = server.getIdentity()
            if not pk_same_public_key(newIdentity, oldIdentity):
                raise UIError("Already know a server named %r with a different identity key." % nickname)

            return 1
        finally:
            self._unlock()

    def learnServerID(self, server):
        """DOCDOC"""
        try:
            self._lock()
            nickname = server.getNickname()
            LOG.info("Learning identity for new server %s", nickname)
            ident = server.getIdentity()
            writePickled(os.path.join(self.serverIDDir,
                                      nickname+"-"+formatFnameTime()),
                         ("V0", (nickname, pk_encode_public_key(ident))))
            
            self.serverIDs[nickname.lower()] = ident
        finally:
            self._unlock()

    def importServerInfo(self, contents, knownOnly=0, server=None):
        """Insert a ServerInfo into the list.  If the server is expired, or
           superseded, or inconsistent, raise a MixError.

           contents -- a string containing the descriptor, or the name of a
               file containing the descriptor (possibly gzip'd)
           knownOnly -- if true, raise MixError is we don't already have
               a descriptor with this nickname.

           DOCDOC
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
                    if oldServer['Server']['Digest'] == server['Server']['Digest']:
                        raise UIError("Server descriptor already inserted.")
                # Okay -- make sure that this server isn't superseded.
                if server.isSupersededBy(
                 [ self.servers[fn] for fn in self.serversByNickname[lcnickname]]):
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
                os.rename(os.path.join(self.serverDir, fn),
                          os.path.join(self.archiveDir, fn))
                del self.servers[fn]
            del self.serversByNickname[lcnickname]
            LOG.info("  (%s servers removed)", len(servers))
        finally:
            self._unlock()
            
    def generateDirectory(self,
                          startAt, endAt, extraTime,
                          identityKey,
                          publicationTime=None,
                          goodServers=None):
        """Generate and sign a new directory, to be effective from <startAt>
           through <endAt>.  It includes all servers that are valid at
           any time between <startAt> and <endAt>+>extraTime>.  The directory
           is signed with <identityKey> """
        try:
            self._lock()
            self.clean()
            if publicationTime is None:
                publicationTime = time.time()
            if previousMidnight(startAt) >= previousMidnight(endAt):
                raise MixError("Validity range does not contain a full day.")
            included = []
            for fn, s in self.servers.items():
                if not s.isValidAtPartOf(startAt, endAt+extraTime):
                    continue
                nickname = s.getNickname()
                validAfter = s['Server']['Valid-After']
                included.append((nickname, validAfter, fn))

            included.sort()
            # FFFF We should probably not do all of this in RAM, but what the hey.
            # FFFF It will only matter if we have many, many servers in the system.
            contents = [ ]
            for _, _, fn in included:
                f = open(os.path.join(self.serverDir, fn), 'r')
                contents.append(f.read())
                f.close()

            if goodServers is None:
                goodServers = [n for n,_,_ in included]
            else:
                goodServers = [n for n,_,_ in included if n in goodServers]
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
                for s in parsed.getServers():
                    foundDigests[s['Server']['Digest']] = 1
                assert foundDigests == includedDigests

            f = open(os.path.join(self.baseDir, "directory"), 'w')
            f.write(directory)
            f.close()

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
        """Remove all expired or superceded servers from the active directory.
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
                        removed[fns[idx]] = "superceded"

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
                os.rename(os.path.join(self.serverDir, fn),
                          os.path.join(self.archiveDir, fn))

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
                    LOG.warn("Somehow, a bad server named %s got into our store",
                             filename)
                    LOG.warn(" (Error was: %s)", str(e))
                    os.rename(path, os.path.join(self.rejectDir, filename))

            # Next, rebuild self.serverIDs:
            self.serverIDs = {}
            for filename in os.listdir(self.serverIDDir):
                path = os.path.join(self.serverIDDir, filename)
                t = readPickled(path)
                if t[0] != 'V0':
                    LOG.warn("Skipping confusing stored key in file %s", filename)
                    continue
                nickname, key = t[1]
                self.serverIDs[nickname.lower()] = pk_decode_public_key(key)

            # (check for consistency)
            for s in self.servers.values():
                lcn = s.getNickname().lower()
                try:
                    ident = self.serverIDs[lcn]
                except KeyError:
                    raise UIError("No stored key for server %s", s.getNickname())

                if not pk_same_public_key(ident, s.getIdentity()):
                    raise UIError("Inconsistent stored key for server %s",
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
        self.lockfile.acquire()

    def _unlock(self):
        self.lockfile.release()
        self.rlock.release()

class ServerQueue:
    """DOCDOC"""
    def __init__(self, incomingDir):
        """DOCDOC"""
        self.incomingDir = incomingDir
        createPrivateDir(self.incomingDir)

    def queueIncomingServer(self, contents, server):
        """DOCDOC"""
        nickname = server.getNickname()
        _writeServer(nickname, contents, self.incomingDir)

    def serversPending(self):
        """DOCDOC"""
        return len(os.listdir(self.incomingDir)) > 0

    def readPendingServers(self):
        res = []
        for fname in os.listdir(self.incomingDir):
            path = os.path.join(self.incomingDir,fname)
            try:
                text, server = _readServer(path)
            except (ConfigError, MixError),e:
                os.unlink(path)
                LOG.warn("Removed a bad server descriptor %s from incoming dir: %s",
                         fname, e)

            res.append((fname, server, text, getIDFingerprint(server)))
        return res

    def delPendingServers(self, fnames):
        for fname in fnames:
            try:
                os.path.unlink(os.path.join(self.incomingDir, fname))
            except OSError:
                LOG.warn("delPendingServers: no such server %s"%fname)

class ServerQueuedException(Exception):
    """DOCDOC"""
    pass

def receiveServer(serverList, incomingQueue, text, source):
    """DOCDOC

       Returns true on OK; raises UIError on failure; raises ServerQueued on
       wait-for-admin."""
    try:
        text, server = _readServer(text)
    except MixError, e:
        LOG.warn("Rejected invalid server from %s: %s", source,e)
        raise UIError("Server descriptor was not valid: %s"%e)

    try:
        known = serverList.isServerKnown(server)
    except MixError, e:
        LOG.warn("Rejected server with mismatched identity from %s", source)
        raise

    if not known:
        LOG.info("Received previously unknown server from %s", source)
        incomingQueue.queueIncomingServer(text,server)
        raise ServerQueuedException()

    serverList.importServerInfo(text, knownOnly=1, server=server)

def acceptServer(serverList, incomingQueue, nickname):
    if ':' in nickname:
        nickname, fingerprint = nickname.split(":")
    else:
        fingerprint = None
        
    lcnickname = nickname.lower()
    incoming = incomingQueue.readPendingServers()
    # Do we have any pending servers of the desired name?
    incoming = [ (fname,server,text,fp)
                 for fname,server,text,fp in incoming
                 if server.getNickname().lower() == lcnickname ]
    if not incoming:
        raise UIError("No incoming servers named %s"%nickname)

    if not fingerprint:
        fps = [fp for f,s,t,fp in incoming]
        for f in fps:
            if f != fps[0]:
                raise UIError("Multiple KeyIDs for servers names %s"%nickname)
        reject = []
    else:
        reject = [ (f,s,t,fp) for f,s,t,fp in incoming
                   if fp != fingerprint ]
        incoming = [ (f,s,t,fp) for f,s,t,fp in incoming
                    if fp == fingerprint ]
        if not incoming:
            raise UIError("No servers named %s with matching KeyID"%nickname)
        if reject:
            LOG.warn("Rejecting %s server(s) named %s with unmatching KeyIDs",
                     len(reject), nickname)

    try:
        serverList._lock()
        serverList.learnServerID(incoming[0][1])
        accepted = []
        for fname,server,text,fp in incoming:
            try:
                serverList.importServerInfo(text,server=server)
                accepted.append(fname)
            except MixError, e:
                LOG.warn("ServerList refused to include server %s: %s",
                         fname, e)
                reject.append((fname,server,text,fp))

        if len(accepted):
            LOG.warn("Key ID learned; no servers actually imported")
        else:
            LOG.info("%s server descriptor(s) imported.", len(accepted))

        LOG.info("Moving %s descriptors to rejected status"%len(reject))
        for fname,_,text,_ in reject:
            _writeServer(serverList.rejectDir, text, "BAD-"+nickname)

        incomingQueue.delPendingServers([fname for fname,_,text,_ in reject])
        incomingQueue.delPendingServers(accepted)
    finally:
        serverList._unlock()

def listPendingServers(f, incomingQueue):
    """DOCDOC"""
    incoming = incomingQueue.readPendingServers()
    # lcnickname->fp->servers
    servers = {}
    # lcnickname->nicknames
    nicknames = {}
    
    for f,s,t,fp in incoming:
        nickname = s.getNickname()
        lcnickname = nickname.lower()
        nicknames.setdefault(lcnickname, []).append(nickname)
        servers.setdefault(lcnickname, {}).setdefault(fp, []).append(s)

    sorted = nicknames.keys()
    sorted.sort()
    maxlen = max([len(n) for n in sorted])
    format = " %"+str(maxlen)+"s:%s [%s descriptors]"
    for lcnickname in sorted:
        nickname = nicknames[lcnickname][0]
        ss = servers[lcnickname]
        if len(ss) > 1:
            print >>f, ("***** MULTIPLE KEYIDS FOR %s:"%nickname)
        for fp, s in ss:
            print >>f, (format%(nickname,fp,len(s)))
        
def _writeServer(directory, contents, nickname):
    newFile = nickname+"-"+formatFnameTime()
    f, newFile = openUnique(os.path.join(directory, "newFile"))
    newFile = os.path.split(newFile)[1]
    f.write(contents)
    f.close()
    return newFile

def _readServer(contents):
    if stringContains(contents, "[Server]"):
        pass
    else:
        contents = readPossiblyGzippedFile(contents)

    # May raise ConfigError, MixError
    return contents, ServerInfo(string=contents, assumeValid=0)

def getIDFingerprint(server):
    """DOCDOC"""
    ident = server.getIdentity()
    return formatBase64(
        mixminion.Crypto.sha1(
             mixminion.Crypto.pk_encode_public_key(ident)))
 
