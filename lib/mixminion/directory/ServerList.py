# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerList.py,v 1.4 2003/01/03 08:47:28 nickm Exp $

"""mixminion.directory.ServerList

   Implements a store of sererinfos for a diectory.
   
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

from mixminion.Crypto import pk_encode_public_key, pk_same_public_key
from mixminion.Common import IntervalSet, LOG, MixError, createPrivateDir, \
     formatBase64, formatDate, formatFnameTime, formatTime, previousMidnight, \
     readPossiblyGzippedFile, stringContains
from mixminion.Config import ConfigError
from mixminion.ServerInfo import ServerDirectory, ServerInfo, \
     _getDirectoryDigestImpl

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
    #  serversByNickname: A map from server nickname to lists of filenames
    #       within <serverDir>
    ##Layout:
    #  basedir
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
    def __init__(self, baseDir):
        """Initialize a ServerList to store servers under baseDir/servers,
           creating directories as needed.
        """
        self.baseDir = baseDir
        self.serverDir = os.path.join(self.baseDir, "servers")
        self.rejectDir = os.path.join(self.baseDir, "reject")
        self.archiveDir = os.path.join(self.baseDir, "archive")
        self.dirArchiveDir = os.path.join(self.baseDir, "dirArchive")
        self.servers = {}
        self.serversByNickname = {}
        createPrivateDir(self.serverDir)
        createPrivateDir(self.rejectDir)
        createPrivateDir(self.archiveDir)
        createPrivateDir(self.dirArchiveDir)
        self.rescan()
        
    def importServerInfo(self, server, knownOnly=0):
        """Insert a ServerInfo into the list.  If the server is expired, or
           superseded, or inconsistent, raise a MixError. 
           
           server -- a string containing the descriptor, or the name of a
               file containing the descriptor (possibly gzip'd)
           knownOnly -- if true, raise MixError is we don't already have
               a descriptor with this nickname.
        """
        # Raises ConfigError, MixError, 
        if stringContains(server, "[Server]"):
            contents = server
        else:
            contents = readPossiblyGzippedFile(server)

        server = ServerInfo(string=contents, assumeValid=0)

        nickname = server.getNickname()
        if knownOnly and not self.serversByNickname.has_key(nickname):
            raise MixError("Unknown server %s: use import-new."%nickname)

        # Is the server already invalid?
        if server.isExpiredAt(time.time()):
            raise MixError("Descriptor has already expired")

        # Is there already a server with the same nickname?
        if self.serversByNickname.has_key(nickname):
            # Make sure the identity key is the same.
            oldServer = self.servers[self.serversByNickname[nickname][0]]
            oldIdentity = oldServer.getIdentity()
            newIdentity = server.getIdentity()
            if not pk_same_public_key(newIdentity, oldIdentity):
                raise MixError("Identity key has changed for %r" % nickname)
            # Okay -- make sure we don't have this same descriptor.
            for fn in self.serversByNickname[nickname]:
                oldServer = self.servers[fn]
                if oldServer['Server']['Digest'] == server['Server']['Digest']:
                    raise MixError("Server descriptor already inserted.")
            # Okay -- make sure that this server isn't superseded.
            if server.isSupersededBy(
               [ self.servers[fn] for fn in self.serversByNickname[nickname]]):
                raise MixError("Server descriptor is superseded")
        
        newFile = nickname+"-"+formatFnameTime()
        f, newFile = _openUnique(os.path.join(self.serverDir, newFile))
        newFile = os.path.split(newFile)[1]
        f.write(contents)
        f.close()

        # Now update the internal structure
        self.servers[newFile] = server
        self.serversByNickname.setdefault(nickname, []).append(newFile)

    def expungeServersByNickname(self, nickname):
        """Forcibly remove all servers named <nickname>"""
        LOG.info("Removing all servers named %s", nickname)
        if not self.serversByNickname.has_key(nickname):
            LOG.info("  (No such servers exist)")
            return
        servers = self.serversByNickname[nickname]
        for fn in servers:
            LOG.info("  Removing %s", fn)
            os.rename(os.path.join(self.serverDir, fn),
                      os.path.join(self.archiveDir, fn))
            del self.servers[fn]
        del self.serversByNickname[nickname]
        LOG.info("  (%s servers removed)", len(servers))

    def generateDirectory(self,
                          startAt, endAt, extraTime,
                          identityKey, publicationTime=None):
        """Generate and sign a new directory, to be effective from <startAt>
           through <endAt>.  It includes all servers that are valid at
           any time between <startAt> and <endAt>+>extraTime>.  The directory
           is signed with <identityKey> """
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
        
        #FFFF Support for multiple signatures
        header = """\
        [Directory]
        Version: 0.1
        Published: %s
        Valid-After: %s
        Valid-Until: %s
        [Signature]
        DirectoryIdentity: %s
        DirectoryDigest:
        DirectorySignature:
        """ % (formatTime(publicationTime), 
               formatDate(startAt), 
               formatDate(endAt),
               formatBase64(pk_encode_public_key(identityKey)))

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

        f, _ = _openUnique(os.path.join(self.dirArchiveDir,
                                        "dir-"+formatFnameTime()))
        f.write(directory)
        f.close()

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

        removed = {} # Map from filename->whyRemoved
        # Find all superseded servers
        for name, servers in self.serversByNickname.items():
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
                name = s.getNickname()
                removed[fn] = "expired"
       
        # This is a kinda nasty hack: we never remove the last descriptor for
        # a given nickname.  If we did, we would lose track of the server's
        # identity key.
        for name, fns in self.serversByNickname.items():
            nRemoved = len([fn for fn in fns if removed.has_key(fn)])
            if nRemoved < len(fns):
                continue
            # We're about to remove all the descriptors--that's bad! 
            # We find the most recent one, and remove it from but 
            servers = [ (self.servers[fn]['Server']['Published'], 
                         fn, self.servers[fn]) for fn in fns ]
            servers.sort()
            fn = servers[-1][1]
            LOG.info("Retaining %s descriptor %s -- it's the last one for %s",
                     removed[fn], fn, name)
            del removed[fn]
 
        # Now, do the actual removing.
        for fn, why in removed.items():
            LOG.info("Removing %s descriptor %s", why, fn)
            os.rename(os.path.join(self.serverDir, fn),
                      os.path.join(self.archiveDir, fn))

            del self.servers[fn]

        self.__buildNicknameMap()        
    
    def rescan(self):
        """Reconstruct this ServerList object's internal state."""
        self.servers = {}
        # First, build self.servers
        for filename in os.listdir(self.serverDir):
            path = os.path.join(self.serverDir, filename)
            try:
                self.servers[filename] = ServerInfo(fname=path)
            except ConfigError, e:
                LOG.warn("Somehow, a bad server named %s got into our store",
                         filename)
                LOG.warn(" (Error was: %s)", str(e))
                os.rename(path, os.path.join(self.rejectDir, filename))

        # Then, rebuild self.serversByNickname
        self.__buildNicknameMap()

    def __buildNicknameMap(self):
        """Helper method. Regenerate self.serversByNickname from
           self.servers"""
        self.serversByNickname = {}
        for fn, server in self.servers.items():
            nickname = server.getNickname()
            self.serversByNickname.setdefault(nickname, []).append(fn)

def _openUnique(fname, mode='w'):
    """Helper function. Returns a file open for writing into the file named
       'fname'.  If fname already exists, opens 'fname.1' or 'fname.2' or
       'fname.3' or so on."""
    # ???? Should this go into common?
    base, rest = os.path.split(fname)
    idx = 0
    while 1:
        try:
            fd = os.open(fname, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0600)
            return os.fdopen(fd, mode), fname
        except OSError:
            pass
        idx += 1
        fname = os.path.join(base, "%s.%s"%(rest,idx))

        
