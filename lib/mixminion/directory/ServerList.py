# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerList.py,v 1.1 2002/12/31 04:33:25 nickm Exp $

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
     formatBase64, formatDate, formatFnameTime, formatTime, stringContains
from mixminion.Config import ConfigError
from mixminion.ServerInfo import ServerInfo, _getDirectoryDigestImpl

# Layout:
#  basedir
#     servers/
#       nickname-dateinserted.
#     archive/
#     reject/
#     directory
#     dirArchive/

class ServerList:
    "DOCDOC"
    ##Fields: DOCDOC
    #  baseDir
    #  serverDir
    #  servers (filename->ServerInfo)
    #  serversByNickname (nickname -> [filename, filename,...])
    def __init__(self, baseDir):
        "DOCDOC"
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
        
    def importServerInfo(self, server):
        "DOCDOC"
        # Raises ConfigError, MixError, 
        if stringContains(server, "[Server]"):
            contents = server
        else:
            f = open(server, 'r')
            contents = f.read()
            f.close()

        server = ServerInfo(string=contents, assumeValid=0)

        nickname = server.getNickname()
        validUntil = server['Server']['Valid-Until']
        # Is the server already invalid?
        if validUntil < time.time():
            raise MixError("Descriptor has already expired")

        # Is there already a server with the same nickname?
        if self.serversByNickname.has_key(nickname):
            # Make sure the identity key is the same.
            oldServer = self.servers[self.serversByNickname[nickname][0]]
            oldIdentity = oldServer['Server']['Identity']
            newIdentity = server['Server']['Identity']
            if not pk_same_public_key(newIdentity, oldIdentity):
                raise MixError("Identity key has changed for %r" % nickname)
            # Okay -- make sure we don't have this same descriptor.
            for fn in self.serversByNickname[nickname]:
                oldServer = self.servers[fn]
                if oldServer['Server']['Digest'] == server['Server']['Digest']:
                    raise MixError("Server descriptor already inserted.")

            newFile = nickname+"-"+formatFnameTime()
            if os.path.exists(os.path.join(self.serverDir, newFile)):
                idx = 1
                # XXXX This is race-prone if we try to run many insert
                # XXXX processes at once.
                while os.path.exists(os.path.join(self.serverDir, 
                                                  "%s.%s"%(newFile,idx))):
                    idx += 1
                newFile = "%s.%s" %(newFile,idx)

            f = open(os.path.join(self.serverDir, newFile), 'w')
            f.write(contents)
            f.close()

            # Now update the internal structure
            self.servers[newFile] = server
            self.serversByNickname.setdefault(nickname, []).append(server)

    def generateDirectory(self,
                          #XXXX two of the next 4 args are redundant... which?
                          startAt, endAt, 
                          dirValidAfter, dirValidUntil, 
                          now,
                          identityKey):
        "DOCDOC"
        included = []
        for fn, s in self.servers.items():
            validAfter = s['Server']['Valid-After']
            validUntil = s['Server']['Valid-Until']
            if validUntil < startAt or endAt < validAfter:
                continue
            nickname = s.getNickname()
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
        """ % (formatTime(now), formatDate(dirValidAfter), 
               formatDate(dirValidUntil),
               formatBase64(pk_encode_public_key(identityKey)))

        directory = header+"".join(contents)
        directory = _getDirectoryDigestImpl(directory, identityKey)

        for fname in (os.path.join(self.baseDir, "directory"),
                  os.path.join(self.dirArchiveDir, "dir-"+formatFnameTime())):
            f = open(fname, 'w')
            f.write(fname)
            f.close()

    def getDirectoryFilename(self):
        "DOCDOC"
        return os.path.join(self.baseDir, "directory")

    def clean(self, now=None):
        "DOCDOC"
        # A server needs to be cleaned out if it is no longer valid,
        # or if its future validity range is wholly covered by other, more
        # recently published descriptors for the same server.

        # This algorithm is inefficient: O(N_descs * N_descs_per_nickname).
        # We're just going to ignore that.
        if now is None:
            now = time.time()

        removed = {}
        beforeNow = IntervalSet([0, time.time()])
        for name, servers in self.serversByNickname.items():
            valid = {}
            published = {}
            for fn in servers:
                s = self.servers[fn]
                published[fn] = s['Server']['Published']
                validAfter = s['Server']['Valid-After']
                validUntil = s['Server']['Valid-Until']
                valid[fn] = IntervalSet([validAfter, validUntil])
            
            for fn in servers:
                vOrig = valid[fn]
                v = vOrig.copy()
                v -= beforeNow
                p = published[fn]
                s = []
                for fn2 in servers:
                    if published[fn2] <= p:
                        continue
                    if vOrig * valid[fn2]:
                        v -= valid[fn2]
                        s.append(fn2)
                if v.isEmpty():
                    LOG.info("Removing superceded descriptor %s", fn)
                    LOG.info("   (superceded by %s", ",".join(s))
                    removed[fn] = 1

        # This is a kinda nasty hack: we never remove the last server for
        # a given nickname.  If we did, 
        nRemovedByNickname = {}
        for name, fns in self.serversByNickname.items():
            nRemovedByNickname[name] = len(
                [fn for fn in fns if removed.has_key(fn)])
            assert nRemovedByNickname[name] < len(fns)

        for fn, s in self.servers.items():
            if removed.has_key(fn):
                continue
            if s['Server']['Valid-Until'] < now - 6000:
                # Don't remove the last key for a nickname.
                name = s.getNickname()
                if (nRemovedByNickname[name] + 1 == 
                               len(self.serversByNickname[name])):
                    continue
                
                LOG.info("Removing expired descriptor %s", fn)
                removed[fn] = 1
        
        for fn in removed.keys():
            os.rename(os.path.join(self.serverDir, fn),
                      os.path.join(self.archiveDir, fn))
        
            del self.servers[fn]

        self.__buildNicknameMap()        
                    
    def rescan(self):
        "DOCDOC"
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

        self.__buildNicknameMap()

    def __buildNicknameMap(self):
        self.serversByNickname = {}
        for fn, server in self.servers.items():
            nickname = server.getNickname()
            self.serversByNickname.setDefault(nickname, []).append(fn)
        
