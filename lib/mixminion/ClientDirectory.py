# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ClientDirectory: Code to handle the 'client' side of 
   dealing with mixminion directories.  This includes:
     - downloading and caching directories
     - path generation
   DOCDOC
     """

__all__ = [ 'ClientDirectory', 'parsePath', 'parseAddress' ]

import cPickle
import errno
import operator
import os
import re
import socket
import stat
import time
import types
import urllib2

import mixminion.ClientMain #XXXX
import mixminion.Config
import mixminion.Crypto
import mixminion.NetUtils
import mixminion.Packet
import mixminion.ServerInfo

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     ceilDiv, createPrivateDir, formatDate, formatFnameTime, openUnique, \
     previousMidnight, readPickled, readPossiblyGzippedFile, \
     replaceFile, tryUnlink, writePickled, floorDiv, isSMTPMailbox
from mixminion.Packet import MBOX_TYPE, SMTP_TYPE, DROP_TYPE, FRAGMENT_TYPE, \
     parseMBOXInfo, parseSMTPInfo, ParseError

# FFFF This should be made configurable and adjustable.
MIXMINION_DIRECTORY_URL = "http://mixminion.net/directory/Directory.gz"
MIXMINION_DIRECTORY_FINGERPRINT = "CD80DD1B8BE7CA2E13C928D57499992D56579CCD"

class ClientDirectory:
    """A ClientDirectory manages a list of server descriptors, either
       imported from the command line or from a directory."""
    ##Fields:
    # dir: directory where we store everything.
    # lastModified: time when we last modified this directory.
    # lastDownload: time when we last downloaded a directory
    # serverList: List of (ServerInfo, 'D'|'D-'|'I:filename') tuples.  The
    #   second element indicates whether the ServerInfo comes from a
    #   directory or a file.  ('D-' is an unrecommended server.)
    # fullServerList: List of (ServerInfo, 'D'|'D-'|'I:filename')
    #   tuples, including servers not on the Recommended-Servers list.
    # digestMap: Map of (Digest -> 'D'|'D-'|'I:filename').
    # byNickname: Map from nickname.lower() to list of (ServerInfo, source)
    #   tuples.
    # byKeyID: Map from desc.getKeyDigest() to list of ServerInfo.
    # byCapability: Map from capability ('mbox'/'smtp'/'relay'/None) to
    #    list of (ServerInfo, source) tuples.
    # allServers: Same as byCapability[None]
    # __scanning: Flag to prevent recursive invocation of self.rescan().
    # clientVersions: String of allowable client versions as retrieved
    #    from most recent directory.
    # goodServerNicknames: A map from lowercased nicknames of recommended
    #    servers to 1.
    ## Layout:
    # DIR/cache: A cPickled tuple of ("ClientKeystore-0.2",
    #         lastModified, lastDownload, clientVersions, serverlist,
    #         fullServerList, digestMap) DOCDOC is this correct?
    # DIR/dir.gz *or* DIR/dir: A (possibly gzipped) directory file.
    # DIR/imported/: A directory of server descriptors.
    MAGIC = "ClientKeystore-0.3"

    # The amount of time to require a path to be valid, by default.
    #
    # (Servers already have a keyOverlap of a few hours, so there's not so
    #  much need to do this at the client side.)
    DEFAULT_REQUIRED_LIFETIME = 1

    def __init__(self, directory):
        """Create a new ClientDirectory to keep directories and descriptors
           under <directory>."""
        self.dir = directory
        createPrivateDir(self.dir)
        createPrivateDir(os.path.join(self.dir, "imported"))
        self.digestMap = {}
        self.__scanning = 0
        try:
            mixminion.ClientMain.clientLock() # XXXX disentangle
            self.__load()
            self.clean()
        finally:
            mixminion.ClientMain.clientUnlock() # XXXX

    def updateDirectory(self, forceDownload=0, now=None):
        """Download a directory from the network as needed."""
        if now is None:
            now = time.time()

        if forceDownload or self.lastDownload < previousMidnight(now):
            self.downloadDirectory()
        else:
            LOG.debug("Directory is up to date.")
    def downloadDirectory(self, timeout=15):
        """Download a new directory from the network, validate it, and
           rescan its servers."""
        # Start downloading the directory.
        url = MIXMINION_DIRECTORY_URL
        LOG.info("Downloading directory from %s", url)

        # XXXX Refactor download logic.
        if timeout: mixminion.NetUtils.setGlobalTimeout(timeout)
        try:
            try:
                infile = urllib2.urlopen(url)
            except IOError, e:
                raise UIError(
                    ("Couldn't connect to directory server: %s.\n"
                     "Try '-D no' to run without downloading a directory.")%e)
            except socket.error, e:
                if mixminion.NetUtils.exceptionIsTimeout(e):
                    raise UIError("Connection to directory server timed out")
                else:
                    raise UIError("Error connecting: %s"%e)
        finally:
            if timeout:
                mixminion.NetUtils.unsetGlobalTimeout()
        
        # Open a temporary output file.
        if url.endswith(".gz"):
            fname = os.path.join(self.dir, "dir_new.gz")
            outfile = open(fname, 'wb')
            gz = 1
        else:
            fname = os.path.join(self.dir, "dir_new")
            outfile = open(fname, 'w')
            gz = 0
        # Read the file off the network.
        while 1:
            s = infile.read(1<<16)
            if not s: break
            outfile.write(s)
        # Close open connections.
        infile.close()
        outfile.close()
        # Open and validate the directory
        LOG.info("Validating directory")
        try:
            directory = mixminion.ServerInfo.ServerDirectory(
                fname=fname,
                validatedDigests=self.digestMap)
        except mixminion.Config.ConfigError, e:
            raise MixFatalError("Downloaded invalid directory: %s" % e)

        # Make sure that the identity is as expected.
        identity = directory['Signature']['DirectoryIdentity']
        fp = MIXMINION_DIRECTORY_FINGERPRINT
        if fp and mixminion.Crypto.pk_fingerprint(identity) != fp:
            raise MixFatalError("Bad identity key on directory")

        tryUnlink(os.path.join(self.dir, "cache"))

        # Install the new directory
        if gz:
            replaceFile(fname, os.path.join(self.dir, "dir.gz"))
        else:
            replaceFile(fname, os.path.join(self.dir, "dir"))

        # And regenerate the cache.
        self.rescan()
        # FFFF Actually, we could be a bit more clever here, and same some
        # FFFF time. But that's for later.

    def rescan(self, force=None, now=None):
        """Regenerate the cache based on files on the disk."""
        self.lastModified = self.lastDownload = -1
        self.serverList = []
        self.fullServerList = []
        self.clientVersions = None
        self.goodServerNicknames = {}

        if force:
            self.digestMap = {}

        # Read the servers from the directory.
        gzipFile = os.path.join(self.dir, "dir.gz")
        dirFile = os.path.join(self.dir, "dir")
        for fname in gzipFile, dirFile:
            if not os.path.exists(fname): continue
            self.lastDownload = self.lastModified = \
                                os.stat(fname)[stat.ST_MTIME]
            try:
                directory = mixminion.ServerInfo.ServerDirectory(
                    fname=fname,
                    validatedDigests=self.digestMap)
            except mixminion.Config.ConfigError:
                LOG.warn("Ignoring invalid directory (!)")
                continue

            for s in directory.getServers():
                self.serverList.append((s, 'D'))
                self.digestMap[s.getDigest()] = 'D'
                self.goodServerNicknames[s.getNickname().lower()] = 1
                
            for s in directory.getAllServers():
                if self.goodServerNicknames.has_key(s.getNickname().lower()):
                    where = 'D'
                else:
                    where = 'D-'
                
                self.fullServerList.append((s, where))
                self.digestMap[s.getDigest()] = where

            self.clientVersions = (
                directory['Recommended-Software'].get("MixminionClient"))
            break

        # Now check the server in DIR/servers.
        serverDir = os.path.join(self.dir, "imported")
        createPrivateDir(serverDir)
        for fn in os.listdir(serverDir):
            # Try to read a file: is it a server descriptor?
            p = os.path.join(serverDir, fn)
            try:
                # Use validatedDigests *only* when not explicitly forced.
                info = mixminion.ServerInfo.ServerInfo(fname=p, assumeValid=0,
                                  validatedDigests=self.digestMap)
            except mixminion.Config.ConfigError:
                LOG.warn("Invalid server descriptor %s", p)
                continue
            mtime = os.stat(p)[stat.ST_MTIME]
            if mtime > self.lastModified:
                self.lastModifed = mtime
            self.serverList.append((info, "I:%s"%fn))
            self.fullServerList.append((info, "I:%s"%fn))
            self.digestMap[info.getDigest()] = "I:%s"%fn
            self.goodServerNicknames[info.getNickname().lower()] = 1

        # Regenerate the cache
        self.__save()
        # Now try reloading, to make sure we can, and to get __rebuildTables.
        self.__scanning = 1
        self.__load()

    def __load(self):
        """Helper method. Read the cached parsed descriptors from disk."""
        try:
            cached = readPickled(os.path.join(self.dir, "cache"))
            magic = cached[0]
            if magic == self.MAGIC:
                _, self.lastModified, self.lastDownload, self.clientVersions, \
                   self.serverList, self.fullServerList, self.digestMap \
                   = cached
                self.__rebuildTables()
                return
            else:
                LOG.warn("Bad version on directory cache; rebuilding...")
        except (OSError, IOError):
            LOG.info("Couldn't read directory cache; rebuilding")
        except (cPickle.UnpicklingError, ValueError), e:
            LOG.info("Couldn't unpickle directory cache: %s", e)
        if self.__scanning:
            raise MixFatalError("Recursive error while regenerating cache")
        self.rescan()

    def __save(self):
        """Helper method. Recreate the cache on disk."""
        data = (self.MAGIC,
                self.lastModified, self.lastDownload,
                self.clientVersions, self.serverList, self.fullServerList,
                self.digestMap)
        writePickled(os.path.join(self.dir, "cache"), data)

    def importFromFile(self, filename):
        """Import a new server descriptor stored in 'filename'"""

        contents = readPossiblyGzippedFile(filename)
        info = mixminion.ServerInfo.ServerInfo(string=contents, 
                                               validatedDigests=self.digestMap)

        nickname = info.getNickname()
        lcnickname = nickname.lower()
        identity = info.getIdentity()
        # Make sure that the identity key is consistent with what we know.
        for s, _ in self.serverList:
            if s.getNickname() == nickname:
                if not mixminion.Crypto.pk_same_public_key(identity,
                                                           s.getIdentity()):
                    raise MixError("Identity key changed for server %s in %s",
                                   nickname, filename)

        # Have we already imported this server?
        if self.digestMap.get(info.getDigest(), "X").startswith("I:"):
            raise UIError("Server descriptor is already imported")

        # Is the server expired?
        if info.isExpiredAt(time.time()):
            raise UIError("Server descriptor is expired")

        # Is the server superseded?
        if self.byNickname.has_key(lcnickname):
            if info.isSupersededBy([s for s,_ in self.byNickname[lcnickname]]):
                raise UIError("Server descriptor is already superseded")

        # Copy the server into DIR/servers.
        fnshort = "%s-%s"%(nickname, formatFnameTime())
        fname = os.path.join(self.dir, "imported", fnshort)
        f = openUnique(fname)[0]
        f.write(contents)
        f.close()
        # Now store into the cache.
        fnshort = os.path.split(fname)[1]
        self.serverList.append((info, 'I:%s'%fnshort))
        self.fullServerList.append((info, 'I:%s'%fnshort))
        self.digestMap[info.getDigest()] = 'I:%s'%fnshort
        self.lastModified = time.time()
        self.__save()
        self.__rebuildTables()

    def expungeByNickname(self, nickname):
        """Remove all imported (non-directory) server nicknamed 'nickname'."""
        lcnickname = nickname.lower()
        n = 0 # number removed
        newList = [] # replacement for serverList.

        for info, source in self.serverList:
            if source == 'D' or info.getNickname().lower() != lcnickname:
                newList.append((info, source))
                continue
            n += 1
            try:
                fn = source[2:]
                os.unlink(os.path.join(self.dir, "imported", fn))
            except OSError, e:
                LOG.error("Couldn't remove %s: %s", fn, e)

        self.serverList = newList
        # Recreate cache if needed.
        if n:
            self.rescan()
        return n

    def __rebuildTables(self):

        """Helper method.  Reconstruct byNickname, byKeyID,
           allServers, and byCapability from the internal start of
           this object.  """
        self.byNickname = {}
        self.byKeyID = {}
        self.allServers = []
        self.byCapability = { 'mbox': [],
                              'smtp': [],
                              'relay': [],
                              'frag': [],
                              None: self.allServers }
        self.goodServerNicknames = {}

        for info, where in self.serverList:
            nn = info.getNickname().lower()
            lists = [ self.allServers, self.byNickname.setdefault(nn, []),
                      self.byKeyID.setdefault(info.getKeyDigest(), []) ]
            for c in info.getCaps():
                lists.append( self.byCapability[c] )
            for lst in lists:
                lst.append((info, where))
            self.goodServerNicknames[nn] = 1

        for info, where in self.fullServerList:
            nn = info.getNickname().lower()
            if self.goodServerNicknames.get(nn):
                continue
            self.byNickname.setdefault(nn, []).append((info, where))

    def listServers(self):
        """Returns a linewise listing of the current servers and their caps.
            This will go away or get refactored in future versions once we
            have client-level modules.
        """
        lines = []
        nicknames = self.byNickname.keys()
        nicknames.sort()
        if not nicknames:
            return [ "No servers known" ]
        longestnamelen = max(map(len, nicknames))
        fmtlen = min(longestnamelen, 20)
        nnFormat = "%"+str(fmtlen)+"s:%s"
        for n in nicknames:
            nnreal = self.byNickname[n][0][0].getNickname()
            isGood = self.goodServerNicknames.get(n, 0)
            if isGood:
                status = ""
            else:
                status = " (not recommended)"
            lines.append(nnFormat%(nnreal,status))
            for info, where in self.byNickname[n]:
                caps = info.getCaps()
                va = formatDate(info['Server']['Valid-After'])
                vu = formatDate(info['Server']['Valid-Until'])
                line = "      [%s to %s] %s"%(va,vu," ".join(caps))
                lines.append(line)
        return lines

    def listServers2(self, features, at=None, goodOnly=0):
        """DOCDOC
           Returns a dict from nickname to (va,vu) to feature to value."""
        result = {}
        if not self.fullServerList:
            return {}
        dirFeatures = [ 'status' ]
        resFeatures = []
        for f in features:
            if f.lower() in dirFeatures:
                resFeatures.append((f, ('+', f.lower())))
            else:
                feature = mixminion.Config.resolveFeatureName(
                    f, mixminion.ServerInfo.ServerInfo)
                resFeatures.append((f, feature))
        for sd, _ in self.fullServerList:
            if at and not sd.isValidAt(at):
                continue
            nickname = sd.getNickname()
            isGood = self.goodServerNicknames.get(nickname, 0)
            if goodOnly and not isGood:
                continue
            va, vu = sd['Server']['Valid-After'], sd['Server']['Valid-Until']
            d = result.setdefault(nickname, {}).setdefault((va,vu), {})
            for feature,(sec,ent) in resFeatures:
                if sec == '+':
                    if ent == 'status':
                        if isGood:
                            d['status'] = "(ok)"
                        else:
                            d['status'] = "(not recommended)"
                    else:
                        assert 0
                else:
                    d[feature] = str(sd.getFeature(sec,ent))

        return result

    def __find(self, lst, startAt, endAt):
        """Helper method.  Given a list of (ServerInfo, where), return all
           elements that are valid for all time between startAt and endAt.

           Only one element is returned for each nickname; if multiple
           elements with a given nickname are valid over the given time
           interval, the most-recently-published one is included.
           """
        # FFFF This is not really good: servers may be the same, even if
        # FFFF their nicknames are different.  The logic should probably
        # FFFF go into directory, though.

        u = {} # Map from lcnickname -> latest-expiring info encountered in lst
        for info, _  in lst:
            if not info.isValidFrom(startAt, endAt):
                continue
            n = info.getNickname().lower()
            if u.has_key(n):
                if u[n].isNewerThan(info):
                    continue
            u[n] = info

        return u.values()

    def getNicknameByKeyID(self, keyid):
        s = self.byKeyID.get(keyid)
        if not s:
            return None
        r = []
        for d in s:
            if d.getNickname().lower() not in r:
                r.append(d.getNickname())
        return "/".join(r)

    def getNameByRelay(self, routingType, routingInfo):
        routingInfo = mixminion.Packet.parseRelayInfoByType(
            routingType, routingInfo)
        nn = self.getNicknameByKeyID(routingInfo.keyinfo)
        if nn is None:
            return routingInfo.format()
        else:
            return nn

    def getLiveServers(self, startAt=None, endAt=None):
        """DOCDOC"""
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = time.time()+self.DEFAULT_REQUIRED_LIFETIME
        return self.__find(self.serverList, startAt, endAt)

    def clean(self, now=None):
        """Remove all expired or superseded descriptors from DIR/servers."""

        if now is None:
            now = time.time()
        cutoff = now - 600

        # List of (ServerInfo,where) not to scratch.
        newServers = []
        for info, where in self.serverList:
            lcnickname = info.getNickname().lower()
            # Find all other SI's with the same name.
            others = [ s for s, _ in self.byNickname[lcnickname] ]
            # Find all digests of servers with the same name, in the directory.
            inDirectory = [ s.getDigest()
                            for s, w in self.byNickname[lcnickname]
                            if w in ('D','D-') ]
            if (where not in ('D', 'D-')
                and (info.isExpiredAt(cutoff)
                     or info.isSupersededBy(others)
                     or info.getDigest() in inDirectory)):
                # If the descriptor is not in the directory, and it is
                # expired, is superseded, or is duplicated by a descriptor
                # from the directory, remove it.
                try:
                    os.unlink(os.path.join(self.dir, "imported", where[2:]))
                except OSError, e:
                    LOG.info("Couldn't remove %s: %s", where[2:], e)
            else:
                # Don't scratch non-superseded, non-expired servers.
                newServers.append((info, where))

        # If we've actually deleted any servers, replace self.serverList and
        # rebuild.
        if len(self.serverList) != len(newServers):
            self.serverList = newServers
            self.rescan()
            
    def getServerInfo(self, name, startAt=None, endAt=None, strict=0):
        """Return the most-recently-published ServerInfo for a given
           'name' valid over a given time range.  If not strict, and no
           such server is found, return None.

           name -- A ServerInfo object, a nickname, or a filename.
           """

        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + self.DEFAULT_REQUIRED_LIFETIME

        if isinstance(name, mixminion.ServerInfo.ServerInfo):
            # If it's a valid ServerInfo, we're done.
            if name.isValidFrom(startAt, endAt):
                return name
            else:
                LOG.error("Server is not currently valid")
        elif self.byNickname.has_key(name.lower()):
            # If it's a nickname, return a serverinfo with that name.
            s = self.__find(self.byNickname[name.lower()], startAt, endAt)

            if not s:
                raise UIError(
                    "Couldn't find any currently live descriptor with name %s"
                    % name)

            s = s[0]
            if not self.goodServerNicknames.has_key(s.getNickname().lower()):
                LOG.warn("Server %s is not recommended",name)
            
            return s
        elif os.path.exists(os.path.expanduser(name)):
            # If it's a filename, try to read it.
            fname = os.path.expanduser(name)
            try:
                return mixminion.ServerInfo.ServerInfo(fname=fname, 
                                                       assumeValid=0)
            except OSError, e:
                raise UIError("Couldn't read descriptor %r: %s" %
                               (name, e))
            except mixminion.Config.ConfigError, e:
                raise UIError("Couldn't parse descriptor %r: %s" %
                               (name, e))
        elif strict:
            raise UIError("Couldn't find descriptor for %r" % name)
        else:
            return None

    def generatePaths(self, nPaths, pathSpec, exitAddress, 
                      startAt=None, endAt=None,
                      prng=None):
        """Return a list of pairs of lists of serverinfo DOCDOC."""

        if prng is None:
            prng = mixminion.Crypto.getCommonPRNG()

        paths = []
        lastHop = exitAddress.getLastHop()
        if lastHop:
            plausibleExits = []
        else:
            plausibleExits = exitAddress.getExitServers(self,startAt,endAt)
            if exitAddress.isSSFragmented:
                # We _must_ have a single common last hop.
                plausibleExits = [ prng.pick(plausibleExits) ]

        for _ in xrange(nPaths):
            p1 = []
            p2 = []
            for p in pathSpec.path1:
                p1.extend(p.getServerNames())
            for p in pathSpec.path2:
                p2.extend(p.getServerNames())

            p = p1+p2
            # Make the exit hop _not_ be None; deal with getPath brokenness.
            #XXXX refactor this.
            if lastHop:
                p.append(lastHop)
            elif p[-1] == None and not exitAddress.isReply:
                p[-1] = prng.pick(plausibleExits)
 
            if pathSpec.lateSplit:
                n1 = ceilDiv(len(p),2)
            else:
                n1 = len(p1)

            path = self.getPath(p, startAt=startAt, endAt=endAt)
            path1,path2 = path[:n1], path[n1:]
            paths.append( (path1,path2) )
            if exitAddress.isReply or exitAddress.isSURB:
                LOG.info("Selected path is %s",
                         ",".join([s.getNickname() for s in path]))
            else:
                LOG.info("Selected path is %s:%s",
                         ",".join([s.getNickname() for s in path1]),
                         ",".join([s.getNickname() for s in path2]))

        return paths
    
    def getPath(self, template, startAt=None, endAt=None, prng=None):
        """Workhorse method for path selection.  Given a template, and
           a capability that must be supported by the exit node, return
           a list of serverinfos that 'matches' the template, and whose
           last node provides exitCap.

           The template is a list of either: strings or serverinfos as
           expected by 'getServerInfo'; or None to indicate that
           getPath should select a corresponding server.

           All servers are chosen to be valid continuously from
           startAt to endAt.

           The path selection algorithm perfers to choose without
           replacement it it can.
        """
        # Fill in startAt, endAt, prng if not provided
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + self.DEFAULT_REQUIRED_LIFETIME
        if prng is None:
            prng = mixminion.Crypto.getCommonPRNG()

        # Resolve explicitly-provided servers
        servers = []
        for name in template:
            if name is None:
                servers.append(name)
            else:
                servers.append(self.getServerInfo(name, startAt, endAt, 1))

        # Now figure out which relays we haven't used yet.
        relays = self.__find(self.byCapability['relay'], startAt, endAt)
        if not relays:
            raise UIError("No relays known")
        elif len(relays) == 2:
            LOG.warn("Not enough servers to avoid same-server hops")
        elif len(relays) == 1:
            LOG.warn("Only one relay known")

        # Now fill in the servers. For each relay we need...
        for i in xrange(len(servers)):
            if servers[i] is not None:
                continue
            # Find the servers adjacent to it, if any...
            if i>0:
                prev = servers[i-1]
            else:
                prev = None
            if i+1<len(servers):
                next = servers[i+1]
            else:
                next = None
            # ...and see if there are any relays left that aren't adjacent?
            candidates = []
            for c in relays:
                if ((prev and c.hasSameNicknameAs(prev)) or
                    (next and c.hasSameNicknameAs(next)) or
                    (prev and not prev.canRelayTo(c)) or
                    ((not prev) and not c.canStartAt()) or
                    (next and not c.canRelayTo(next))):
                    continue
                candidates.append(c)                    
            if candidates:
                # Good.  There are.
                servers[i] = prng.pick(candidates)
            else:
                # Nope.  Can we duplicate a relay?
                LOG.warn("Repeating a relay because of routing restrictions.")
                if prev and next: 
                    if prev.canRelayTo(next):
                        servers[i] = prev
                    elif next.canRelayTo(next):
                        servers[i] = next
                    else:
                        raise UIError("Can't generate path %s->???->%s"%(
                                      prev.getNickname(),next.getNickname()))
                elif prev and not next:
                    servers[i] = prev
                elif next and not prev:
                    servers[i] = next
                else:
                    raise UIError("No servers known.")

        # FFFF We need to make sure that the path isn't totally junky.

        return servers

    def validatePath(self, pathSpec, exitAddress, startAt=None, endAt=None):
        """DOCDOC 
           takes pathspec; raises UIError or does nothing."""
        if startAt is None: startAt = time.time()
        if endAt is None: endAt = startAt+self.DEFAULT_REQUIRED_LIFETIME

        p = pathSpec.path1+pathSpec.path2
        # Make sure all elements are valid.
        for e in p:
            e.validate(self, startAt, endAt)

        #XXXX006 make sure p can never be empty!

        # If there is a 1st element, make sure we can route to it.
        fixed = p[0].getFixedServer(self, startAt, endAt)
        if fixed and not fixed.canStartAt():
            raise UIError("Cannot relay messages to %s"%fixed.getNickname())

        # When there are 2 elements in a row, make sure each can route to
        # the next.
        prevFixed = None
        for e in p:
            fixed = e.getFixedServer(self, startAt, endAt)
            if prevFixed and fixed and not prevFixed.canRelayTo(fixed):
                raise UIError("Server %s can't relay to %s",
                              prevFixed.getNickname(), fixed.getNickname())
            prevFixed = fixed

        fs = p[-1].getFixedServer(self,startAt,endAt)
        lh = exitAddress.getLastHop()
        if lh is not None:
            lh_s = self.getServerInfo(lh, startAt, endAt)
            if lh_s is None:
                raise UIError("No known server descriptor named %s",lh)
            if fs and not fs.canRelayTo(lh_s):
                raise UIError("Server %s can't relay to %s",
                              fs.getNickname(), lh)
            fs = lh_s
        if fs is not None:
            exitAddress.checkSupportedByServer(fs)
        elif exitAddress.isServerRelative():
            raise UIError("%s exit type expects a fixed exit server.",
                          exitAddress.getPrettyExitType())
            
    def checkClientVersion(self):
        """Check the current client's version against the stated version in
           the most recently downloaded directory; print a warning if this
           version isn't listed as recommended.
           """
        if not self.clientVersions:
            return
        allowed = self.clientVersions.split()
        current = mixminion.__version__
        if current in allowed:
            # This version is recommended.
            return
        current_t = mixminion.version_info
        more_recent_exists = 0
        for a in allowed:
            try:
                t = mixminion.parse_version_string(a)
            except ValueError:
                LOG.warn("Couldn't parse recommended version %s", a)
                continue
            try:
                if mixminion.cmp_versions(current_t, t) < 0:
                    more_recent_exists = 1
            except ValueError:
                pass
        if more_recent_exists:
            LOG.warn("This software may be obsolete; "
                      "You should consider upgrading.")
        else:
            LOG.warn("This software is newer than any version "
                     "on the recommended list.")

#----------------------------------------------------------------------
def compressServerList(featureMap, ignoreGaps=0, terse=0):
    """DOCDOC
        featureMap is nickname -> va,vu -> feature -> value .
        result is  same format, but time is compressed.
    """
    result = {}
    for nickname in featureMap.keys():
        byStartTime = featureMap[nickname].items()
        byStartTime.sort()
        r = []
        for (va,vu),features in byStartTime:
            if not r:
                r.append((va,vu,features))
                continue
            lastva, lastvu, lastfeatures = r[-1]
            if (ignoreGaps or lastvu == va) and lastfeatures == features:
                r[-1] = lastva, vu, features
            else:
                r.append((va,vu,features))
        result[nickname] = {}
        for va,vu,features in r:
            result[nickname][(va,vu)] = features

        if not terse: continue
        if not result[nickname]: continue
        
        ritems = result[nickname].items()
        minva = min([ va for (va,vu),features in ritems ])
        maxvu = max([ vu for (va,vu),features in ritems ])
        rfeatures = {}
        for (va,vu),features in ritems:
            for f,val in features.items():
                if rfeatures.setdefault(f,val) != val:
                    rfeatures[f] += " / %s"%val
        result[nickname] = { (minva,maxvu) : rfeatures }
    
    return result

def formatFeatureMap(features, featureMap, showTime=0, cascade=0, sep=" "):
    # No cascade:
    # nickname:time1: value value value
    # nickname:time2: value value value

    # Cascade=1:
    # nickname:
    #     time1: value value value
    #     time2: value value value

    # Cascade = 2:
    # nickname:
    #     time:
    #       feature:value
    #       feature:value
    #       feature:value
    nicknames = [ (nn.lower(), nn) for nn in featureMap.keys() ]
    nicknames.sort()
    lines = []
    if not nicknames: return lines
    for _, nickname in nicknames:
        d = featureMap[nickname]
        if not d: continue
        items = d.items()
        items.sort()
        if cascade: lines.append("%s:"%nickname)
        for (va,vu),fmap in items:
            ftime = "%s to %s"%(formatDate(va),formatDate(vu))
            if cascade and showTime:
                lines.append("  %s:"%ftime)
            if cascade:
                for f in features:
                    v = fmap[f]
                    lines.append("    %s:%s"%(f,v))
            elif showTime:
                lines.append("%s:%s:%s" %(nickname,ftime,
                   sep.join([fmap[f] for f in features])))
            else:
                lines.append("%s:%s" %(nickname,
                   sep.join([fmap[f] for f in features])))
    return lines

#----------------------------------------------------------------------

KNOWN_STRING_EXIT_TYPES = [
    "mbox", "smtp", "drop"
]

class ExitAddress:
    #FFFF Perhaps this crams too much into ExitAddress.
    def __init__(self,exitType=None,exitAddress=None,lastHop=None,isReply=0, 
                 isSURB=0,isSSFragmented=0):
        if isReply:
            assert exitType is None
            assert exitAddress is None
        else:
            assert exitType is not None
            assert exitAddress is not None
        if type(exitType) == types.StringType:
            if exitType not in KNOWN_STRING_EXIT_TYPES:
                raise UIError("Unknown exit type: %r"%exitType)
        elif type(exitType) == types.IntType:
            if not (0 <= exitType <0xFFFF):
                raise UIError("Exit type 0x%04X is out of range."%exitType)
        else:
            raise UIError("Unknown exit type: %r"%exitType)
        self.exitType = exitType
        self.exitAddress = exitAddress
        self.lastHop = lastHop
        self.isReply = isReply
        self.isSURB = isSURB
        self.isSSFragmented = isSSFragmented #server-side frag reassembly only.
        self.nFragments = self.exitSize = 0
        self.headers = {}
    def getFragmentedMessagePrefix(self):
        routingType, routingInfo, _ = self.getRouting()
        return mixminion.Packet.ServerSideFragmentedMessage(
            routingType, routingInfo, "").pack()
        
    def setFragmented(self, isSSFragmented, nFragments):
        self.isSSFragmented = isSSFragmented
        self.nFragments = nFragments
    def hasPayload(self):
        return self.exitType not in ('drop', DROP_TYPE)
    def setExitSize(self, exitSize):
        self.exitSize = exitSize
    def setHeaders(self, headers):
        self.headers = headers
    def getLastHop(self):
        return self.lastHop
    def isSupportedByServer(self, desc):
        try:
            self.checkSupportedByServer(desc,verbose=0)
            return 1
        except UIError:
            return 0
    def checkSupportedByServer(self, desc,verbose=1):
        if self.isReply:
            return
        nickname = desc.getNickname()

        if self.headers:
            #XXXX006 remove this eventually.
            sware = desc['Server'].get("Software")
            if (sware.startswith("Mixminion 0.0.4") or 
                sware.startswith("Mixminion 0.0.5alpha1")):
                raise UIError("Server %s is running old software that doesn't support exit headers.", nickname)

        if self.isSSFragmented:
            dfsec = desc['Delivery/Fragmented']
            if not dfsec.get("Version"):
                raise UIError("Server %s doesn't support fragment reassembly."
                              %nickname)
            if self.nFragments > dfsec.get("Maximum-Fragments",0):
                raise UIError("Too many fragments for server %s to reassemble."
                              %nickname)
        if self.exitType in ('smtp', SMTP_TYPE):
            ssec = desc['Delivery/SMTP']
            if not ssec.get("Version"):
                raise UIError("Server %s doesn't support SMTP"%nickname)
            if self.headers.has_key("FROM") and not ssec['Allow-From']:
                raise UIError("Server %s doesn't support user-supplied From"%
                              nickname)
            if floorDiv(self.exitSize,1024) > ssec['Maximum-Size']:
                raise UIError("Message to long for server %s to deliver."%
                              nickname)
        elif self.exitType in ('mbox', MBOX_TYPE):
            msec = desc['Delivery/MBOX']
            if not msec.get("Version"):
                raise UIError("Server %s doesn't support MBOX"%nickname)
            if self.headers.has_key("FROM") and not msec['Allow-From']:
                raise UIError("Server %s doesn't support user-supplied From"%
                              nickname)
            if floorDiv(self.exitSize,1024) > msec['Maximum-Size']:
                raise UIError("Message to long for server %s to deliver."%
                              nickname)
        elif self.exitType in ('drop', DROP_TYPE):
            # everybody supports 'drop'.
            pass
        else:
            if not verbose: return
            LOG.warn("No way to tell if server %s supports exit type %s.",
                     nickname, self.getPrettyExitType())

    def getPrettyExitType(self):
        if type(self.exitType) == types.IntType:
            return "0x%04X"%self.exitType
        else:
            return self.exitType

    def isServerRelative(self):
        return self.exitType in ('mbox', MBOX_TYPE)
            
    def getExitServers(self, directory, startAt=None, endAt=None):
        """DOCDOC
           Return a list of all exit servers that might work."""
        assert self.lastHop is None
        liveServers = directory.getLiveServers(startAt, endAt)
        result = [ desc for desc in liveServers
                   if self.isSupportedByServer(desc) ]
        return result

    def getRouting(self):
        """DOCDOC"""
        ri = self.exitAddress
        if self.isSSFragmented:
            rt = FRAGMENT_TYPE
            ri = ""
        elif self.exitType == 'smtp':
            rt = SMTP_TYPE
        elif self.exitType == 'drop':
            rt = DROP_TYPE
        elif self.exitType == 'mbox':
            rt = MBOX_TYPE
        else:
            assert type(self.exitType) == types.IntType
            rt = self.exitType
        return rt, ri, self.lastHop

def parseAddress(s):
    """Parse and validate an address; takes a string, and returns an
       ExitAddress object.

       Accepts strings of the format:
              mbox:<mailboxname>@<server>
           OR smtp:<email address>
           OR <email address> (smtp is implicit)
           OR drop
           OR 0x<routing type>:<routing info>
    """
    # ???? Should this should get refactored into clientmodules, or someplace?
    if s.lower() == 'drop':
        return ExitAddress('drop',"")
    elif s.lower() == 'test':
        return ExitAddress(0xFFFE, "")
    elif ':' not in s:
        if isSMTPMailbox(s):
            return ExitAddress('smtp', s)
        else:
            raise ParseError("Can't parse address %s"%s)
    tp,val = s.split(':', 1)
    tp = tp.lower()
    if tp.startswith("0x"):
        try:
            tp = int(tp[2:], 16)
        except ValueError:
            raise ParseError("Invalid hexidecimal value %s"%tp)
        if not (0x0000 <= tp <= 0xFFFF):
            raise ParseError("Invalid type: 0x%04x"%tp)
        return ExitAddress(tp, val)
    elif tp == 'mbox':
        if "@" in val:
            mbox, server = val.split("@",1)
            return ExitAddress('mbox', parseMBOXInfo(mbox).pack(), server)
        else:
            return ExitAddress('mbox', parseMBOXInfo(val).pack(), None)
    elif tp == 'smtp':
        # May raise ParseError
        return ExitAddress('smtp', parseSMTPInfo(val).pack(), None)
    elif tp == 'test':
        return ExitAddress(0xFFFE, val, None)
    else:
        raise ParseError("Unrecognized address type: %s"%s)

class PathElement:
    def validate(self, directory, start, end):
        raise NotImplemented()
    def getFixedServer(self, directory, start, end):
        raise NotImplemented()
    def getServerNames(self):
        raise NotImplemented()
    def getMinLength(self):
        raise NotImplemented()

class ServerPathElement(PathElement):
    def __init__(self, nickname):
        self.nickname = nickname
    def validate(self, directory, start, end):
        if None == directory.getServerInfo(self.nickname, start, end):
            raise UIError("No valid server found with name %r"%self.nickname)
    def getFixedServer(self, directory, start, end):
        return directory.getServerInfo(self.nickname, start, end)
    def getServerNames(self):
        return [ self.nickname ]
    def getMinLength(self):
        return 1
    def __repr__(self):
        return "ServerPathElement(%r)"%self.nickname

class DescriptorPathElement(PathElement):
    def __init__(self, desc):
        self.desc = desc
    def validate(self, directory, start, end):
        if not self.desc.isValidFrom(start, end):
            raise UIError("Server %r is not valid during given time range",
                           self.desc.getNickname())
    def getFixedServer(self, directory, start, end):
        return self.desc
    def getServerNames(self):
        return [ self.desc ]
    def getMinLength(self):
        return 1
    def __repr__(self):
        return "DescriptorPathElement(%r)"%self.desc

class RandomServersPathElement(PathElement):
    def __init__(self, n=None, approx=None):
        assert not (n and approx)
        assert n is None or approx is None
        self.n=n
        self.approx=approx
    def validate(self, directory, start, end):
        pass
    def getFixedServer(self, directory, start, end):
        return None
    def getServerNames(self):
        if self.n is not None:
            n = self.n
        else:
            prng = mixminion.Crypto.getCommonPRNG()
            n = int(prng.getNormal(self.approx,1.5)+0.5)
        return [ None ] * n
    def getMinLength(self):
        if self.n is not None: 
            return self.n
        else:
            return self.approx
    def __repr__(self):
        if self.n:
            assert not self.approx
            return "RandomServersPathElement(n=%r)"%self.n
        else:
            return "RandomServersPathElement(approx=%r)"%self.approx

#----------------------------------------------------------------------
class PathSpecifier:
    def __init__(self, path1, path2, isReply, isSURB, lateSplit):
        if isSURB:
            assert path2 and not path1
        elif isReply:
            assert path1 and not path2
        elif not lateSplit:
            assert path1 and path2
        else:
            assert path1 or path2
        self.path1=path1
        self.path2=path2
        self.isReply=isReply
        self.isSURB=isSURB
        self.lateSplit=lateSplit

    def getFixedLastServer(self,directory,startAt,endAt):
        """DOCDOC"""
        if self.path2:
            return self.path2[-1].getFixedServer(directory,startAt,endAt)
        else:
            return None

#----------------------------------------------------------------------
def parsePath(config, path, nHops=None, isReply=0, isSURB=0,
              defaultNHops=None):
    """DOCDOC ; Returns a pathSpecifier.  This documentation is no longer
       even vaguely accurate.

       Resolve a path as specified on the command line.  Returns a
       (path-leg-1, path-leg-2) tuple, where each leg is a list of ServerInfo.

       directory -- the ClientDirectory to use.
       config -- unused for now.
       path -- the path, in a format described below.  If the path is
          None, all servers are chosen as if the path were '*'.
       address -- the address to deliver the message to; if it specifies
          an exit node, the exit node is appended to the second leg of the
          path and does not count against the number of hops.  If 'address'
          is None, the exit node must support relay.
       nHops -- the number of hops to use.  Defaults to defaultNHops.
       startAt/endAt -- A time range during which all servers must be valid.
       halfPath -- If true, we generate only the second leg of the path
          and leave the first leg empty.
       defaultNHops -- The default path length to use when we encounter a
          wildcard in the path.  Defaults to 6.

       Paths are ordinarily comma-separated lists of server nicknames or
       server descriptor filenames, as in:
             'foo,bar,./descriptors/baz,quux'.

       You can use a colon as a separator to divides the first leg of the path
       from the second:
             'foo,bar:baz,quux'.
       If nSwap and a colon are both used, they must match, or MixError is
       raised.

       You can use a question mark to indicate a randomly chosen server:
             'foo,bar,?,quux,?'.
       As an abbreviation, you can use star followed by a number to indicate
       that number of randomly chosen servers:
             'foo,bar,*2,quux'.
       You can use a star without a number to specify a fill point
       where randomly-selected servers will be added:
             'foo,bar,*,quux'.
       Finally, you can use a tilde followed by a number to specify an
       approximate number of servers to add.  (The actual number will be
       chosen randomly, according to a normal distribution with standard
       deviation 1.5):
             'foo,bar,~2,quux'

       The nHops argument must be consistent with the path, if both are
       specified.  Specifically, if nHops is used _without_ a star on the
       path, nHops must equal the path length; and if nHops is used _with_ a
       star on the path, nHops must be >= the path length.
    """
    halfPath = isReply or isSURB
    if not path:
        path = '*'
    # Break path into a list of entries of the form:
    #        Nickname
    #     or "<swap>"
    #     or "?"
    p = []
    while path:
        if path[0] == "'":
            m = re.match(r"'([^']+|\\')*'", path)
            if not m: 
                raise UIError("Mismatched quotes in path.")
            p.append(m.group(1).replace("\\'", "'"))
            path = path[m.end():]
            if path and path[0] not in ":,":
                raise UIError("Invalid quotes in path.")
        elif path[0] == '"':
            m = re.match(r'"([^"]+|\\")*"', path)
            if not m: 
                raise UIError("Mismatched quotes in path.")
            p.append(m.group(1).replace('\\"', '"'))
            path = path[m.end():]
            if path and path[0] not in ":,":
                raise UIError("Invalid quotes in path.")
        else:
            m = re.match(r"[^,:]+",path)
            if not m:
                raise UIError("Invalid path") 
            p.append(m.group(0))
            path = path[m.end():]
        if not path:
            break 
        elif path[0] == ',':
            path = path[1:]
        elif path[0] == ':':
            path = path[1:]
            p.append("<swap>")

    pathEntries = []
    for ent in p:
        if re.match(r'\*(\d+)', ent):
            pathEntries.append(RandomServersPathElement(n=int(ent[1:])))
        elif re.match(r'\~(\d+)', ent):
            pathEntries.append(RandomServersPathElement(approx=int(ent[1:])))
        elif ent == '*':
            pathEntries.append("*")
        elif ent == '<swap>':
            pathEntries.append("<swap>")
        elif ent == '?':
            pathEntries.append(RandomServersPathElement(n=1))
        else:
            pathEntries.append(ServerPathElement(ent))

    # If there's a variable-length wildcard...
    if "*" in pathEntries:
        # Find out how many hops we should have.
        starPos = pathEntries.index("*")
        if "*" in pathEntries[starPos+1:]:
            raise UIError("Only one '*' is permitted in a single path")
        approxHops = reduce(operator.add,
                            [ ent.getMinLength() for ent in pathEntries
                              if ent not in ("*", "<swap>") ], 0)
        myNHops = nHops or defaultNHops or 6
        extraHops = max(myNHops-approxHops, 0)
        pathEntries[starPos:starPos+1] =[RandomServersPathElement(n=extraHops)]

    # Figure out how long the first leg should be.
    lateSplit = 0
    if "<swap>" in pathEntries:
        # Calculate colon position
        if halfPath:
            raise UIError("Can't specify swap point with replies")
        colonPos = pathEntries.index("<swap>")
        if "<swap>" in pathEntries[colonPos+1:]:
            raise UIError("Only one ':' is permitted in a single path")
        firstLegLen = colonPos
        del pathEntries[colonPos]
    elif isReply:
        firstLegLen = len(pathEntries)
    elif isSURB:
        firstLegLen = 0
    else:
        firstLegLen = 0
        lateSplit = 1

    # Split the path into 2 legs.
    path1, path2 = pathEntries[:firstLegLen], pathEntries[firstLegLen:]
    if not lateSplit and not halfPath:
        if len(path1)+len(path2) < 2:
            raise UIError("The path must have at least 2 hops")
        if not path1 or not path2:
            raise UIError("Each leg of the path must have at least 1 hop")
    else:
        minLen = reduce(operator.add,
                        [ ent.getMinLength() for ent in pathEntries ], 0)
        if halfPath and minLen < 1:
            raise UIError("The path must have at least 1 hop")
        if not halfPath and minLen < 2:
            raise UIError("The path must have at least 2 hops")
        
    return PathSpecifier(path1, path2, isReply, isSURB, lateSplit=lateSplit)
