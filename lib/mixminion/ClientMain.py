# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.60 2003/02/14 17:01:49 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.
   """

__all__ = [ 'Address', 'ClientKeyring', 'ClientDirectory', 'MixminionClient',
    'parsePath', ]

import anydbm
import binascii
import cPickle
import getopt
import getpass
import os
import stat
import sys
import time
import urllib
from types import ListType

import mixminion.BuildMessage
import mixminion.Crypto
import mixminion.MMTPClient
from mixminion.Common import IntervalSet, LOG, floorDiv, MixError, \
     MixFatalError, MixProtocolError, UIError, UsageError, ceilDiv, \
     createPrivateDir, isSMTPMailbox, formatDate, formatFnameTime, formatTime,\
     Lockfile, openUnique, previousMidnight, readPossiblyGzippedFile, \
     secureDelete, stringContains, succeedingMidnight
from mixminion.Crypto import sha1, ctr_crypt, trng
from mixminion.Config import ClientConfig, ConfigError
from mixminion.ServerInfo import ServerInfo, ServerDirectory
from mixminion.Packet import ParseError, parseMBOXInfo, parseReplyBlocks, \
     parseSMTPInfo, parseTextEncodedMessage, parseTextReplyBlocks, ReplyBlock,\
     MBOX_TYPE, SMTP_TYPE, DROP_TYPE

# FFFF This should be made configurable and adjustable.
MIXMINION_DIRECTORY_URL = "http://www.mixminion.net/directory/directory.gz"
MIXMINION_DIRECTORY_FINGERPRINT = "CD80DD1B8BE7CA2E13C928D57499992D56579CCD"

#----------------------------------------------------------------------
# Global variable; holds an instance of Common.Lockfile used to prevent
# concurrent access to the directory cache, message pool, or SURB log.
_CLIENT_LOCKFILE = None

def clientLock():
    """Acquire the client lock."""
    assert _CLIENT_LOCKFILE is not None
    _CLIENT_LOCKFILE.acquire(blocking=1)

def clientUnlock():
    """Release the client lock."""    
    _CLIENT_LOCKFILE.release()

def configureClientLock(filename):
    """Prepare the client lock for use."""
    global _CLIENT_LOCKFILE
    _CLIENT_LOCKFILE = Lockfile(filename)

#----------------------------------------------------------------------

class MyURLOpener(urllib.FancyURLopener):
    def http_error_default(self, url, fp, errcode, errmsg, headers):
        message = fp.read()
        fp.close()
        raise UIError("Error connecting to %s: %s %s\n(Server said:\n%s)" % (url, errcode, errmsg, message))
    
class ClientDirectory:
    """A ClientDirectory manages a list of server descriptors, either
       imported from the command line or from a directory."""
    ##Fields:
    # dir: directory where we store everything.
    # lastModified: time when we last modified this directory.
    # lastDownload: time when we last downloaded a directory
    # serverList: List of (ServerInfo, 'D'|'I:filename') tuples.  The
    #   second element indicates whether the ServerInfo comes from a
    #   directory or a file.
    # digestMap: Map of (Digest -> 'D'|'I:filename').
    # byNickname: Map from nickname.lower() to list of (ServerInfo, source)
    #   tuples.
    # byCapability: Map from capability ('mbox'/'smtp'/'relay'/None) to
    #    list of (ServerInfo, source) tuples.
    # allServers: Same as byCapability[None]
    # __scanning: Flag to prevent recursive invocation of self.rescan().
    # clientVersions: String of allowable client versions as retrieved
    #    from most recent directory.
    ## Layout:
    # DIR/cache: A cPickled tuple of ("ClientKeystore-0.1",
    #         lastModified, lastDownload, clientVersions, serverlist,
    #         digestMap)
    # DIR/dir.gz *or* DIR/dir: A (possibly gzipped) directory file.
    # DIR/imported/: A directory of server descriptors.
    MAGIC = "ClientKeystore-0.1"

    # The amount of time to require a path to be valid, by default.
    DEFAULT_REQUIRED_LIFETIME = 3600

    def __init__(self, directory):
        """Create a new ClientDirectory to keep directories and descriptors
           under <directory>."""
        self.dir = directory
        createPrivateDir(self.dir)
        createPrivateDir(os.path.join(self.dir, "imported"))
        self.digestMap = {}
        self.__scanning = 0
        try:
            clientLock()
            self.__load()
            self.clean()
        finally:
            clientUnlock()

        # Mixminion 0.0.1 used an obsolete directory-full-of-servers in
        #   DIR/servers.  If there's nothing there, we remove it.  Otherwise,
        #   we warn.
        sdir = os.path.join(self.dir,"servers")
        if os.path.exists(sdir):
            if os.listdir(sdir):
                LOG.warn("Skipping obsolete server directory %s", sdir)
            else:
                try:
                    LOG.warn("Removing obsolete server directory %s", sdir)
                    os.rmdir(sdir)
                except OSError, e:
                    LOG.warn("Failed: %s", e)

    def updateDirectory(self, forceDownload=0, now=None):
        """Download a directory from the network as needed."""
        if now is None:
            now = time.time()

        if forceDownload or self.lastDownload < previousMidnight(now):
            self.downloadDirectory()
        else:
            LOG.debug("Directory is up to date.")

    def downloadDirectory(self):
        """Download a new directory from the network, validate it, and
           rescan its servers."""
        # Start downloading the directory.
        url = MIXMINION_DIRECTORY_URL
        LOG.info("Downloading directory from %s", url)
        try:
            infile = MyURLOpener().open(url)
        except IOError, e:
            raise UIError(
                ("Couldn't connect to directory server: %s.\n"
                 "Try '-D no' to run without downloading a directory.")%e)
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
            directory = ServerDirectory(fname=fname,
                                        validatedDigests=self.digestMap)
        except ConfigError, e:
            raise MixFatalError("Downloaded invalid directory: %s" % e)

        # Make sure that the identity is as expected.
        identity = directory['Signature']['DirectoryIdentity']
        fp = MIXMINION_DIRECTORY_FINGERPRINT
        if fp and mixminion.Crypto.pk_fingerprint(identity) != fp:
            raise MixFatalError("Bad identity key on directory")

        try:
            os.unlink(os.path.join(self.dir, "cache"))
        except OSError:
            pass

        # Install the new directory
        if gz:
            os.rename(fname, os.path.join(self.dir, "dir.gz"))
        else:
            os.rename(fname, os.path.join(self.dir, "dir"))

        # And regenerate the cache.
        self.rescan()
        # FFFF Actually, we could be a bit more clever here, and same some
        # FFFF time. But that's for later.

    def rescan(self, force=None, now=None):
        """Regenerate the cache based on files on the disk."""
        self.lastModified = self.lastDownload = -1
        self.serverList = []
        self.clientVersions = None
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
                directory = ServerDirectory(fname=fname,
                                            validatedDigests=self.digestMap)
            except ConfigError:
                LOG.warn("Ignoring invalid directory (!)")
                continue

            for s in directory.getServers():
                self.serverList.append((s, 'D'))
                self.digestMap[s.getDigest()] = 'D'

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
                info = ServerInfo(fname=p, assumeValid=0,
                                  validatedDigests=self.digestMap)
            except ConfigError:
                LOG.warn("Invalid server descriptor %s", p)
                continue
            mtime = os.stat(p)[stat.ST_MTIME]
            if mtime > self.lastModified:
                self.lastModifed = mtime
            self.serverList.append((info, "I:%s"%fn))
            self.digestMap[info.getDigest()] = "I:%s"%fn

        # Regenerate the cache
        self.__save()
        # Now try reloading, to make sure we can, and to get __rebuildTables.
        self.__scanning = 1
        self.__load()

    def __load(self):
        """Helper method. Read the cached parsed descriptors from disk."""
        try:
            f = open(os.path.join(self.dir, "cache"), 'rb')
            cached = cPickle.load(f)
            f.close()
            magic = cached[0]
            if magic == self.MAGIC:
                _, self.lastModified, self.lastDownload, self.clientVersions, \
                   self.serverList, self.digestMap = cached
                self.__rebuildTables()
                return
            else:
                LOG.warn("Bad magic on directory cache; rebuilding...")
        except (OSError, IOError):
            LOG.info("Couldn't read directory cache; rebuilding")
        except (cPickle.UnpicklingError, ValueError), e:
            LOG.info("Couldn't unpickle directory cache: %s", e)
        if self.__scanning:
            raise MixFatalError("Recursive error while regenerating cache")
        self.rescan()

    def __save(self):
        """Helper method. Recreate the cache on disk."""
        fname = os.path.join(self.dir, "cache.new")
        try:
            os.unlink(fname)
        except OSError:
            pass
        f = open(fname, 'wb')
        cPickle.dump((self.MAGIC,
                      self.lastModified, self.lastDownload,
                      self.clientVersions, self.serverList,
                      self.digestMap),
                     f, 1)
        f.close()
        os.rename(fname, os.path.join(self.dir, "cache"))

    def importFromFile(self, filename):
        """Import a new server descriptor stored in 'filename'"""

        contents = readPossiblyGzippedFile(filename)
        info = ServerInfo(string=contents, validatedDigests=self.digestMap)

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
            raise UIError("Server desciptor is expired")

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
            self.lastModifed = time.time()
            self.__save()
            self.__rebuildTables()
        return n

    def __rebuildTables(self):
        """Helper method.  Reconstruct byNickname, allServers, and byCapability
           from the internal start of this object.
        """
        self.byNickname = {}
        self.allServers = []
        self.byCapability = { 'mbox': [],
                              'smtp': [],
                              'relay': [],
                              None: self.allServers }

        for info, where in self.serverList:
            nn = info.getNickname().lower()
            lists = [ self.allServers, self.byNickname.setdefault(nn, []) ]
            for c in info.getCaps():
                lists.append( self.byCapability[c] )
            for lst in lists:
                lst.append((info, where))

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
        format = "%"+str(fmtlen)+"s:"
        for n in nicknames:
            nnreal = self.byNickname[n][0][0].getNickname()
            lines.append(format%nnreal)
            for info, where in self.byNickname[n]:
                caps = info.getCaps()
                va = formatDate(info['Server']['Valid-After'])
                vu = formatDate(info['Server']['Valid-Until'])
                line = "   %15s (valid %s to %s)"%(" ".join(caps),va,vu)
                lines.append(line)
        return lines

    def __findOne(self, lst, startAt, endAt):
        """Helper method.  Given a list of (ServerInfo, where), return a
           single element that is valid for all time between startAt and
           endAt.

           Watch out: this element is _not_ randomly chosen.
           """
        res = self.__find(lst, startAt, endAt)
        if res:
            return res[0]
        return None

    def __find(self, lst, startAt, endAt):
        """Helper method.  Given a list of (ServerInfo, where), return all
           elements that are valid for all time between startAt and endAt.

           Only one element is returned for each nickname; if multiple
           elements with a given nickname are valid over the given time
           interval, the most-recently-published one is included.
           """
        # XXXX This is not really good: servers may be the same, even if
        # XXXX their nicknames are different.  The logic should probably
        # XXXX go into directory, though.

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
                            if w == 'D' ]
            if (where != 'D'
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
            self.__save()
            self.__rebuildTables()

    def getServerInfo(self, name, startAt=None, endAt=None, strict=0):
        """Return the most-recently-published ServerInfo for a given
           'name' valid over a given time range.  If strict, and no
           such server is found, return None.

           name -- A ServerInfo object, a nickname, or a filename.
           """

        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + self.DEFAULT_REQUIRED_LIFETIME

            
        if isinstance(name, ServerInfo):
            # If it's a valid ServerInfo, we're done.
            if name.isValidFrom(startAt, endAt):
                return name
            else:
                LOG.error("Server is not currently valid")
        elif self.byNickname.has_key(name.lower()):
            # If it's a nickname, return a serverinfo with that name.
            s = self.__findOne(self.byNickname[name.lower()], startAt, endAt)
            if not s:
                # FFFF Beef up this message to say that we know about that
                # FFFF nickname, but that all suchnamed servers are dead.
                raise UIError("Couldn't find any valid descriptor with name %s"
                              % name)
            return s
        elif os.path.exists(os.path.expanduser(name)):
            # If it's a filename, try to read it.
            fname = os.path.expanduser(name)
            try:
                return ServerInfo(fname=fname, assumeValid=0)
            except OSError, e:
                raise UIError("Couldn't read descriptor %r: %s" %
                               (name, e))
            except ConfigError, e:
                raise UIError("Couldn't parse descriptor %r: %s" %
                               (name, e))
        elif strict:
            raise UIError("Couldn't find descriptor for %r" % name)
        else:
            return None

    def getPath(self, midCap=None, endCap=None, length=None,
                startServers=(), endServers=(),
                startAt=None, endAt=None, prng=None):
        """Workhorse method for path selection.  Constructs a path of length
           >= 'length' hops, path, beginning with startServers and ending with
           endServers.  If more servers are required to make up 'length' hops,
           they are selected at random.

           All servers are chosen to be valid continuously from startAt to
           endAt.  All newly-selected servers except the last are required to
           have 'midCap' (typically 'relay'); the last server (if endServers
           is not set) is selected to have 'endCap' (typically 'mbox' or
           'smtp').

           The path selection algorithm is a little complicated, but gets
           more reasonable as we know about more servers.
        """
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + self.DEFAULT_REQUIRED_LIFETIME
        if prng is None:
            prng = mixminion.Crypto.getCommonPRNG()

        # Look up the manditory servers.
        startServers = [ self.getServerInfo(name,startAt,endAt,1)
                         for name in startServers ]
        endServers = [ self.getServerInfo(name,startAt,endAt,1)
                       for name in endServers ]

        # Are we done?
        nNeeded = 0
        if length:
            nNeeded = length - len(startServers) - len(endServers)

        if nNeeded <= 0:
            return startServers + endServers

        # Do we need to specify the final server in the path?
        if not endServers:
            # If so, find all candidates...
            endList = self.__find(self.byCapability[endCap],startAt,endAt)
            if not endList:
                raise UIError("Can't build path: no %s servers known" % endCap)
            # ... and pick one that hasn't been used, if possible.
            used = [ info.getNickname().lower() for info in startServers ]
            unusedEndList = [ info for info in endList
                              if info.getNickname().lower() not in used ]
            if unusedEndList:
                endServers = [ prng.pick(unusedEndList) ]
            else:
                endServers = [ prng.pick(endList) ]
            LOG.debug("Chose %s at exit server", endServers[0].getNickname())
            nNeeded -= 1

        # Now are we done?
        if nNeeded == 0:
            return startServers + endServers

        # This is hard.  We need to find a number of relay servers for
        # the midddle of the list.  If len(candidates) > length, we should
        # remove all servers that already appear, and shuffle from the
        # rest.  Otherwise, if len(candidates) >= 3, we pick one-by-one from
        # the list of possibilities, just making sure not to get 2 in a row.
        # Otherwise, len(candidates) <= 3, so we just wing it.
        #
        # FFFF This algorithm is far from ideal, but the answer is to
        # FFFF get more servers deployed.

        # Find our candidate servers.
        midList = self.__find(self.byCapability[midCap],startAt,endAt)
        # Which of them are we using now?
        used = [ info.getNickname().lower()
                 for info in list(startServers)+list(endServers) ]
        # Which are left?
        unusedMidList = [ info for info in midList
                          if info.getNickname().lower() not in used ]
        if len(unusedMidList) >= nNeeded:
            # We have enough enough servers to choose without replacement.
            midServers = prng.shuffle(unusedMidList, nNeeded)
        elif len(midList) >= 3:
            # We have enough servers to choose without two hops in a row to
            # the same server.
            LOG.warn("Not enough servers for distinct path (%s unused, %s known)",
                     len(unusedMidList), len(midList))

            midServers = []
            if startServers:
                prevNickname = startServers[-1].getNickname().lower()
            else:
                prevNickname = " (impossible nickname) "
            if endServers:
                endNickname = endServers[0].getNickname().lower()
            else:
                endNickname = " (impossible nickname) "

            while nNeeded:
                info = prng.pick(midList)
                n = info.getNickname().lower()
                if n != prevNickname and (nNeeded > 1 or n != endNickname):
                    midServers.append(info)
                    prevNickname = n
                    nNeeded -= 1
        elif len(midList) == 2:
            # We have enough servers to concoct a path that at least
            # _sometimes_ doesn't go to the same server twice in a row.
            LOG.warn("Not enough relays to avoid same-server hops")
            midList = prng.shuffle(midList)
            midServers = (midList * ceilDiv(nNeeded, 2))[:nNeeded]
        elif len(midList) == 1:
            # There's no point in choosing a long path here: it can only
            # have one server in it.
            LOG.warn("Only one relay known")
            midServers = midList
        else:
            # We don't know any servers at all.
            raise UIError("No relays known")

        LOG.debug("getPath: [%s][%s][%s]",
                  " ".join([ s.getNickname() for s in startServers ]),
                  " ".join([ s.getNickname() for s in midServers   ]),
                  " ".join([ s.getNickname() for s in endServers   ]))

        return startServers + midServers + endServers

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
            except:
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
            
def resolvePath(directory, address, enterPath, exitPath,
                nHops, nSwap, startAt=None, endAt=None, halfPath=0):
    """Compute a two-leg validated path from options as entered on
       the command line.

       Otherwise, we generate an nHops-hop path, swapping at the nSwap'th
       server, starting with the servers on enterPath, and finishing with the
       servers on exitPath (followed by the server, if any, mandated by
       address.

       All descriptors chosen are valid from startAt to endAt.  If the
       specified descriptors don't support the required capabilities,
       we raise MixError.

       If 'halfPath' is true, then we're only trying to generate one leg
       of the path.  In this case, nSwap must be -1; the first leg will be
       empty, and the second leg will have all the servers.

       If 'address' is None, we make no requirements of the last node in
       the path except that it support relay.
       """
    assert (not halfPath) or (nSwap==-1)
    # First, find out what the exit node needs to be (or support).
    if address is None:
        routingType = None
        exitNode = None
    else:
        routingType, _, exitNode = address.getRouting()
        
    if exitNode:
        exitNode = directory.getServerInfo(exitNode, startAt, endAt)
    if routingType == MBOX_TYPE:
        exitCap = 'mbox'
    elif routingType == SMTP_TYPE:
        exitCap = 'smtp'
    elif halfPath and address is None:
        exitCap = 'relay'
    else:
        exitCap = None

    # We have a normally-specified path.
    if exitNode is not None:
        exitPath = exitPath[:]
        exitPath.append(exitNode)

    # Find an appropriate path.
    path = directory.getPath(length=nHops,
                             startServers=enterPath,
                             endServers=exitPath,
                             midCap='relay', endCap=exitCap,
                             startAt=startAt, endAt=endAt)

    # Make sure all relay servers support relaying.
    for server in path[:-1]:
        if "relay" not in server.getCaps():
            raise UIError("Server %s does not support relay"
                          % server.getNickname())

    # Make sure the exit server can support the exit capability.
    if exitCap and exitCap not in path[-1].getCaps():
        raise UIError("Server %s does not support %s capability"
                      % (path[-1].getNickname(), exitCap))

    # If there is no specified swap point, find one.
    if nSwap is None:
        nSwap = ceilDiv(len(path),2)-1

    path1, path2 = path[:nSwap+1], path[nSwap+1:]
    if not halfPath and (not path1 or not path2):
        raise UIError("Each leg of the path must have at least 1 hop")
    return path1, path2

def parsePath(directory, config, path, address, nHops=None,
              nSwap=None, startAt=None, endAt=None, halfPath=0,
              defaultNHops=None):
    """Resolve a path as specified on the command line.  Returns a
       (path-leg-1, path-leg-2) tuple, where each leg is a list of ServerInfo.

       directory -- the ClientDirectory to use.
       config -- unused for now.
       path -- the path, in a format described below.  If the path is
          None, all servers are chosen as if the path were '*'.
       address -- the address to deliver the message to; if it specifies
          an exit node, the exit node is appended to the second leg of the
          path and does not count against the number of hops.  If 'address'
          is None, the exit node must support realy.
       nHops -- the number of hops to use.  Defaults to defaultNHops.
       nSwap -- the index of the swap-point server.  Defaults to nHops/2.
       startAt/endAt -- A time range during which all servers must be valid.
       halfPath -- If true, we generate only the second leg of the path
          and leave the first leg empty.  nSwap must equal -1.
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

       You can use a star to specify a fill point where randomly-selected
       servers will be added:
             'foo,bar,*,quux'.

       The nHops argument must be consistent with the path, if both are
       specified.  Specifically, if nHops is used _without_ a star on the
       path, nHops must equal the path length; and if nHops is used _with_ a
       star on the path, nHops must be >= the path length.
    """
    if not path:
        path = '*'

    # Turn 'path' into a list of server names, '*', and '*swap*'.
    #  (* is not a valid nickname character, so we're safe.)
    path = path.replace(":", ",*swap*,").split(",")
    # Strip whitespace around the commas and colon.
    path = [ s.strip() for s in path ]
    # List of servers that appear on the path before the '*'
    enterPath = []
    # List of servers that appear after the '*'.
    exitPath = []
    # Path we're currently appending to.
    cur = enterPath
    # Positions of '*' and ':" within the path, if we've seen them yet.
    starPos = swapPos = None
    # Walk over the path
    for idx in xrange(len(path)):
        ent = path[idx]
        if ent == "*":
            if starPos is not None:
                raise UIError("Can't have two wildcards in a path")
            starPos = idx
            cur = exitPath
        elif ent == "*swap*":
            if swapPos is not None:
                raise UIError("Can't specify swap point twice")
            swapPos = idx
        else:
            cur.append(ent)

    # Now, we set the variables myNHops and myNSwap to the values of
    # nHops and nSwap (if any) implicit in the parsed path.
    if starPos is None:
        myNHops = len(enterPath)
    else:
        if nHops:
            myNHops = nHops
        elif defaultNHops is not None:
            myNHops = defaultNHops
        else:
            myNHops = 6

    if swapPos is None:
        # a,b,c,d or a,b,*,c
        myNSwap = None
    elif starPos is None or swapPos < starPos:
        # a,b:c,d or a,b:c,*,d
        myNSwap = swapPos - 1
    else:
        # a,*,b:c,d
        # There are len(path)-swapPos-1 servers after the swap point.
        # There are a total of myNHops servers.
        # Thus, there are myNHops-(len(path)-swapPos-1) servers up to and
        #  including the swap server.
        # So, the swap server is at index myNHops - (len(path)-swapPos-1) -1,
        #   which is the same as...
        myNSwap = myNHops - len(path) + swapPos
        # But we need to adjust for the last node that we may have to
        #   add because of the address
        if address.getRouting()[2]:
            myNSwap -= 1

    # Check myNSwap for consistency
    if nSwap is not None:
        if myNSwap is not None and myNSwap != nSwap:
            raise UIError("Mismatch between specified swap points")
        myNSwap = nSwap

    # Check myNHops for consistency
    if nHops is not None:
        if myNHops is not None and myNHops != nHops:
            raise UIError("Mismatch between specified number of hops")
        elif nHops < len(enterPath)+len(exitPath):
            raise UIError("Mismatch between specified number of hops")

        myNHops = nHops

    # Finally, resolve the path.
    return resolvePath(directory, address, enterPath, exitPath,
                       myNHops, myNSwap, startAt, endAt, halfPath=halfPath)

def parsePathLeg(directory, config, path, nHops, address=None,
                 startAt=None, endAt=None, defaultNHops=None):
    """Parse a single leg of a path.  Used for generating SURBs (second leg
       only) or reply messages (first leg only).  Returns a list of
       ServerInfo.

       directory -- the ClientDirectory to use.
       config -- unused for now.
       path -- The path, as described in parsePath, except that ':' is not
           allowed.
       nHops -- the number of hops to use.  Defaults to defaultNHops.
       startAt/endAt -- A time range during which all servers must be valid.
       defaultNHops -- The default path length to use when we encounter a
          wildcard in the path.  Defaults to 6.
       """
    path1, path2 = parsePath(directory, config, path, address, nHops, nSwap=-1,
                             startAt=startAt, endAt=endAt, halfPath=1,
                             defaultNHops=defaultNHops)
    assert path1 == []
    return path2
    
class ClientKeyring:
    """Class to manage storing encrypted keys for a client.  Right now, this
       is limited to a single SURB decryption key.  In the future, we may
       include more SURB keys, as well as end-to-end encryption keys.
    """
    ## Fields:
    # keyDir: The directory where we store our keys.
    # surbKey: a 20-byte key for SURBs.
    ## Format:
    # We store keys in a file holding:
    #  variable         [Key specific magic]        "SURBKEY0"
    #   8               [8 bytes of salt]
    #  keylen+20 bytes  ENCRYPTED DATA:KEY=sha1(salt+password+salt)[:16]
    #                                  DATA=encrypted_key+sha1(data+salt+magic)
    def __init__(self, keyDir):
        """Create a new ClientKeyring to store data in keyDir"""
        self.keyDir = keyDir
        createPrivateDir(self.keyDir)
        self.surbKey = None

    def getSURBKey(self, create=0):
        """Return the 20-byte SURB key.  If it has not already been loaded,
           load it, asking the user for a password if needed.  If 'create' is
           true and the key doesn't exist, ask the user for a new password
           and create a new SURB key.  If 'create' is false and the key
           doesn't exist, return None."""
        if self.surbKey is not None:
            return self.surbKey
        fn = os.path.join(self.keyDir, "SURBKey")
        self.surbKey = self._getKey(fn, magic="SURBKEY0", which="reply block",
                                    create=create)
        return self.surbKey

    def _getKey(self, fn, magic, which, bytes=20, create=0):
        """Helper: Load an arbitrary key from the keystore, from file 'fn'.
           We expect the magic to be 'magic'; Error messages will describe the
           key as the "'which' key" .  If create is true, and the key doesn't
           exist, generate a new 'bytes'-byte key.  Else if the key doesn't
           exist, return None.
        """
        
        if os.path.exists(fn):
            # If the key exists, make sure the magic is correct.
            self._checkMagic(fn, magic)
            # ...then see if we can load it without a password...
            try:
                return self._load(fn, magic, "")
            except MixError:
                pass
            # ...then ask the user for a password 'till it loads.
            while 1:
                p = self._getPassword("Enter password for %s key:"%which)
                try:
                    return self._load(fn, magic, p)
                except MixError, e:
                    LOG.error("Cannot load %s key: %s", which, e)
        elif create:
            # If the key file doesn't exist, and 'create' is set, create it.
            LOG.warn("No %s key found; generating.", which)
            key = trng(bytes)
            p = self._getNewPassword(which)
            self._save(fn, key, magic, p)
            return key
        else:
            return None

    def _checkMagic(self, fn, magic):
        """Make sure that the magic string on a given key file %s starts with
           is equal to 'magic'.  Raise MixError if it isn't."""
        f = open(fn, 'rb')
        s = f.read()
        f.close()
        if not s.startswith(magic):
            raise MixError("Invalid magic on key file")

    def _save(self, fn, data, magic, password):
        """Save the key data 'data' into the file 'fn' using the magic string
           'magic' and the password 'password'."""
        salt = mixminion.Crypto.getCommonPRNG().getBytes(8)
        key = sha1(salt+password+salt)[:16]
        f = open(fn, 'wb')
        f.write(magic)
        f.write(salt)
        f.write(ctr_crypt(data+sha1(data+salt+magic), key))
        f.close()

    def _load(self, fn, magic, password):
        """Load and return the key stored in 'fn' using the magic string
           'magic' and the password 'password'.  Raise MixError on failure."""
        f = open(fn, 'rb')
        s = f.read()
        f.close()
        if not s.startswith(magic):
            raise MixError("Invalid key file")
        s = s[len(magic):]
        if len(s) < 8:
            raise MixError("Key file too short")
        salt = s[:8]
        s = s[8:]
        if len(s) < 20:
            raise MixError("Key file too short")
        key = sha1(salt+password+salt)[:16]
        s = ctr_crypt(s, key)
        data, hash = s[:-20], s[-20:]
        if hash != sha1(data+salt+magic):
            raise MixError("Incorrect password")
        return data

    def _getPassword(self, message):
        """Read a password from the console, then return it.  Use the string
           'message' as a prompt."""
        # getpass.getpass uses stdout by default .... but stdout may have
        # been redirected.  If stdout is not a terminal, write the message
        # to stderr instead.
        if os.isatty(sys.stdout.fileno()):
            f = sys.stdout
            nl = 0
        else:
            f = sys.stderr
            nl = 1
        f.write(message)
        f.flush()
        p = getpass.getpass("")
        if nl:
            f.write("\n")
            f.flush()
        return p

    def _getNewPassword(self, which):
        """Read a new password from the console, then return it."""
        s1 = "Enter new password for %s:"%which
        s2 = "Verify password:".rjust(len(s1))
        if os.isatty(sys.stdout.fileno()):
            f = sys.stdout
        else:
            f = sys.stderr
        while 1:
            p1 = self._getPassword(s1)
            p2 = self._getPassword(s2)
            if p1 == p2:
                return p1
            f.write("Passwords do not match.\n")
            f.flush()

def installDefaultConfig(fname):
    """Create a default, 'fail-safe' configuration in a given file"""
    LOG.warn("No configuration file found. Installing default file in %s",
                  fname)
    f = open(os.path.expanduser(fname), 'w')
    f.write("""\
# This file contains your options for the mixminion client.
[Host]
## Use this option to specify a 'secure remove' command.
#ShredCommand: rm -f
## Use this option to specify a nonstandard entropy source.
#EntropySource: /dev/urandom

[DirectoryServers]
# Not yet implemented

[User]
## By default, mixminion puts your files in ~/.mixminion.  You can override
## this directory here.
#UserDir: ~/.mixminion

[Security]
## Default length of forward message paths.
#PathLength: 4
## Address to use by default when generating reply blocks
#SURBAddress: <your address here>
## Default length of paths for reply blocks
#SURBPathLength: 3
## Deault reply block lifetime
#SURBLifetime: 7 days

[Network]
ConnectionTimeout: 20 seconds

""")
    f.close()

class SURBLog:
    """A SURBLog manipulates a database on disk to remember which SURBs we've
       used, so we don't reuse them accidentally.
       """
    # XXXX004 write unit tests
    
    #FFFF Using this feature should be optional.

    ##Fields
    # log -- a database, as returned by anydbm.open.
    ## Format:
    # The database holds two kinds of keys:
    #    "LAST_CLEANED" -> an integer of the last time self.clean() was called.
    #    20-byte-hash-of-SURB -> str(expiry-time-of-SURB)
    def __init__(self, filename, forceClean=0):
        """Open a new SURBLog to store data in the file 'filename'.  If
           forceClean is true, remove expired entries on startup.
        """
        clientLock()
        parent, shortfn = os.path.split(filename)
        createPrivateDir(parent)
        LOG.debug("Opening SURB log")
        self.log = anydbm.open(filename, 'c')
        try:
            lastCleaned = int(self.log['LAST_CLEANED'])
        except (KeyError, ValueError):
            lastCleaned = 0

        forceClean = 1
        if lastCleaned < time.time()-24*60*60 or forceClean:
            self.clean()

    def findUnusedSURB(self, surbList, verbose=0,now=None):
        """Given a list of ReplyBlock objects, find the first that is neither
           expired, about to expire, or used in the past.  Return None if
           no such reply block exists."""
        if now is None:
            now = time.time()
        nUsed = nExpired = nShortlived = 0
        result = None
        for surb in surbList:
            expiry = surb.timestamp
            timeLeft = expiry - now
            if self.isSURBUsed(surb):
                nUsed += 1
            elif timeLeft < 60:
                nExpired += 1
            elif timeLeft < 3*60*60:
                nShortlived += 1
            else:
                result = surb
                break

        if verbose:
            if nUsed:
                LOG.warn("Skipping %s used reply blocks", nUsed)
            if nExpired:
                LOG.warn("Skipping %s expired reply blocks", nExpired)
            if nShortlived:
                LOG.warn("Skipping %s sooon-to-expire reply blocks", nShortlived)
        
        return result

    def close(self):
        """Release resources associated with the surblog."""
        self.log.close()
        clientUnlock()

    def isSURBUsed(self, surb):
        """Return true iff the ReplyBlock object 'surb' is marked as used."""
        hash = binascii.b2a_hex(sha1(surb.pack()))
        try:
            _ = self.log[hash]
            return 1
        except KeyError:
            return 0

    def markSURBUsed(self, surb):
        """Mark the ReplyBlock object 'surb' as used."""
        hash = binascii.b2a_hex(sha1(surb.pack()))
        self.log[hash] = str(surb.timestamp)

    def clean(self, now=None):
        """Remove all entries from this SURBLog the correspond to expired
           SURBs.  This is safe because if a SURB is expired, we'll never be
           able to use it inadvertantly."""
        if now is None:
            now = time.time() + 60*60
        allHashes = self.log.keys()
        removed = []
        for hash in allHashes:
            if self.log[hash] < now:
                removed.append(hash)
        del allHashes
        for hash in removed:
            del self.log[hash]
        self.log['LAST_CLEANED'] = str(int(now))

class ClientPool:
    """A ClientPool holds packets that have been scheduled for delivery
       but not yet delivered.  As a matter of policy, we pool messages if
       the user tells us to, or if deliver has failed and the user didn't
       tell us not to."""
    ## Fields:
    # dir -- a directory to store packets in.
    # prng -- an instance of mixminion.Crypto.RNG.
    ## Format:
    # The directory holds files with names of the form pkt_<handle>.
    # Each file holds pickled tuple containing:
    #           ("PACKET-0", 
    #             a 32K string (the packet),
    #             an instance of IPV4Info (the first hop),
    #             the latest midnight preceeding the time when this
    #                 packet was inserted into the pool.
    #           )
    # XXXX004 change this to be OO; add nicknames.
    
    # XXXX004 write unit tests

    def __init__(self, directory, prng=None):
        """Create a new ClientPool object, storing packets in 'directory'
           and generating random filenames using 'prng'."""
        self.dir = directory
        createPrivateDir(directory)
        if prng is not None:
            self.prng = prng
        else:
            self.prng = mixminion.Crypto.getCommonPRNG()

    def poolPacket(self, message, routing):
        """Insert the 32K packet 'message' (to be delivered to 'routing')
           into the pool.  Return the handle of the newly inserted packet."""
        clientLock()
        f, handle = self.prng.openNewFile(self.dir, "pkt_", 1)
        cPickle.dump(("PACKET-0", message, routing,
                      previousMidnight(time.time())), f, 1)
        f.close()
        return handle
    
    def getHandles(self):
        """Return a list of the handles of all messages currently in the
           pool."""
        clientLock()
        fnames = os.listdir(self.dir)
        handles = []
        for fname in fnames:
            if fname.startswith("pkt_"):
                handles.append(fname[4:])
        return handles

    def getPacket(self, handle):
        """Given a handle, return a 3-tuple of the corresponding
           32K packet, IPV4Info, and time of first pooling.  (The time
           is rounded down to the closest midnight GMT.)"""
        f = open(os.path.join(self.dir, "pkt_"+handle), 'rb')
        magic, message, routing, when = cPickle.load(f)
        f.close()
        if magic != "PACKET-0":
            LOG.error("Unrecognized packet format for %s",handle)
            return None
        return message, routing, when

    def packetExists(self, handle):
        """Return true iff the pool contains a packet with the handle
           'handle'."""
        fname = os.path.join(self.dir, "pkt_"+handle)
        return os.path.exists(fname)
        
    def removePacket(self, handle):
        """Remove the packet named with the handle 'handle'."""
        fname = os.path.join(self.dir, "pkt_"+handle)
        secureDelete(fname, blocking=1)

    def inspectPool(self, now=None):
        """Print a message describing how many messages in the pool are headed
           to which addresses."""
        if now is None:
            now = time.time()
        handles = self.getHandles()
        if not handles:
            print "[Pool is empty.]"
            return
        timesByServer = {}
        for h in handles:
            _, routing, when = self.getPacket(h)
            timesByServer.setdefault(routing, []).append(when)
        for s in timesByServer.keys():
            count = len(timesByServer[s])
            oldest = min(timesByServer[s])
            days = floorDiv(now - oldest, 24*60*60)
            if days < 1:
                days = "<1"
            print "%2d messages for server at %s:%s (oldest is %s days old)"%(
                count, s.ip, s.port, days)

class MixminionClient:
    """Access point for client functionality.  Currently, this is limited
       to generating and sending forward messages"""
    ## Fields:
    # config: The ClientConfig object with the current configuration
    # prng: A pseudo-random number generator for padding and path selection
    # keys: A ClientKeyring object.
    # pool: A ClientPool object.
    # surbLogFilename: The filename used by the SURB log.
    def __init__(self, conf):
        """Create a new MixminionClient with a given configuration"""
        self.config = conf

        # Make directories
        userdir = os.path.expanduser(self.config['User']['UserDir'])
        createPrivateDir(userdir)
        keyDir = os.path.join(userdir, "keys")
        self.keys = ClientKeyring(keyDir)
        self.surbLogFilename = os.path.join(userdir, "surbs", "log")

        # Initialize PRNG
        self.prng = mixminion.Crypto.getCommonPRNG()
        self.pool = ClientPool(os.path.join(userdir, "pool"))

    def sendForwardMessage(self, address, payload, servers1, servers2,
                           forcePool=0, forceNoPool=0):
        """Generate and send a forward message.
            address -- the results of a parseAddress call
            payload -- the contents of the message to send
            servers1,servers2 -- lists of ServerInfos for the first and second 
               legs the path, respectively.
            forcePool -- if true, do not try to send the message; simply
               pool it and exit.
            forceNoPool -- if true, do not pool the message even if delivery
               fails."""
        assert not (forcePool and forceNoPool)

        message, firstHop = \
                 self.generateForwardMessage(address, payload,
                                             servers1, servers2)

        routing = firstHop.getRoutingInfo()

        if forcePool:
            self.poolMessages([message], routing)
        else:
            self.sendMessages([message], routing, noPool=forceNoPool)

    def sendReplyMessage(self, payload, servers, surbList, forcePool=0,
                         forceNoPool=0):
        """Generate and send a reply message.
            payload -- the contents of the message to send
            servers -- a list of ServerInfos for the first leg of the path.
            surbList -- a list of SURBs to consider for the second leg of
               the path.  We use the first one that is neither expired nor
               used, and mark it used.
            forcePool -- if true, do not try to send the message; simply
               pool it and exit.
            forceNoPool -- if true, do not pool the message even if delivery
               fails."""
        #XXXX004 write unit tests
        message, firstHop = \
                 self.generateReplyMessage(payload, servers, surbList)

        routing = firstHop.getRoutingInfo()
        
        if forcePool:
            self.poolMessages([message], routing)
        else:
            self.sendMessages([message], routing, noPool=forceNoPool)


    def generateReplyBlock(self, address, servers, expiryTime=0):
        """Generate an return a new ReplyBlock object.
            address -- the results of a parseAddress call
            servers -- lists of ServerInfos for the reply leg of the path.
            expiryTime -- if provided, a time at which the replyBlock must
               still be valid, and after which it should not be used.
        """
        #XXXX004 write unit tests
        key = self.keys.getSURBKey(create=1)
        exitType, exitInfo, _ = address.getRouting()

        block = mixminion.BuildMessage.buildReplyBlock(
            servers, exitType, exitInfo, key, expiryTime)

        return block

    def generateForwardMessage(self, address, payload, servers1, servers2):
        """Generate a forward message, but do not send it.  Returns
           a tuple of (the message body, a ServerInfo for the first hop.)

            address -- the results of a parseAddress call
            payload -- the contents of the message to send  (None for DROP
              messages)
            servers1,servers2 -- lists of ServerInfo.
            """
        #XXXX004 write unit tests
        routingType, routingInfo, _ = address.getRouting()
        LOG.info("Generating payload...")
        msg = mixminion.BuildMessage.buildForwardMessage(
            payload, routingType, routingInfo, servers1, servers2,
            self.prng)
        return msg, servers1[0]

    def generateReplyMessage(self, payload, servers, surbList, now=None):
        """Generate a forward message, but do not send it.  Returns
           a tuple of (the message body, a ServerInfo for the first hop.)

            address -- the results of a parseAddress call
            payload -- the contents of the message to send  (None for DROP
              messages)
            servers -- list of ServerInfo for the first leg of the path.
            surbList -- a list of SURBs to consider for the second leg of
               the path.  We use the first one that is neither expired nor
               used, and mark it used.
            """
        #XXXX004 write unit tests
        if now is None:
            now = time.time()
        clientLock()
        surbLog = self.openSURBLog()
        try:
            surb = surbLog.findUnusedSURB(surbList, verbose=1, now=now)
            if surb is None:
                raise UIError("No usable reply blocks found; all were used or expired.")

            LOG.info("Generating packet...")
            msg = mixminion.BuildMessage.buildReplyMessage(
                payload, servers, surb, self.prng)

            surbLog.markSURBUsed(surb)
            return msg, servers[0]
        finally:
            surbLog.close()
            clientUnlock()

    def openSURBLog(self):
        """Return a new, open SURBLog object for this client; it must be closed
           when no longer in use.
        """
        return SURBLog(self.surbLogFilename)

    def sendMessages(self, msgList, routingInfo, noPool=0, lazyPool=0,
                     warnIfLost=1):
        """Given a list of packets and an IPV4Info object, sends the
           packets to the server via MMTP.

           If noPool is true, do not pool the message even on failure.
           If lazyPool is true, only pool the message on failure.
           Otherwise, insert the message in the pool, and remove it on
           success.

           If warnIfLost is true, log a warning if we fail to deliver
           the message, and we don't pool it.
           """
        #XXXX004 write unit tests
        timeout = self.config['Network'].get('ConnectionTimeout')
        if timeout:
            timeout = timeout[2]

        if noPool or lazyPool: 
            handles = []
        else:
            handles = self.poolMessages(msgList, routingInfo)

        if len(msgList) > 1:
            mword = "messages"
        else:
            mword = "message"

        try:
            try:
                # May raise TimeoutError
                LOG.info("Connecting...")
                mixminion.MMTPClient.sendMessages(routingInfo,
                                                  msgList,
                                                  timeout)
                LOG.info("... %s sent", mword)
            except:
                if noPool and warnIfLost:
                    LOG.error("Error with pooling disabled: %s lost", mword)
                elif lazyPool:
                    LOG.info("Error while delivering %s; %s pooled",
                             mword,mword)
                    self.poolMessages(msgList, routingInfo)
                else:
                    LOG.info("Error while delivering %s; leaving in pool",
                             mword)
                raise
            try:
                clientLock()
                for h in handles:
                    if self.pool.packetExists(h):
                        self.pool.removePacket(h)
            finally:
                clientUnlock()
        except MixProtocolError, e:
            raise UIError(str(e))
            
    def flushPool(self):
        """Try to send end all messages in the queue to their destinations.
        """
        #XXXX004 write unit tests

        LOG.info("Flushing message pool")
        # XXXX This is inefficient in space!
        clientLock()
        try:
            handles = self.pool.getHandles()
            LOG.info("Found %s pending messages", len(handles))
            messagesByServer = {}
            for h in handles:
                message, routing, _ = self.pool.getPacket(h)
                messagesByServer.setdefault(routing, []).append((message, h))
        finally:
            clientUnlock()
            
        for routing in messagesByServer.keys():
            LOG.info("Sending %s messages to %s:%s...",
                     len(messagesByServer[routing]), routing.ip, routing.port)
            msgs = [ m for m, _ in messagesByServer[routing] ]
            handles = [ h for _, h in messagesByServer[routing] ] 
            try:
                self.sendMessages(msgs, routing, noPool=1, warnIfLost=0)
                try:
                    clientLock()
                    for h in handles:
                        if self.pool.packetExists(h):
                            self.pool.removePacket(h)
                finally:
                    clientUnlock()
            except MixError:
                LOG.error("Can't deliver messages to %s:%s; leaving in pool",
                          routing.ip, routing.port)
        LOG.info("Pool flushed")

    def poolMessages(self, msgList, routing):
        """Insert all the messages in msgList into the pool, to be sent
           to the server identified by the IPV4Info object 'routing'.
        """
        #XXXX004 write unit tests
        LOG.trace("Pooling messages")
        handles = []
        try:
            clientLock()
            for msg in msgList:
                h = self.pool.poolPacket(msg, routing)
                handles.append(h)
        finally:
            clientUnlock()
        if len(msgList) > 1:
            LOG.info("Messages pooled")
        else:
            LOG.info("Message pooled")
        return handles

    def decodeMessage(self, s, force=0):
        """Given a string 's' containing one or more text-encoed messages,
           return a list containing the decoded messages.
           
           Raise ParseError on malformatted messages.  Unless 'force' is
           true, do not uncompress possible zlib bombs. 
        """
        #XXXX004 write unit tests
        results = []
        idx = 0
        while idx < len(s):
            msg, idx = parseTextEncodedMessage(s, idx=idx, force=force)
            if msg is None:
                return results
            if msg.isOvercompressed() and not force:
                LOG.warn("Message is a possible zlib bomb; not uncompressing")
            if not msg.isEncrypted():
                results.append(msg.getContents())
            else:
                surbKey = self.keys.getSURBKey(create=0)
                results.append(
                    mixminion.BuildMessage.decodePayload(msg.getContents(),
                                                         tag=msg.getTag(),
                                                         userKey=surbKey))
        return results

def parseAddress(s):
    """Parse and validate an address; takes a string, and returns an Address
       object.

       Accepts strings of the format:
              mbox:<mailboxname>@<server>
           OR smtp:<email address>
           OR <email address> (smtp is implicit)
           OR drop
           OR 0x<routing type>:<routing info>
    """
    # ???? Should this should get refactored into clientmodules, or someplace?
    if s.lower() == 'drop':
        return Address(DROP_TYPE, "", None)
    elif s.lower() == 'test':
        return Address(0xFFFE, "", None)
    elif ':' not in s:
        if isSMTPMailbox(s):
            return Address(SMTP_TYPE, s, None)
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
        return Address(tp, val, None)
    elif tp == 'mbox':
        if "@" in val:
            mbox, server = val.split("@",1)
            return Address(MBOX_TYPE, parseMBOXInfo(mbox).pack(), server)
        else:
            return Address(MBOX_TYPE, parseMBOXInfo(val).pack(), None)
    elif tp == 'smtp':
        # May raise ParseError
        return Address(SMTP_TYPE, parseSMTPInfo(val).pack(), None)
    elif tp == 'test':
        return Address(0xFFFE, val, None)
    else:
        raise ParseError("Unrecognized address type: %s"%s)

class Address:
    """Represents the target address for a Mixminion message.
       Consists of the exitType for the final hop, the routingInfo for
       the last hop, and (optionally) a server to use as the last hop.
       """
    def __init__(self, exitType, exitAddress, lastHop=None):
        self.exitType = exitType
        self.exitAddress = exitAddress
        self.lastHop = lastHop
    def getRouting(self):
        return self.exitType, self.exitAddress, self.lastHop

def readConfigFile(configFile):
    """Given a configuration file (possibly none) as specified on the command
       line, return a ClientConfig object.

       Tries to look for the configuration file in the following places:
          - as specified on the command line,
          - as specifed in $MIXMINIONRC
          - in ~/.mixminionrc.

       If the configuration file is not found in the specified location,
       we create a fresh one.
    """
    if configFile is None:
        configFile = os.environ.get("MIXMINIONRC", None)
    if configFile is None:
        configFile = "~/.mixminionrc"
    configFile = os.path.expanduser(configFile)

    if not os.path.exists(configFile):
        installDefaultConfig(configFile)

    try:
        return ClientConfig(fname=configFile)
    except (IOError, OSError), e:
        print >>sys.stderr, "Error reading configuration file %r:"%configFile
        print >>sys.stderr, "   ", str(e)
        sys.exit(1)
    except ConfigError, e:
        print >>sys.stderr, "Error in configuration file %r"%configFile
        print >>sys.stderr, "   ", str(e)
        sys.exit(1)
    return None #suppress pychecker warning

class CLIArgumentParser:
    """Helper class to parse common command line arguments.

       The following arguments are recognized:
          COMMON
             -h | --help : print usage and exit.
             -f | --config : specify a configuration file.
             -v | --verbose : run verbosely.
          DIRECTORY ONLY   
             -D | --download-directory : force/disable directory downloading.
          PATH-RELEATED
             -t | --to : specify an exit address
             -R | --reply-block : specify a reply block
             --swap-at : specify a swap point numerically
             -H | --hops : specify a path length
             -P | --path : specify a literal path.
          REPLY PATH ONLY   
             --lifetime : Required lifetime of new reply blocks.
          MESSAGE-SENDING ONLY:
             --pool | --no-pool : force/disable pooling.

         The class's constructor parses command line options, as required.
         The .init() method initializes a config file, logging, a
           MixminionClient object, or the ClientDirectory object as requested.
         The parsePath method parses the path as given.
    """
    ##Fields:
    #  want*: as given as arguments to __init__
    # [CALL "init()" before using these.
    #  config: ClientConfig, or None.
    #  directory: ClientDirectory, or None.
    #  client: MixminionClient, or None.
    #  keyring: ClientKeyring, or None.
    # [As specified on command line"
    #  path: path string, or None.
    #  nHops: number of hops, or None.
    #  swapAt: index of swap point, or None.
    #  address: exit address, or None.
    #  lifetime: SURB lifetime, or None.
    #  replyBlockFiles: list of SURB filenames.
    #  configFile: Filename of configuration file, or None.
    #  forcePool: true if "--pool" is set.
    #  forceNoPool: true if "--no-pool" is set.
    #  verbose: true if verbose mode is set.
    #  download: 1 if the user told us to download the directory, 0 if
    #    they told us not to download it, and None if they didn't say.
    # [Not public]
    #  path1, path2 -- path as generated by parsePath.
    
    def __init__(self, opts,
                 wantConfig=0, wantClientDirectory=0, wantClient=0, wantLog=0,
                 wantDownload=0, wantForwardPath=0, wantReplyPath=0,
                 minHops=0):
        """Parse the command line options 'opts' as returned by getopt.getopt.

           wantConfig -- If true, accept options pertaining to the config file,
              and generate a ClientConfig object when self.init() is called.
           wantClientDiredctory -- If true, accept options pertaining to the
              client directory, and generate a ClientDirectory object when
              self.init() is called.
           wantClient -- If true, generate a MixminionClient when self.init()
              is called.
           wantLog -- If true, configure logging.
           wantDownload -- If true, accept options pertaining to downloading
              a new directory, and download the directrory as required.
           wantForawrdPath -- If true, accept options to specify a forward
              path (for forward or reply messages), and enable self.parsePath.
           wantReplyPath -- If true, accept options to specify a path for
              a reply block, and enable seslf.parsePath.
           minHops -- Smallest allowable value for -H option.   
        """
        self.config = None
        self.directory = None
        self.client = None
        self.path1 = None
        self.path2 = None

        if wantForwardPath: wantClientDirectory = 1
        if wantReplyPath: wantClientDirectory = 1
        if wantDownload: wantClientDirectory = 1
        if wantClientDirectory: wantConfig = 1
        if wantClient: wantConfig = 1

        self.wantConfig = wantConfig
        self.wantClientDirectory = wantClientDirectory
        self.wantClient = wantClient
        self.wantLog = wantLog
        self.wantDownload = wantDownload
        self.wantForwardPath = wantForwardPath
        self.wantReplyPath = wantReplyPath
        
        self.configFile = None
        self.verbose = 0
        self.download = None

        self.path = None
        self.nHops = None
        self.swapAt = None
        self.address = None
        self.lifetime = None
        self.replyBlockFiles = []

        self.forcePool = None
        self.forceNoPool = None

        for o,v in opts:
            if o in ('-h', '--help'):
                raise UsageError()
            elif o in ('-f', '--config'):
                self.configFile = v
            elif o in ('-v', '--verbose'):
                self.verbose = 1
            elif o in ('-D', '--download-directory'):
                assert wantDownload
                download = v.lower()
                if download in ('0','no','false','n','f'):
                    dl = 0
                elif download in ('1','yes','true','y','t','force'):
                    dl = 1
                else:
                    raise UIError(
                        "Unrecognized value for %s. Expected 'yes' or 'no'"%o)
                if self.download not in (None, dl):
                    raise UIError(
                        "Value of %s for %o conflicts with earlier value" %
                        (v, o))
                self.download = dl
            elif o in ('-t', '--to'):
                assert wantForwardPath or wantReplyPath
                if self.address is not None:
                    raise UIError("Multiple addresses specified.")
                try:
                    self.address = parseAddress(v)
                except ParseError, e:
                    raise UsageError(str(e))
            elif o in ('-R', '--reply-block'):
                assert wantForwardPath
                self.replyBlockFiles.append(v)
            elif o == '--swap-at':
                assert wantForwardPath
                if self.swapAt is not None:
                    raise UIError("Multiple --swap-at arguments specified")
                try:
                    self.swapAt = int(v)-1
                except ValueError:
                    raise UsageError("%s expects an integer"%o)
            elif o in ('-H', '--hops'):
                assert wantForwardPath or wantReplyPath
                if self.nHops is not None:
                    raise UIError("Multiple %s arguments specified"%o)
                try:
                    self.nHops = int(v)
                    if minHops and self.nHops < minHops:
                        raise UIError("Must have at least %s hops", minHops)
                except ValueError:
                    raise UIError("%s expects an integer"%o)
            elif o in ('-P', '--path'):
                assert wantForwardPath or wantReplyPath
                if self.path is not None:
                    raise UIError("Multiple paths specified")
                self.path = v
            elif o in ('--lifetime',):
                assert wantReplyPath
                if self.lifetime is not None:
                    raise UIError("Multiple --lifetime arguments specified")
                try:
                    self.lifetime = int(v)
                except ValueError:
                    raise UsageError("%s expects an integer"%o)
            elif o in ('--pool',):
                self.forcePool = 1
            elif o in ('--no-pool',):
                self.forceNoPool = 1

    def init(self):
        """Configure objects and initialize subsystems as specified by the
           command line."""
        if self.wantConfig:
            self.config = readConfigFile(self.configFile)
            if self.wantLog:
                LOG.configure(self.config)
                if self.verbose:
                    LOG.setMinSeverity("TRACE")
                else:
                    LOG.setMinSeverity("INFO")
            mixminion.Common.configureShredCommand(self.config)
            if not self.verbose:
                try:
                    LOG.setMinSeverity("WARN")
                    mixminion.Crypto.init_crypto(self.config)
                finally:
                    LOG.setMinSeverity("INFO")
            else:
                mixminion.Crypto.init_crypto(self.config)
                
            userdir = os.path.expanduser(self.config['User']['UserDir'])
            configureClientLock(os.path.join(userdir, "lock"))
        else:
            if self.wantLog:
                LOG.setMinSeverity("ERROR")
            userdir = None
            
        if self.wantClient:
            assert self.wantConfig
            LOG.debug("Configuring client")
            self.client = MixminionClient(self.config)

        if self.wantClientDirectory:
            assert self.wantConfig
            LOG.debug("Configuring server list")
            self.directory = ClientDirectory(userdir)

        if self.wantDownload:
            assert self.wantClientDirectory
            if self.download != 0:
                try:
                    clientLock()
                    self.directory.updateDirectory(forceDownload=self.download)
                finally:
                    clientUnlock()

        if self.wantClientDirectory or self.wantDownload:
            self.directory.checkClientVersion()

    def parsePath(self):
        """Parse the path specified on the command line and generate a
           new list of servers to be retrieved by getForwardPath or
           getReplyPath."""
        if self.wantReplyPath and self.address is None:
            address = self.config['Security'].get('SURBAddress')
            if address is None:
                raise UIError("No recipient specified; exiting.")
            try:
                self.address = parseAddress(address)
            except ParseError, e:
                raise UIError(str(e))
        elif self.address is None and self.replyBlockFiles == []:
            raise UIError("No recipients specified; exiting")
        elif self.address is not None and self.replyBlockFiles:
            raise UIError("Cannot use both a recipient and a reply block")
        elif self.replyBlockFiles:
            useRB = 1
            surbs = []
            for fn in self.replyBlockFiles:
                if fn == '-':
                    s = sys.stdin.read()
                else:
                    f = open(fn, 'rb')
                    s = f.read()
                    f.close()
                try:
                    if stringContains(s, "== BEGIN TYPE III REPLY BLOCK =="):
                        surbs.extend(parseTextReplyBlocks(s))
                    else:
                        surbs.extend(parseReplyBlocks(s))
                except ParseError, e:
                        raise UIError("Error parsing %s: %s" % (fn, e))
        else:
            assert self.address is not None
            useRB = 0

        if self.wantReplyPath:
            if self.lifetime is not None:
                duration = self.lifetime * 24*60*60
            else:
                duration = self.config['Security']['SURBLifetime'][2]
                
            self.endTime = succeedingMidnight(time.time() + duration)

            defHops = self.config['Security'].get("SURBPathLength", 4)
            self.path1 = parsePathLeg(self.directory, self.config, self.path,
                                      self.nHops, self.address,
                                      startAt=time.time(),
                                      endAt=self.endTime,
                                      defaultNHops=defHops)
            self.path2 = None
            LOG.info("Selected path is %s",
                     ",".join([ s.getNickname() for s in self.path1 ]))
        elif useRB:
            assert self.wantForwardPath
            defHops = self.config['Security'].get("PathLength", 6)
            self.path1 = parsePathLeg(self.directory, self.config, self.path,
                                      self.nHops, defaultNHops=defHops)
            self.path2 = surbs
            self.usingSURBList = 1
            LOG.info("Selected path is %s:<reply block>",
                     ",".join([ s.getNickname() for s in self.path1 ]))
        else:
            assert self.wantForwardPath
            defHops = self.config['Security'].get("PathLength", 6)
            self.path1, self.path2 = \
                        parsePath(self.directory, self.config, self.path,
                                  self.address, self.nHops, self.swapAt,
                                  defaultNHops=defHops)
            self.usingSURBList = 0
            LOG.info("Selected path is %s:%s",
                     ",".join([ s.getNickname() for s in self.path1 ]),
                     ",".join([ s.getNickname() for s in self.path2 ]))

    def getForwardPath(self):
        """Return a 2-tuple of lists of ServerInfo for the most recently
           parsed forward path."""
        return self.path1, self.path2
    
    def getReplyPath(self):
        """Return a list of ServerInfo for the most recently parsed reply
           block path."""
        return self.path1
    
_SEND_USAGE = """\
Usage: %(cmd)s [options] <-t address>|<--to=address>|
                          <-R reply-block>|--reply-block=reply-block>
Options:
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -D <yes|no>, --download-directory=<yes|no>
                             Force the client to download/not to download a
                               fresh directory.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
  -H <n>, --hops=<n>         Force the path to use <n> hops.
  -i <file>, --input=<file>  Read the messagefrom <file>. (Defaults to stdin.)
  -P <path>, --path=<path>   Specify an explicit message path.
  -t address, --to=address   Specify the recipient's address.
  -R <file>, --reply-block=<file>
                             %(Send)s the message to a reply block in <file>,
                             or '-' for a reply block read from stdin.
  --swap-at=<n>              Spcecify an explicit swap point.
%(extra)s

EXAMPLES:
  %(Send)s a message contained in a file <data> to user@domain.
      %(cmd)s -t user@domain -i data
  As above, but force 6 hops.
      %(cmd)s -t user@domain -i data -H 6
  As above, but use the server nicknamed Foo for the first hop and the server
  whose descriptor is stored in bar/baz for the last hop.
      %(cmd)s -t user@domain -i data -H 6 -P 'Foo,*,bar/baz'
  As above, but switch legs of the path after the second hop.
      %(cmd)s -t user@domain -i data -H 6 -P 'Foo,*,bar/baz' --swap-at=2
  Specify an explicit path
      %(cmd)s -t user@domain -i data -P 'Foo,Bar,Baz,Quux,Fee,Fie,Foe'
  Specify an explicit path with a swap point
      %(cmd)s -t user@domain -i data -P 'Foo,Bar,Baz,Quux:Fee,Fie,Foe'
  %(Send)s the message to a reply block stored in 'FredsBlocks', using a 
  randomly chosen first leg.
      %(cmd)s -t user@domain -i data -R FredsBlocks
  %(Send)s the message to a reply block stored in 'FredsBlocks', specifying
  the first leg.
      %(cmd)s -t user@domain -i data -R FredsBlocks -P 'Foo,Bar,Baz'
  Read the message from standard input.
      %(cmd)s -t user@domain
  Force a fresh directory download
      %(cmd)s -D yes
  %(Send)s a message without downloading a new directory, even if the current
  directory is out of date.
      %(cmd)s -D no -t user@domain -i data
""".strip()

def usageAndExit(cmd, error=None):
    if error:
        print >>sys.stderr, "ERROR: %s"%error
        print >>sys.stderr, "For usage, run 'mixminion send --help'"
        sys.exit(1)
    if cmd.endswith(" pool"):
        print _SEND_USAGE % { 'cmd' : cmd, 'send' : 'pool', 'Send': 'Pool',
                              'extra' : '' }
    else:
        print _SEND_USAGE % { 'cmd' : cmd, 'send' : 'send', 'Send': 'Send',
                              'extra' : """\
  --pool                     Pool the message; don't send it.
  --no-pool                  Do not attempt to pool the message.""" }
    sys.exit(0)

# NOTE: This isn't the final client interface.  Many or all options will
#     change between now and 1.0.0
def runClient(cmd, args):
    #DOCDOC Comment this function
    if cmd.endswith(" client"): #XXXX004 remove this.
        print "The 'client' command is deprecated.  Use 'send' instead."
    poolMode = 0
    if cmd.endswith(" pool"):
        poolMode = 1

    options, args = getopt.getopt(args, "hvf:D:t:H:P:R:i:",
             ["help", "verbose", "config=", "download-directory=",
              "to=", "hops=", "swap-at=", "path=", "reply-block=",
              "input=", "pool", "no-pool" ])
              
    if not options:
        usageAndExit(cmd)
    
    inFile = None
    for opt,val in options:
        if opt in ('-i', '--input'):
            inFile = val

    if args:
        usageAndExit(cmd,"Unexpected arguments")

    try:
        parser = CLIArgumentParser(options, wantConfig=1,wantClientDirectory=1,
                                   wantClient=1, wantLog=1, wantDownload=1,
                                   wantForwardPath=1)
        if poolMode and parser.forceNoPool:
            raise UsageError("Can't use --no-pool option with pool command")
        if parser.forcePool and parser.forceNoPool:
            raise UsageError("Can't use both --pool and --no-pool")
    except UsageError, e:
        e.dump()
        usageAndExit(cmd)

    if inFile in (None, '-') and '-' in parser.replyBlockFiles:
        raise UIError(
            "Can't read both message and reply block from stdin")

    # FFFF Make pooling configurable from .mixminionrc
    forcePool = poolMode or parser.forcePool
    forceNoPool = parser.forceNoPool

    parser.init()
    client = parser.client

    parser.parsePath()

    path1, path2 = parser.getForwardPath()
    address = parser.address

    if parser.usingSURBList and inFile in ('-', None):
        # We check to make sure that we have a valid SURB before reading
        # from stdin.
        surblog = client.openSURBLog()
        try:
            s = surblog.findUnusedSURB(parser.path2)
            if s is None:
                raise UIError("No unused, unexpired reply blocks found.")
        finally:
            surblog.close()
        
    # XXXX Clean up this ugly control structure.
    if address and inFile is None and address.getRouting()[0] == DROP_TYPE:
        payload = None
        LOG.info("Sending dummy message")
    else:
        if address and address.getRouting()[0] == DROP_TYPE:
            raise UIError("Cannot send a payload with a DROP message.")

        if inFile is None:
            inFile = "-"

        if inFile == '-':
            f = sys.stdin
            print "Enter your message now.  Type Ctrl-D when you are done."
        else:
            f = open(inFile, 'r')

        try:
            payload = f.read()
            f.close()
        except KeyboardInterrupt:
            print "Interrupted.  Message not sent."
            sys.exit(1)

    if parser.usingSURBList:
        assert isinstance(path2, ListType)
        client.sendReplyMessage(payload, path1, path2,
                                forcePool, forceNoPool)
    else:
        client.sendForwardMessage(address, payload, path1, path2,
                                  forcePool, forceNoPool)

_IMPORT_SERVER_USAGE = """\
Usage: %(cmd)s [options] <filename> ...
Options:
   -h, --help:             Print this usage message and exit.
   -v, --verbose           Display extra debugging messages.
   -f FILE, --config=FILE  Use a configuration file other than ~/.mixminionrc

EXAMPLES:
  Import a ServerInfo from the file MyServer into our local directory.
      %(cmd)s MyServer
""".strip()

def importServer(cmd, args):
    options, args = getopt.getopt(args, "hf:v", ['help', 'config=', 'verbose'])

    try:
        parser = CLIArgumentParser(options, wantConfig=1,wantClientDirectory=1,
                                   wantLog=1)
    except UsageError, e:
        e.dump()
        print _IMPORT_SERVER_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    directory = parser.directory

    try:
        clientLock()
        for filename in args:
            print "Importing from", filename
            try:
                directory.importFromFile(filename)
            except MixError, e:
                print "Error while importing %s: %s" % (filename, e)
    finally:
        clientUnlock()
        
    print "Done."

_LIST_SERVERS_USAGE = """\
Usage: %(cmd)s [options]
Options:
  -h, --help:                Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~/.mixminionrc
  -D <yes|no>, --download-directory=<yes|no>
                             Force the client to download/not to download a
                               fresh directory.

EXAMPLES:
  List all currently known servers.
      %(cmd)s
""".strip()

def listServers(cmd, args):
    options, args = getopt.getopt(args, "hf:D:v",
                                  ['help', 'config=', "download-directory=",
                                   'verbose'])
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantClientDirectory=1,
                                   wantLog=1, wantDownload=1)
    except UsageError, e:
        e.dump()
        print _LIST_SERVERS_USAGE % {'cmd' : cmd}
        sys.exit(1)

    parser.init()
    directory = parser.directory

    for line in directory.listServers():
        print line

_UPDATE_SERVERS_USAGE = """\
Usage: %(cmd)s [options]
Options:
  -h, --help:                Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~/.mixminionrc
                             (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Download a new list of servers.  (Note that the 'mixminion send' and
  the 'mixminion generate-surbs' commands do this by default.)
      %(cmd)s
""".strip()

def updateServers(cmd, args):
    options, args = getopt.getopt(args, "hvf:", ['help', 'verbose', 'config='])
    
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantClientDirectory=1,
                                   wantLog=1)
    except UsageError, e:
        e.dump()
        print _UPDATE_SERVERS_USAGE % { 'cmd' : cmd } 
        sys.exit(1)

    parser.init()
    directory = parser.directory
    try:
        clientLock()
        directory.updateDirectory(forceDownload=1)
    finally:
        clientUnlock()
    print "Directory updated"

_CLIENT_DECODE_USAGE = """\
Usage: %(cmd)s [options] -i <file>|--input=<file>
Options:
  -h, --help:                Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~/.mixminionrc
                             (You can also use MIXMINIONRC=FILE)
  -F, --force:               Decode the input files, even if they seem
                             overcompressed.
  -o <file>, --output=<file> Write the results to <file> rather than stdout.
  -i <file>, --input=<file>  Read the results from <file>.  

EXAMPLES:
  Decode message(s) stored in 'NewMail', writing the result to stdout.
      %(cmd)s -i NewMail
  Decode message(s) stored in 'NewMail', writing the result to 'Decoded'.
      %(cmd)s -i NewMail -o  Decoded
""".strip()

def clientDecode(cmd, args):
    #DOCDOC Comment me
    options, args = getopt.getopt(args, "hvf:o:Fi:",
          ['help', 'verbose', 'config=',
           'output=', 'force', 'input='])
           
    outputFile = '-'
    inputFile = None
    force = 0
    for o,v in options:
        if o in ('-o', '--output'):
            outputFile = v
        elif o in ('-F', '--force'):
            force = 1
        elif o in ('-i', '--input'):
            inputFile = v

    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantClient=1,
                                   wantLog=1)
    except UsageError, e:
        e.dump()
        print _CLIENT_DECODE_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    if args:
        msg = "Unexpected arguments."
        if len(args) == 1:
            msg += " (Did you mean '-i %s'?)" % args[0]
        raise UIError(msg)

    if not inputFile:
        raise UIError("No input file specified")

    parser.init()
    client = parser.client
        
    if outputFile == '-':
        out = sys.stdout
    else:
        # ???? Should we sometimes open this in text mode?
        out = open(outputFile, 'wb')

    if inputFile == '-':
        s = sys.stdin.read()
    else:
        try:
            f = open(inputFile, 'r')
            s = f.read()
            f.close()
        except OSError, e:
            LOG.error("Could not read file %s: %s", inputFile, e)
    try:
        res = client.decodeMessage(s, force=force)
    except ParseError, e:
        raise UIError("Couldn't parse message: %s"%e)
        
    for r in res:
        out.write(r)
    out.close()

_GENERATE_SURB_USAGE = """\
Usage: %(cmd)s [options]
Options:
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -D <yes|no>, --download-directory=<yes|no>
                             Force the client to download/not to download a
                               fresh directory.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
  -H <n>, --hops=<n>         Force the path to use <n> hops.
  -P <path>, --path=<path>   Specify an explicit path.
  -t address, --to=address   Specify the block's address. (Defaults to value
                               in configuration file.)
  -o <file>, --output=<file> Write the reply blocks to <file> instead of
                               stdout.
  -b, --binary               Write the reply blocks in binary mode instead
                               of ascii mode.
  -n <N>, --count=<N>        Generate <N> reply blocks. (Defaults to 1.)

EXAMPLES:
  Generate a reply block to deliver messages to the address given in
  ~/.mixminiond.conf; choose a path at random; write the block to stdout.
      %(cmd)s
  As above, but force change address to deliver to user@domain.
      %(cmd)s -t user@domain
  As above, but force a 6-hop path.
      %(cmd)s -t user@domain -H 6
  As above, but force the first hop to be 'Foo' and the last to be 'Bar'.
      %(cmd)s -t user@domain -H 6 -P 'Foo,*,Bar'
  As above, but write the reply block to the file 'MyBlocks'.
      %(cmd)s -t user@domain -H 6 -P 'Foo,*,Bar' -o MyBlocks
  As above, but write the reply block in binary mode.
      %(cmd)s -t user@domain -H 6 -P 'Foo,*,Bar' -o MyBlocks -b
  As above, but generate 100 reply blocks.
      %(cmd)s -t user@domain -H 6 -P 'Foo,*,Bar' -o MyBlocks -b -n 100
  Specify an explicit path.
      %(cmd)s -P 'Foo,Bar,Baz,Quux'
  Generate 10 reply blocks without downloading a new directory, even if the
  current directory is out of date.
      %(cmd)s -D no -n 10
""".strip()

def generateSURB(cmd, args):
    #DOCDOC Comment me
    options, args = getopt.getopt(args, "hvf:D:t:H:P:o:bn:",
          ['help', 'verbose', 'config=', 'download-directory=',
           'to=', 'hops=', 'path=', 'lifetime=',
           'output=', 'binary', 'count='])
           
    outputFile = '-'
    binary = 0
    count = 1
    for o,v in options:
        if o in ('-o', '--output'):
            outputFile = v
        elif o in ('-b', '--binary'):
            binary = 1
        elif o in ('-n', '--count'):
            try:
                count = int(v)
            except ValueError:
                print "ERROR: %s expects an integer" % o
                sys.exit(1)
            
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantClient=1,
                                   wantLog=1, wantClientDirectory=1,
                                   wantDownload=1, wantReplyPath=1)
    except UsageError, e:
        e.dump()
        print _GENERATE_SURB_USAGE % { 'cmd' : cmd }
        sys.exit(0)

    if args:
        print >>sys.stderr, "ERROR: Unexpected arguments"
        print _GENERATE_SURB_USAGE % { 'cmd' : cmd }
        sys.exit(0)

    parser.init()
        
    client = parser.client

    parser.parsePath()
    
    path1 = parser.getReplyPath()
    address = parser.address

    if outputFile == '-':
        out = sys.stdout
    elif binary:
        out = open(outputFile, 'wb')
    else:
        out = open(outputFile, 'w')

    for i in xrange(count):
        surb = client.generateReplyBlock(address, path1, parser.endTime)
        if binary:
            out.write(surb.pack())
        else:
            out.write(surb.packAsText())
        if i != count-1:
            parser.parsePath()
            path1 = parser.getReplyPath()
          
    out.close()

_INSPECT_SURBS_USAGE = """\
Usage: %(cmd)s [options] <files>
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Examine properties of reply blocks stored in 'FredsBlocks'.
      %(cmd)s FredsBlocks
""".strip()

def inspectSURBs(cmd, args):
    options, args = getopt.getopt(args, "hvf:",
             ["help", "verbose", "config=", ])

    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1)
    except UsageError, e:
        e.dump()
        print _INSPECT_SURBS_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()

    surblog = parser.client.openSURBLog()

    try:
        for fn in args:
            f = open(fn, 'rb')
            s = f.read()
            f.close()
            print "==== %s"%fn
            try:
                if stringContains(s, "== BEGIN TYPE III REPLY BLOCK =="):
                    surbs = parseTextReplyBlocks(s)
                else:
                    surbs = parseReplyBlocks(s)

                for surb in surbs:
                    used = surblog.isSURBUsed(surb) and "yes" or "no"
                    print surb.format()
                    print "Used:", used
            except ParseError, e:
                print "Error while parsing: %s"%e
    finally:
        surblog.close()

_FLUSH_POOL_USAGE = """\
Usage: %(cmd)s [options]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Try to send all currently pooled messages.
      %(cmd)s
""".strip()

def flushPool(cmd, args):
    options, args = getopt.getopt(args, "hvf:",
             ["help", "verbose", "config=", ])
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1)
    except UsageError, e:
        e.dump()
        print _FLUSH_POOL_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client

    client.flushPool()


_LIST_POOL_USAGE = """\
Usage: %(cmd)s [options]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Describe the current contents of the pool.
      %(cmd)s
""".strip()

def listPool(cmd, args):
    options, args = getopt.getopt(args, "hvf:",
             ["help", "verbose", "config=", ])
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1)
    except UsageError, e:
        e.dump()
        print _LIST_POOL_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client

    try:
        clientLock()
        client.pool.inspectPool()
    finally:
        clientUnlock()
