# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.19 2003/01/03 08:25:47 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.

   NOTE: THIS IS NOT THE FINAL VERSION OF THE CODE.  It needs to
         support replies and end-to-end encryption.
   """

__all__ = []

# (NOTE: The stuff in the next comment isn't implemented yet.)
# The client needs to store:
#      - config
#      - keys for pending SURBs
#      - server directory
#      - Per-system directory location is a neat idea, but individual users
#        must check signature.  That's a way better idea for later.

import cPickle
import getopt
import os
import stat
import sys
import time
import types
import urllib

import mixminion.BuildMessage
import mixminion.Crypto
import mixminion.MMTPClient
from mixminion.Common import IntervalSet, LOG, floorDiv, MixError, \
     MixFatalError, ceilDiv, createPrivateDir, isSMTPMailbox, formatDate, \
     formatFnameTime
from mixminion.Config import ClientConfig, ConfigError
from mixminion.ServerInfo import ServerInfo, ServerDirectory
from mixminion.Packet import ParseError, parseMBOXInfo, parseSMTPInfo, \
     MBOX_TYPE, SMTP_TYPE, DROP_TYPE

# FFFF This should be made configurable.
MIXMINION_DIRECTORY_URL = "http://www.mixminion.net/directory/latest.gz"
# FFFF This should be made configurable.
MIXMINION_DIRECTORY_FINGERPRINT = ""
                                
class ClientKeystore:
    """A ClientKeystore manages a list of server descriptors, either 
       imported from the command line or from a directory."""
    ##Fields:
    # dir: directory where we store everything.
    # lastModified: time when we last modified this keystore
    # lastDownload: time when we last downloaded a directory
    # serverList: List of (ServerInfo, 'D'|'I:filename') tuples.  The second
    #    element indicates whether the ServerInfo comes from a directory or
    #    a file.
    # byNickname: Map from nickname to list of (ServerInfo, source) tuples.
    # byCapability: Map from capability ('mbox'/'smtp'/'relay'/None) to
    #    list of (ServerInfo, source) tuples.
    # allServers: Same as byCapability[None]
    # __scanning: Flag to prevent recursive invocation of self.rescan().
    ## Layout:
    # DIR/cache: A cPickled tuple of (lastModified, lastDownload, serverlist)
    # DIR/dir.gz *or* DIR/dir: A (possibly gzipped) directory file.
    # DIR/servers/: A directory of server descriptors.
    def __init__(self, directory):
        """Create a new ClientKeystore to keep directories and descriptors
           under <directory>."""
        self.dir = directory
        createPrivateDir(self.dir)
        self.__scanning = 0
        self.__load()
    def downloadDirectory(self):
        """Download a new directory from the network, validate it, and 
           rescan its servers."""
        # Start downloading the directory.
        opener = URLopener()
        url = MIXMINION_DIRECTORY_URL
        LOG.info("Downloading directory from %s", url)
        infile = FancyURLopener().open(url)
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
            directory = ServerDirectory(fname=fname)
        except ConfigError, e:
            raise MixFatalError("Downloaded invalid directory: %s" % e)

        # Make sure that the identity is as expected.
        identity = directory['Signature']['DirectoryIdentity']
        fp = MIXMINION_DIRECTORY_FINGERPRINT
        if fp and pk_fingerprint(identity) != fp:
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
        # FFFF Actually, we could be a bit more clever here, and more clever
        # FFFF about not revalidating already-known-to-be-correct descriptors.
        # FFFF But that's for later.
        
    def rescan(self, now=None):
        """Regenerate the cache based on files on the disk."""
        self.lastModified = self.lastDownload = -1
        self.serverList = []

        # Read the servers from the directory.
        gzipFile = os.path.join(self.dir, "dir.gz")
        dirFile = os.path.join(self.dir, "dir")
        f = None
        for fname in gzipFile, dirFile:
            if not os.path.exists(fname): continue
            self.lastDownload = self.lastModified = \
                                os.stat(fname)[stat.ST_MTIME]
            try:
                directory = ServerDirectory(fname=fname)
            except ConfigError:
                LOG.warn("Ignoring invalid directory (!)")
                continue
            f.close()
            for s in directory.getServers():
                self.serverList.append((s, 'D'))
            break

        # Now check the server in DIR/servers.
        serverDir = os.path.join(self.dir, "servers")
        createPrivateDir(serverDir)
        for fn in os.listdir(serverDir):
            # Try to read a file: is it a server descriptor?
            p = os.path.join(self.directory, fn)
            try:
                info = ServerInfo(fname=p, assumeValid=0)
            except ConfigError:
                LOG.warn("Invalid server descriptor %s", p)
                continue
            mtime = os.stat(p)[stat.ST_MTIME]
            if mtime > self.lastModified:
                self.lastModifed = mtime
            self.serverList.append((info, "I:%s"%fn))

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
            self.lastModified, self.lastDowload, self.serverList = cached
            f.close()
            self.__rebuildTables()
            return        
        except OSError, e:
            LOG.info("Couldn't create server cache: %s", e)
        except (cPickle.UnpicklingError, ValueError), e:
            LOG.info("Couldn't unpickle server cache: %s", e)
        if self.__scanning:
            raise MixFatalError("Recursive error while regenerating cache")
        self.rescan()
        
    def __save(self):
        """Helper method. Recreate the cache on disk."""
        fname = os.path.join(self.dir, "cache.new")
        os.unlink(fname)
        f = open(fname, 'wb')
        cPickle.dump((self.lastModified, self.lastDownload, self.serverList),
                     f, 1)
        f.close()
        os.rename(fname, os.path.join(self.dir, "cache"))

    def importFromFile(self, filename):
        """Import a new server descriptor storred in 'filename'"""
        
        contents = readPossiblyGzippedFile(filename)
        info = ServerInfo(string=contents)

        nickname = info.getNickname()
        identity = info.getIdentity()
        # Make sure that the identity key is consistent with what we know.
        for s, _ in self.serverList:
            if s.getNickname() == nickname:
                if not pk_same_public_key(identity, s.getIdentity()):
                    raise MixError("Identity key changed for server %s in %s",
                                   nickname, filename)
        
        # Copy the server into DIR/servers.
        fnshort = "%s-%s"%(nickname, formatFnameTime())
        fname = os.path.join(self.dir, "servers", fnshort)
        f = open(fname, 'w')
        f.write(contents)
        f.close()
        # Now store into the cache.
        self.serverList.append((info, 'I:%s', fnshort))
        self.lastModified = time.time()
        self.__save()
        self.__rebuildTables()

    def expungeByNickname(self, nickname):
        """Remove all imported (non-directory) server nicknamed 'nickname'."""

        n = 0 # number removed
        newList = [] # replacement for serverList.

        for info, source in self.serverList:
            if source == 'D' or info.getNickname() != nickname:
                newList.append((info, source))
                continue
            n += 1
            try:
                os.unlink(os.path.join(self.dir, "servers", fn))
            except OSError, e:
                Log.error("Couldn't remove %s", fn)

        self.serverList = newList
        # Recreate cache if needed.
        if n:
            self.lastModifed = time.time()
            self.__save()
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
            nn = info.getNickname()
            lists = [ self.allServers, self.byNickname.setdefault(nn, []) ]
            for c in info.getCaps():
                lists.append( self.byCapability[c] )
            for lst in lists:
                lst.append((info, where))

    def listServers(self):
        """Returns a linewise listing of the current servers and their caps.
           stdout.  This will go away or get refactored in future versions
           once we have client-level modules."""
        lines = []
        nicknames = self.byNickname.keys()
        nicknames.sort()
        longestnamelen = max(map(len, nicknames))
        fmtlen = min(longestnamelen, 20)
        format = "%"+str(fmtlen)+"s:"
        for n in nicknames:
            lines.append(format%n)
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

        u = {} # Map from nickname -> latest-expiring info encountered in lst
        for info, _  in lst:
            if not info.isValidFrom(startAt, endAt):
                continue
            n = info.getNickname()
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

        newServers = []
        for info, where in self.serverList:
            if where == 'D':
                # Don't scratch servers from directory.
                newServers.append((info, where))
                continue
            elif info.isExpiredAt(cutoff):
                pass
            else:
                valid = info.getIntervalSet()
                for s in self.byNickname[info.getNickname()]:
                    if s.isNewerThan(info):
                        valid -= s.getIntervalSet()
                if not valid.isEmpty():
                    # Don't scratch non-superseded, non-expired servers.
                    newServers.append((info, where))
                    continue
            
            # Otherwise, remove it.
            try:
                os.unlink(os.path.join(self.dir, "servers", where[2:]))
            except OSError, e:
                LOG.info("Couldn't remove %s: %s", where[2:], e)

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
            endAt = startAt + 3600

        if isinstance(name, ServerInfo):
            if name.isValidFrom(startAt, endAt):
                return name
            else:
                LOG.error("Server is not currently valid")
        elif self.byNickname.has_key(name):
            s = self.__find(self.byNickname[name], startAt, endAt)
            if not s:
                raise MixError("Couldn't find valid descriptor %s")
        elif os.path.exists(name):
            try:
                return ServerInfo(fname=name, assumeValid=0)
            except OSError, e:
                raise MixError("Couldn't read descriptor %s: %s" %
                               (name, e))
            except ConfigError, e:
                raise MixError("Couldn't parse descriptor %s: %s" %
                               (name, e))
        elif strict:
            raise MixError("Couldn't find descriptor %s")
        else:
            return None

    def getPath(self, midCap=None, endCap=None, length=None,
                startServers=(), endServers=(),
                startAt=None, endAt=None, prng=None):
        """Workhorse method for path selection.  Constructs a 'length'-hop
           path, beginning with startServers and ending with endServers.  If
           more servers are required to make up 'length' hops, they are
           selected at random.
           
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
            endAt = startAt + 3600
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
                raise MixError("No %s servers known"% endCap)
            # ... and pick one.
            LOG.info("Choosing from among %s %s servers",
                     len(endList), endCap)
            endServers = [ self.prng.pick(endList) ]
            LOG.debug("Chose %s", endServers[0].getNickname())
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
        used = [ info.getNickname() 
                 for info in list(startServers)+list(endServers) ]
        # Which are left?
        unusedMidList = [ info for info in midList 
                          if info.getNickname() not in used ]
        if len(unusedMidList) >= length:
            # We have enough enough servers to choose without replacement.
            midServers = prng.shuffle(unusedMidList, nNeeded)
        elif len(midList) >= 3:
            # We have enough servers to choose without two hops in a row to
            # the same server.
            LOG.warn("Not enough servers for distinct path (only %s unused)",
                     len(unusedMidList))
            midServers = []
            if startServers:
                prevNickname = startServers[-1].getNickname()
            else:
                prevNickname = " (impossible nickname) "
            if endServers:
                endNickname = endServers[0].getNickname()
            else:
                endNickname = " (impossible nickname) "

            while nNeeded: 
                info = prng.pick(midList)
                n = info.getNickname()
                if n != prevNickname and (nNeeded > 1 or n != endNickname):
                    midServers.append(info)
                    prevNickname = n
                    nNeeded -= 1
        elif midList == 2:
            # We have enough servers to concoct a path that at least 
            # _sometimes_ doesn't go to the same server twice in a row.
            LOG.warn("Not enough relays to avoid same-server hops")
            midList = prng.shuffle(midList)
            midServers = (midList * ceilDiv(nNeeded, 2))[-nNeeded]
        elif midList == 1:
            # There's no point in choosing a long path here: it can only
            # have one server in it.
            LOG.warn("Only one relay known")
            midServers = midList
        else:
            # We don't know any servers at all.
            raise MixError("No relays known")
        
        LOG.info("Chose path: [%s][%s][%s]",
                 " ".join([s.getNickname() for n in startServers]),
                 " ".join([s.getNickname() for n in midServers]),
                 " ".join([s.getNickname() for n in endServers]))

        return startServers + midServers + endServers

def resolvePath(keystore, address, enterPath, exitPath,
                nHops, nSwap, startAt=None, endAt=None):
    """Compute a two-leg validated path from options as entered on
       the command line.

       Otherwise, we generate an nHops-hop path, swapping at the nSwap'th
       server, starting with the servers on enterPath, and finishing with the
       servers on exitPath (followed by the server, if any, mandated by
       address.

       All descriptors chosen are valid from startAt to endAt.  If the
       specified descriptors don't support the required capabilities,
       we raise MixError.
       """
    if startAt is None:
        startAt = time.time()
    if endAt is None:
        endAt = time.time()+3*60*60 # FFFF Configurable

    # First, find out what the exit node needs to be (or support).
    routingType, _, exitNode = address.getRouting()
    if exitNode:
        exitNode = keystore.getServerInfo(exitNode, startAt, endAt)
    if routingType == MBOX_TYPE:
        exitCap = 'mbox'
    elif routingType == SMTP_TYPE:
        exitCap = 'smtp'
    else:
        exitCap = None

    # We have a normally-specified path. 
    if exitNode is not None:
        exitPath.append(exitNode)
        nHops -= 1
    path = keystore.getPath(length=nHops,
                            startServers=enterPath,
                            endServers=exitPath,
                            midCap='relay', endCap=exitCap,
                            startAt=startAt, endAt=endAt)

    for server in path[:-1]:
        if "relay" not in server.getCaps():
            raise MixError("Server %s does not support relay"
                           % server.getNickname())
    if exitCap and exitCap not in path[-1].getCaps():
        raise MixError("Server %s does not support %s"
                       % (server.getNickname(), exitCap))
 
    if nSwap is None:
        nSwap = ceilDiv(len(path),2)   
    return path[:nSwap+1], path[nSwap+1:]

def parsePath(keystore, config, path, address, nHops=None, 
              nSwap=None, startAt=None, endAt=None):
    """Resolve a path as specified on the command line.  Returns a
       (path-leg-1, path-leg-2) tuple.
       
       keystore -- the keystore to use.
       path -- the path, in a format described below.  If the path is
          None, all servers are chosen as if the path were '*'.
       address -- the address to deliver the message to; if it specifies
          an exit node, the exit node is appended to the second leg of the
          path and does not count against the number of hops.
       nHops -- the number of hops to use.  Defaults to 6.
       nSwap -- the index of the swap-point server.  Defaults to nHops/2.
       startAt/endAt -- A time range during which all servers must be valid.

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
                raise MixError("Can't have two wildcards in a path")
            starPos = idx
            cur = exitPath
        elif ent == "*swap*":
            if swapPos is not None:
                raise MixError("Can't specify swap point twice")
            swapPos = idx
        else:
            cur.append(ent)
    
    # Now, we set the variables myNHops and myNSwap to the values of
    # nHops and nSwap (if any) implicit in the parsed path.
    if starPos is None:
        myNHops = len(enterPath)
    else:
        myNHops = nHops or 6 # FFFF Configurable default!

    if swapPos is None:
        # a,b,c,d or a,b,*,c
        myNSwap = None
    elif starPos is None or swapPos < starPos:
        # a,b:c,d or a,b:c,*,d
        myNSwap = swapPos - 1
    else:
        # a,*,b:c,d
        myNSwap = myNHops - (len(path)-swapPos-1)

    # Check myNSwap for consistency
    if nSwap is not None:
        if myNSwap is not None and myNSwap != nSwap:
            raise MixError("Mismatch between specified swap points")
        myNSwap = nSwap

    # Check myNHops for consistency
    if nHops is not None:
        if myNHops is not None and myNHops != nHops:
            raise MixError("Mismatch between specified number of hops")
        elif nHops < len(enterPath)+len(exitPath):
            raise MixError("Mismatch between specified number of hops")

        myNHops = nHops

    # Finally, resolve the path.
    return resolvePath(keystore, address, enterPath, exitPath,
                       myNHops, myNSwap, startAt, endAt)

## class TrivialKeystore:
##     """This is a temporary keystore implementation until we get a working
##        directory server implementation.

##        The idea couldn't be simpler: we just keep a directory of files, each
##        containing a single server descriptor.  We cache nothing; we validate
##        everything; we have no automatic path generation.  Servers can be
##        accessed by nickname, by filename within our directory, or by filename
##        from elsewhere on the filesystem.

##        We skip all server descriptors that have expired, that will
##        soon expire, or which aren't yet in effect.
##        """
##     ## Fields:
##     # directory: path to the directory we scan for server descriptors.
##     # byNickname: a map from nickname to valid ServerInfo object.
##     # byFilename: a map from filename within self.directory to valid
##     #     ServerInfo object.
##     def __init__(self, directory, now=None):
##         """Create a new TrivialKeystore to access the descriptors stored in
##            directory.  Selects descriptors that are valid at the time 'now',
##            or at the current time if 'now' is None."""
##         self.directory = directory
##         createPrivateDir(directory)
##         self.byNickname = {}
##         self.byFilename = {}

##         if now is None:
##             now = time.time()

##         for f in os.listdir(self.directory):
##             # Try to read a file: is it a server descriptor?
##             p = os.path.join(self.directory, f)
##             try:
##                 info = ServerInfo(fname=p, assumeValid=0)
##             except ConfigError:
##                 LOG.warn("Invalid server descriptor %s", p)
##                 continue

##             # Find its nickname and normalized filename
##             serverSection = info['Server']
##             nickname = serverSection['Nickname']

##             if '.' in f:
##                 f = f[:f.rindex('.')]

##             # Skip the descriptor if it isn't valid yet...
##             if now < serverSection['Valid-After']:
##                 LOG.info("Ignoring future decriptor %s", p)
##                 continue
##             # ... or if it's expired ...
##             if now >= serverSection['Valid-Until']:
##                 LOG.info("Ignoring expired decriptor %s", p)
##                 continue
##             # ... or if it's going to expire within 3 hours (HACK!).
##             if now + 3*60*60 >= serverSection['Valid-Until']:
##                 LOG.info("Ignoring soon-to-expire decriptor %s", p)
##                 continue
##             # Only allow one server per nickname ...
##             if self.byNickname.has_key(nickname):
##                 LOG.warn(
##                     "Ignoring descriptor %s with duplicate nickname %s",
##                     p, nickname)
##                 continue
##             # ... and per normalized filename.
##             if self.byFilename.has_key(f):
##                 LOG.warn(
##                     "Ignoring descriptor %s with duplicate prefix %s",
##                     p, f)
##                 continue
##             LOG.info("Loaded server %s from %s", nickname, f)
##             # Okay, it's good. Cache it.
##             self.byNickname[nickname] = info
##             self.byFilename[f] = info

##     def getServerInfo(self, name):
##         """Return a ServerInfo object corresponding to 'name'.  If 'name' is
##            a ServerInfo object, returns 'name'.  Otherwise, checks server by
##            nickname, then by filename within the keystore, then by filename
##            on the file system. If no server is found, returns None."""
##         if isinstance(name, ServerInfo):
##             return name
##         elif self.byNickname.has_key(name):
##             return self.byNickname[name]
##         elif self.byFilename.has_key(name):
##             return self.byFilename[name]
##         elif os.path.exists(name):
##             try:
##                 return ServerInfo(fname=name, assumeValid=0)
##             except OSError, e:
##                 raise MixError("Couldn't read descriptor %s: %s" %
##                                (name, e))
##             except ConfigError, e:
##                 raise MixError("Couldn't parse descriptor %s: %s" %
##                                (name, e))
##         else:
##             return None

##     def getPath(self, serverList):
##         """Given a sequence of strings of ServerInfo objects, resolves each
##            one according to the rule of getServerInfo, and returns a list of
##            ServerInfos.  Raises MixError if any server can't be resolved."""
##         path = []
##         for s in serverList:
##             if isinstance(s, ServerInfo):
##                 path.append(s)
##             elif isinstance(s, types.StringType):
##                 server = self.getServerInfo(s)
##                 if server is not None:
##                     path.append(server)
##                 else:
##                     raise MixError("Couldn't find descriptor %s" % s)
##         return path

##     def listServers(self):
##         """Returns a linewise listing of the current servers and their caps.
##            stdout.  This will go away or get refactored in future versions
##            once we have real path selection and client-level modules."""
##         lines = []
##         nicknames = self.byNickname.keys()
##         nicknames.sort()
##         longestnamelen = max(map(len, nicknames))
##         fmtlen = min(longestnamelen, 20)
##         format = "%"+str(fmtlen)+"s (expires %s): %s"
##         for n in nicknames:
##             caps = []
##             si = self.byNickname[n]
##             if si['Delivery/MBOX'].get('Version',None):
##                 caps.append("mbox")
##             if si['Delivery/SMTP'].get('Version',None):
##                 caps.append("smtp")
##             # XXXX This next check is highly bogus.
##             if (si['Incoming/MMTP'].get('Version',None) and 
##                 si['Outgoing/MMTP'].get('Version',None)):
##                 caps.append("relay")
##             until = formatDate(si['Server']['Valid-Until'])
##             line = format % (n, until, " ".join(caps))
##             lines.append(line)
##         return lines

##     def getRandomServers(self, prng, n):
##         """Returns a list of n different servers, in random order, according
##            to prng.  Raises MixError if not enough exist.

##            (This isn't actually used.)"""
##         vals = self.byNickname.values()
##         if len(vals) < n:
##             raise MixError("Not enough servers (%s requested)", n)
##         return prng.shuffle(vals, n)

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
PathLength: 4

## Not yet implemented:
# SURBAddress: mbox:quux
# SURBPathLength: 8

""")
    f.close()

class MixminionClient:
    """Access point for client functionality.  Currently, this is limited
       to generating and sending forward messages"""
    ## Fields:
    # config: The ClientConfig object with the current configuration
    # prng: A pseudo-random number generator for padding and path selection
    def __init__(self, conf):
        """Create a new MixminionClient with a given configuration"""
        self.config = conf

        # Make directories
        userdir = os.path.expanduser(self.config['User']['UserDir'])
        createPrivateDir(userdir)
        #createPrivateDir(os.path.join(userdir, 'surbs'))
        createPrivateDir(os.path.join(userdir, 'servers'))

        # Initialize PRNG
        self.prng = mixminion.Crypto.getCommonPRNG()

    def sendForwardMessage(self, address, payload, servers1, servers2):
        """Generate and send a forward message.
            address -- the results of a parseAddress call
            payload -- the contents of the message to send
            path1,path2 -- lists of servers for the first and second legs of
               the path, respectively."""

        message, firstHop = \
                 self.generateForwardMessage(address, payload, 
                                             servers1, servers2)

        self.sendMessages([message], firstHop)

    def generateForwardMessage(self, address, payload, servers1, servers2):
        """Generate a forward message, but do not send it.  Returns
           a tuple of (the message body, a ServerInfo for the first hop.)

            address -- the results of a parseAddress call
            payload -- the contents of the message to send
            path1,path2 -- lists of servers."""

        routingType, routingInfo, _ = address.getRouting()
        msg = mixminion.BuildMessage.buildForwardMessage(
            payload, routingType, routingInfo, servers1, servers2,
            self.prng)
        return msg, servers1[0]

    def sendMessages(self, msgList, server):
        """Given a list of packets and a ServerInfo object, sends the
           packets to the server via MMTP"""
        con = mixminion.MMTPClient.BlockingClientConnection(server.getAddr(),
                                                            server.getPort(),
                                                            server.getKeyID())
        try:
            con.connect()
            for msg in msgList:
                con.sendPacket(msg)
        finally:
            con.shutdown()

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
        return Address(DROP_TYPE, None, None)
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
        print >>sys.stderr, str(e)
        sys.exit(1)
    return None #suppress pychecker warning

def usageAndExit(cmd, error=None):
    #XXXX002 correct this.
    if error:
        print >>stderr, "ERROR: %s"%error
    print >>sys.stderr, """\
Usage: %s [-h] [-v] [-f configfile] [-i inputfile]
          [--path1=server1,server2,...]
          [--path2=server1,server2,...] [-t <address>]"""%cmd
    sys.exit(1)

# NOTE: This isn't anything LIKE the final client interface.  Many or all
#       options will change between now and 1.0.0
def runClient(cmd, args):
    # DOCDOC
    options, args = getopt.getopt(args, "hvf:i:t:H:P:",
                                  ["help", "verbose", "config=", "input=",
                                   "to=", "hops=", "swap-at=", "path",
                                  ])
    configFile = '~/.mixminionrc'
    usage = 0
    inFile = "-"
    verbose = 0
    path = None
    nHops = None
    nSwap = None
    address = None
    for opt,val in options:
        if opt in ('-h', '--help'):
            usageAndExit(cmd)
        elif opt in ('-f', '--config'):
            configFile = val
        elif opt in ('-i', '--input'):
            inFile = val
        elif opt in ('-v', '--verbose'):
            verbose = 1
        elif opt in ('-P', '--path'):
            path = val
        elif opt in ('-H', '--hops'):
            try:
                nHops = int(val)
            except ValueError:
                usageAndExit(cmd, "%s expects an integer"%opt)
        elif opt == '--swap-at':
            try:
                nHops = int(val)
            except ValueError:
                usageAndExit(cmd, "%s expects an integer"%opt)
        elif opt in ('-t', '--to'):
            address = parseAddress(val)
    if args:
        usageEndExit(cmd,"Unexpected options")
    if address is None:
        usageAndExit(cmd,"No recipient specified")

    config = readConfigFile(configFile)
    LOG.configure(config)
    if verbose:
        LOG.setMinSeverity("DEBUG")

    LOG.debug("Configuring client")
    mixminion.Common.configureShredCommand(config)
    mixminion.Crypto.init_crypto(config)

    keystore = ClientKeystore(os.path.expanduser(config['User']['UserDir']))
    #try:
    if 1:
        path1, path2 = parsePath(keystore, config, path, address, nHops, nSwap)
    #except MixError, e:
    #    print e
    #    sys.exit(1)

    client = MixminionClient(config)

    if inFile == '-':
        f = sys.stdin
    else:
        f = open(inFile, 'r')
    payload = f.read()
    f.close()

    client.sendForwardMessage(address, payload, path1, path2)

def listServers(cmd, args):
    options, args = getopt.getopt(args, "hf:", ['help', 'config='])
    configFile = None
    for o,v in options:
        if o in ('-h', '--help'):
            print "Usage %s [--help] [--config=configFile]"
            sys.exit(1)
        elif o in ('-f', '--config'):
            configFile = v

    config = readConfigFile(configFile)
    userdir = os.path.expanduser(config['User']['UserDir'])
    createPrivateDir(os.path.join(userdir, 'servers'))

    keystore = TrivialKeystore(os.path.join(userdir,"servers"))
        
    for line in keystore.listServers():
        print line
