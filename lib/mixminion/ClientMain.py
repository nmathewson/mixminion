# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.18 2003/01/03 05:14:47 nickm Exp $

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
#          (Have dir of files from which to reconstruct a shelf of cached
#           info.)
#          (Don't *name* files in dir; or at least, don't make their names
#           magic.  Files can be: ServerInfos, ServerDirectories, or 'fake'
#           directories.  Each server can have any number of virtual or
#           official tags.  Users should use the CLI to add/remove entries from
#           dir.)
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
     MixFatalError, createPrivateDir, isSMTPMailbox, formatDate, \
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
    """DOCDOC"""
    #DOCDOC
    ##Fields:
    # dir
    # lastModified
    # lastDownload
    # serverList: list of (ServerInfo, 'D'|'I:filename')
    # byNickname:
    # byCapability:
    # allServers:
    #     All are maps/lists of (ServerInfo, where)
    # __scanning
    ## Layout:
    # DIR/cache
    # DIR/dir.gz *or* DIR/dir
    # DIR/servers/X
    #             Y
    def __init__(self, directory):
        "DOCDOC"
        self.dir = directory
        createPrivateDir(self.dir)
        self.__scanning = 0
        self._load()
    def downloadDirectory(self):
        "DOCDOC"
        #DOCDOC
        opener = URLopener()
        url = MIXMINION_DIRECTORY_URL
        LOG.info("Downloading directory from %s", url)
        infile = FancyURLopener().open(url)
        if url.endswith(".gz"):
            fname = os.path.join(self.dir, "dir_new.gz")
            outfile = open(fname, 'wb')
            gz = 1
        else:
            fname = os.path.join(self.dir, "dir_new")
            outfile = open(fname, 'w')
            gz = 0
        while 1:
            s = infile.read(1<<16)
            if not s: break
            outfile.write(s)
        infile.close()
        outfile.close()
        LOG.info("Validating directory")
        try:
            directory = ServerDirectory(fname=fname)
        except ConfigError, e:
            raise MixFatalError("Downloaded invalid directory: %s" % e)

        identity = directory['Signature']['DirectoryIdentity']
        fp = MIXMINION_DIRECTORY_FINGERPRINT
        if fp and pk_fingerprint(identity) != fp:
            raise MixFatalError("Bad identity key on directory")

        try:
            os.unlink(os.path.join(self.dir, "cache"))
        except OSError:
            pass

        if gz:
            os.rename(fname, os.path.join(self.dir, "dir.gz"))
        else:
            os.rename(fname, os.path.join(self.dir, "dir"))

        self.rescan()
    def rescan(self, now=None):
        "DOCDOC"
        #DOCDOC
        self.lastModified = self.lastDownload = -1
        self.serverList = []
        gzipFile = os.path.join(self.dir, "dir.gz")
        dirFile = os.path.join(self.dir, "dir")
        f = None
        for fname in gzipFile, dirFile:
            if not os.path.exists(fname): continue
            self.lastDownload = self.lastModified = \
                                os.stat(fname)[stat.ST_MTIME]
            directory = ServerDirectory(fname=fname)
            try:
                directory = ServerDirectory(f.read())
            except ConfigError:
                LOG.warn("Ignoring invalid directory (!)")
                continue
            f.close()
            for s in directory.getServers():
                self.serverList.append((s, 'D'))
            break

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
        self.__save()
        self.__scanning = 1
        self.__load()
    def __load(self):
        "DOCDOC"
        #DOCDOC
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
        "DOCDOC"
        fname = os.path.join(self.dir, "cache.new")
        os.unlink(fname)
        f = open(fname, 'wb')
        cPickle.dump((self.lastModified, self.lastDownload, self.serverList),
                     f, 1)
        f.close()
        os.rename(fname, os.path.join(self.dir, "cache"))
    def importFromFile(self, filename):
        "DOCDOC"
        #DOCDOC
        f = open(filename, 'r')
        contents = f.read()
        f.close()
        info = ServerInfo(string=contents)

        nickname = info.getNickname()
        identity = info.getIdentity()
        for s, _ in self.serverList:
            if s.getNickname() == nickname:
                if not pk_same_public_key(identity, s.getIdentity()):
                    raise MixError("Identity key changed for server %s in %s",
                                   nickname, filename)
        
        fnshort = "%s-%s"%(nickname, formatFnameTime())
        fname = os.path.join(self.dir, "servers", fnshort)
        f = open(fname, 'w')
        f.write(contents)
        f.close()
        self.serverList.append((info, 'I:%s', fnshort))
        self.__save()
        self.__rebuildTables()
    def expungeByNickname(self, nickname):
        "DOCDOC"
        #DOCDOC
        n = 0
        newList = []
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
        if n:
            self.lastModifed = time.time()
            self.__save()
        return n

    def __rebuildTables(self):
        "DOCDOC"
        #DOCDOC
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
        #DOCDOC
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
        "DOCDOC"
        res = self.__find(lst, startAt, endAt)
        if res:
            return res[0]
        return None

    def __find(self, lst, startAt, endAt):
        "DOCDOC"
        lst = [ info for info, _ in lst if info.isValidFrom(startAt, endAt) ]
        # XXXX This is not really good: servers may be the same, even if
        # XXXX their nicknames are different.  The logic should probably
        # XXXX go into directory, though.
        u = {}
        for info in lst:
            n = info.getNickname()
            if u.has_key(n):
                if info.isExpiredAt(u[n]['Server']['Valid-Until']):
                    continue
            u[n] = info

        return u.values()

    def clean(self, now=None):
        "DOCDOC"
        #DOCDOC
        if now is None:
            now = time.time()
        cutoff = now - 600

        newServers = []
        for info, where in self.serverList:
            if where == 'D':
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
                    newServers.append((info, where))
                    continue
            try:
                os.unlink(os.path.join(self.dir, "servers", where[2:]))
            except OSError, e:
                LOG.info("Couldn't remove %s: %s", where[2:], e)
                    
        self.serverList = newServers
        self.__rebuildTables()

    def getServerInfo(self, name, startAt=None, endAt=None, strict=0):
        "DOCDOC"
        #DOCDOC
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + 3600

        if isinstance(name, ServerInfo):
            return name
        elif self.byNickname.has_key(name):
            s = self.__find(self.byNickname[name], startAt, endAt)
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
        "DOCDOC"
        #DOCDOC
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + 3600
        if prng is None:
            prng = mixminion.Crypto.getCommonPRNG()
        
        startServers = [ self.getServerInfo(name,startAt,endAt,1) 
                         for name in startServers ]
        endServers = [ self.getServerInfo(name,startAt,endAt,1)
                       for name in endServers ]
        nNeeded = 0
        if length:
            nNeeded = length - len(startServers) - len(endServers)
        
        if nNeeded <= 0:
            return startServers + endServers

        endList = self.__find(self.byCapability[endCap],startAt,endAt)
        if not endServers:
            if not endList:
                raise MixError("No %s servers known"% endCap)
            LOG.info("Choosing from among %s %s servers",
                     len(endList), endCap)
            endServers = [ self.prng.pick(endList) ]
            LOG.debug("Chose %s", endServers[0].getNickname())
            nNeeded -= 1

        if nNeeded == 0:
            return startServers + endServers

        # This is hard.  We need to find a number of relay servers for
        # the midddle of the list.  If len(midList) >> length, we should
        # remove all servers that already appear, and shuffle from the
        # rest.  Otherwise, if len(midList) >= 3, we pick one-by-one from 
        # the list of possibilities, just making sure not to get 2 in a row.
        # Otherwise, len(midList) <= 3, so we just wing it.
        #
        # FFFF This algorithm is far from ideal, but the answer is to
        # FFFF get more servers deployed.
        midList = self.__find(self.byCapability[midCap],startAt,endAt)
        used = [ info.getNickname() 
                 for info in list(startServers)+list(endServers) ]
        unusedMidList = [ info for info in midList 
                          if info.getNickname() not in used ]
        if len(unusedMidList) >= length*1.1:
            midServers = prng.shuffle(unusedMidList, nNeeded)
        elif len(midList) >= 3:
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
            LOG.warn("Not enough relays to avoid same-server hops")
            midList = prng.shuffle(midList)
            midServers = (midList * ceilDiv(nNeeded, 2))[-nNeeded]
        elif midList == 1:
            LOG.warn("Only one relay known")
            midServers = midList
        else:
            raise MixError("No relays known")
            
        LOG.info("Chose path: [%s][%s][%s]",
                 " ".join([s.getNickname() for n in startServers]),
                 " ".join([s.getNickname() for n in midServers]),
                 " ".join([s.getNickname() for n in endServers]))

        return startServers + midServers + endServers

def resolvePath(keystore, address, path1, path2, enterPath, exitPath,
                nHops, nSwap, startAt=None, endAt=None):
    "DOCDOC"
    #DOCDOC
    if startAt is None:
        startAt = time.time()
    if endAt is None:
        endAt = time.time()+3*60*60 # FFFF Configurable

    routingType, _, exitNode = address.getRouting()
    if exitNode:
        exitNode = keystore.getServerInfo(exitNode, startAt, endAt)

    if routingType == MBOX_TYPE:
        exitCap = 'mbox'
    elif routingType == SMTP_TYPE:
        exitCap = 'smtp'
    else:
        exitCap = None
 
    if path1 and path2:
        path = path1+path2
        path = keystore.getPath(length=len(path), startServers=path,
                                startAt=startAt, endAt=endAt)
        if exitNode is not None:
            path.append(exitNode)
        nSwap = len(path1)-1
    elif path1 or path2:
        raise MixError("--path1 and --path2 must both be specified or not")
    else:
        if exitNode is not None:
            exitPath.append(exitNode)
        nHops = nHops - len(enterPath) - len(exitPath)
        path = keystore.getPath(length=nHops,
                                startServers=enterPath,
                                endServers=exitPath,
                                midCap='relay', endCap=exitCap,
                                startAt=startAt, endAt=endAt)
        if nSwap < 0:
            nSwap = ceilDiv(len(path),2)

    for server in path[:-1]:
        if "relay" not in server.getCaps():
            raise MixError("Server %s does not support relay"
                           % server.getNickname())
    if exitCap and exitCap not in path[-1].getCaps():
        raise MixError("Server %s does not support %s"
                       % (server.getNickname(), exitCap))
    
    return path[:nSwap+1], path[nSwap+1:]

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
    "DOCDOC"
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
    options, args = getopt.getopt(args, "hvf:i:t:H:",
                                  ["help", "verbose", "config=", "input=",
                                   "path1=", "path2=", "to=", "hops=",
                                   "swap-at=", "enter=", "exit=",
                                  ])
    configFile = '~/.mixminionrc'
    usage = 0
    inFile = "-"
    verbose = 0
    path1 = []
    path2 = []
    enter = []
    exit = []
    swapAt = -1
    hops = -1 # XXXX Make configurable
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
        elif opt == '--path1':
            path1.extend(val.split(","))
        elif opt == '--path2':
            path2.extend(val.split(","))
        elif opt in ('-H', '--hops'):
            try:
                hops = int(val)
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
        path1, path2 = resolvePath(keystore, address,
                                   path1, path2,
                                   enterPath, exitPath,
                                   nHops, nSwap)
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
