# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.
   """

__all__ = [ 'Address', 'ClientKeyring', 'ClientDirectory', 'MixminionClient',
    'parsePath', ]

import anydbm
import binascii
import errno
import cPickle
import getopt
import getpass
import os
import re
import signal
import socket
import stat
import sys
import time
import urllib2
from types import ListType

import mixminion.BuildMessage
import mixminion.Crypto
import mixminion.MMTPClient

from mixminion.Common import AtomicFile, IntervalSet, LOG, floorDiv, \
     MixError, MixFatalError, MixProtocolError, MixProtocolBadAuth, UIError, \
     UsageError, ceilDiv, createPrivateDir, isPrintingAscii, isSMTPMailbox, \
     formatDate, formatFnameTime, formatTime, Lockfile, openUnique, \
     previousMidnight, readFile, readPickled, readPossiblyGzippedFile, \
     secureDelete, stringContains, succeedingMidnight, tryUnlink, writeFile, \
     writePickled
from mixminion.Crypto import sha1, ctr_crypt, trng
from mixminion.Config import ClientConfig, ConfigError
from mixminion.ServerInfo import ServerInfo, ServerDirectory
from mixminion.Packet import ParseError, parseMBOXInfo, parseReplyBlocks, \
     parseSMTPInfo, parseTextEncodedMessages, parseTextReplyBlocks, \
     ReplyBlock, MBOX_TYPE, SMTP_TYPE, DROP_TYPE

# FFFF This should be made configurable and adjustable.
MIXMINION_DIRECTORY_URL = "http://mixminion.net/directory/Directory.gz"
MIXMINION_DIRECTORY_FINGERPRINT = "CD80DD1B8BE7CA2E13C928D57499992D56579CCD"

#----------------------------------------------------------------------
# Global variable; holds an instance of Common.Lockfile used to prevent
# concurrent access to the directory cache, message queue, or SURB log.
_CLIENT_LOCKFILE = None

def clientLock():
    """Acquire the client lock."""
    assert _CLIENT_LOCKFILE is not None
    pidStr = str(os.getpid())
    try:
        _CLIENT_LOCKFILE.acquire(blocking=0, contents=pidStr)
    except IOError:
        LOG.info("Waiting for pid %s", _CLIENT_LOCKFILE.getContents())
        _CLIENT_LOCKFILE.acquire(blocking=1, contents=pidStr)

def clientUnlock():
    """Release the client lock."""
    _CLIENT_LOCKFILE.release()

def configureClientLock(filename):
    """Prepare the client lock for use."""
    global _CLIENT_LOCKFILE
    _CLIENT_LOCKFILE = Lockfile(filename)

#----------------------------------------------------------------------
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
    #         fullServerList, digestMap)
    # DIR/dir.gz *or* DIR/dir: A (possibly gzipped) directory file.
    # DIR/imported/: A directory of server descriptors.
    MAGIC = "ClientKeystore-0.2"

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
        # FFFF Make configurable
        DIRECTORY_TIMEOUT = 15
        # Start downloading the directory.
        url = MIXMINION_DIRECTORY_URL
        LOG.info("Downloading directory from %s", url)
        def sigalrmHandler(sig, _):
            pass
        signal.signal(signal.SIGALRM, sigalrmHandler)
        signal.alarm(DIRECTORY_TIMEOUT)
        try:
            try:
                infile = urllib2.urlopen(url)
            except IOError, e:
                raise UIError(
                    ("Couldn't connect to directory server: %s.\n"
                     "Try '-D no' to run without downloading a directory.")%e)
            except socket.error, e:
                if e.errno == errno.EINTR:
                    raise UIError("Connection to directory server timed out")
                else:
                    raise UIError("Error connecting: %s",e)
                raise UIError
        finally:
            signal.alarm(0)
        
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

        tryUnlink(os.path.join(self.dir, "cache"))

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
                directory = ServerDirectory(fname=fname,
                                            validatedDigests=self.digestMap)
            except ConfigError:
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
                info = ServerInfo(fname=p, assumeValid=0,
                                  validatedDigests=self.digestMap)
            except ConfigError:
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
        """Helper method.  Reconstruct byNickname, allServers, and byCapability
           from the internal start of this object.
        """
        self.byNickname = {}
        self.allServers = []
        self.byCapability = { 'mbox': [],
                              'smtp': [],
                              'relay': [],
                              None: self.allServers }
        self.goodServerNicknames = {}

        for info, where in self.serverList:
            nn = info.getNickname().lower()
            lists = [ self.allServers, self.byNickname.setdefault(nn, []) ]
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
                raise UIError(
                    "Couldn't find any currently live descriptor with name %s"
                    % name)

            if not self.goodServerNicknames.has_key(s.getNickname().lower()):
                LOG.warn("Server %s is not recommended",name)
            
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

    def getPath(self, endCap, template, startAt=None, endAt=None, prng=None):
        """Workhorse method for path selection.  Given a template, and
           a capability that must be supported by the exit node, return
           a list of serverinfos that 'matches' the template, and whose
           last node provides exitCap.

           The template is a list of either: strings or serverinfos as
           expected by 'getServerInfo'; or None to indicate that
           getPath should select a corresponding server.

           All servers are chosen to be valid continuously from
           startAt to endAt.  The last server is not set) is selected
           to have 'endCap' (typically 'mbox' or 'smtp').  Set endCap
           to 'None' if you don't care.

           The path selection algorithm perfers to choose without
           replacement it it can.
        """
        def setSub(s1, s2):
            """Helper function. Given two lists of serverinfo, returns all
               members of s1 that are not members of s2.  ServerInfos are
               considered equivalent if their nicknames are the same,
               ignoring case.
            """
            n = [ inf.getNickname().lower() for inf in s2 ]
            return [ inf for inf in s1 if inf.getNickname().lower() not in n]

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

        # If we need to pick the last server, pick it first.
        if servers[-1] is None:
            # Who has the required exit capability....
            endCandidates = self.__find(self.byCapability[endCap],
                                        startAt,endAt)
            if not endCandidates:
                raise UIError("Can't build path: no %s servers known"%endCap)
            # ....that we haven't used yet?
            used = filter(None, servers)
            unusedEndCandidates = setSub(endCandidates, used)
            if unusedEndCandidates:
                # Somebody with the capability is unused
                endCandidates = unusedEndCandidates
            elif len(endCandidates) > 1 and servers[-2] is not None:
                # We can at least avoid of picking someone with the
                # capability who isn't the penultimate node.
                penultimate = servers[-2].getNickname().lower()
                endCandidates = setSub(endCandidates, [penultimate])
            else:
                # We're on our own.
                assert len(endCandidates)

            # Finally, fill in the last server.
            servers[-1] = prng.pick(endCandidates)

        # Now figure out which relays we haven't used yet.
        used = filter(None, servers)
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
                abutters = filter(None,[ servers[i-1], servers[i+1]])
            else:
                abutters = filter(None,[ servers[i+1] ])
            # ...and see if there are any relays left that aren't adjacent.
            candidates = setSub(relays, abutters)
            if candidates:
                # Good.  There are.
                servers[i] = prng.pick(candidates)
            else:
                # Nope.  Choose a random relay.
                servers[i] = prng.pick(relays)

        # FFFF We need to make sure that the path isn't totally junky.

        return servers

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

def parsePath(directory, config, path, address, nHops=None,
              startAt=None, endAt=None, halfPath=0,
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
    # Break path into a list of entries of the form:
    #        Nickname
    #     or "<swap>"
    #     or "?"
    p = path.replace(":", ",<swap>,").split(",")
    path = []
    for ent in p:
        if re.match(r'\*(\d+)', ent):
            path.extend(["?"]*int(ent[1:]))
        else:
            path.append(ent)

    # set explicitSwap to true iff the user specified a swap point.
    explicitSwap = path.count("<swap>")
    # set colonPos to the index of the explicit swap point, if any.
    if path.count("<swap>") > 1:
        raise UIError("Can't specify swap point twise")

    # set starPos to the index of the var-length wildcard, if any.
    if path.count("*") > 1:
        raise UIError("Can't have two variable-length wildcards in a path")
    elif path.count("*") == 1:
        starPos = path.index("*")
    else:
        starPos = None

    # If there's a variable-length wildcard...
    if starPos is not None:
        # Find out how many hops we should have.
        myNHops = nHops or defaultNHops or 6
        # Figure out how many nodes we need to add.
        haveHops = len(path) - 1
        # A colon will throw the count off.
        if explicitSwap:
            haveHops -= 1
        path[starPos:starPos+1] = ["?"]*max(0,myNHops-haveHops)

    # Figure out how long the first leg should be.
    if explicitSwap:
        # Calculate colon position
        colonPos = path.index("<swap>")
        if halfPath:
            raise UIError("Can't specify swap point with replies")
        firstLegLen = colonPos
        del path[colonPos]
    elif halfPath:
        firstLegLen = 0
    else:
        firstLegLen = ceilDiv(len(path), 2)

    # Do we have the right # of hops?
    if nHops is not None and len(path) != nHops:
        raise UIError("Mismatch between specified path lengths")

    # Replace all '?'s in path with [None].
    for i in xrange(len(path)):
        if path[i] == '?': path[i] = None

    # Figure out what capability we need in our exit node, so that
    # we can tell the directory.
    if address is None:
        rt, ri, exitNode = None, None, None
        exitCap = 'relay'
    else:
        rt, ri, exitNode = address.getRouting()
        if rt == MBOX_TYPE:
            exitCap = 'mbox'
        elif rt == SMTP_TYPE:
            exitCap = 'smtp'
        else:
            exitCap = None

    # If we have an explicit exit node from the address, append it.
    if exitNode is not None:
        path.append(exitNode)

    # Get a list of serverinfo.
    path = directory.getPath(endCap=exitCap,
                             template=path, startAt=startAt, endAt=endAt)

    # Now sanity-check the servers.

    # Make sure all relay servers support relaying.
    for server in path[:-1]:
        if "relay" not in server.getCaps():
            raise UIError("Server %s does not support relay"
                          % server.getNickname())

    # Make sure the exit server can support the exit capability.
    if exitCap and exitCap not in path[-1].getCaps():
        raise UIError("Server %s does not support %s capability"
                      % (path[-1].getNickname(), exitCap))


    # Split the path into 2 legs.
    path1, path2 = path[:firstLegLen], path[firstLegLen:]
    if not halfPath and len(path1)+len(path2) < 2:
        raise UIError("Path is too short")
    if not halfPath and (not path1 or not path2):
        raise UIError("Each leg of the path must have at least 1 hop")

    # Make sure the path can fit into the headers.
    mixminion.BuildMessage.checkPathLength(path1, path2,
                                           rt,ri,
                                           explicitSwap)

    # Return the two legs of the path.
    return path1, path2

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
    path1, path2 = parsePath(directory, config, path, address, nHops,
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
    # keyring: Dict to map from strings of the form "SURB-keyname" to SURB
    #     secrets.
    # keyringPassword: The password for our encrypted keyfile
    ## Format:
    # We store keys in a file holding:
    #  variable         [File specific magic]       "KEYRING1"
    #  8                [8 bytes of salt]
    #  variable         ENCRYPTED DATA:KEY=sha1(salt+password+salt)
    #                                  DATA=encrypted_pickled_data+
    #                                                   sha1(data+salt+magic)
    
    # XXXX There needs to be some way to rotate and expire SURB secrets.
    # XXXX Otherwise, we're very vulnerable to compromise.
    
    def __init__(self, keyDir):
        """Create a new ClientKeyring to store data in keyDir"""
        self.keyDir = keyDir
        createPrivateDir(self.keyDir)
        self.keyring = None
        self.keyringPassword = None

    def getKey(self, keyid, create=0, createFn=None, password=None):
        """Helper function. Return a key for a given keyid.

           keyid -- the name of the key.
           create -- If true, create a new key if none is found.
           createFn -- a callback to return a new key.
           password -- Optionally, a password for the keyring.
        """
        if self.keyring is None:
            self.getKeyring(create=create,password=password)
            if self.keyring is None:
                return None
        try:
            return self.keyring[keyid]
        except KeyError:
            if not create:
                return None
            else:
                LOG.info("Creating new key for identity %r", keyid)
                key = createFn()
                self.keyring[keyid] = key
                self._saveKeyring()
                return key

    def getKeyring(self, create=0, password=None):
        """Return a the current keyring, loading it if necessary.

           create -- if true, create a new keyring if none is found.
           password -- optionally, a password for the keyring.
        """
        if self.keyring is not None:
            return self.keyring
        fn = os.path.join(self.keyDir, "keyring")
        magic = "KEYRING1"
        if os.path.exists(fn):
            # If the keyring exists, make sure the magic is correct.
            self._checkMagic(fn, magic)
            # ...then see if we can load it without a password...
            try:
                data = self._load(fn, magic, "")
                self.keyring = cPickle.loads(data)
                self.keyringPassword = ""
                return self.keyring
            except MixError, e:
                pass
            # ...then ask the user for a password 'till it loads.
            while 1:
                if password is not None:
                    p = password
                else:
                    p = self._getPassword("Enter password for keyring:")
                try:
                    data = self._load(fn, magic, p)
                    self.keyring = cPickle.loads(data)
                    self.keyringPassword = p
                    return self.keyring
                except (MixError, cPickle.UnpicklingError), e:
                    LOG.error("Cannot load keyring: %s", e)
                    if password is not None: return None
        elif create:
            # If the key file doesn't exist, and 'create' is set, create it.
            LOG.warn("No keyring found; generating.")
            if password is not None:
                self.keyringPassword = password
            else:
                self.keyringPassword = self._getNewPassword("keyring")
            self.keyring = {}
            self._saveKeyring()
            return self.keyring
        else:
            return {}

    def _saveKeyring(self):
        """Save the current keyring to disk."""
        assert self.keyringPassword is not None
        fn = os.path.join(self.keyDir, "keyring")
        LOG.trace("Saving keyring to %s", fn)
        self._save(fn+"_tmp",
                   cPickle.dumps(self.keyring,1),
                   "KEYRING1", self.keyringPassword)
        os.rename(fn+"_tmp", fn)

    def getSURBKey(self, name="", create=0, password=None):
        """Return the key for a given SURB identity."""
        k = self.getKey("SURB-"+name,
                        create=create, createFn=lambda: trng(20),
                        password=password)
        if k is not None and len(k) != 20:
            raise MixError("Bad length on SURB key")
        return k

    def getSURBKeys(self,password=None):
        """Return the keys for _all_ SURB identities as a map from name
           to key."""
        self.getKeyring(create=0,password=password)
        if not self.keyring: return {}
        r = {}
        for k in self.keyring.keys():
            if k.startswith("SURB-"):
                r[k[5:]] = self.keyring[k]
        return r

    def _checkMagic(self, fn, magic):
        """Make sure that the magic string on a given key file %s starts with
           is equal to 'magic'.  Raise MixError if it isn't."""
        if not readFile(fn, 1).startswith(magic):
            raise MixError("Invalid versioning on key file")

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
        s = readFile(fn, 1)
        if not s.startswith(magic):
            raise MixError("Invalid versioning on key file")

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
        try:
            p = getpass.getpass("")
        except KeyboardInterrupt:
            if nl: print >>f
            raise UIError("Interrupted")
        if nl: print >>f
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

    writeFile(os.path.expanduser(fname),
              """\
# This file contains your options for the mixminion client.
[Host]
## Use this option to specify a 'secure remove' command.
#ShredCommand: rm -f
## Use this option to specify a nonstandard entropy source.
#EntropySource: /dev/urandom
## Set this option to 'no' to disable permission checking
#FileParanoia: yes

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

### Default paths to use if no path given on command line:
## For forward messages
#ForwardPath: ?,?,?:?,FavoriteExit
## For reply messages
#ReplyPath: ?,?,?,FavoriteSwap
## For reply blocks
#SURBPath: ?,?,?,FavoriteExit

[Network]
ConnectionTimeout: 20 seconds

""")


class SURBLog:
    """A SURBLog manipulates a database on disk to remember which SURBs we've
       used, so we don't reuse them accidentally.
       """
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

class ClientQueue:
    """A ClientQueue holds packets that have been scheduled for delivery
       but not yet delivered.  As a matter of policy, we queue messages if
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
    #                 packet was inserted into the queue
    #           )
    # XXXX change this to be OO; add nicknames.

    # XXXX write unit tests

    def __init__(self, directory, prng=None):
        """Create a new ClientQueue object, storing packets in 'directory'
           and generating random filenames using 'prng'."""
        self.dir = directory
        createPrivateDir(directory)
        if prng is not None:
            self.prng = prng
        else:
            self.prng = mixminion.Crypto.getCommonPRNG()

    def queuePacket(self, message, routing):
        """Insert the 32K packet 'message' (to be delivered to 'routing')
           into the queue.  Return the handle of the newly inserted packet."""
        clientLock()
        try:
            f, handle = self.prng.openNewFile(self.dir, "pkt_", 1)
            cPickle.dump(("PACKET-0", message, routing,
                          previousMidnight(time.time())), f, 1)
            f.close()
            return handle
        finally:
            clientUnlock()

    def getHandles(self):
        """Return a list of the handles of all messages currently in the
           queue."""
        clientLock()
        try:
            fnames = os.listdir(self.dir)
            handles = []
            for fname in fnames:
                if fname.startswith("pkt_"):
                    handles.append(fname[4:])
            return handles
        finally:
            clientUnlock()

    def getPacket(self, handle):
        """Given a handle, return a 3-tuple of the corresponding
           32K packet, IPV4Info, and time of first queueing.  (The time
           is rounded down to the closest midnight GMT.)"""
        fname = os.path.join(self.dir, "pkt_"+handle)
        magic, message, routing, when = readPickled(fname)
        if magic != "PACKET-0":
            LOG.error("Unrecognized packet format for %s",handle)
            return None
        return message, routing, when

    def packetExists(self, handle):
        """Return true iff the queue contains a packet with the handle
           'handle'."""
        fname = os.path.join(self.dir, "pkt_"+handle)
        return os.path.exists(fname)

    def removePacket(self, handle):
        """Remove the packet named with the handle 'handle'."""
        fname = os.path.join(self.dir, "pkt_"+handle)
        secureDelete(fname, blocking=1)

    def inspectQueue(self, now=None):
        """Print a message describing how many messages in the queue are headed
           to which addresses."""
        if now is None:
            now = time.time()
        handles = self.getHandles()
        if not handles:
            print "[Queue is empty.]"
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
    # queue: A ClientQueue object.
    # surbLogFilename: The filename used by the SURB log.
    def __init__(self, conf):
        """Create a new MixminionClient with a given configuration"""
        self.config = conf

        # Make directories
        userdir = self.config['User']['UserDir']
        createPrivateDir(userdir)
        keyDir = os.path.join(userdir, "keys")
        self.keys = ClientKeyring(keyDir)
        self.surbLogFilename = os.path.join(userdir, "surbs", "log")

        # Initialize PRNG
        self.prng = mixminion.Crypto.getCommonPRNG()
        self.queue = ClientQueue(os.path.join(userdir, "queue"))

    def sendForwardMessage(self, address, payload, servers1, servers2,
                           forceQueue=0, forceNoQueue=0):
        """Generate and send a forward message.
            address -- the results of a parseAddress call
            payload -- the contents of the message to send
            servers1,servers2 -- lists of ServerInfos for the first and second
               legs the path, respectively.
            forceQueue -- if true, do not try to send the message; simply
               quque it and exit.
            forceNoQueue -- if true, do not queue the message even if delivery
               fails."""
        assert not (forceQueue and forceNoQueue)

        message, firstHop = \
                 self.generateForwardMessage(address, payload,
                                             servers1, servers2)

        routing = firstHop.getRoutingInfo()

        if forceQueue:
            self.queueMessages([message], routing)
        else:
            self.sendMessages([message], routing, noQueue=forceNoQueue)

    def sendReplyMessage(self, payload, servers, surbList, forceQueue=0,
                         forceNoQueue=0):
        """Generate and send a reply message.
            payload -- the contents of the message to send
            servers -- a list of ServerInfos for the first leg of the path.
            surbList -- a list of SURBs to consider for the second leg of
               the path.  We use the first one that is neither expired nor
               used, and mark it used.
            forceQueue -- if true, do not try to send the message; simply
               queue it and exit.
            forceNoQueue -- if true, do not queue the message even if delivery
               fails."""
        #XXXX write unit tests
        message, firstHop = \
                 self.generateReplyMessage(payload, servers, surbList)

        routing = firstHop.getRoutingInfo()

        if forceQueue:
            self.queueMessages([message], routing)
        else:
            self.sendMessages([message], routing, noQueue=forceNoQueue)

    def generateReplyBlock(self, address, servers, name="", expiryTime=0):
        """Generate an return a new ReplyBlock object.
            address -- the results of a parseAddress call
            servers -- lists of ServerInfos for the reply leg of the path.
            expiryTime -- if provided, a time at which the replyBlock must
               still be valid, and after which it should not be used.
        """
        #XXXX write unit tests
        key = self.keys.getSURBKey(name=name, create=1)
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
        #XXXX write unit tests
        if now is None:
            now = time.time()
        surbLog = self.openSURBLog() # implies lock
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
            surbLog.close() #implies unlock

    def openSURBLog(self):
        """Return a new, open SURBLog object for this client; it must be closed
           when no longer in use.
        """
        return SURBLog(self.surbLogFilename)

    def pingServer(self, routingInfo):
        """Given an IPV4Info, try to connect to a server and find out if
           it's up.  Returns a boolean and a status message."""
        timeout = self.config['Network'].get('ConnectionTimeout')
        if timeout:
            timeout = int(timeout)
        else:
            timeout = 60

        try:
            mixminion.MMTPClient.pingServer(routingInfo, timeout)
            return 1, "Server seems to be running"
        except MixProtocolBadAuth:
            return 0, "Server seems to be running, but its key is wrong!"
        except MixProtocolError, e:
            return 0, "Couldn't connect to server: %s" % e

    def sendMessages(self, msgList, routingInfo, noQueue=0, lazyQueue=0,
                     warnIfLost=1):
        """Given a list of packets and an IPV4Info object, sends the
           packets to the server via MMTP.

           If noQueue is true, do not queue the message even on failure.
           If lazyQueue is true, only queue the message on failure.
           Otherwise, insert the message in the queue, and remove it on
           success.

           If warnIfLost is true, log a warning if we fail to deliver
           the message, and we don't queue it.
           """
        #XXXX write unit tests
        timeout = self.config['Network'].get('ConnectionTimeout')
        if timeout:
            timeout = int(timeout)
        else:
            timeout = 60

        if noQueue or lazyQueue:
            handles = []
        else:
            handles = self.queueMessages(msgList, routingInfo)

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
                if noQueue and warnIfLost:
                    LOG.error("Error with queueing disabled: %s lost", mword)
                elif lazyQueue:
                    LOG.info("Error while delivering %s; %s queued",
                             mword,mword)
                    self.queueMessages(msgList, routingInfo)
                else:
                    LOG.info("Error while delivering %s; leaving in queue",
                             mword)
                raise
            try:
                clientLock()
                for h in handles:
                    if self.queue.packetExists(h):
                        self.queue.removePacket(h)
            finally:
                clientUnlock()
        except MixProtocolError, e:
            raise UIError(str(e))

    def flushQueue(self, maxMessages=None):
        """Try to send end all messages in the queue to their destinations.
        """
        #XXXX write unit tests

        LOG.info("Flushing message queue")
        # XXXX This is inefficient in space!
        clientLock()
        try:
            handles = self.queue.getHandles()
            LOG.info("Found %s pending messages", len(handles))
            if maxMessages is not None:
                handles = mixminion.Crypto.getCommonPRNG().shuffle(handles,
                                                               maxMessages)
            LOG.info("Flushing %s", len(handles))
            messagesByServer = {}
            for h in handles:
                message, routing, _ = self.queue.getPacket(h)
                messagesByServer.setdefault(routing, []).append((message, h))
        finally:
            clientUnlock()

        sentSome = 0; sentAll = 1
        for routing in messagesByServer.keys():
            LOG.info("Sending %s messages to %s:%s...",
                     len(messagesByServer[routing]), routing.ip, routing.port)
            msgs = [ m for m, _ in messagesByServer[routing] ]
            handles = [ h for _, h in messagesByServer[routing] ]
            try:
                self.sendMessages(msgs, routing, noQueue=1, warnIfLost=0)
                try:
                    clientLock()
                    for h in handles:
                        if self.queue.packetExists(h):
                            self.queue.removePacket(h)
                finally:
                    clientUnlock()
                sentSome = 1
            except MixError, e:
                LOG.error("Can't deliver messages to %s:%s: %s; leaving messages in queue",
                          routing.ip, routing.port, str(e))
                sentAll = 0

        if sentAll:
            LOG.info("Queue flushed")
        elif sentSome:
            LOG.info("Queue partially flushed")
        else:
            LOG.info("No messages delivered")

    def queueMessages(self, msgList, routing):
        """Insert all the messages in msgList into the queue, to be sent
           to the server identified by the IPV4Info object 'routing'.
        """
        #XXXX write unit tests
        LOG.trace("Queueing messages")
        handles = []
        try:
            clientLock()
            for msg in msgList:
                h = self.queue.queuePacket(msg, routing)
                handles.append(h)
        finally:
            clientUnlock()
        if len(msgList) > 1:
            LOG.info("Messages queued")
        else:
            LOG.info("Message queued")
        return handles

    def decodeMessage(self, s, force=0, isatty=0):
        """Given a string 's' containing one or more text-encoed messages,
           return a list containing the decoded messages.

           Raise ParseError on malformatted messages.  Unless 'force' is
           true, do not uncompress possible zlib bombs.
        """
        #XXXX write unit tests
        results = []
        for msg in parseTextEncodedMessages(s, force=force):
            if msg.isOvercompressed() and not force:
                LOG.warn("Message is a possible zlib bomb; not uncompressing")
            if not msg.isEncrypted():
                results.append(msg.getContents())
            else:
                surbKeys = self.keys.getSURBKeys()
                p = mixminion.BuildMessage.decodePayload(msg.getContents(),
                                                         tag=msg.getTag(),
                                                         userKeys=surbKeys)
                if p:
                    results.append(p)
                else:
                    raise UIError("Unable to decode message")
        if isatty and not force:
            for p in results:
                if not isPrintingAscii(p,allowISO=1):
                    raise UIError("Not writing binary message to terminal: Use -F to do it anyway.")
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
        configFile = os.environ.get("MIXMINIONRC")
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
             -H | --hops : specify a path length
             -P | --path : specify a literal path.
          REPLY PATH ONLY
             --lifetime : Required lifetime of new reply blocks.
          MESSAGE-SENDING ONLY:
             --queue | --no-queue : force/disable queueing.

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
    #  address: exit address, or None.
    #  lifetime: SURB lifetime, or None.
    #  replyBlockFiles: list of SURB filenames.
    #  configFile: Filename of configuration file, or None.
    #  forceQueue: true if "--queue" is set.
    #  forceNoQueue: true if "--no-queue" is set.
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
        self.address = None
        self.lifetime = None
        self.replyBlockFiles = []

        self.forceQueue = None
        self.forceNoQueue = None

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
                        "Value of %s for %s conflicts with earlier value" %
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
            elif o in ('--queue',):
                self.forceQueue = 1
            elif o in ('--no-queue',):
                self.forceNoQueue = 1

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
            mixminion.Common.configureFileParanoia(self.config)
            if not self.verbose:
                try:
                    LOG.setMinSeverity("WARN")
                    mixminion.Crypto.init_crypto(self.config)
                finally:
                    LOG.setMinSeverity("INFO")
            else:
                mixminion.Crypto.init_crypto(self.config)

            userdir = self.config['User']['UserDir']
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
                raise UIError("No recipient specified; exiting.  (Try "
                              "using -t <your-address>)")
            try:
                self.address = parseAddress(address)
            except ParseError, e:
                raise UIError("Error in SURBAddress:"+str(e))
        elif self.address is None and self.replyBlockFiles == []:
            raise UIError("No recipients specified; exiting. (Try using "
                          "-t <recipient-address>")
        elif self.address is not None and self.replyBlockFiles:
            raise UIError("Cannot use both a recipient and a reply block")
        elif self.replyBlockFiles:
            useRB = 1
            surbs = []
            for fn in self.replyBlockFiles:
                if fn == '-':
                    s = sys.stdin.read()
                else:
                    s = readFile(fn, 1)
                try:
                    if stringContains(s,
                                      "-----BEGIN TYPE III REPLY BLOCK-----"):
                        surbs.extend(parseTextReplyBlocks(s))
                    else:
                        surbs.extend(parseReplyBlocks(s))
                except ParseError, e:
                        raise UIError("Error parsing %s: %s" % (fn, e))
        else:
            assert self.address is not None
            useRB = 0

        if self.path is None:
            if self.wantReplyPath:
                p = 'SURBPath'
            elif useRB:
                p = 'ReplyPath'
            else:
                p = 'ForwardPath'
            self.path = self.config['Security'].get(p, "*")

        if self.wantReplyPath:
            if self.lifetime is not None:
                duration = self.lifetime * 24*60*60
            else:
                duration = int(self.config['Security']['SURBLifetime'])

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
                                  self.address, self.nHops,
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
      %(cmd)s -t user@domain -i data -H 6 -P 'Foo,?:*,bar/baz'
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

def sendUsageAndExit(cmd, error=None):
    """Print a usage message for the mixminion send command (and family)
       and exit."""
    if error:
        print >>sys.stderr, "ERROR: %s"%error
        print >>sys.stderr, "For usage, run 'mixminion send --help'"
        sys.exit(1)
    if cmd.endswith(" queue"):
        print _SEND_USAGE % { 'cmd' : cmd, 'send' : 'queue', 'Send': 'Queue',
                              'extra' : '' }
    else:
        print _SEND_USAGE % { 'cmd' : cmd, 'send' : 'send', 'Send': 'Send',
                              'extra' : """\
  --queue                    Queue the message; don't send it.
  --no-queue                 Do not attempt to queue the message.""" }
    sys.exit(0)

def runClient(cmd, args):
    """[Entry point]  Generate an outgoing mixminion message and possibly
       send it.  Implements 'mixminion send' and 'mixminion queue'."""

    # Are we queueing?
    queueMode = 0
    if cmd.endswith(" queue"):
        queueMode = 1

    ###
    # Parse and validate our options.
    options, args = getopt.getopt(args, "hvf:D:t:H:P:R:i:",
             ["help", "verbose", "config=", "download-directory=",
              "to=", "hops=", "path=", "reply-block=",
              "input=", "queue", "no-queue" ])

    if not options:
        sendUsageAndExit(cmd)

    inFile = None
    for opt,val in options:
        if opt in ('-i', '--input'):
            inFile = val

    if args:
        sendUsageAndExit(cmd,"Unexpected arguments")

    try:
        parser = CLIArgumentParser(options, wantConfig=1,wantClientDirectory=1,
                                   wantClient=1, wantLog=1, wantDownload=1,
                                   wantForwardPath=1)
        if queueMode and parser.forceNoQueue:
            raise UsageError("Can't use --no-queue option with queue command")
        if parser.forceQueue and parser.forceNoQueue:
            raise UsageError("Can't use both --queue and --no-queue")
    except UsageError, e:
        e.dump()
        sendUsageAndExit(cmd)

    if inFile in (None, '-') and '-' in parser.replyBlockFiles:
        raise UIError(
            "Can't read both message and reply block from stdin")

    # FFFF Make queueing configurable from .mixminionrc
    forceQueue = queueMode or parser.forceQueue
    forceNoQueue = parser.forceNoQueue

    parser.init()
    client = parser.client

    parser.parsePath()

    path1, path2 = parser.getForwardPath()
    address = parser.address

    # Get our surb, if any.
    if parser.usingSURBList and inFile in ('-', None):
        # We check to make sure that we have a valid SURB before reading
        # from stdin.
        surblog = client.openSURBLog()
        try:
            s = surblog.findUnusedSURB(parser.path2)
            if s is None:
                raise UIError("No unused and unexpired reply blocks found.")
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

        try:
            if inFile == '-':
                print "Enter your message now.  Type Ctrl-D when you are done."
                payload = sys.stdin.read()
            else:
                payload = readFile(inFile)
        except KeyboardInterrupt:
            print "Interrupted.  Message not sent."
            sys.exit(1)

    if parser.usingSURBList:
        assert isinstance(path2, ListType)
        client.sendReplyMessage(payload, path1, path2,
                                forceQueue, forceNoQueue)
    else:
        client.sendForwardMessage(address, payload, path1, path2,
                                  forceQueue, forceNoQueue)

_PING_USAGE = """\
Usage: mixminion ping [options] serverName
Options
  -h, --help:             Print this usage message and exit.
  -v, --verbose           Display extra debugging messages.
  -f FILE, --config=FILE  Use a configuration file other than ~/.mixminionrc
  -D <yes|no>, --download-directory=<yes|no>
                          Force the client to download/not to download a
                            fresh directory.
"""
def runPing(cmd, args):
    """[Entry point] Send link padding to servers to see if they're up."""
    if len(args) == 1 and args[0] in ('-h', '--help'):
        print _PING_USAGE
        sys.exit(0)

    options, args = getopt.getopt(args, "hvf:D:",
             ["help", "verbose", "config=", "download-directory=", ])

    if len(args) == 0:
        raise UsageError("(No servers provided)")

    print "==========================================================="
    print "WARNING: Pinging a server is potentially dangerous, since"
    print "      it might alert people that you plan to use the server"
    print "      for your messages.  Even if you ping *all* the servers,"
    print "      an attacker can see _when_ you pinged the servers and"
    print "      use this information to help a traffic analysis attack."
    print
    print "      This command is for testing only, and will go away before"
    print "      Mixminion 1.0.  By then, all listed servers will be"
    print "      reliable anyway.  <wink>"
    print "==========================================================="

    parser = CLIArgumentParser(options, wantConfig=1,
                               wantClientDirectory=1, wantClient=1,
                               wantLog=1, wantDownload=1)

    parser.init()

    directory = parser.directory
    client = parser.client

    for arg in args:
        info = directory.getServerInfo(arg,
                                       startAt=time.time(), endAt=time.time(),
                                       strict=1)

        ok, status = client.pingServer(info.getRoutingInfo())
        print ">>>", status
        print info.getNickname(), (ok and "is up" or "is down")

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
    """[Entry point] Manually add a server to the client directory."""
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
    """[Entry point] Print info about """
    options, args = getopt.getopt(args, "hf:D:v",
                                  ['help', 'config=', "download-directory=",
                                   'verbose'])
    try:
        parser = CLIArgumentParser(options, wantConfig=1,
                                   wantClientDirectory=1,
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
    """[Entry point] Decode a message."""
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

    tty = os.isatty(out.fileno())

    if inputFile == '-':
        s = sys.stdin.read()
    else:
        try:
            s = readFile(inputFile)
        except OSError, e:
            LOG.error("Could not read file %s: %s", inputFile, e)
    try:
        res = client.decodeMessage(s, force=force, isatty=tty)
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
  --identity=<name>          Specify a pseudonymous identity.

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
    options, args = getopt.getopt(args, "hvf:D:t:H:P:o:bn:",
          ['help', 'verbose', 'config=', 'download-directory=',
           'to=', 'hops=', 'path=', 'lifetime=',
           'output=', 'binary', 'count=', 'identity='])

    outputFile = '-'
    binary = 0
    count = 1
    identity = ""
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
        elif o in ('--identity',):
            identity = v
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
        surb = client.generateReplyBlock(address, path1, name=identity,
                                         expiryTime=parser.endTime)
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
            s = readFile(fn, 1)
            print "==== %s"%fn
            try:
                if stringContains(s, "-----BEGIN TYPE III REPLY BLOCK-----"):
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

_FLUSH_QUEUE_USAGE = """\
Usage: %(cmd)s [options]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
  -n <n>, --count=<n>        Send no more than <n> messages from the queue.

EXAMPLES:
  Try to send all currently queued messages.
      %(cmd)s
""".strip()

def flushQueue(cmd, args):
    options, args = getopt.getopt(args, "hvf:n:",
             ["help", "verbose", "config=", "count="])
    count=None
    for o,v in options:
        if o in ('-n','--count'):
            try:
                count = int(v)
            except ValueError:
                print "ERROR: %s expects an integer" % o
                sys.exit(1)
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1)
    except UsageError, e:
        e.dump()
        print _FLUSH_QUEUE_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client

    client.flushQueue(count)


_LIST_QUEUE_USAGE = """\
Usage: %(cmd)s [options]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Describe the current contents of the queue.
      %(cmd)s
""".strip()

def listQueue(cmd, args):
    options, args = getopt.getopt(args, "hvf:",
                                  ["help", "verbose", "config=", ])
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1)
    except UsageError, e:
        e.dump()
        print _LIST_QUEUE_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client

    try:
        clientLock()
        client.queue.inspectQueue()
    finally:
        clientUnlock()
