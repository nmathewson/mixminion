# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ClientDirectory: Code to handle the 'client' side of
   dealing with mixminion directories.  This includes:
     - downloading and caching directories
     - path generation
     - address parsing.
"""

__all__ = [ 'ClientDirectory', 'parsePath', 'parseAddress',
            'DirectoryDownloadError', 'GotInvalidDirectoryError' ]

import cPickle
import errno
import operator
import os
import re
import socket
import stat
import threading
import time
import types
import rfc822
import urllib2

from httplib import HTTPException

import mixminion.Config
import mixminion.Crypto
import mixminion.NetUtils
import mixminion.ServerInfo

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     ceilDiv, createPrivateDir, formatDate, formatFnameTime, openUnique, \
     previousMidnight, readPickled, readPossiblyGzippedFile, \
     replaceFile, tryUnlink, writePickled, floorDiv, isSMTPMailbox
from mixminion.Packet import MBOX_TYPE, SMTP_TYPE, DROP_TYPE, FRAGMENT_TYPE, \
     parseMBOXInfo, parseRelayInfoByType, parseSMTPInfo, ParseError, \
     ServerSideFragmentedMessage
from mixminion.ThreadUtils import RWLock, DummyLock

# FFFF This should be made configurable and adjustable.
MIXMINION_DIRECTORY_URL = "http://mixminion.net/directory/Directory.gz"
MIXMINION_DIRECTORY_FINGERPRINT = "CD80DD1B8BE7CA2E13C928D57499992D56579CCD"
DEFAULT_REQUIRED_LIFETIME = 1

class DirectoryDownloadError(UIError):
    """Raised when we have any error when downloading the directory"""

class GotInvalidDirectoryError(DirectoryDownloadError):
    """Raised when we have downloaded an invalid directory."""

class _DescriptorSourceSharedState:
    """Holds data shared in common across several descriptor sources.
       Remembers which descriptors we've validated in the past, so we don't
       need to do public-key operations when we see a descriptor more than
       once.
    """
    ##Fields:
    # digestMap: A map from 20-byte descriptor digests to server descriptor
    #   expiry times.
    # _changed: True iff digestMap has been changed since we last loaded or
    #   saved.  (When saving, other classes set _changed to 0 for us.)

    # Used to identify version when pickling
    MAGIC = "DSSS-0.1"
    # How long do we hang on expired digests?
    EXPIRY_SLOPPINESS = 7200
    def __init__(self):
        """Create a new _DescriptorSourceSharedState"""
        self.digestMap = {}
        self._changed = 1
    def clean(self, now=None):
        """Forget about all descriptor digests that are expired."""
        if now is None:
            now = time.time()
        cutoff = now + self.EXPIRY_SLOPPINESS
        for k in self.digestMap.keys():
            if k > cutoff:
                del self.digestMap[k]
                self._changed = 1
    def hasChanged(self):
        """Return true iff this object has changd since we last loaded,
           or since we last explicitly set self._changed to false."""
        return self._changed
    def _addDigest(self,s):
        """Add the digest for the ServerInfo 's' to the set of validated
           descriptors.
        """
        d = s.getDigest()
        if not self.digestMap.has_key(d):
            self.digestMap[d] = s['Server']['Valid-Until']
            self._changed = 1
    def __getstate__(self):
        return self.MAGIC, self.digestMap
    def __setstate__(self,state):
        if (type(state) != types.TupleType or len(state)<1 or
            state[0] != self.MAGIC):
            LOG.warn("Uncognized state on picked DSSS; rebuilding.")
            self.digestMap = {}
            self._changed = 1
        else:
            self.digestMap = state[1]
            self._changed = 0

class DescriptorSource:
    """Abstract class for a container holding server descriptors.

       Note that DescriptorSources are managed by
       CachingDescriptorSource and loadCachingDescriptorSource below;
       subclasses should assume that they are called accordingly.
    """
    ## Fields:
    # _s: an instance of _DescriptorSourceSharedState
    # _changed: true iff there is information in this DescriptorSource that
    #   needs to be flushed to disk.
    def __init__(self):
        """Create a new DescriptorSource"""
        assert self.__class__ != DescriptorSource
        self._s = None
        self._changed = 0
    def hasChanged(self):
        """Return true iff self has information that needs to be
           flushed to disk"""
        return self._changed
    def getServerList(self):
        """Return a list of all ServerInfo objects in self."""
        raise NotImplemented()
    def getRecommendedNicknames(self):
        """Return a list of the nicknames of all 'recommended' ServerInfo
           objects in self."""
        return []
    def configure(self, config):
        """Configure self based on a client or server configuration in
           'config'. """
        pass
    def update(self, force=0, now=None, lock=None):
        """Retrieve any new information needed for this store, for
           example by downloading a fresh directory.  If 'force' is
           true, then update the information regardless of whether we
           think we need to.  If 'lock' is provided, use 'lock' to protect
           the critical sections of the update.
        """
        pass
    def rescan(self, force=0):
        """Update the state of self based on any local changes."""
        pass
    def clean(self, now=None):
        """Remove any out-of-date information from this object."""
        pass
    def save(self):
        """Flush any changes from this object to disk."""
        self._changed = 0
    def _setSharedState(self,state):
        """Helper: set the shared state for this object to 'state'."""
        self._s = state

class FSBackedDescriptorSource(DescriptorSource):
    """A FSBackedDescriptorStore holds a number of server descriptors in a
       filesystem, one per file.  All files are kept in a single directory,
       and are managed by the FSBackedDescriptorSource object.
    """
    ## Fields:
    # directory: the location for this store on the filesystem
    # servers: A map from filename within the directory to tuples of
    #     (file mtime, ServerInfo).
    MAGIC = "FBBDS-0.1"
    EXPIRY_SLOPPINESS = 7200
    def __init__(self, state):
        """Create a new FSBackedDescriptorSource"""
        DescriptorSource.__init__(self)
        self._setSharedState(state)
        self.directory = None
        self.servers = {}
        self._changed = 1
        self.rescan()

    def getServerList(self):
        return [ s for _,s in self.servers.values() ]

    def getRecommendedNicknames(self):
        # XXXX008 !!!! Major security implications here: are all the
        # descriptors on disk considered recommended?  Reconsider
        # this.
        return [ s.getNickname().lower() for _,s in self.servers.values() ]

    def configure(self, config):
        """Set up the directory where imported descriptors are stored."""
        self.directory = os.path.join(config.getDirectoryRoot(),
                                      "imported")
        createPrivateDir(self.directory)

    def rescan(self, force=0):
        """Scan all the files in the underlying directory.  If there are any
           new descriptors, or if any descriptors have changed, then
           rescan them.  If force is true, reload all descriptors no matter
           what.
        """
        if self.directory is None:
            return
        if force:
            self.servers = {}
            self._changed = 1

        fnames = {}
        # Rescan any files that are new, or that have changed.
        for fname in os.listdir(self.directory):
            fnames[fname] = 1
            fullname = os.path.join(self.directory, fname)
            try:
                mtime = long(os.stat(fullname)[stat.ST_MTIME])
            except OSError:
                LOG.warn("Unable to stat file %s", fullname)
                del self.servers[fname]
                continue
            if (self.servers.has_key(fname) and
                mtime >= self.servers[fname][0]):
                continue
            try:
                s = mixminion.ServerInfo.ServerInfo(
                    fname=fullname, assumeValid=0,
                    validatedDigests=self._s.digestMap)
            except mixminion.Config.ConfigError, e:
                LOG.warn("Invalid entry %s in %s: %s",
                         fname, self.directory, e)
                continue
            self.servers[fname] = (mtime, s)
            self._s._addDigest(s)
            self._changed = 1
        # Remove any servers whose files are missing.
        for fname in self.servers.keys():
            if not fnames.has_key(fname):
                del self.servers[fname]
                self._changed = 1

    def clean(self, now=None):
        """Remove all expired or superseded servers from the directory."""
        if now is None:
            now = time.time()
        cutoff = now + self.EXPIRY_SLOPPINESS
        removed = []
        byNickname = {}
        for _,s in self.servers.values():
            byNickname.setdefault(s.getNickname().lower(),[]).append(s)
        for fname, (_, s) in self.servers.items():
            expires = s['Server']['Valid-Until']
            if expires > cutoff:
                LOG.debug("Removing expired server %s",fname)
                removed.append(fname)
            elif s.isSupersededBy(byNickname[s.getNickname().lower()]):
                LOG.debug("Removing superseded server %s",fname)
                removed.append(fname)
        for fname in removed:
            del self.servers[fname]
            self._changed = 1
            self._removeOne(fname)

    def _removeOne(self, fname):
        """Helper: remove the file fname from the directory."""
        tryUnlink(os.path.join(self.directory, fname))

    def importFromFile(self, sourceFname):
        """Read and validate a descriptor stored in the possibly
           gzipped file 'sourceFName'.  If the descriptor is valid, and not
           already stored in this directory, and not superseded, then copy it
           in.  Does *not* remove any descriptors superseded by sourceFName.
        """
        contents = readPossiblyGzippedFile(sourceFname)
        try:
            s = mixminion.ServerInfo.ServerInfo(string=contents,assumeValid=0)
        except mixminion.Config.ConfigError, e:
            raise UIError("Invalid server descriptor: %s"%e)

        nameBase = "%s-%s" %(s.getNickname(),
                             formatFnameTime(s['Server']['Published']))

        if s.isExpiredAt(time.time()):
            raise UIError("Server descriptor is already expired")
        samenickname = [ sd for _,sd in self.servers.values() if
                         sd.getNickname().lower() == s.getNickname().lower()]
        for sd in samenickname:
            if not mixminion.Crypto.pk_same_public_key(s.getIdentity(),
                                                       sd.getIdentity()):
                raise MixError("Mismatched identity key for server")
        if s.isSupersededBy(samenickname):
            raise UIError("Server descriptor is already superseded")

        f, fname = openUnique(os.path.join(self.directory,nameBase))
        f.write(contents)
        f.close()
        shortname = os.path.split(fname)[1]
        self.servers[shortname] = (os.stat(fname)[stat.ST_MTIME], s)
        self._s._addDigest(s)
        self._changed = 1

    def expungeByNickname(self, nickname):
        """Remove all descriptors for the server 'nickname' from the directory.
        """
        badFnames = {}
        for fname, (_, sd) in self.servers.items():
            if sd.getNickname().lower() == nickname.lower():
                badFnames[fname]=1
        if not badFnames:
            return
        for fname in badFnames.keys():
            tryUnlink(os.path.join(self.directory, fname))
            del self.servers[fname]
        self._changed = 1

    def __getstate__(self):
        return self.MAGIC, self.servers

    def __setstate__(self,state):
        if (type(state) != types.TupleType or len(state)<1 or
            state[0] != self.MAGIC):
            LOG.warn("Unrecognized state on picked FSBDS; rebuilding.")
            self.servers = {}
            self._changed = 1
        else:
            self.servers = state[1]
            self._changed = 0

class DirectoryBackedDescriptorSource(DescriptorSource):
    """A DirectoryBakedDescriptorSource gets server descriptors by
        reading directories from directory servers, and caching them
        on disk.
    """
    ## Fields:
    # fnameBase: The name of the file where we'll store a cached directory.
    #   We may append '.gz' or '_new' or '_new.gz' as appropriate.
    # serverDir: An instance of mixminion.ServerInfo.ServerDirectory, or
    #   None.
    # lastDownload: When did we last download the directory?
    # __downloading: Boolean: are we currently downloading a new directory?
    # timeout: How long do we wait when trying to download?  A number
    #   of seconds, or None.
    MAGIC = "BDBS-0.1"
    def __init__(self, state):
        """Create a new DirectoryBackedDescriptorSource"""
        DescriptorSource.__init__(self)
        self._setSharedState(state)
        self.fnameBase = None
        self.serverDir = None
        self.lastDownload = 0
        self._changed = 1
        self.__downloading = 0
        self.timeout = None

    def getServerList(self):
        if self.serverDir is None:
            return []
        else:
            return self.serverDir.getAllServers()

    def getRecommendedNicknames(self):
        if self.serverDir is None:
            return []
        else:
            return self.serverDir.getRecommendedNicknames()

    def getRecommendedVersions(self):
        """Return a 2-tuple of the software versions recommended for clients
           and servers by the directory."""
        if self.serverDir == None:
            return [], []
        sec = self.serverDir['Recommended-Software']
        return (sec.get("MixminionClient",[]),
                sec.get("MixminionServer",[]))

    def configure(self, config):
        self.fnameBase = os.path.join(config.getDirectoryRoot(), "dir")
        createPrivateDir(config.getDirectoryRoot())
        timeout =config.get('DirectoryServers',{}).get('DirectoryTimeout',None)
        if timeout:
            self.timeout = int(timeout)
        else:
            self.timeout = None

    def rescan(self, force=0):
        if not self.fnameBase:
            return
        try:
            serverDir = None
            # Check "dir" and "dir.gz"
            for ext in "", ".gz":
                fname = self.fnameBase + ext
                if not os.path.exists(fname):
                    continue
                serverDir = mixminion.ServerInfo.parseDirectory(
                    fname=fname, validatedDigests=self._s.digestMap)
                lastDownload = os.stat(fname)[stat.ST_MTIME]
            if serverDir is None:
                return
            self.serverDir = serverDir
            self.lastDownload = lastDownload
        except mixminion.Config.ConfigError, e:
            LOG.warn("Found invalid cached directory; not using: %s",e)
            return
        for s in self.serverDir.getAllServers():
            self._s._addDigest(s)
        self._changed = 1

    def update(self, force=0, now=None, lock=None):
        self.updateDirectory(forceDownload=force,now=now,lock=lock)

    def updateDirectory(self, forceDownload=0, url=None,
                        now=None, lock=None):
        """Download a directory if necessary, or if 'forceDownload is true.

           Same behavior as self.update, except that you may configure
           a non-default URL.
        """
        if now is None:
            now = time.time()
        if url is None:
            url = MIXMINION_DIRECTORY_URL

        if (self.serverDir is None or forceDownload or
            self.lastDownload < previousMidnight(now)):
            self.downloadDirectory(url=url,lock=lock)
        else:
            LOG.debug("Directory is up to date.")

    def downloadDirectory(self, url=MIXMINION_DIRECTORY_URL,
                          lock=None):
        """Fetch a new directory."""
        if self.__downloading:
            LOG.info("Download already in progress")
            return
        self.__downloading = 1
        self._downloadDirectoryImpl(url,lock)
        self.__downloading = 0

    def _warnIfSkewed(self, dateHeader, expected=None):
        """We just fetched a directory and got 'dateHeader' as the
           Date header in the HTTP response.  Parse the date, and warn
           if the date is too far from what we believe the current
           time to be.
        """
        if expected is None:
            expected = time.time()
        try:
            parsedDate = rfc822.parsedate_tz(dateHeader)
        except ValueError:
            LOG.warn("Invalid date header from directory: %r",dateHeader)
            return
        if not parsedDate: return

        LOG.trace("Directory server said date is %r", dateHeader)
        skew = (expected - rfc822.mktime_tz(parsedDate))/60.0
        if abs(skew) > 30:
            LOG.warn("The directory said that the date is %r; we are skewed by %+d minutes",
                     dateHeader, skew)

    def _downloadDirectoryImpl(self, url, lock=None):
        """Helper function: does the actual work of fetching a directory."""
        LOG.info("Downloading directory from %s", url)
        # XXXX Refactor download logic.
        if self.timeout:
            mixminion.NetUtils.setGlobalTimeout(self.timeout)
        if lock is None:
            lock = RWLock()
        try:
            try:
                # Tell HTTP proxies and their ilk not to cache the directory.
                # Really, the directory server should set an Expires header
                # in its response, but that's harder.
                request = urllib2.Request(url,
                          headers={ 'Pragma' : 'no-cache',
                                    'Cache-Control' : 'no-cache', })
                startTime = time.time()
                infile = urllib2.urlopen(request)
            except IOError, e:
                #XXXX008 the "-D no" note makes no sense for servers.
                raise DirectoryDownloadError(
                    ("Couldn't connect to directory server: %s.\n"
                     "Try '-D no' to run without downloading a directory.")%e)
            except socket.error, e:
                if mixminion.NetUtils.exceptionIsTimeout(e):
                    raise DirectoryDownloadError(
                        "Connection to directory server timed out")
                else:
                    raise DirectoryDownloadError(
                        "Error connecting to directory server: %s"%e)
            except HTTPException, e:
                raise DirectoryDownloadError(
                    "HTTP exception downloading directory: %s"%e)
        finally:
            if self.timeout:
                mixminion.NetUtils.unsetGlobalTimeout()

        if url.endswith(".gz"):
            isGzipped = 1
            tmpname = self.fnameBase + "_new.gz"
        else:
            isGzipped = 0
            tmpname = self.fnameBase + "_new"

        # Open a temporary output file.
        outfile = open(tmpname, 'wb')

        # Read the file off the network.
        while 1:
            s = infile.read(1<<16)
            if not s: break
            outfile.write(s)
        # Close open connections.
        infile.close()
        outfile.close()

        dateHeader = infile.info().get("Date","")
        if dateHeader: self._warnIfSkewed(dateHeader, expected=startTime)

        # Open and validate the directory
        LOG.info("Validating directory")

        lock.read_in()
        digestMap = self._s.digestMap.copy()
        lock.read_out()

        try:
            directory = mixminion.ServerInfo.parseDirectory(
                fname=tmpname,
                validatedDigests=digestMap)
        except mixminion.Config.ConfigError, e:
            raise GotInvalidDirectoryError(
                "Received an invalid directory: %s"%e)

        if isinstance(directory, mixminion.ServerInfo.ServerDirectory):
            identity = directory['Signature']['DirectoryIdentity']
            fp = MIXMINION_DIRECTORY_FINGERPRINT #XXXX
            if fp and mixminion.Crypto.pk_fingerprint(identity) != fp:
                raise MixFatalError("Bad identity key on directory")
        else:
            #XXXX CHECK THAT SIGNATURES ARE WHAT WE EXPECT!!!!!!
            pass

        if isGzipped:
            replaceFile(tmpname, self.fnameBase+".gz")
            tryUnlink(self.fnameBase)
        else:
            replaceFile(tmpname, self.fnameBase)
            tryUnlink(self.fnameBase+".gz")

        lock.write_in()
        try:
            self.serverDir = directory
            self.lastDownload = time.time()
            self._changed = 1
            for s in self.serverDir.getAllServers():
                self._s._addDigest(s)
        finally:
            lock.write_out()

    def __getstate__(self):
        return self.MAGIC, self.lastDownload, self.serverDir

    def __setstate__(self,state):
        if (type(state) != types.TupleType or len(state)<1 or
            state[0] != self.MAGIC):
            LOG.warn("Unrecognized state on picked FSBDS; rebuilding.")
            self.serverDir = None
            self.lastDownload = 0
            self._changed = 1
        else:
            _, self.lastDownload, self.serverDir = state
            self._changed = 0
        self.__downloading = 0
        self.fnameBase = None
        self.timeout = None

class CachingDescriptorSource(DescriptorSource):
    """A CachingDescriptorSource aggregates several base DescriptorSources,
       combines their results, and handles caching their descriptors.

       Method calls to methods supported only by a single DescriptorSource
       are delegated to the appropriate object.
    """
    ##Fields:
    # bases: a list of DescriptorSource objects to delegate to.
    # cacheFile: filename to store our cache in.
    MAGIC = "CDS-0.1"
    def __init__(self,state):
        """Create a new CachingDescriptorSource."""
        DescriptorSource.__init__(self)
        self.bases = []
        self._setSharedState(state)
        self.cacheFile = None

    def getServerList(self):
        servers = []
        for b in self.bases:
            servers.extend(b.getServerList())
        return servers

    def getRecommendedNicknames(self):
        nicknames = []
        for b in self.bases:
            nicknames.extend(b.getRecommendedNicknames())
        return nicknames

    def configure(self,config):
        self.cacheFile = os.path.join(config.getDirectoryRoot(),
                                      "cache")
        createPrivateDir(config.getDirectoryRoot())
        for b in self.bases: b.configure(config)

    def _setSharedState(self,state):
        self._s = state
        for b in self.bases: b._setSharedState(state)

    def clean(self,now=None):
        for b in self.bases: b.clean(now)
        self._s.clean(now)

    def rescan(self,force=0):
        for b in self.bases:
            b.rescan(force)

    def update(self,force=0,now=None,lock=None):
        for b in self.bases: b.update(force=force,now=now,lock=lock)

    def addBase(self, b):
        if b not in self.bases:
            self.bases.append(b)
            b._setSharedState(self._s)

    def __getstate__(self):
        return self.MAGIC, self.bases, self._s

    def __setstate__(self,state):
        if (type(state) != types.TupleType or len(state)<1 or
            state[0] != self.MAGIC):
            LOG.warn("Unrecognized state on picked FSBDS; rebuilding.")
            self.bases = []
        else:
            self.bases = state[1]
            self._setSharedState(state[2])

    def hasChanged(self):
        if self._s.hasChanged():
            return 1
        for b in self.bases:
            if b.hasChanged():
                return 1
        return 0

    def save(self):
        if not self.hasChanged():
            return

        writePickled(self.cacheFile, self)

        for b in self.bases:
            b._changed = 0
        self._s._changed = 0

    def __getattr__(self, attr):
        candidate = None
        for b in self.bases:
            o = getattr(b,attr,None)
            if isinstance(o, types.MethodType):
                if candidate is None:
                    candidate = o
                else:
                    raise AttributeError("Too many options for %s"%attr)
        if candidate is None:
            raise AttributeError(attr)
        else:
            return candidate

def loadCachingDescriptorSource(config):
    """Return an instance of CachingDescriptorSource for our current
       configuration, loading it from disk as necessary.
    """
    if hasattr(config, 'isServerConfig') and config.isServerConfig():
        isServer = 1
    else:
        isServer = 0
    cacheFile = os.path.join(config.getDirectoryRoot(), "cache")

    try:
        store = readPickled(cacheFile)
        if isinstance(store, CachingDescriptorSource):
            store.configure(config)
            return store
        elif isinstance(store, types.TupleType):
            # changed to OO format in 0.0.8.
            LOG.info("Found out-of-date directory cache; rebuilding.")
        else:
            LOG.info("Found strange type in directory cache: %s.  Rebuilding",
                     type(store))
    except (OSError, IOError):
        LOG.info("Couldn't read directory cache; rebuilding")
    except (cPickle.UnpicklingError, ValueError), e:
        LOG.info("Couldn't unpickle directory cache: %s", e)

    LOG.info("Generating fresh directory cache...")

    state = _DescriptorSourceSharedState()
    store = CachingDescriptorSource(state)
    store.addBase(DirectoryBackedDescriptorSource(state))
    if not isServer:
        store.addBase(FSBackedDescriptorSource(state))
    store.configure(config)
    store.rescan(1)
    store.save()
    return store

class ClientDirectory:
    """Utility wrapper around a CachingDescriptorSource to handle common
       functionality such as server lookup, path generation, and so on.
    """
    ## Fields:
    # _lock: An instance of RWLock; protects all modifications to self or
    #    to the underlying sources.
    # _diskLock: A lock to protect all access to the disk.
    # store: An instance of DescriptorSource.
    ## Fields derived from self.source:
    # allServers: A list of all known server descriptors.
    # clientVersions, serverVersions: Lists of recommended software.
    # goodNicknames: a dict whose keys are all recommended
    #   nicknames. (lowercase)
    # goodServers: A list of all server descriptors whose nicknames
    #   are recommended.
    # byNickname: A map from lowercase nickname to a list of ServerInfo with
    #   that nickname.
    # byKeyID: A map from identity key digest to a list of ServerInfo for that
    #   server.
    # blockedNicknames: a map from lowercase nickname to a list of the purposes
    #   ('entry', 'exit', or '*') for which the corresponding server shouldn't
    #   be selected in automatic path generation.  Set by configure.
    def __init__(self, config=None, store=None, diskLock=None):
        self._lock = RWLock()
        if diskLock is None:
            self._diskLock = DummyLock()
        else:
            self._diskLock = diskLock
        if store:
            self.store = store
        elif config:
            self._diskLock.acquire()
            try:
                self.store = loadCachingDescriptorSource(config)
            finally:
                self._diskLock.release()
        if config:
            self.configure(config)
        self.__scan()

    def __scan(self):
        """Helper: update all fields derived from self.store.

           Must hold write lock if other threads can reach this object.
        """
        self.allServers = self.store.getServerList()
        self.clientVersions, self.serverVersions = \
                             self.store.getRecommendedVersions()
        self.goodNicknames = {}
        self.goodServers = []
        self.byNickname = {}
        self.byKeyID = {}
        for n in self.store.getRecommendedNicknames():
            assert n == n.lower()
            self.goodNicknames[n]=1
        for s in self.allServers:
            lcnickname = s.getNickname().lower()
            keydigest = s.getKeyDigest()
            self.byKeyID.setdefault(keydigest,[]).append(s)
            self.byNickname.setdefault(lcnickname,[]).append(s)
            if self.goodNicknames.has_key(lcnickname):
                self.goodServers.append(s)

    def flush(self):
        """Save any pending changes to disk, and update all derivative
           fields that would need to change.
        """
        self._diskLock.acquire()
        self._lock.write_in()
        try:
            if self.store.hasChanged():
                self.store.save()
                self.__scan()
        finally:
            self._lock.write_out()
            self._diskLock.release()

    def __scanAsNeeded(self):
        """Helper: if there are any changes in the underlying store, then
           flush them to disk.

           Callers should hold no locks; a little faster than just calling
           'flush'.
        """
        #XXXX008 some calls are probably needless.
        self._lock.read_in()
        try:
            if not self.store.hasChanged():
                return
        finally:
            self._lock.read_out()

        self.flush()

    def configure(self,config):
        """ """
        self._lock.write_in()
        try:
            self.store.configure(config)

            sec = config.get("Security", {})
            blocked = {}
            for lst in sec.get("BlockEntries", []):
                for nn in lst:
                    blocked.setdefault(nn.lower(),[]).append('entry')
            for lst in sec.get("BlockExits", []):
                for nn in lst:
                    blocked.setdefault(nn.lower(),[]).append('exit')
            for lst in sec.get("BlockServers", []):
                for nn in lst:
                    blocked[nn.lower()] = ['*']

            self.blockedNicknames = blocked
        finally:
            self._lock.write_out()

    def save(self):
        """Flush all changes to disk, whether we need to or not."""
        self._diskLock.acquire()
        self._lock.read_in()
        try:
            self.store.save()
        finally:
            self._lock.read_out()
            self._diskLock.release()

    def rescan(self,force=0):
        """Rescan the underlying source."""
        self._diskLock.acquire()
        self._lock.write_in()
        try:
            self.store.rescan(force)
        finally:
            self._lock.write_out()
            self._diskLock.release()
        self.__scanAsNeeded()

    def update(self, force=0, now=None):
        """Download a directory as needed."""
        self._diskLock.acquire()
        try:
            self.store.update(force=force,now=now,lock=self._lock)
        finally:
            self._diskLock.release()
        self.__scanAsNeeded()

    def clean(self, now=None):
        """Remove expired and superseded descriptors."""
        self._diskLock.acquire()
        self._lock.write_in()
        try:
            self.store.clean(now=None)
        finally:
            self._lock.write_out()
            self._diskLock.release()
        self.__scanAsNeeded()

    def importFromFile(self, sourceFname):
        """See FSBackedDescriptorSource.importFromFile"""
        self._diskLock.acquire()
        self._lock.write_in()
        try:
            fn = getattr(self.store, "importFromFile", None)
            if fn is None:
                raise MixFatalError("Attempted to import a server with no FS-backed store configured.")
            fn(sourceFname)
        finally:
            self._lock.write_out()
            self._diskLock.release()
        self.__scanAsNeeded()

    def expungeByNickname(self, nickname):
        """See FSBackedDescriptorSource.expungeByNickname"""
        self._diskLock.acquire()
        self._lock.write_in()
        try:
            fn = getattr(self.store, "expungeByNickname", None)
            if fn is None:
                raise MixFatalError("Attempted to expunge a server with no FS-backed store configured.")
            fn(nickname)
        finally:
            self._lock.write_out()
            self._diskLock.release()
        self.__scanAsNeeded()

    def getServerList(self):
        """Return a list of all known ServerInfo."""
        return self.allServers

    def getAllServers(self):
        """Return a list of all known ServerInfo."""
        return self.allServers

    def getAllNicknames(self):
        """Return a sorted list of all known nicknames."""
        lst = self.byNickname.keys()
        lst.sort()
        return lst

    def getRecommendedNicknames(self):
        """Return a list of sorted nicknames for all recommended servers."""
        lst = self.goodNicknames.keys()
        lst.sort()
        return lst

    def getServersByNickname(self, name):
        """Return a list of all ServerInfo for servers named 'name'"""
        try:
            return self.byNickname[name][:]
        except KeyError:
            return []

    def _installAsKeyIDResolver(self):
        """Use this ClientDirectory to identify servers in calls to
           ServerInfo.displayServer*.
        """
        mixminion.ServerInfo._keyIDToNicknameFn = self.getNicknameByKeyID
        mixminion.ServerInfo._addressToNicknameFn = self.getNicknameByAddress

    def getNicknameByAddress(self, addr):
        """Given an address (hostname) return the nickname of
           the server with that hostname.  Return None if no such
           server is known, and a slash-separated string if multiple
           servers are known.
        """
        #XXXX008 unit tests
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            nicknames = []
            for desc in self.allServers:
                if addr == desc.getHostname():
                    if desc.getNickname() not in nicknames:
                        nicknames.append(desc.getNickname())
            if nicknames:
                return "/".join(nicknames)
            else:
                return None
        finally:
            self._lock.read_out()

    def getNicknameByKeyID(self, keyid):
        """Given a keyid, return the nickname of the server with that
           keyid.  Return None if no such server is known, and a
           slash-separated string if multiple servers are known."""
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            s = self.byKeyID.get(keyid)
            if not s:
                return None
            r = []
            for desc in s:
                if desc.getNickname() not in r:
                    r.append(desc.getNickname())
            if r:
                return "/".join(r)
            else:
                return None
        finally:
            self._lock.read_out()

    def getKeyIDByNickname(self, nickname):
        """Given the nickname of the server, return the corresponding
           keyid, or None if the nickname is not recognized.
        """
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            s = self.byNickname.get(nickname.lower())
            if not s:
                return None
            return s[0].getKeyDigest()
        finally:
            self._lock.read_out()

    def getNameByRelay(self, routingType, routingInfo):
        """Given a routingType, routingInfo (as string) tuple, return the
           nickname of the corresponding server.  If no such server is
           known, return a string representation of the routingInfo.
        """
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            routingInfo = parseRelayInfoByType(routingType, routingInfo)
            nn = self.getNicknameByKeyID(routingInfo.keyinfo)
            if nn is None:
                return routingInfo.format()
            else:
                return nn
        finally:
            self._lock.read_out()

    def getFeatureMap(self, features, at=None, goodOnly=0):
        """Given a list of feature names (see Config.resolveFeatureName for
           more on features, returns a dict mapping server nicknames to maps
           from (valid-after,valid-until) tuples to maps from feature to
           value.

           That is: { nickname : { (time1,time2) : { feature : val } } }

           If 'at' is provided, use only server descriptors that are valid at
           the time 'at'.

           If 'goodOnly' is true, use only recommended servers.
        """
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            result = {}
            if not self.allServers:
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
            for sd in self.allServers:
                if at and not sd.isValidAt(at):
                    continue
                nickname = sd.getNickname()
                isGood = self.goodNicknames.get(nickname.lower(), 0)
                blocked = self.blockedNicknames.get(nickname.lower(), [])
                if goodOnly and not isGood:
                    continue
                va = sd['Server']['Valid-After']
                vu = sd['Server']['Valid-Until']
                d = result.setdefault(nickname, {}).setdefault((va,vu), {})
                for feature,(sec,ent) in resFeatures:
                    if sec == '+':
                        if ent == 'status':
                            stat = []
                            if not isGood:
                                stat.append("not recommended")
                            if '*' in blocked:
                                stat.append("blocked")
                            else:
                                if 'entry' in blocked:
                                    stat.append("blocked as entry")
                                if 'exit' in blocked:
                                    stat.append("blocked as exit")
                            if stat:
                                d['status'] = "(%s)"%(",".join(stat))
                            else:
                                d['status'] = "(ok)"
                        else:
                            raise AssertionError # Unreached.
                    else:
                        d[feature] = str(sd.getFeature(sec,ent))

            return result
        finally:
            self._lock.read_out()

    def __find(self, lst, startAt, endAt):
        """Helper method.  Given a list of ServerInfo, return all
           elements that are valid for all time between startAt and endAt.

           Only one element is returned for each nickname; if multiple
           elements with a given nickname are valid over the given time
           interval, the most-recently-published one is included.

           Caller must hold read lock.
        """
        # FFFF This is not really good: servers may be the same, even if
        # FFFF their nicknames are different.  The logic should probably
        # FFFF go into directory, though.

        u = {} # Map from lcnickname -> latest-expiring info encountered in lst
        for info in lst:
            if not info.isValidFrom(startAt, endAt):
                continue
            if not info.supportsPacketVersion():
                continue
            n = info.getNickname().lower()
            if u.has_key(n):
                if u[n].isNewerThan(info):
                    continue
            u[n] = info

        return u.values()

    def __nicknameIsBlocked(self, nn, isEntry=0, isExit=0):
        """Return true iff 'nn' is blocked.  By default, check for nicknames
           blocked in every position.  If isEntry is true, also check for
           nicknames blocked as entries; and if isExit is true, also check
           for nicknames blocked as exits.
        """
        # must hold lock
        b = self.blockedNicknames.get(nn.lower(), None)
        if b is None:
            return 0
        elif '*' in b:
            return 1
        elif isEntry and 'entry' in b:
            return 1
        elif isExit and 'exit' in b:
            return 1
        else:
            return 0

    def __excludeBlocked(self, lst, isEntry=0, isExit=0):
        """Given a list of ServerInfo, return a new list with all the
           blocked servers removed.  'isEntry' and 'isExit' are as for
           __nicknameIsBlocked.
        """
        # must hold lock
        res = []
        for info in lst:
            if not self.__nicknameIsBlocked(info.getNickname(),isEntry,isExit):
                res.append(info)
        return res

    def getLiveServers(self, startAt=None, endAt=None, isEntry=0, isExit=0):
        """Return a list of all server desthat are live from startAt through
           endAt.  The list is in the standard (ServerInfo,where) format,
           as returned by __find.  If 'isEntry' or 'isExit' is true, return
           servers suitable as entries or exits.  Exclude servers in
           the not-recommended or blocked lists.
           DOCDOC
        """
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = time.time() + DEFAULT_REQUIRED_LIFETIME
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            return self.__excludeBlocked(
                self.__find(self.goodServers, startAt, endAt),
                isEntry=isEntry, isExit=isExit)
        finally:
            self._lock.read_out()

    def getServerInfo(self, name, startAt=None, endAt=None, strict=0):
        """Return the most-recently-published ServerInfo for a given
           'name' valid over a given time range.  If not strict, and no
           such server is found, return None.

           name -- A ServerInfo object, a nickname, or a filename.
        """
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + DEFAULT_REQUIRED_LIFETIME

        if isinstance(name, mixminion.ServerInfo.ServerInfo):
            # If it's a valid ServerInfo, we're done.
            if name.isValidFrom(startAt, endAt):
                return name
            else:
                LOG.debug("Time-invalid descriptor for %s, looking for another one.", name.getNickname())
                name=name.getNickname()

        self.__scanAsNeeded()
        # If it's a nickname, return a serverinfo with that name.
        self._lock.read_in()
        try:
            lst = self.byNickname.get(name.lower())
        finally:
            self._lock.read_out()

        if lst is not None:
            sds = self.__find(lst, startAt, endAt)
            if strict and not sds:
                raise UIError(
                    "Couldn't find any currently live descriptor with name %s"
                    % name)
            elif not sds:
                return None
            return sds[0]
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
        """Generate a list of paths for delivering packets to a given
           exit address, using a given path spec.  Each path is returned
           as a tuple of lists of ServerInfo.

                nPaths -- the number of paths to generate.  (You need
                   to generate multiple paths at once when you want them
                   to converge at the same exit server -- for example,
                   for delivering server-side fragmented messages.)
                pathSpec -- A PathSpecifier object.
                exitAddress -- An ExitAddress object.
                startAt, endAt -- A duration of time over which the
                   paths must remain valid.
        """
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            return self._generatePaths(nPaths, pathSpec, exitAddress,
                                       startAt, endAt, prng)
        finally:
            self._lock.read_out()

    def _generatePaths(self, nPaths, pathSpec, exitAddress,
                       startAt=None, endAt=None,
                       prng=None):
        """Helper: implement generatePaths, without getting lock"""
        assert pathSpec.isReply == exitAddress.isReply

        if prng is None:
            prng = mixminion.Crypto.getCommonPRNG()

        path1, path2 = pathSpec.path1[:], pathSpec.path2[:]

        paths = []
        lastHop = exitAddress.getLastHop()
        if lastHop:
            plausibleExits = []
            if path2 and path2[-1]:
                fixed = path2[-1].getFixedServer(self, startAt,endAt)
                if fixed and fixed.getNickname().lower() == lastHop.lower():
                    lastHop = None
            if lastHop:
                path2.append(ServerPathElement(lastHop))
        else:
            plausibleExits = exitAddress.getExitServers(self,startAt,endAt)
            if exitAddress.isSSFragmented:
                # We _must_ have a single common last hop.
                plausibleExits = [ prng.pick(plausibleExits) ]

        for _ in xrange(nPaths):
            p1 = []
            p2 = []
            for p in path1:
                p1.extend(p.getServerNames())
            for p in path2:
                p2.extend(p.getServerNames())

            p = p1+p2
            # Make the exit hop _not_ be None; deal with getPath brokenness.
            #XXXX refactor this.
            if p[-1] == None and not exitAddress.isReply:
                assert not lastHop
                p[-1] = prng.pick(plausibleExits)

            if pathSpec.lateSplit:
                n1 = ceilDiv(len(p),2)
            else:
                n1 = len(p1)

            # Make sure that we always have at least one server in each
            # subpath that we use.  (Duh.)
            if n1 == 0 and not pathSpec.isSURB:
                n1 = 1
                p.insert(0, None)
            if n1 >= len(p) and not pathSpec.isReply:
                p.insert(n1, None)

            result = self._getPath(p, startAt=startAt, endAt=endAt)
            r1,r2 = result[:n1], result[n1:]
            paths.append( (r1,r2) )
            if pathSpec.isReply or pathSpec.isSURB:
                LOG.info("Selected path is %s",
                         ",".join([s.getNickname() for s in result]))
            else:
                LOG.info("Selected path is %s:%s",
                         ",".join([s.getNickname() for s in r1]),
                         ",".join([s.getNickname() for s in r2]))

        return paths

    def getPath(self, template, startAt=None, endAt=None, prng=None):
        """Workhorse method for path selection.  Given a template, return
           a list of serverinfos that 'matches' the template, and whose
           last node provides exitCap.

           The template is a list of either: strings or serverinfos as
           expected by 'getServerInfo'; or None to indicate that
           getPath should select a corresponding server.

           All servers are chosen to be valid continuously from
           startAt to endAt.

           The path selection algorithm is described in path-spec.txxt
        """
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            return self._getPath(template, startAt, endAt, prng)
        finally:
            self._lock.read_out()

    def _getPath(self, template, startAt=None, endAt=None, prng=None):
        """Helper: implement getPath, without getting lock"""
        # Fill in startAt, endAt, prng if not provided
        if startAt is None:
            startAt = time.time()
        if endAt is None:
            endAt = startAt + DEFAULT_REQUIRED_LIFETIME
        if prng is None:
            prng = mixminion.Crypto.getCommonPRNG()

        # Resolve explicitly-provided servers (we already warned.)
        servers = []
        for name in template:
            if name is None:
                servers.append(name)
            else:
                servers.append(self.getServerInfo(name, startAt, endAt, 1))

        # Now figure out which relays we haven't used yet.
        relays = self.__find(self.goodServers, startAt, endAt)
        relays = self.__excludeBlocked(relays)
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
                # Skip blocked entry points
                if i==0 and self.__nicknameIsBlocked(c.getNickname(),
                                                     isEntry=1):
                    continue
                # Skip blocked exit points
                if i==(len(servers)-1) and self.__nicknameIsBlocked(
                    c.getNickname(), isExit=1):
                    continue
                # Avoid same-server hops
                if ((prev and c.hasSameNicknameAs(prev)) or
                    (next and c.hasSameNicknameAs(next))):
                    continue
                # Avoid hops that can't relay to one another.
                if ((prev and not prev.canRelayTo(c)) or
                    (next and not c.canRelayTo(next))):
                    continue
                # Avoid first hops that we can't deliver to.
                if (not prev) and not c.canStartAt():
                    continue
                candidates.append(c)
            if candidates:
                # Good.  There are some okay servers.
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

    def validatePath(self, pathSpec, exitAddress, startAt=None, endAt=None,
                     warnUnrecommended=1):
        """Given a PathSpecifier and an ExitAddress, check whether any
           valid paths can satisfy the spec for delivery to the address.
           Raise UIError if no such path exists; else returns.

           If warnUnrecommended is true, give a warning if the user has
           requested any unrecommended servers.
           """
        self.__scanAsNeeded()
        self._lock.read_in()
        try:
            return self._validatePath(pathSpec, exitAddress, startAt, endAt,
                                      warnUnrecommended)
        finally:
            self._lock.read_out()

    def _validatePath(self, pathSpec, exitAddress, startAt=None, endAt=None,
                     warnUnrecommended=1):
        """Helper: implement validatePath without getting lock"""
        if startAt is None: startAt = time.time()
        if endAt is None: endAt = startAt+DEFAULT_REQUIRED_LIFETIME

        p = pathSpec.path1+pathSpec.path2
        assert p
        # Make sure all elements are valid.
        for e in p:
            e.validate(self, startAt, endAt)

        # If there is a 1st element, make sure we can route to it.
        fixed = p[0].getFixedServer(self, startAt, endAt)
        if fixed and not fixed.canStartAt():
            raise UIError("Cannot relay messages to %s"%fixed.getNickname())

        # When there are 2 elements in a row, make sure each can route to
        # the next.
        prevFixed = None
        for e in p:
            fixed = e.getFixedServer(self, startAt, endAt)
            if fixed and not fixed.supportsPacketVersion():
                raise UIError("We don't support any packet formats used by %s",
                              fixed.getNickname())
            if prevFixed and fixed and not prevFixed.canRelayTo(fixed):
                raise UIError("Server %s can't relay to %s" %
                              prevFixed.getNickname(), fixed.getNickname())
            prevFixed = fixed

        fs = p[-1].getFixedServer(self,startAt,endAt)
        lh = exitAddress.getLastHop()
        if lh is not None:
            lh_s = self.getServerInfo(lh, startAt, endAt)
            if lh_s is None:
                raise UIError("No known server descriptor named %s" % lh)
            if fs and not fs.canRelayTo(lh_s):
                raise UIError("Server %s can't relay to %s" %(
                              fs.getNickname(), lh))
            fs = lh_s
        if fs is not None:
            exitAddress.checkSupportedByServer(fs)
        elif exitAddress.isServerRelative():
            raise UIError("%s exit type expects a fixed exit server." %
                          exitAddress.getPrettyExitType())

        if fs is None and lh is None:
            for desc in self.getLiveServers(startAt, endAt, isExit=1):
                if exitAddress.isSupportedByServer(desc):
                    break
            else:
                raise UIError("No recommended server supports delivery type.")

        # Check for unrecommended servers
        if not warnUnrecommended:
            return
        warned = {}
        for i in xrange(len(p)):
            e = p[i]
            fixed = e.getFixedServer(self, startAt, endAt)
            if not fixed: continue
            nick = fixed.getNickname()
            lc_nickname = nick.lower()
            if warned.has_key(lc_nickname):
                continue
            if not self.goodNicknames.has_key(lc_nickname):
                warned[lc_nickname] = 1
                LOG.warn("Server %s is not recommended", nick)
            b = self.blockedNicknames.get(lc_nickname,None)
            if not b: continue
            if '*' in b:
                warned[lc_nickname] = 1
                LOG.warn("Server %s is blocked", nick)
            else:
                if i == 0 and 'entry' in b:
                    warned[lc_nickname] = 1
                    LOG.warn("Server %s is blocked as an entry", nick)
                elif i==(len(p)-1) and 'exit' in b:
                    warned[lc_nickname] = 1
                    LOG.warn("Server %s is blocked as an exit", nick)

    def checkSoftwareVersion(self,client=1):
        """Check the current client's version against the stated version in
           the most recently downloaded directory; log a warning if this
           version isn't listed as recommended.
           """
        self._lock.read_in()
        try:
            if client:
                allowed = self.clientVersions
            else:
                allowed = self.serverVersions
        finally:
            self._lock.read_out()

        if not allowed: return

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
def compressFeatureMap(featureMap, ignoreGaps=0, terse=0):
    """Given a feature map as returned by ClientDirectory.getFeatureMap,
       compress the data from each server's server descriptors.  The
       default behavior is:  if a server has two server descriptors such
       that one becomes valid immediately after the other becomes invalid,
       and they have the same features, compress the two entries into one.

       If ignoreGaps is true, the requirement for sequential lifetimes is
       omitted.

       If terse is true, server descriptors are compressed even if their
       features don't match.  If a feature has different values at different
       times, they are concatenated with ' / '.
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
            if (ignoreGaps or lastva <= va <= lastvu) and lastfeatures == features:
                r[-1] = lastva, vu, features
            else:
                r.append((va,vu,features))
        result[nickname] = {}
        for va,vu,features in r:
            result[nickname][(va,vu)] = features

        if not terse: continue
        if not result[nickname]: continue

        ritems = result[nickname].items()
        ritems.sort()
        minva = min([ va for (va,vu),features in ritems ])
        maxvu = max([ vu for (va,vu),features in ritems ])
        rfeatures = {}
        for (va,vu),features in ritems:
            for f,val in features.items():
                if rfeatures.setdefault(f,val) != val:
                    rfeatures[f] += " / %s"%val
        result[nickname] = { (minva,maxvu) : rfeatures }

    return result

def formatFeatureMap(features, featureMap, showTime=0, cascade=0, sep=" ",
                     just=0):
    """Given a list of features (by name; see Config.resolveFeatureName) and
       a featureMap as returned by ClientDirectory.getFeatureMap or
       compressFeatureMap, formats the map for display to an end users.
       Returns a list of strings suitable for printing on separate lines.

       If 'showTime' is false, omit descriptor validity times from the
       output.

       'cascade' is an integer between 0 and 2.  Its values generate the
       following output formats:
           0 -- Put nickname, time, and feature values on one line.
                If there are multiple times for a given nickname,
                generate multiple lines.  This format is best for grep.
           1 -- Put nickname on its own line; put time and feature lists
                one per line.
           2 -- Put nickname, time, and each feature value on its own line.

       'sep' is used to concatenate feauture values when putting them on
       the same line.

       If 'just' is true, we left-justify features in columns.
    """
    nicknames = [ (nn.lower(), nn) for nn in featureMap.keys() ]
    nicknames.sort()
    lines = []
    if not nicknames: return lines

    if just:
        maxnicklen = max([len(nn) for nn in featureMap.keys()])
        nnformat = "%-"+str(maxnicklen)+"s"
        maxFeatureLength = {}
        for f in features: maxFeatureLength[f] = 0
        for byTime in featureMap.values():
            for fMap in byTime.values():
                for k, v in fMap.items():
                    if maxFeatureLength[k] < len(v):
                        maxFeatureLength[k] = len(v)
        formatEntries = [ "%-"+str(maxFeatureLength[f])+"s" for
                          f in features ]
        format = sep.join(formatEntries)
    else:
        nnformat = "%s"
        format = sep.join(["%s"]*len(features))

    for _, nickname in nicknames:
        d = featureMap[nickname]
        if not d: continue
        items = d.items()
        items.sort()
        if cascade: lines.append("%s:"%nickname)
        for (va,vu),fmap in items:
            ftime = "%s to %s"%(formatDate(va),formatDate(vu))
            fvals = tuple([fmap[f] for f in features])
            if cascade==1:
                lines.append("  [%s] %s"%(ftime, format%fvals))
            elif cascade==2:
                if showTime:
                    lines.append("  [%s]"%ftime)
                for f in features:
                    v = fmap[f]
                    lines.append("    %s:%s"%(f,v))
            elif showTime:
                lines.append("%s:%s:%s" %(nnformat%nickname,ftime,
                                          format%fvals))
            else:
                lines.append("%s:%s" %(nnformat%nickname,format%fvals))
    return lines

#----------------------------------------------------------------------

# What exit type names do we know about?
KNOWN_STRING_EXIT_TYPES = [
    "mbox", "smtp", "drop"
]

# Map from (type, nickname) to 1 for servers we've already warned about.
WARN_HISTORY = {}

class ExitAddress:
    """An ExitAddress represents the target of a Mixminion message or SURB.
       It also encodes other properties off the message that must be known to
       choose the exit hop (including fragmentation and message size).
    """
    ## Fields:
    # exitType, exitAddress: None (for a reply message), or the delivery
    #     routing type and routing info for the address.
    # isReply: boolean: is target address a SURB or set of SURBs?
    # lastHop: None, or the nickname of a server that must be used as the
    #     last hop of the path.
    # isSSFragmented: boolean: Is the message going to be fragmented and
    #     reassembled at the exit server?
    # nFragments: How many fragments are going to be assembled at the exit
    #     server?
    # exitSize: How large (in bytes) will the message be at the exit server?
    # headers: A map from header name to value.
    def __init__(self,exitType=None,exitAddress=None,lastHop=None,isReply=0,
                 isSSFragmented=0):
        """Create a new ExitAddress.
            exitType,exitAddress -- the routing type and routing info
               for the delivery (if not a reply)
            lastHop -- the nickname of the last hop in the path, if the
               exit address is specific to a single hop.
            isReply -- true iff this message is a reply
            isSSFragmented -- true iff this message is fragmented for
               server-side reassembly.
        """
        #FFFF Perhaps this crams too much into ExitAddress.
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
        elif exitType is not None:
            raise UIError("Unknown exit type: %r"%exitType)
        self.exitType = exitType
        self.exitAddress = exitAddress
        self.lastHop = lastHop
        self.isReply = isReply
        self.isSSFragmented = isSSFragmented #server-side frag reassembly only.
        self.nFragments = self.exitSize = 0
        self.headers = {}
    def getFragmentedMessagePrefix(self):
        """Return the prefix to be prepended to server-side fragmented
           messages"""
        routingType, routingInfo, _ = self.getRouting()
        return ServerSideFragmentedMessage(routingType, routingInfo, "").pack()

    def setFragmented(self, isSSFragmented, nFragments):
        """Set the fragmentation parameters of this exit address
        """
        self.isSSFragmented = isSSFragmented
        self.nFragments = nFragments
    def hasPayload(self):
        """Return true iff this exit type requires a payload"""
        return self.exitType not in ('drop', DROP_TYPE)
    def setExitSize(self, exitSize):
        """Set the size of the message at the exit."""
        self.exitSize = exitSize
    def setHeaders(self, headers):
        """Set the headers of the message at the exit."""
        self.headers = headers
    def getLastHop(self):
        """Return the forced last hop of this exit address (or None)"""
        return self.lastHop
    def isSupportedByServer(self, desc):
        """Return true iff the server described by 'desc' supports this
           exit type.
        """
        try:
            self.checkSupportedByServer(desc,verbose=0)
            return 1
        except UIError:
            return 0
    def checkSupportedByServer(self, desc,verbose=1):
        """Check whether the server described by 'desc' supports this
           exit type. Returns if yes, raises a UIError if no.  If
           'verbose' is true, give warnings for iffy cases.
        """

        if self.isReply:
            return
        nickname = desc.getNickname()

        if self.headers:
            #XXXX007 remove this eventually, once all servers have upgraded
            #XXXX007 to 0.0.6 or later.
            sware = desc['Server'].get("Software","")
            if (sware.startswith("Mixminion 0.0.4") or
                sware.startswith("Mixminion 0.0.5alpha1")):
                raise UIError("Server %s is running old software that doesn't support exit headers."% nickname)

        exitKB = ceilDiv(self.exitSize, 1024)

        if self.isSSFragmented:
            dfsec = desc['Delivery/Fragmented']
            if not dfsec.get("Version"):
                raise UIError("Server %s doesn't support fragment reassembly."
                              %nickname)
            if self.nFragments > dfsec.get("Maximum-Fragments",0):
                raise UIError("Too many fragments for server %s to reassemble."
                              %nickname)
        else:
            # If we're not asking the server to defrag, we only need 32K
            if exitKB > 32:
                exitKB = 32

        needFrom = self.headers.has_key("FROM")

        if self.exitType in ('smtp', SMTP_TYPE):
            ssec = desc['Delivery/SMTP']
            if not ssec.get("Version"):
                raise UIError("Server %s doesn't support SMTP"%nickname)
            if needFrom and not ssec['Allow-From']:
                raise UIError("Server %s doesn't support user-supplied From"%
                              nickname)
            if exitKB > ssec['Maximum-Size']:
                raise UIError("Message to long for server %s to deliver."%
                              nickname)
        elif self.exitType in ('mbox', MBOX_TYPE):
            msec = desc['Delivery/MBOX']
            if not msec.get("Version"):
                raise UIError("Server %s doesn't support MBOX"%nickname)
            if needFrom and not msec['Allow-From']:
                raise UIError("Server %s doesn't support user-supplied From"%
                              nickname)
            if exitKB > msec['Maximum-Size']:
                raise UIError("Message to long for server %s to deliver."%
                              nickname)
        elif self.exitType in ('drop', DROP_TYPE):
            # everybody supports 'drop'.
            pass
        else:
            if not verbose: return
            if WARN_HISTORY.has_key((self.exitType, nickname)):
                return
            LOG.warn("No way to tell if server %s supports exit type %s.",
                     nickname, self.getPrettyExitType())
            WARN_HISTORY[(self.exitType, nickname)] = 1

    def getPrettyExitType(self):
        """Return a human-readable representation of the exit type."""
        if type(self.exitType) == types.IntType:
            return "0x%04X"%self.exitType
        else:
            return self.exitType

    def isServerRelative(self):
        """Return true iff the exit type's addresses are specific to a
           given exit hop.
        """
        return self.exitType in ('mbox', MBOX_TYPE)

    def getExitServers(self, directory, startAt=None, endAt=None):
        """Given a ClientDirectory and a time range, return a list of
           server descriptors for all servers that might work for this
           exit address.
        """
        assert self.lastHop is None
        liveServers = directory.getLiveServers(startAt, endAt, isExit=1)
        result = [ desc for desc in liveServers
                   if self.isSupportedByServer(desc) and
                      desc.supportsPacketVersion() ]
        return result

    def getRouting(self):
        """Return a routingType, routingInfo, last-hop-nickname tuple for
           this exit address.
        """
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

    def suppressTag(self):
        """Return true iff we should suppress the decoding handle when
           generating packets for this address.
        """
        if self.isSSFragmented:
            return 1
        elif self.exitType == 'drop':
            return 1
        else:
            return 0

def parseAddress(s):
    """Parse and validate an address; takes a string, and returns an
       ExitAddress object.

       Accepts strings of the format:
              mbox:<mailboxname>@<server>
           OR smtp:<email address>
           OR <email address> (smtp is implicit)
           OR drop
           OR 0x<routing type>:<routing info>
           OR 0x<routing type>
    """
    if s.lower() == 'drop':
        return ExitAddress('drop',"")
    elif s.lower() == 'test':
        return ExitAddress(0xFFFE, "")
    elif s.startswith("0x") or s.startswith("0X"):
        # Address of the form 0xABCD and 0xABCD:address
        if len(s) < 6 or (len(s)>=7 and s[6] != ':'):
            raise ParseError("Invalid address %r"%s)
        try:
            tp = int(s[2:6],16)
        except ValueError:
            raise ParseError("Invalid hexidecimal value %r"%s[2:6])
        if not (0x0000 <= tp <= 0xFFFF):
            raise ParseError("Invalid type: 0x%04x"%tp)
        return ExitAddress(tp, s[7:])
    elif ':' not in s:
        if isSMTPMailbox(s):
            return ExitAddress('smtp', s)
        else:
            raise ParseError("Can't parse address %s"%s)
    tp,val = s.split(':', 1)
    tp = tp.lower()
    if tp == 'mbox':
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
    """A PathElement is a single user-specified component of a path. This
       is an abstract class; it's only used to describe the interface.
    """
    def validate(self, directory, start, end):
        """Check whether this path element could be valid; if not, raise
           UIError."""
        raise NotImplemented()
    def getFixedServer(self, directory, start, end):
        """If this element describes a single fixed server, look up
           and return the ServerInfo for that server."""
        raise NotImplemented()
    def getServerNames(self):
        """Return a list containing either names of servers for this
           path element, or None for randomly chosen servers.
        """
        raise NotImplemented()
    def getMinLength(self):
        """Return the fewest number of servers that this element might
           contain."""
        raise NotImplemented()
    def getAvgLength(self):
        """Return the likeliest number of servers for this element to
           contain."""
        return self.getMinLength()

class ServerPathElement(PathElement):
    """A path element for a single server specified by filename or nickname
    """
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
    def __str__(self):
        return self.nickname

class DescriptorPathElement(PathElement):
    """A path element for a single server descriptor"""
    def __init__(self, desc):
        self.desc = desc
    def validate(self, directory, start, end):
        if not self.desc.isValidFrom(start, end):
            raise UIError("Server %r is not valid during given time range" %
                           self.desc.getNickname())
    def getFixedServer(self, directory, start, end):
        return self.desc
    def getServerNames(self):
        return [ self.desc ]
    def getMinLength(self):
        return 1
    def __repr__(self):
        return "DescriptorPathElement(%r)"%self.desc
    def __str__(self):
        return self.desc.getNickname()

class RandomServersPathElement(PathElement):
    """A path element for randomly chosen servers.  If 'n' is set, exactly
       n servers are chosen.  If 'approx' is set, approximately 'approx'
       servers are chosen.
    """
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
            if n < 0: n = 0
        return [ None ] * n
    def getMinLength(self):
        if self.n is not None:
            return self.n
        else:
            return 1
    def getAvgLength(self):
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
    def __str__(self):
        if self.n is None:
            assert self.approx
            return "~%d"%self.approx
        elif self.n == 1:
            return "?"
        else:
            return "*%d"%self.n

#----------------------------------------------------------------------
class PathSpecifier:
    """A PathSpecifer represents a user-provided description of a path.
       It's generated by parsePath.
    """
    ## Fields:
    # path1, path2: Two lists containing PathElements for the two
    #     legs of the path.
    # isReply: boolean: Is this a path for a reply? (If so, path2
    #     should be empty.)
    # isSURB: boolean: Is this a path for a SURB? (If so, path1
    #     should be empty.)
    # lateSplit: boolean: Does the path have an explicit swap point,
    #     or do we split it in two _after_ generating it?
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
        """If there is a fixed exit server on the path, return a descriptor
           for it; else return None."""
        if self.path2:
            return self.path2[-1].getFixedServer(directory,startAt,endAt)
        else:
            return None

    def __str__(self):
        p1s = map(str,self.path1)
        p2s = map(str,self.path2)
        if self.isSURB or self.isReply or self.lateSplit:
            return ",".join(p1s+p2s)
        else:
            return "%s:%s"%(",".join(p1s), ",".join(p2s))

#----------------------------------------------------------------------
def parsePath(config, path, isReply=0, isSURB=0):
    """Resolve a path as specified on the command line.  Returns a
       PathSpecifier object.

       config -- unused for now.
       path -- the path, in a format described below.
       startAt/endAt -- A time range during which all servers must be valid.
       isReply -- Boolean: is this a path for a reply?
       isSURB -- Boolean: is this a path for a reply block?

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
       where randomly-selected servers will be added:  {DEPRECATED}
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
    # Break path into a list of entries of the form:
    #        string
    #     or "<swap>"
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

    # Convert each parsed entry into a PathElement, or the string
    # '*', or the string '<swap>'.
    pathEntries = []
    for ent in p:
        if re.match(r'\*(\d+)', ent):
            pathEntries.append(RandomServersPathElement(n=int(ent[1:])))
        elif re.match(r'\~(\d+)', ent):
            pathEntries.append(RandomServersPathElement(approx=int(ent[1:])))
        elif ent == '*':
            #XXXX008 remove entirely; we gave a warning in 0.0.6 and
            #XXXX008 stopped supporting it in 0.0.7.
            raise UIError("* without a number is no longer supported.")
        elif ent == '<swap>':
            pathEntries.append("<swap>")
        elif ent == '?':
            pathEntries.append(RandomServersPathElement(n=1))
        else:
            pathEntries.append(ServerPathElement(ent))

    # Figure out how long the first leg should be.
    lateSplit = 0
    if "<swap>" in pathEntries:
        # We got a colon...
        if halfPath:
            # ...in a reply or SURB. That's an error.
            raise UIError("Can't specify swap point with replies")
        # Divide the path at the '<swap>'.
        colonPos = pathEntries.index("<swap>")
        if "<swap>" in pathEntries[colonPos+1:]:
            raise UIError("Only one ':' is permitted in a single path")
        firstLegLen = colonPos
        del pathEntries[colonPos]
    elif isReply:
        # A reply message is all first leg.
        firstLegLen = len(pathEntries)
    elif isSURB:
        # A SURB is all second-leg.
        firstLegLen = 0
    else:
        # We have no explicit swap point, but we have a foward message.  Thus,
        # we set 'lateSplit' so that we'll know to divide the path into two
        # legs later on.
        firstLegLen = 0
        lateSplit = 1

    # This is a kludge to convert paths of the form ~N to ?,~(N-1), when
    # we're generating a two-legged path.  Otherwise, there is a possibility
    # that ~N could expand into only a single server, thus leaving one leg
    # empty.
    if (len(pathEntries) == 1
        and not halfPath
        and isinstance(pathEntries[0], RandomServersPathElement)
        and pathEntries[0].approx):
        n_minus_1 = max(pathEntries[0].approx-1,0)
        pathEntries = [ RandomServersPathElement(n=1),
                        RandomServersPathElement(approx=n_minus_1) ]
        assert lateSplit

    path1, path2 = pathEntries[:firstLegLen], pathEntries[firstLegLen:]

    # Die if the path is too short, or if either leg is empty in a full path.
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
