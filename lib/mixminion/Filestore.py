# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Filestore.py,v 1.6 2003/08/17 21:09:56 nickm Exp $

"""mixminion.Filestore

   Common code for directory-based, security conscious, threadsafe
   unordered file stores.  Also contains common code for journalable
   DB-backed threadsafe stores.
   """

# Formerly, this was all in mixminion.server.ServerQueue.  But
# ClientMain had already grown a minimal version for client file
# queues, and we needed another for fragment stores anyway.  So it was
# time to refactor the common code.

import anydbm
import binascii
import cPickle
import dumbdbm
import errno
import os
import stat
import threading
import time

from mixminion.Common import MixFatalError, secureDelete, LOG, \
     createPrivateDir, readFile, tryUnlink
from mixminion.Crypto import getCommonPRNG

__all__ = [ "StringStore", "StringMetadataStore",
            "ObjectStore", "ObjectMetadataStore", 
            "MixedStore", "MixedMetadataStore",
            "DBBase", "JournaledDBBase", "BooleanJournaledDBBase"
            ]


# ======================================================================
# Filestores.

# Mode to pass to open(2) for creating a new file, and dying if it already
# exists.
_NEW_FILE_FLAGS = os.O_WRONLY+os.O_CREAT+os.O_EXCL
# On windows or (old-school) mac, binary != text.
_NEW_FILE_FLAGS += getattr(os, 'O_BINARY', 0)

# Any inp_* files older than INPUT_TIMEOUT seconds old are assumed to be
# trash.
INPUT_TIMEOUT = 6000

class BaseStore:
    """A BaseStore is an unordered collection of files with secure insert,
       move, and delete operations.

       This class is not for direct use; combine it with one of the
       mixin classes below.
       
       Abstractly, a BaseStore is a consistent collection of 'things'
       with (optional) persistant metadata.  The 'things' support
       insert, move, and delete operations.  The metadata supports
       modification.
       
       Implementation: a BaseStore is a directory of 'message' files.
       Each filename in the directory has a name in one of the
       following formats:
             rmv_HANDLE  (A message waiting to be deleted)
             msg_HANDLE  (A message waiting in the queue.
             inp_HANDLE  (An incomplete message being created.)
       (Where HANDLE is a randomly chosen 8-character string of characters
       chosen from 'A-Za-z0-9+-'.  [Collision probability is negligible, and
       collisions are detected.])

       If metadata is present, is has a names with the analogous
             rmvm_HANDLE
             meta_HANDLE
             inpm_HANDLE
 
       Threading notes:  Although BaseStore itself is threadsafe, you'll want
       to synchronize around any multistep operations that you want to
       run atomically.  Use BaseStore.lock() and BaseStore.unlock() for this.

       In the Mixminion server, no queue currently has more than one producer
       or more than one consumer ... so synchronization turns out to be
       fairly easy.
       """

    # Fields:   dir--the location of the file store.
    #           n_entries: the number of complete messages in the queue.
    #                 <0 if we haven't counted yet.
    #           _lock: A lock that must be held while modifying or accessing
    #                 the queue object.  Filesystem operations are allowed
    #                 without holding the lock, but they must not be visible
    #                 to users of the queue.
    def __init__(self, location, create=0, scrub=0):
        """Creates a file store object for a given directory, 'location'.  If
           'create' is true, creates the directory if necessary.  If 'scrub'
           is true, removes any incomplete or invalidated messages from the
           store."""
        secureDelete([]) # Make sure secureDelete is configured. HACK!

        self._lock = threading.RLock()
        self.dir = location

        if not os.path.isabs(location):
            LOG.warn("Directory path %s isn't absolute.", location)

        if os.path.exists(location) and not os.path.isdir(location):
            raise MixFatalError("%s is not a directory" % location)

        createPrivateDir(location, nocreate=(not create))

        if scrub:
            self.cleanQueue()

        # Count messages on first time through.
        self.n_entries = -1

    def lock(self):
        """Prevent access to this filestore from other threads."""
        self._lock.acquire()

    def unlock(self):
        """Release the lock on this filestore."""
        self._lock.release()

    def count(self, recount=0):
        """Returns the number of complete messages in the filestore."""
        try:
            self._lock.acquire()
            if self.n_entries >= 0 and not recount:
                return self.n_entries
            else:
                res = 0
                for fn in os.listdir(self.dir):
                    if fn.startswith("msg_"):
                        res += 1
                self.n_entries = res
                return res
        finally:
            self._lock.release()

    def pickRandom(self, count=None):
        """Returns a list of 'count' handles to messages in this filestore.
           The messages are chosen randomly, and returned in a random order.

           If there are fewer than 'count' messages in the filestore,
           all the messages will be included."""
        handles = self.getAllMessages() # handles locking

        return getCommonPRNG().shuffle(handles, count)

    def getAllMessages(self):
        """Returns handles for all messages currently in the filestore.
           Note: this ordering is not guaranteed to be random."""
        self._lock.acquire()
        hs = [fn[4:] for fn in os.listdir(self.dir) if fn.startswith("msg_")]
        self._lock.release()
        return hs

    def messageExists(self, handle):
        """DOCDOC"""
        return os.path.exists(os.path.join(self.dir, "msg_"+handle))

    def removeMessage(self, handle):
        """Given a handle, removes the corresponding message from the
           filestore.  """
        self._changeState(handle, "msg", "rmv") # handles locking.

    def removeAll(self, secureDeleteFn=None):
        """Removes all messages from this filestore."""
        try:
            self._lock.acquire()
            for m in os.listdir(self.dir):
                if m[:4] in ('inp_', 'msg_'):
                    self._changeState(m[4:], m[:3], "rmv")
                elif m[:4] in ('inpm_', 'meta_'):
                    self._changeState(m[5:], m[:4], "rmvm")
            self.n_entries = 0
            self.cleanQueue(secureDeleteFn)
        finally:
            self._lock.release()

    def getMessagePath(self, handle):
        """Given a handle for an existing message, return the name of the
           file that contains that message."""
        # We don't need to lock here: the handle is still valid, or it isn't.
        return os.path.join(self.dir, "msg_"+handle)

    def openMessage(self, handle):
        """Given a handle for an existing message, returns a file descriptor
           open to read that message."""
        # We don't need to lock here; the handle is still valid, or it isn't.
        return open(os.path.join(self.dir, "msg_"+handle), 'rb')

    def openNewMessage(self):
        """Returns (file, handle) tuple to create a new message.  Once
           you're done writing, you must call finishMessage to
           commit your changes, or abortMessage to reject them."""
        file, handle = getCommonPRNG().openNewFile(self.dir, "inp_", 1)
        return file, handle

    def finishMessage(self, f, handle, _ismeta=0):
        """Given a file and a corresponding handle, closes the file
           commits the corresponding message."""
        # if '_ismeta' is true, we're finishing not a message, but the
        # metadata for a message
        f.close()
        if _ismeta:
            self._changeState(handle, "inpm", "meta")
        else:
            self._changeState(handle, "inp", "msg")

    def abortMessage(self, f, handle, _ismeta=0):
        """Given a file and a corresponding handle, closes the file
           rejects the corresponding message."""
        # if '_ismeta' is true, we're finishing not a message, but the
        # metadata for a message
        f.close()
        if _ismeta:
            self._changeState(handle, "inpm", "rmvm")
        else:
            self._changeState(handle, "inp", "rmv")

    def cleanQueue(self, secureDeleteFn=None):
        """Removes all timed-out or trash messages from the filestore.

           If secureDeleteFn is provided, it is called with a list of
           filenames to be removed.  Otherwise, files are removed using
           secureDelete.

           Returns 1 if a clean is already in progress; otherwise
           returns 0.
        """
        # We don't need to hold the lock here; we synchronize via the
        # filesystem.

        rmv = []
        allowedTime = int(time.time()) - INPUT_TIMEOUT
        for m in os.listdir(self.dir):
            if m.startswith("rmv_") or m.startswith("rmvm_"):
                rmv.append(os.path.join(self.dir, m))
            elif m.startswith("inp_"):
                try:
                    s = os.stat(m)
                    if s[stat.ST_MTIME] < allowedTime:
                        self._changeState(m[4:], "inp", "rmv")
                        rmv.append(os.path.join(self.dir, m))
                except OSError:
                    pass
        if secureDeleteFn:
            secureDeleteFn(rmv)
        else:
            secureDelete(rmv, blocking=1)

    def _changeState(self, handle, s1, s2):
        """Helper method: changes the state of message 'handle' from 's1'
           to 's2', and changes the internal count."""
        try:
            self._lock.acquire()
            try:
                os.rename(os.path.join(self.dir, s1+"_"+handle),
                          os.path.join(self.dir, s2+"_"+handle))
            except OSError, e:
                # WWWW On windows, replacing metdata can create an error!
                contents = os.listdir(self.dir)
                LOG.error("Error while trying to change %s from %s to %s: %s",
                          handle, s1, s2, e)
                LOG.error("Directory %s contains: %s", self.dir, contents)
                self.count(1)
                return
            
            if self.n_entries < 0:
                return
            if s1 == 'msg' and s2 != 'msg':
                self.n_entries -= 1
            elif s1 != 'msg' and s2 == 'msg':
                self.n_entries += 1
        finally:
            self._lock.release()

class StringStoreMixin:
    """Combine the 'StringStoreMixin' class with a BaseStore in order
       to implement a BaseStore that stores strings.
    """
    def __init__(self): pass
    def messageContents(self, handle):
        """Given a message handle, returns the contents of the corresponding
           message."""
        try:
            self._lock.acquire()
            return readFile(os.path.join(self.dir, "msg_"+handle), 1)
        finally:
            self._lock.release()

    def queueMessage(self, contents):
        """Creates a new message in the filestore whose contents are
           'contents', and returns a handle to that message."""

        f, handle = self.openNewMessage()
        f.write(contents)
        self.finishMessage(f, handle) # handles locking
        return handle

class ObjectStoreMixin:
    """Combine the 'ObjectStoreMixin' class with a BaseStore in order
       to implement a BaseStore that stores strings.
    """
    def __init__(self): pass
    def getObject(self, handle):
        """Given a message handle, read and unpickle the contents of the
           corresponding message."""
        try:
            self._lock.acquire()
            f = open(os.path.join(self.dir, "msg_"+handle), 'rb')
            res = cPickle.load(f)
            f.close()
            return res
        finally:
            self._lock.release()

    def queueObject(self, object):
        """Queue an object using cPickle, and return a handle to that
           object."""
        f, handle = self.openNewMessage()
        cPickle.dump(object, f, 1)
        self.finishMessage(f, handle) # handles locking
        return handle

class BaseMetadataStore(BaseStore):
    """A BaseMetadataStore is a BaseStore that stores a metadata
       object for every object in the store.  We assume metadata to be
       relatively volitile compared to the underlying stored objects.
       Metadata is not always wiped before removal.

       The representation of a store with metadata is the same as that
       of a simple store, except that:
           1) The meta_, rmvm_, and inpm_ tags are used.
           2) For every file in msg_ state, there is a corresponding meta_
              file.
    """
    ##Fields:
    # _metadata_cache: map from handle to cached metadata object.  This is
    #    a write-through cache.
    def __init__(self, location, create=0, scrub=0):
        """Create a new BaseMetadataStore to store files in 'location'. The
           'create' and 'scrub' arguments are as for BaseStore(...)."""
        BaseStore.__init__(self, location=location, create=create, scrub=scrub)
        self._metadata_cache = {}
        if scrub:
            self.cleanMetadata()

    def cleanMetadata(self,secureDeleteFn=None):
        """Find all orphaned metadata files and remove them."""
        hSet = {}
        for h in self.getAllMessages():
            hSet[h] = 1
        rmv = []
        for h in [fn[5:] for fn in os.listdir(self.dir)
                  if fn.startswith("meta_")]:
            if not hSet.get(h):
                rmv.append("meta_"+h)
        if rmv:
            LOG.warn("Removing %s orphaned metadata files from %s",
                     len(rmv), self.dir)
            if secureDeleteFn:
                secureDeleteFn(rmv)
            else:
                secureDelete(rmv, blocking=1)

    def loadAllMetadata(self, newDataFn):
        """For all objects in the store, load their metadata into the internal
           cache.  If any object is missing its metadata, create metadata for
           it by invoking newDataFn(handle)."""
        try:
            self._lock.acquire()
            self._metadata_cache = {}
            for h in self.getAllMessages():
                try:
                    self.getMetadata(h)
                except KeyError:
                    LOG.warn("Missing metadata for file %s",h)
                    self.setMetadata(h, newDataFn(h))
        finally:
            self._lock.release()

    def getMetadata(self, handle):
        """Return the metadata associated with a given handle."""
        fname = os.path.join(self.dir, "meta_"+handle)
        if not os.path.exists(fname):
            raise KeyError(handle)
        try:
            self._lock.acquire()
            try:
                return self._metadata_cache[handle]
            except KeyError:
                pass
            f = open(fname, 'rb')
            res = cPickle.load(f)
            f.close()
            self._metadata_cache[handle] = res
            return res
        finally:
            self._lock.release()

    def setMetadata(self, handle, object):
        """Change the metadata associated with a given handle."""
        try:
            self._lock.acquire()
            fname = os.path.join(self.dir, "inpm_"+handle)
            f = os.fdopen(os.open(fname, _NEW_FILE_FLAGS, 0600), "wb")
            cPickle.dump(object, f, 1)
            self.finishMessage(f, handle, _ismeta=1)
            self._metadata_cache[handle] = object
            return handle
        finally:
            self._lock.release()

    def removeMessage(self, handle):
        """Given a handle, removes the corresponding message from the
           filestore.  """
        try:
            self._lock.acquire()
            # Remove the message before the metadata, so we don't have
            # a message without metadata.
            BaseStore.removeMessage(self, handle)
            if os.path.exists(os.path.join(self.dir, "meta_"+handle)):
                self._changeState(handle, "meta", "rmvm")

            try:
                del self._metadata_cache[handle]
            except KeyError:
                pass
        finally:
            self._lock.release()

class StringMetadataStoreMixin(StringStoreMixin):
    """Add this mixin class to a BaseMetadataStore in order to get a
       filestore that stores strings with metadata."""
    def __init__(self):
        StringStoreMixin.__init__(self)
    def queueMessage(self, message):
        LOG.warn("Called 'queueMessage' on a metadata store.")
        return self.queueMessageAndMetadata(message, None)
    def queueMessageAndMetadata(self, message, metadata):
        f, handle = self.openNewMessage()
        f.write(message)
        self.setMetadata(handle, metadata)
        self.finishMessage(f, handle) # handles locking
        return handle

class ObjectMetadataStoreMixin(ObjectStoreMixin):
    """Add this mixin class to a BaseMetadataStore in order to get a
       filestore that stores objects with metadata."""
    def __init__(self):
        ObjectStoreMixin.__init__(self)
    def queueObject(self, object):
        LOG.warn("Called 'queueObject' on a metadata store.")
        return self.queueObjectAndMetadata(message, None)
    def queueObjectAndMetadata(self, object, metadata):
        f, handle = self.openNewMessage()
        cPickle.dump(object, f, 1)
        self.setMetadata(handle, metadata)
        self.finishMessage(f, handle) # handles locking
        return handle

class StringStore(BaseStore, StringStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseStore.__init__(self, location, create, scrub)
        StringStoreMixin.__init__(self)

class StringMetadataStore(BaseMetadataStore, StringMetadataStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseMetadataStore.__init__(self, location, create, scrub)
        StringMetadataStoreMixin.__init__(self)

class ObjectStore(BaseStore, ObjectStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseStore.__init__(self, location, create, scrub)
        ObjectStoreMixin.__init__(self)

class ObjectMetadataStore(BaseMetadataStore, ObjectMetadataStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseMetadataStore.__init__(self, location, create, scrub)
        ObjectMetadataStoreMixin.__init__(self)
        
class MixedStore(BaseStore, StringStoreMixin, ObjectStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseStore.__init__(self, location, create, scrub)
        StringStoreMixin.__init__(self)
        ObjectStoreMixin.__init__(self)

class MixedMetadataStore(BaseMetadataStore, StringMetadataStoreMixin,
                         ObjectMetadataStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseMetadataStore.__init__(self, location, create, scrub)
        StringMetadataStoreMixin.__init__(self)
        ObjectMetadataStoreMixin.__init__(self)

# ======================================================================
# Database wrappers

class DBBase:
    """A DBBase is a persistant store that maps keys to values, using
       a Python anydbm object.

       It differs from the standard python 'shelve' module:
          - by handling broken databases files,
          - by warning when using dumbdbm,
          - by providing a 'sync' feature,
          - by bypassing the pickle module's overhead,
          - by providing thread-safety

       To use this class for non-string keys or values, override the
       _{en|de}code{Key|Value} methods."""
    ## Fields:
    # _lock -- A threading.RLock to protect access to database.
    # filename -- The name of the underlying database file.  Note that some
    #       database implementations (such as dumdbm) create multiple files,
    #       using <filename> as a prefix.
    # log -- The underlying anydbm object.
    def __init__(self, filename, purpose=""):
        """Create a DBBase object for a database stored in 'filename',
           creating the underlying database if needed."""
        self._lock = threading.RLock()
        self.filename = filename
        parent = os.path.split(filename)[0]
        createPrivateDir(parent)

        # If the file can't be read, bail.
        try:
            st = os.stat(filename)
        except OSError, e:
            if e.errno != errno.ENOENT:
                raise
            st = None
        # If the file is empty, delete it and start over.
        if st and st[stat.ST_SIZE] == 0:
            LOG.warn("Half-created database %s found; cleaning up.", filename)
            tryUnlink(filename)

        LOG.debug("Opening %s database at %s", purpose, filename)
        self.log = anydbm.open(filename, 'c')
        if not hasattr(self.log, 'sync'):
            if hasattr(self.log, '_commit'):
                # Workaround for dumbdbm to allow syncing. (Standard in 
                # Python 2.3.)
                self.log.sync = self.log._commit
            else:
                # Otherwise, force a no-op sync method.
                self.log.sync = lambda : None

        if isinstance(self.log, dumbdbm._Database):
            LOG.warn("Warning: using a flat file for %s database", purpose)

        # Subclasses may want to check whether this is the right database,
        # flush the journal, and so on.

    def _encodeKey(self, k):
        """Given a key for this mapping (a Python object), return a string
           usable as a key by the underlying databse."""
        return k
    def _encodeVal(self, v):
        """Given a value for this mapping (a Python object), return a string
           usable as a value by the underlying databse."""
        return v
    def _decodeVal(self, v):
        """Given a string-encoded value as used in the underlying database,
           return the original Python object."""
        return v

    def has_key(self, k):
        try:
            _ = self[k]
            return 1
        except KeyError:
            return 0

    def __getitem__(self, k):
        return self.getItem(k)

    def keys(self):
        return map(self._decodeKey, self.log.keys())

    def get(self, k, default=None):
        try:
            return self[k]
        except KeyError:
            return default

    def __setitem__(self, k, v):
        self.setItem(k, v)

    def __delitem__(self, k):
        self.delItem(k)

    def getItem(self, k):
        try:
            self._lock.acquire()
            return self._decodeVal(self.log[self._encodeKey(k)])
        finally:
            self._lock.release()

    def setItem(self, k, v):
        self._lock.acquire()
        try:
            self.log[self._encodeKey(k)] = self._encodeVal(v)
        finally:
            self._lock.release()

    def delItem(self, k):
        try:
            self._lock.acquire()
            del self.log[self._encodeKey(k)]
        finally:
            self._lock.release()
        
    def sync(self):
        """Flush all pending changes to disk"""
        self._lock.acquire()
        try:
            self.log.sync()
        finally:
            self._lock.release()

    def close(self):
        """Release resources associated with this database."""
        self._lock.acquire()
        try:
            self.log.close()
            self.log = None
        finally:
            self._lock.release()

# Flags for use when opening the journal.
_JOURNAL_OPEN_FLAGS = os.O_WRONLY|os.O_CREAT|getattr(os,'O_SYNC',0)|getattr(os,'O_BINARY',0)

class JournaledDBBase(DBBase):
    """Optimized version of DBBase that requires fewer sync() operations.
       Uses a journal file to cache keys and values until they can be written
       to the underlying database.  Keys and values must all encode to stings
       of the same length."""
    # Largest allowed number of journal entries before we flush the journal
    # to disk.
    MAX_JOURNAL = 128
    ## Fields:
    # klen -- required length of journal-encoded keys
    # vlen -- required length of journal-encoded values
    # vdflt -- If vlen is 0, default value used when reading journaled value
    #      from disk.
    # journal -- map from journal-encoded key to journal-encoded value.
    # journalFileName -- filename to use for journal file.
    # journalFile -- fd for the journal file
    
    def __init__(self, location, purpose, klen, vlen, vdflt):
        """Create a new JournaledDBBase that stores its files to match the
           pattern 'location*', whose journal-encoded keys are all of length
           klen, whose journal-encoded values are all of length vlen."""
        DBBase.__init__(self, location, purpose)

        self.klen = klen
        self.vlen = vlen
        self.vdefault = vdflt

        self.journalFileName = location+"_jrnl"
        self.journal = {}
        # If there's a journal file, snarf it into memory.
        if os.path.exists(self.journalFileName):
            j = readFile(self.journalFileName, 1)
            for i in xrange(0, len(j), klen+vlen):
                if vlen:
                    self.journal[j[i:i+klen]] = j[i+klen:i+klen+vlen]
                else:
                    self.journal[j[i:i+klen]] = self.vdefault

        self.journalFile = os.open(self.journalFileName,
                                   _JOURNAL_OPEN_FLAGS|os.O_APPEND, 0600)

        self.sync()

    getItemNoJournal = DBBase.getItem
    setItemNoJournal = DBBase.setItem

    def _jEncodeKey(self, k):
        return k
    def _jDecodeKey(self, k):
        return k
    def _jEncodeVal(self, v):
        return v
    def _jDecodeVal(self, v):
        return v

    def getItem(self, k):
        jk = self._jEncodeKey(k)
        assert len(jk) == self.klen
        self._lock.acquire()
        try:
            if self.journal.has_key(jk):
                return self._jDecodeVal(self.journal[jk])
            return self.getItemNoJournal(k)
        finally:
            self._lock.release()

    def keys(self):
        return map(self._decodeKey,  self.log.keys()) + \
               map(self._jDecodeKey, self.journal.keys())

    def setItem(self, k, v):
        jk = self._jEncodeKey(k)
        jv = self._jEncodeVal(v)
        assert len(jk) == self.klen
        if self.vlen: assert len(jv) == self.vlen
        self._lock.acquire()
        try:
            self.journal[jk] = jv
            os.write(self.journalFile, jk)
            if self.vlen:
                os.write(self.journalFile, jv)
            if len(self.journal) > self.MAX_JOURNAL:
                self.sync()
        finally:
            self._lock.release()

    def delItem(self, k):
        raise NotImplemented

    def sync(self):
        self._lock.acquire()
        try:
            for jk in self.journal.keys():
                ek = self._encodeKey(self._jDecodeKey(jk))
                ev = self._encodeVal(self._jDecodeVal(self.journal[jk]))
                self.log[ek] = ev
            self.log.sync()
            os.close(self.journalFile)
            self.journalFile = os.open(self.journalFileName,
                                       _JOURNAL_OPEN_FLAGS|os.O_TRUNC, 0600)
            self.journal = {}
        finally:
            self._lock.release()
    
    def close(self):
        try:
            self._lock.acquire()
            self.sync()
            self.log.close()
            self.log = None
            os.close(self.journalFile)
        finally:
            self._lock.release()

class BooleanJournaledDBBase(JournaledDBBase):
    """Specialization of JournaledDBBase that encodes a set of keys, mapping
       each key to the value '1'.

       (By default, constant-length string keys are accepted, and are
       hex-encoded when stored in the database, in case the database
       isn't 8-bit clean.)
       """
    def __init__(self, location, purpose, klen):
        JournaledDBBase.__init__(self,location,purpose,klen,0,"1")
    def _encodeKey(self, k):
        return binascii.b2a_hex(k)
    def _jEncodeVal(self, v):
        return ""
    def _jDecodeVal(self, k):
        return 1
    def _encodeVal(self, v):
        return "1"
    def _decodeVal(self, v):
        return 1
