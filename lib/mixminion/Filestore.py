# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Filestore.py,v 1.4 2003/08/08 21:40:42 nickm Exp $

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
import dumbdbm
import os
import errno
import time
import stat
import cPickle
import threading

from mixminion.Common import MixFatalError, secureDelete, LOG, \
     createPrivateDir, readFile, tryUnlink
from mixminion.Crypto import getCommonPRNG

__all__ = [ "StringStore", "StringMetadataStore",
            "ObjectStore", "ObjectMetadataStore", 
            "MixedStore", "MixedMetadataStore" ]

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

    def finishMessage(self, f, handle, ismeta=0):
        """Given a file and a corresponding handle, closes the file
           commits the corresponding message."""
        f.close()
        if ismeta:
            self._changeState(handle, "inpm", "meta")
        else:
            self._changeState(handle, "inp", "msg")

    def abortMessage(self, f, handle, ismeta=0):
        """Given a file and a corresponding handle, closes the file
           rejects the corresponding message."""
        f.close()
        if ismeta:
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
        return 0

    def _changeState(self, handle, s1, s2):
        """Helper method: changes the state of message 'handle' from 's1'
           to 's2', and changes the internal count."""
        try:
            self._lock.acquire()
            try:
                os.rename(os.path.join(self.dir, s1+"_"+handle),
                          os.path.join(self.dir, s2+"_"+handle))
            except OSError, e:
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

    def moveMessage(self, handle, other):
        """Given a handle and a queue, moves the corresponding message
           from this filestore to the filestore provided.  Returns a
           new handle for the message in the destination queue."""

        # Since we're switching handles, we don't want to just rename;
        # We really want to copy and delete the old file.
        try:
            self._lock.acquire()
            newHandle = other.queueMessage(self.messageContents(handle))
            self.removeMessage(handle)
        finally:
            self._lock.release()

        return newHandle    

class ObjectStoreMixin:
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
    def __init__(self, location, create=0, scrub=0):
        BaseStore.__init__(self, location=location, create=create, scrub=scrub)
        self._metadata_cache = {}

    def loadAllMetadata(self, newDataFn):
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
        """DOCDOC"""
        try:
            self._lock.acquire()
            fname = os.path.join(self.dir, "inpm_"+handle)
            f = os.fdopen(os.open(fname, _NEW_FILE_FLAGS, 0600), "wb")
            cPickle.dump(object, f, 1)
            self.finishMessage(f, handle, ismeta=1)
            self._metadata_cache[handle] = object
            return handle
        finally:
            self._lock.release()

    def removeMessage(self, handle):
        try:
            self._lock.acquire()
            BaseStore.removeMessage(self, handle)
            if os.path.exists(os.path.join(self.dir, "meta_"+handle)):
                self._changeState(handle, "meta", "rmvm")

            try:
                del self._metadata_cache[handle]
            except KeyError:
                pass
        finally:
            self._lock.release()

class StringStore(BaseStore, StringStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseStore.__init__(self, location, create, scrub)
        StringStoreMixin.__init__(self)

class StringMetadataStore(BaseMetadataStore, StringStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseMetadataStore.__init__(self, location, create, scrub)
        StringStoreMixin.__init__(self)

class ObjectStore(BaseStore, ObjectStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseStore.__init__(self, location, create, scrub)
        ObjectStoreMixin.__init__(self)

class ObjectMetadataStore(BaseMetadataStore, ObjectStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseMetadataStore.__init__(self, location, create, scrub)
        ObjectStoreMixin.__init__(self)
        
class MixedStore(BaseStore, StringStoreMixin, ObjectStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseStore.__init__(self, location, create, scrub)
        StringStoreMixin.__init__(self)
        ObjectStoreMixin.__init__(self)

class MixedMetadataStore(BaseMetadataStore, StringStoreMixin,
                         ObjectStoreMixin):
    def __init__(self, location, create=0, scrub=0):
        BaseMetadataStore.__init__(self, location, create, scrub)
        StringStoreMixin.__init__(self)
        ObjectStoreMixin.__init__(self)

# ======================================================================
# Database wrappers

class DBBase:
    # _lock
    def __init__(self, filename, purpose=""):
        self._lock = threading.RLock()
        self.filename = filename
        parent = os.path.split(filename)[0]
        createPrivateDir(parent)

        try:
            st = os.stat(filename)
        except OSError, e:
            if e.errno != errno.ENOENT:
                raise
            st = None

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
        return k
    def _encodeVal(self, v):
        return v
    def _decodeVal(self, v):
        return v

    def has_key(self, k):
        try:
            _ = self[k]
            return 1
        except KeyError:
            return 0

    def __getitem__(self, k):
        return self.getItem(k)

    def get(self, k, default=None):
        try:
            return self[k]
        except KeyError:
            return default

    def __setitem__(self, k, v):
        self.setItem(k, v)

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
        
    def sync(self):
        self._lock.acquire()
        try:
            self.log.sync()
        finally:
            self._lock.release()

    def close(self):
        self._lock.acquire()
        try:
            self.log.close()
            self.log = None
        finally:
            self._lock.release()

_JOURNAL_OPEN_FLAGS = os.O_WRONLY|os.O_CREAT|getattr(os,'O_SYNC',0)|getattr(os,'O_BINARY',0)

class JournaledDBBase(DBBase):
    MAX_JOURNAL = 128
    def __init__(self, location, purpose, klen, vlen, vdflt):
        DBBase.__init__(self, location, purpose)

        self.klen = klen
        self.vlen = vlen
        self.vdefault = vdflt

        self.journalFileName = location+"_jrnl"
        self.journal = {}
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
