# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: HashLog.py,v 1.23 2003/08/14 19:37:25 nickm Exp $

"""mixminion.server.HashLog

   Persistent memory for the hashed secrets we've seen.  Used by
   PacketHandler to prevent replay attacks."""

import binascii
import errno
import os
import stat
import anydbm, dumbdbm
import threading
import mixminion.Filestore
from mixminion.Common import MixFatalError, LOG, createPrivateDir, readFile, \
     secureDelete, tryUnlink
from mixminion.Packet import DIGEST_LEN

__all__ = [ 'HashLog', 'getHashLog', 'deleteHashLog' ]

# FFFF Mechanism to force a different default db module.

# FFFF Two-copy journaling to protect against catastrophic failure that
# FFFF underlying DB code can't handle.

# Lock to protect _OPEN_HASHLOGS
_HASHLOG_DICT_LOCK = threading.RLock()
# Map from (filename) to (keyid,open HashLog). Needed to implement getHashLog.
_OPEN_HASHLOGS = {}

def getHashLog(filename, keyid):
    """Given a filename and keyid, return a HashLog object with that fname
       and ID, opening a new one if necessary.  This function is needed to
       implement key rotation: we want to assemble a list of current
       hashlogs, but we can't open the same HashLog database twice at once."""
    try:
        _HASHLOG_DICT_LOCK.acquire()
        try:
            keyid_orig, hl = _OPEN_HASHLOGS[filename]
            if keyid != keyid_orig:
                raise MixFatalError("KeyID changed for hashlog %s"%filename)
            LOG.trace("getHashLog() returning open hashlog at %s",filename)
        except KeyError:
            LOG.trace("getHashLog() opening hashlog at %s",filename)
            hl = HashLog(filename, keyid)
            _OPEN_HASHLOGS[filename] = (keyid, hl)
        return hl
    finally:
        _HASHLOG_DICT_LOCK.release()

def deleteHashLog(filename):
    """Remove all files associated with a hashlog."""
    try:
        _HASHLOG_DICT_LOCK.acquire()
        try:
            _, hl = _OPEN_HASHLOGS[filename]
            LOG.trace("deleteHashLog() removing open hashlog at %s",filename)
            hl.close()
        except KeyError:
            LOG.trace("deleteHashLog() removing closed hashlog at %s",filename)
            pass
        remove = []
        parent,name = os.path.split(filename)
        prefix1 = name+"."
        prefix2 = name+"."
        if os.path.exists(parent):
            for fn in os.listdir(parent):
                if fn.startswith(prefix1) or fn.startswith(prefix2):
                    remove.append(os.path.join(parent, fn))
        remove = [f for f in remove if os.path.exists(f)]
        secureDelete(remove, blocking=1)
    finally:
        _HASHLOG_DICT_LOCK.release()

class HashLog(mixminion.Filestore.BooleanJournaledDBBase):
    def __init__(self, filename, keyid):
        mixminion.Filestore.BooleanJournaledDBBase.__init__(self,
                 filename, "digest hash", 20)

        self.keyid = keyid
        try:
            if self.log["KEYID"] != keyid:
                raise MixFatalError("Log KEYID does not match current KEYID")
        except KeyError:
            self.log["KEYID"] = keyid
            self.log.sync()

    def seenHash(self, hash):
        return self.has_key(hash)

    def logHash(self, hash):
        assert len(hash) == DIGEST_LEN
        self[hash] = 1

    def close(self):
        try:
            _HASHLOG_DICT_LOCK.acquire()
            mixminion.Filestore.JournaledDBBase.close(self)
            try:
                del _OPEN_HASHLOGS[self.filename]
            except KeyError:
                pass
        finally:
            _HASHLOG_DICT_LOCK.release()

# We flush the log every MAX_JOURNAL hashes.
MAX_JOURNAL = 128
# flags to pass to os.open when opening the journal file.
_JOURNAL_OPEN_FLAGS = os.O_WRONLY|os.O_CREAT|getattr(os,'O_SYNC',0)|getattr(os,'O_BINARY',0)
class XHashLog:
    """A HashLog is a file containing a list of message digests that we've
       already processed.

       Each HashLog corresponds to a single public key (whose hash is the
       log's keyid).  A HashLog must persist for as long as the key does.

       It is not necessary to sync the HashLog to the disk every time
       a new message is seen; instead, we must only ensure that every
       _retransmitted_ message is first inserted into the hashlog and
       synced.  (One way to implement this is to process messages from
       'state A' into 'state B', marking them in the hashlog as we go,
       and syncing the hashlog before any message is sent from 'B' to
       the network.  On a restart, we reinsert all messages waiting in 'B'
       into the log.)

       HashLogs are implemented using Python's anydbm interface.  This defaults
       to using Berkeley DB, GDBM, or --if you have none of these-- a flat
       text file.

       The base HashLog implementation assumes an 8-bit-clean database that
       maps strings to strings."""
    ##
    # Internally, we also keep a flat 'journal' file to which we append
    # values that we've seen but not yet written to the database.  This way
    # we can survive crashes between 'logHash' and 'sync'.
    #
    # Fields:
    #   log: an anydbm instance.
    #   journalFileName: the name of our journal file
    #   journalFile: a file object for our journal file
    #   journal: a dictionary, used to cache values currently in the
    #       journal file.
    def __init__(self, filename, keyid):
        """Create a new HashLog to store data in 'filename' for the key
           'keyid'."""
        self.filename = filename
        self.keyid = keyid
        parent = os.path.split(filename)[0]
        createPrivateDir(parent)

        # Catch empty logfiles: these can be created if we exit before
        # syncing the log for the first time.
        try:
            st = os.stat(filename)
        except OSError, e:
            if e.errno != errno.ENOENT:
                raise
            st = None
        if st and st[stat.ST_SIZE] == 0:
            LOG.warn("Half-created database %s found; cleaning up.", filename)
            tryUnlink(filename)

        LOG.debug("Opening database %s for packet digests", filename)
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
            LOG.warn("Warning: logging packet digests to a flat file.")
        try:
            if self.log["KEYID"] != keyid:
                raise MixFatalError("Log KEYID does not match current KEYID")
        except KeyError:
            self.log["KEYID"] = keyid
            self.log.sync()

        # Scan the journal file
        self.journalFileName = filename+"_jrnl"
        self.journal = {}
        if os.path.exists(self.journalFileName):
            j = readFile(self.journalFileName, 1)
            for i in xrange(0, len(j), DIGEST_LEN):
                self.journal[j[i:i+DIGEST_LEN]] = 1

        self.journalFile = os.open(self.journalFileName,
                    _JOURNAL_OPEN_FLAGS|os.O_APPEND, 0600)

        self.__lock = threading.RLock()
        # On startup, we flush everything to disk.
        self.sync()

    def seenHash(self, hash):
        """Return true iff 'hash' has been logged before."""
        try:
            self.__lock.acquire()
            try:
                if self.journal.get(hash,0):
                    LOG.trace("Checking hash %s: seen recently",
                              binascii.b2a_hex(hash))
                    return 1
                _ = self.log[hash]
                LOG.trace("Checking hash %s: seen a while ago",
                          binascii.b2a_hex(hash))
                return 1
            except KeyError:
                return 0
        finally:
            self.__lock.release()

    def logHash(self, hash):
        """Insert 'hash' into the database."""
        assert len(hash) == DIGEST_LEN
        LOG.trace("Logging hash %s", binascii.b2a_hex(hash))
        try:
            self.__lock.acquire()
            self.journal[hash] = 1
            os.write(self.journalFile, hash)
            # FFFF Make this configurable.
            if len(self.journal) > MAX_JOURNAL:
                self.sync()
        finally:
            self.__lock.release()

    def sync(self):
        """Flushes changes to this log to the filesystem."""
        LOG.trace("Flushing hash log to disk")
        try:
            self.__lock.acquire()
            for hash in self.journal.keys():
                self.log[hash] = "1"
            self.log.sync()
            os.close(self.journalFile)
            self.journalFile = os.open(self.journalFileName,
                       _JOURNAL_OPEN_FLAGS|os.O_TRUNC, 0600)
            self.journal = {}
        finally:
            self.__lock.release()

    def close(self):
        """Closes this log."""
        try:
            _HASHLOG_DICT_LOCK.acquire()
            self.__lock.acquire()
            LOG.trace("Closing hashlog at self.filename")
            self.sync()
            self.log.close()
            self.log = None
            os.close(self.journalFile)
            try:
                del _OPEN_HASHLOGS[self.filename]
            except KeyError:
                pass
        finally:
            self.__lock.release()
            _HASHLOG_DICT_LOCK.release()
