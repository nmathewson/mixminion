# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: HashLog.py,v 1.11 2003/05/30 13:54:45 nickm Exp $

"""mixminion.server.HashLog

   Persistant memory for the hashed secrets we've seen.  Used by
   PacketHandler to prevent replay attacks."""

import binascii
import os
import stat
import anydbm, dumbdbm
import threading
from mixminion.Common import MixFatalError, LOG, createPrivateDir
from mixminion.Packet import DIGEST_LEN

__all__ = [ 'HashLog' ]

# FFFF Mechanism to force a different default db module.

# FFFF Two-copy journaling to protect against catastrophic failure that
# FFFF underlying DB code can't handle.

# We flush the log every MAX_JOURNAL hashes.
MAX_JOURNAL = 128

#DOCDOC
_OPEN_HASHLOGS = {}

#XXXX004 locking??
def getHashLog(filename, keyid):
    try:
        return _OPEN_HASHLOGS[(filename, keyid)]
    except KeyError:
        hl = HashLog(filename, keyid)
        _OPEN_HASHLOGS[(filename, keyid)] = hl
        return hl

# flags to pass to os.open when opening the journal file.
_JOURNAL_OPEN_FLAGS = os.O_WRONLY|os.O_CREAT|getattr(os,'O_SYNC',0)
class HashLog:
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
        parent = os.path.split(filename)[0]
        createPrivateDir(parent)

        # Catch empty logfiles: these can be created if we exit before
        # syncing the log for the first time.
        try:
            if os.stat(filename)[stat.ST_SIZE] == 0:
                LOG.warn("Half-created database %s found; cleaning up.")
                os.unlink(filename)
        except os.error:
            pass

        LOG.debug("Opening database %s for packet digests", filename)
        self.log = anydbm.open(filename, 'c')
        if isinstance(self.log, dumbdbm._Database):
            LOG.warn("Warning: logging packet digests to a flat file.")
        try:
            if self.log["KEYID"] != keyid:
                raise MixFatalError("Log KEYID does not match current KEYID")
        except KeyError:
            self.log["KEYID"] = keyid
            if hasattr(self.log, 'sync'): self.log.sync()

        # Scan the journal file
        self.journalFileName = filename+"_jrnl"
        self.journal = {}
        if os.path.exists(self.journalFileName):
            f = open(self.journalFileName, 'r')
            j = f.read()
            for i in xrange(0, len(j), DIGEST_LEN):
                self.journal[j[i:i+DIGEST_LEN]] = 1
            f.close()

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
            #XXXX Make this configurable.
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
            if hasattr(self.log, "sync"):
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
            self.__lock.acquire()
            self.sync()
            self.log.close()
            os.close(self.journalFile)
        finally:
            self.__lock.release()
