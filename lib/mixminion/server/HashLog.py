# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.

"""mixminion.server.HashLog

   Persistent memory for the hashed secrets we've seen.  Used by
   PacketHandler to prevent replay attacks."""

import os
import threading
import mixminion.Filestore
from mixminion.Common import MixFatalError, LOG, secureDelete
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
       text file."""
    def __init__(self, filename, keyid):
        mixminion.Filestore.BooleanJournaledDBBase.__init__(self,
                 filename, "digest hash", 20)

        self.keyid = keyid
        try:
            if self.log["KEYID"] != keyid:
                raise MixFatalError("Log KEYID does not match current KEYID")
        except KeyError:
            self.log["KEYID"] = keyid
            self._syncLog()

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

