# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: HashLog.py,v 1.11 2002/09/10 14:45:30 nickm Exp $

"""mixminion.HashLog

   Persistant memory for the hashed secrets we've seen."""

import os
import anydbm, dumbdbm
from mixminion.Common import MixFatalError, getLog, createPrivateDir

__all__ = [ 'HashLog' ]

# FFFF Mechanism to force a different default db module.

# FFFF Journaling for dbs that don't recover from catastrophic failure during
# FFFF writes.

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
    def __init__(self, filename, keyid):
        """Create a new HashLog to store data in 'filename' for the key
           'keyid'."""
        parent = os.path.split(filename)[0]
	createPrivateDir(parent)
        self.log = anydbm.open(filename, 'c')
        if isinstance(self.log, dumbdbm._Database):
            getLog().warn("Warning: logging packet digests to a flat file.")
        try:
            if self.log["KEYID"] != keyid:
                raise MixFatalError("Log KEYID does not match current KEYID")
        except KeyError:
            self.log["KEYID"] = keyid

    def seenHash(self, hash):
        """Return true iff 'hash' has been logged before."""
        try:
            _ = self.log[hash]
            return 1
        except KeyError:
            return 0

    def logHash(self, hash):
        """Insert 'hash' into the database."""
        self.log[hash] = "1"

    def sync(self):
        """Flushes changes to this log to the filesystem."""
        if hasattr(self.log, "sync"):
            self.log.sync()

    def close(self):
        """Closes this log."""
        self.sync()
        self.log.close()

