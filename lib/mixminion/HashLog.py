# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: HashLog.py,v 1.4 2002/06/24 20:28:19 nickm Exp $

"""mixminion.HashLog

   Persistant memory for the hashed secrets we've seen."""

import anydbm
from mixminion.Common import MixFatalError

__all__ = [ 'HashLog' ]

# FFFF Mechanism to force a different default db module.

class HashLog:
    """A HashLog is a file containing a list of message digests that we've
       already processed.

       Each HashLog corresponds to a single public key (whose hash is the
       log's keyid.  A HashLog must persist for as long as the key does.

       It is not necessary to sync the HashLog to the disk every time a new
       message is seen; rather, the HashLog must be synced before any messages
       are sent to the network.

       HashLogs are implemented using Python's anydbm interface.  This defaults
       to using Berkeley DB, GDBM, or --if you have none of these-- a flat
       text file.

       The base HashLog implementation assumes an 8-bit-clean database that
       maps strings to strings."""
    def __init__(self, filename, keyid):
        """HashLog(filename, keyid) -> hashlog

           Creates a new HashLog to store data in 'filename' for the key
           'keyid'."""
        self.log = anydbm.open(filename, 'c')
        #FFFF Warn if we're using dumbdbm
        try:
            if self.log["KEYID"] != keyid:
                raise MixFatalError("Log KEYID does not match current KEYID")
        except KeyError:
            self.log["KEYID"] = keyid

    def seenHash(self, hash):
        """seenHash(hash) -> bool

           Returns true iff 'hash' has been logged before."""
        try:
            _ = self.log[hash]
            return 1
        except KeyError:
            return 0

    def logHash(self, hash):
        """logHash(hash)

           Inserts 'hash' into the database."""
        self.log[hash] = "1"

    def sync(self):
        """sync()

           Flushes changes to this log to the filesystem."""
        if hasattr(self.log, "sync"):
            self.log.sync()

    def close(self):
        """close()

           Closes this log."""
        self.sync()
        self.log.close()

