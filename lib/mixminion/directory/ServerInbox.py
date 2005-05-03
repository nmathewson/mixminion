# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInbox.py,v 1.13 2005/05/03 03:26:50 nickm Exp $

"""mixminion.directory.ServerInbox

   A ServerInbox holds server descriptors received from the outside world
   that are not yet ready to be included in the directory.  It is designed
   to be written to by an untrusted user (e.g., CGI).
   """

__all__ = [ 'ServerInbox' ]

import os

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     formatBase64, readPickled, tryUnlink, writePickled
from mixminion.ServerInfo import ServerInfo

class ServerInbox:
    """A ServerInbox holds server descriptors received from the outside
       world that are not yet ready to be included in the directory.
       """
    ## Fields:
    def __init__(self, store, voteFile):
        """DOCDOC"""
        self.store = store
        self.voteFile = voteFile

    def receiveServer(self, text, source, now=None):
        """Process a new server descriptor and store it for later action.
           (To be run by the CGI user.)

           If the server will be automatically inserted, return true.
           If the server will be inserted (given administrator intervention),
              raise ServerQueuedException.
           If there is a problem, log it, and raise UIError.

           text -- a string containing a new server descriptor.
           source -- a (human readable) string describing the source
               of the descriptor, used in error messages.

        """
        if now is None:
            now = time.time()

        try:
            server = ServerInfo(string=text,assumeValid=0,_keepContents=1)
        except MixError, e:
            LOG.warn("Rejected invalid server from %s: %s", source,e)
            raise UIError("Server descriptor was not valid: %s"%e)

        status = self.voteFile.getServerStatus(server)
        if status == "mismatch":#XXXX missing case? (I found an elif here)
            LOG.warn("Rejected server with mismatched identity for %s from %s",
                     nickname, source)
            self.store.addServer(server)
            raise UIError(("I already know a server named "
                           "%s with a different key.")%server.getNickname())

        if server.isExpiredAt(time.time()):
            LOG.warn("Rejecting expired descriptor from %s", source)
            raise UIError("That descriptor is already expired; your clock"
                          " is probably skewed.")

        if status in ("yes", "no", "abstain"):
            LOG.warn("Received update for already-seen server %r from %s (vote=%s)",
                     server.getNickname(), source, status)
            self.store.addServer(server)
            return 1
        else:
            assert status == "unknown"
            LOG.info("Received previously unknown server %s from %s",
                     nickname, source)
            self.store.addServer(server)
            raise ServerQueuedException(
                "Server queued pending manual checking")

    def moveEntriesToStore(self, intoStore):
        keys = self.store.listKeys()
        unknown = {}
        for k in keys:
            try:
                s = self.store.loadServer(k, keepContents=1, assumeValid=0)
            except (OSError, mixminion.Config.ConfigError), _:
                self.store.delServer(s)
            else:
                status = self.voteFile.getServerStatus(s)
                if status not in ("ignore", "mismatch"):
                    intoStore.addServer(s)
                    if status == 'unknown':
                        unknown[(s.getNickname(), getIdentityFingerprint())]=1
                self.store.delServer(k)
            if unknown:
                self.voteFile.appendUnknownServers(unknown.keys())

class ServerQueuedException(Exception):
    """Exception: raised when an incoming server is received for a previously
       unknown nickname."""
    pass
