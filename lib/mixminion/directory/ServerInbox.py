# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInbox.py,v 1.12 2003/11/28 04:14:04 nickm Exp $

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

from mixminion.directory.Directory import getIDFingerprint, MismatchedID
from mixminion.directory.ServerList import _writeServer, _readServer

class ServerInbox:
    """A ServerInbox holds server descriptors received from the outside
       world that are not yet ready to be included in the directory.
       """
    ## Fields:
    # newQueue: IncomingQueue object to hold descriptors for previously
    #      unknown servers.
    # updateQueue:  IncomingQueue object to hold descriptors for currently
    #      known servers.
    def __init__(self, base, idCache):
        """Initialize a ServerInbox to store its files in 'base', and
           check server descriptors against the IDCache 'idCache'."""
        self.newQueue = IncomingQueue(os.path.join(base, "new"),
                                      os.path.join(base, "reject"))
        self.updateQueue = IncomingQueue(os.path.join(base, "updates"),
                                         os.path.join(base, "reject"))
        self.idCache = idCache

    def receiveServer(self, text, source):
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
        try:
            server = ServerInfo(string=text,assumeValid=0)
        except MixError, e:
            LOG.warn("Rejected invalid server from %s: %s", source,e)
            raise UIError("Server descriptor was not valid: %s"%e)

        nickname = server.getNickname()

        try:
            known = self.idCache.containsServer(server)
        except MismatchedID:
            LOG.warn("Rejected server with mismatched identity from %s",
                     source)
            self.updateQueue.queueRejectedServer(text,server)
            raise UIError(("I already know a server named "
                           "%s with a different key.")%nickname)

        if not known:
            LOG.info("Received previously unknown server %s from %s",
                     nickname, source)
            self.newQueue.queueIncomingServer(text,server)
            raise ServerQueuedException(
                "Server queued pending manual checking")
        else:
            LOG.info("Received update for server %s from %s",
                     nickname, source)
            self.updateQueue.queueIncomingServer(text,server)
            return 1

    def _doAccept(self, serverList, q, incoming, reject, knownOnly):
        """Helper function: move servers from an IncomingQueue into
           a ServerList.  (To be run by the directory user.)

           serverList -- an instance of ServerList
           q -- an instance of IncomingQueue
           incoming -- a list of [filename, serverinfo, descriptor text,
                fingerprint] for servers to insert.
           reject -- a list of [filename, serverinfo, desc text, fprint]
                for servers to reject.
           knownOnly -- boolean: accept only servers with previously
                known identity keys?
        """
        accepted = []
        for fname, server, text, fp in incoming:
            try:
                serverList.importServerInfo(text,server=server,
                                            knownOnly=knownOnly)
                accepted.append(fname)
            except MixError, e:
                LOG.warn("ServerList refused to include server %s: %s",
                         fname, e)
                reject.append((fname,server,text,fp))

        for fname, server, text, fp in reject:
            self.updateQueue.queueRejectedServer(text,server)

        fnames = accepted + [fn for fn,_,_,_ in reject]
        q.delPendingServers(fnames)

    def acceptUpdates(self, serverList):
        """Move updates for existing servers into the directory.  (To
           be run by the directory user.)"""
        incoming = self.updateQueue.readPendingServers()
        self._doAccept(serverList, self.updateQueue, incoming, [],
                       knownOnly=1)

    def acceptNewServer(self, serverList, nickname):
        """Move the descriptors for a new server with a given nickname
           into the directory.  (To be run by a the directory user.)

           If the nickname is of the format name:FINGERPRINT, then
           only insert servers with the nickname/fingerprint pair.
        """
        if ':' in nickname:
            nickname, fingerprint = nickname.split(":")
        else:
            fingerprint = None

        lcnickname = nickname.lower()
        incoming = self.newQueue.readPendingServers()
        # Do we have any pending servers of the desired name?
        incoming = [ (fname,server,text,fp)
                     for fname,server,text,fp in incoming
                     if server.getNickname().lower() == lcnickname ]
        if not incoming:
            raise UIError("No incoming servers named %s"%nickname)

        if not fingerprint:
            fps = [fp for f,s,t,fp in incoming]
            for f in fps:
                if f != fps[0]:
                    raise UIError("Multiple KeyIDs for servers named %s"%
                                  nickname)
            reject = []
        else:
            reject = [ (f,s,t,fp) for f,s,t,fp in incoming
                       if fp != fingerprint ]
            incoming = [ (f,s,t,fp) for f,s,t,fp in incoming
                        if fp == fingerprint ]
            if not incoming:
                raise UIError("No servers named %s with matching KeyID"%
                              nickname)
            if reject:
                LOG.warn("Rejecting %s servers named %s with unmatched KeyIDs",
                         len(reject), nickname)

        try:
            serverList._lock()
            serverList.learnServerID(incoming[0][1])
            self._doAccept(serverList, self.newQueue, incoming, reject,
                           knownOnly=1)
        finally:
            serverList._unlock()

    def listNewPendingServers(self, f):
        """Print a list of new servers waiting admin attention to the file
           f."""
        incoming = self.newQueue.readPendingServers()
        # lcnickname->fp->servers
        servers = {}
        # lcnickname->nicknames
        nicknames = {}

        for fname,s,t,fp in incoming:
            nickname = s.getNickname()
            lcnickname = nickname.lower()
            nicknames.setdefault(lcnickname, []).append(nickname)
            servers.setdefault(lcnickname, {}).setdefault(fp, []).append(s)

        sorted = nicknames.keys()
        sorted.sort()
        if not sorted:
            print >>f, "No incoming descriptors"
            return
        maxlen = max([len(n) for n in sorted])
        format = " %"+str(maxlen)+"s:%s [%s descriptors]"
        for lcnickname in sorted:
            nickname = nicknames[lcnickname][0]
            ss = servers[lcnickname]
            if len(ss) > 1:
                print >>f, ("***** MULTIPLE KEYIDS FOR %s:"%nickname)
            for fp, s in ss.items():
                print >>f, (format%(nickname,fp,len(s)))

class IncomingQueue:
    """Implementation helper: holds incoming server descriptors as
       separate files in a directory."""
    def __init__(self, incomingDir, rejectDir):
        """Create an IncomingQueue to hold incoming servers in incomingDir
           and rejected servers in rejectDir."""
        self.incomingDir = incomingDir
        self.rejectDir = rejectDir
        if not os.path.exists(incomingDir):
            raise MixFatalError("Incoming directory doesn't exist")
        if not os.path.exists(rejectDir):
            raise MixFatalError("Reject directory doesn't exist")

    def queueIncomingServer(self, contents, server):
        """Write a server into the incoming directory.

           contents -- the text of the server descriptor.
           server -- the parsed server descriptor.
        """
        nickname = server.getNickname()
        _writeServer(self.incomingDir, contents, nickname, 0644)

    def queueRejectedServer(self, contents, server):
        """Write a server into the rejected directory.

           contents -- the text of the server descriptor.
           server -- the parsed server descriptor.
        """
        nickname = server.getNickname()
        _writeServer(self.rejectDir, contents, nickname, 0644)

    def newServersPending(self, newServ):
        """Return true iff there is a new server waiting in the incoming
           directory."""
        return len(os.listdir(self.incomingDir)) > 0

    def readPendingServers(self):
        """Scan all of the servers waiting in the incoming directory.  If
           any are bad, remove them.  Return a list of
              (filename, ServerInfo, server descriptor, ID Fingerprint)
           tuples for all the servers in the directory.
           """
        res = []
        for fname in os.listdir(self.incomingDir):
            path = os.path.join(self.incomingDir,fname)
            try:
                text, server = _readServer(path)
            except MixError, e:
                os.unlink(path)
                LOG.warn(
                    "Removed a bad server descriptor %s from incoming dir: %s",
                    fname, e)
                continue
            fp = formatBase64(getIDFingerprint(server))
            res.append((fname, server, text, fp))
        return res

    def delPendingServers(self, fnames):
        """Remove a list of pending servers with filename 'filename' from
           the incoming directory."""
        for fname in fnames:
            if not tryUnlink(os.path.join(self.incomingDir, fname)):
                LOG.warn("delPendingServers: no such server %s"%fname)

class ServerQueuedException(Exception):
    """Exception: raised when an incoming server is received for a previously
       unknown nickname."""
    pass
