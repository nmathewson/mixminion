# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInbox.py,v 1.2 2003/05/25 23:11:43 nickm Exp $

"""mixminion.directory.ServerInbox

   DOCDOC

   """

__all__ = [ 'ServerInbox' ]

import os

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     readPickled, writePickled

from mixminion.directory.Directory import getIDFingerprint, MismatchedID
from mixminion.directory.ServerList import _writeServer, _readServer

class ServerInbox:
    def __init__(self, base, idCache):
        self.newQueue = IncomingQueue(os.path.join(base, "new"),
                                      os.path.join(base, "reject"))
        self.updateQueue = IncomingQueue(os.path.join(base, "updates"),
                                         os.path.join(base, "reject"))
        self.idCache = idCache

    def receiveServer(self, text, source):
        """DOCDOC

           Returns true on OK; raises UIError on failure; raises
           ServerQueued on wait-for-admin.
           """
        try:
            text, server = _readServer(text)
        except MixError, e:
            LOG.warn("Rejected invalid server from %s: %s", source,e)
            raise UIError("Server descriptor was not valid: %s"%e)

        nickname = server.getNickname()

        try:
            known = self.idCache.containsServer(nickname)
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
            return
        else:
            LOG.info("Received update for server %s from %s",
                     nickname, source)
            self.updateQueue.queueIncomingServer(text,server)
            return

    def _doAccept(self, serverList, q, incoming, reject, knownOnly):
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
        incoming = self.updateQueue.readPendingServers()
        self._doAccept(serverList, self.updateQueue, incoming, [],
                       knownOnly=1)

    def acceptNewServers(self, serverList, nickname):
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
        """DOCDOC"""
        incoming = self.newQueue.readPendingServers()
        # lcnickname->fp->servers
        servers = {}
        # lcnickname->nicknames
        nicknames = {}
    
        for f,s,t,fp in incoming:
            nickname = s.getNickname()
            lcnickname = nickname.lower()
            nicknames.setdefault(lcnickname, []).append(nickname)
            servers.setdefault(lcnickname, {}).setdefault(fp, []).append(s)

        sorted = nicknames.keys()
        sorted.sort()
        maxlen = max([len(n) for n in sorted])
        format = " %"+str(maxlen)+"s:%s [%s descriptors]"
        for lcnickname in sorted:
            nickname = nicknames[lcnickname][0]
            ss = servers[lcnickname]
            if len(ss) > 1:
                print >>f, ("***** MULTIPLE KEYIDS FOR %s:"%nickname)
            for fp, s in ss:
                print >>f, (format%(nickname,fp,len(s)))

class IncomingQueue:
    """DOCDOC"""
    def __init__(self, incomingDir, rejectDir):
        """DOCDOC"""
        self.incomingDir = incomingDir
        self.rejectDir = rejectDir
        if not os.path.exists(incomingDir):
            raise MixFatalError("Incoming directory doesn't exist")
        if not os.path.exists(rejectDir):
            raise MixFatalError("Reject directory doesn't exist")

    def queueIncomingServer(self, contents, server):
        """DOCDOC"""
        nickname = server.getNickname()
        _writeServer(nickname, contents, self.incomingDir)

    def queueRejectedServer(self, contents, server):
        nickname = server.getNickname()
        _writeServer(nickname, contents, self.rejectDir)        

    def newServersPending(self, newServ):
        """DOCDOC"""
        return len(os.listdir(self.incomingDir)) > 0

    def readPendingServers(self):
        res = []
        for fname in os.listdir(self.incomingDir):
            path = os.path.join(self.incomingDir,fname)
            try:
                text, server = _readServer(path)
            except MixError, e:
                os.unlink(path)
                LOG.warn("Removed a bad server descriptor %s from incoming dir: %s",
                         fname, e)
                continue
            res.append((fname, server, text, getIDFingerprint(server)))
        return res

    def delPendingServers(self, fnames):
        for fname in fnames:
            try:
                os.path.unlink(os.path.join(self.incomingDir, fname))
            except OSError:
                LOG.warn("delPendingServers: no such server %s"%fname)

class ServerQueuedException(Exception):
    """DOCDOC"""
    pass
