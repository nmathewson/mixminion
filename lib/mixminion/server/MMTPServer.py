# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPServer.py,v 1.46 2003/07/15 04:41:18 nickm Exp $
"""mixminion.MMTPServer

   This package implements the Mixminion Transfer Protocol as described
   in the Mixminion specification.  It uses a select loop to provide
   a nonblocking implementation of *both* the client and the server sides
   of the protocol.

   If you just want to send messages into the system, use MMTPClient.
   """

# NOTE FOR THE CURIOUS: The 'asyncore' module in the standard library
#    is another general select/poll wrapper... so why are we using our
#    own?  Basically, because asyncore has IMO a couple of mismatches
#    with our design, the largest of which is that it has the 'server
#    loop' periodically query the connections for their status,
#    whereas we have the connections inform the server of their status
#    whenever they change.  This latter approach turns out to be far
#    easier to use with TLS.

import errno
import socket
import select
import re
import time
from types import StringType

import mixminion._minionlib as _ml
from mixminion.Common import MixError, MixFatalError, MixProtocolError, \
     LOG, stringContains
from mixminion.Crypto import sha1, getCommonPRNG
from mixminion.Packet import MESSAGE_LEN, DIGEST_LEN
from mixminion.MMTPClient import PeerCertificateCache
import mixminion.server.EventStats as EventStats

__all__ = [ 'AsyncServer', 'ListenConnection', 'MMTPServerConnection',
            'MMTPClientConnection' ]

trace = LOG.trace
info = LOG.info
debug = LOG.info
warn = LOG.warn
error = LOG.error

#DOCDOC
IN_PROGRESS_ERRNOS = [ getattr(errno, ename) 
   for ename in [ "EINPROGRESS", "WSAEWOULDBLOCK"]
   if hasattr(errno,ename) ]
del ename

class AsyncServer:
    """AsyncServer is the core of a general-purpose asynchronous
       select-based server loop.  AsyncServer maintains two lists of
       Connection objects that are waiting for reads and writes
       (respectively), and waits for their underlying sockets to be
       available for the desired operations.
       """
    ## Fields:
    # writers: map from fd to 'Connection' objects that are interested
    #      in write events.
    # readers: map from fd to 'Connection' objects that are interested
    #      in read events.
    # _timeout: the interval after which we drop open inactive connections.
    def __init__(self):
        """Create a new AsyncServer with no readers or writers."""
        self.writers = {}
        self.readers = {}
        self._timeout = None

    def process(self, timeout):
        """If any relevant file descriptors become available within
           'timeout' seconds, call the appropriate methods on their
           connections and return immediately after. Otherwise, wait
           'timeout' seconds and return.

           If we receive an unblocked signal, return immediately.
           """

        readfds = self.readers.keys()
        writefds = self.writers.keys()
 
        if not (readfds or writefds):
            #DOCDOC
            time.sleep(timeout)
            return
   
        try:
            readfds,writefds,exfds = select.select(readfds,writefds,[],timeout)
        except select.error, e:
            if e[0] == errno.EINTR:
                return
            else:
                raise e

        for fd in readfds:
            self.readers[fd].handleRead()
        for fd in writefds:
            self.writers[fd].handleWrite()
        for fd in exfds:
            if self.readers.has_key(fd): del self.readers[fd]
            if self.writers.has_key(fd): del self.writers[fd]

    def hasReader(self, reader):
        """Return true iff 'reader' is a reader on this server."""
        fd = reader.fileno()
        return self.readers.get(fd) is reader

    def hasWriter(self, writer):
        """Return true iff 'writer' is a writer on this server."""
        fd = writer.fileno()
        return self.writers.get(fd) is writer

    def registerReader(self, reader):
        """Register a connection as a reader.  The connection's 'handleRead'
           method will be called whenever data is available for reading."""
        fd = reader.fileno()
        self.readers[fd] = reader
        if self.writers.has_key(fd):
            del self.writers[fd]

    def registerWriter(self, writer):
        """Register a connection as a writer.  The connection's 'handleWrite'
           method will be called whenever the buffer is free for writing.
        """
        fd = writer.fileno()
        self.writers[fd] = writer
        if self.readers.has_key(fd):
            del self.readers[fd]

    def registerBoth(self, connection):
        """Register a connection as a reader and a writer.  The
           connection's 'handleRead' and 'handleWrite' methods will be
           called as appropriate.
        """
        fd = connection.fileno()
        self.readers[fd] = self.writers[fd] = connection

    def unregister(self, connection):
        """Removes a connection from this server."""
        fd = connection.fileno()
        w = self.writers.has_key(fd)
        r = self.readers.has_key(fd)
        if r: del self.readers[fd]
        if w: del self.writers[fd]

    def tryTimeout(self, now=None):
        """Timeout any connection that is too old."""
        if self._timeout is None:
            return
        if now is None:
            now = time.time()
        # All connections older than 'cutoff' get purged.
        cutoff = now - self._timeout
        # Maintain a set of filenos for connections we've checked, so we don't
        # check any more than once.
        filenos = {}
        for group in self.readers, self.writers:
            for fd, con in group.items():
                if filenos.has_key(fd): continue
                con.tryTimeout(cutoff)
                filenos[fd] = 1

class Connection:
    "A connection is an abstract superclass for asynchronous channels"
    def handleRead(self):
        """Invoked when there is data to read."""
        pass
    def handleWrite(self):
        """Invoked when there is data to write."""
        pass
    def register(self, server):
        """Invoked to register this connection with an AsyncServer."""
        pass
    def fileno(self):
        """Returns an integer file descriptor for this connection, or returns
           an object that can return such a descriptor."""
        pass
    def tryTimeout(self, cutoff):
        """If this connection has seen no activity since 'cutoff', and it
           is subject to aging, shut it down."""
        pass

class ListenConnection(Connection):
    """A ListenConnection listens on a given port/ip combination, and calls
       a 'connectionFactory' method whenever a new connection is made to that
       port."""
    ## Fields:
    # ip: IP to listen on.
    # port: port to listen on.
    # sock: socket to bind.
    # connectionFactory: a function that takes as input a socket from a
    #    newly received connection, and returns a Connection object to
    #    register with the async server.
    def __init__(self, ip, port, backlog, connectionFactory):
        """Create a new ListenConnection"""
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(backlog)
        self.connectionFactory = connectionFactory
        info("Listening at %s on port %s (fd %s)", ip, port,self.sock.fileno())

    def register(self, server):
        server.registerReader(self)
        self.server = server

    def handleRead(self):
        con, addr = self.sock.accept()
        debug("Accepted connection from %s (fd %s)", addr, con.fileno())
        rw = self.connectionFactory(con)
        rw.register(self.server)

    def shutdown(self):
        debug("Closing listener connection (fd %s)", self.sock.fileno())
        self.server.unregister(self)
        del self.server
        self.sock.close()
        info("Server connection closed")

    def fileno(self):
        return self.sock.fileno()

class SimpleTLSConnection(Connection):
    """SimpleTLSConnection is an abstract superclass for asynchronous TLS
       connections.  Conceptually, a SimpleTLSConnection is in one of 5 states:
           1. Negotiating a new connection (server side)
           2. Negotiating a new connection (client side)
           3. Reading
           4. Writing
           5. Shutting down.
       Reads proceed until either a given number of bytes have been received,
       or until a provided terminator has been found.  Writes procede until
       a buffer is exhausted.

       After leaving states 1,2,3,or 4, the connection's "finished" method
       is called.  After leaving state 5, the connection's "shutdownFinished"
       method is called.
    """
    # Fields:
    #    lastActivity: the last time when we had a read or a write.
    #    address: Human readable IP address of our peer.  For debugging.
    #    fd: fileno for the underlying socket __con.
    #
    #    __con: an underlying TLS object
    #    __state: a callback to use whenever we get a read or a write. May
    #           throw _ml.TLSWantRead or _ml.TLSWantWrite.  See __acceptFn,
    #           __connectFn, __shutdownFn, __readFn, __writeFn.  If __state
    #           is None, the connection should close immediately.
    #    __server: an AsyncServer.  If None, the connection is closed.
    #    __inbuf: A list of strings that we've read since the last expectRead.
    #    __inbuflen: The total length of all the strings in __inbuf
    #    __expectReadLen: None, or the number of bytes to read before
    #           the current read succeeds.
    #    __terminator: None, or a string which will terminate the current read.
    #    __outbuf: None, or the remainder of the string we're currently
    #           writing.
    #    __servermode: If true, we're the server side of the connection.
    #           Else, we're the client side.
    #    __connection: Are we currently trying to start a connection? (boolean)
    #    __failed: Have we given up on this connection?

    def __init__(self, sock, tls, serverMode, address=None):
        """Create a new SimpleTLSConnection.

           tls -- An underlying TLS connection.
           serverMode -- If true, we start with a server-side negotatiation.
                         otherwise, we start with a client-side negotatiation.
        """
        self.__sock = sock
        self.__con = tls
        self.fd = self.__con.fileno()
        self.lastActivity = time.time()
        self.__serverMode = serverMode
        self.__failed = 0
        self.__inbuf = []
        self.__inbuflen = 0

        if serverMode:
            self.__connecting = 0
            self.__state = self.__acceptFn
        else:
            self.__connecting = 1
            self.__state = self.__connectFn

        if address is not None:
            self.address = "%s (fd %s)" % (address, self.fd)
        else:
            self.address = "remote host (fd %s)" % self.fd

    def isShutdown(self):
        """Returns true iff this connection is finished shutting down"""
        return self.__state is None

    def register(self, server):
        self.__server = server
        if self.__state == self.__acceptFn:
            server.registerReader(self)
        else:
            assert self.__state == self.__connectFn
            server.registerWriter(self)

    def expectRead(self, bytes=None, terminator=None):
        """Begin reading from the underlying TLS connection.

           After the read is finished, this object's finished method
           is invoked.  A call to 'getInput' will retrieve the contents
           of the input buffer since the last call to 'expectRead'.

           If 'terminator' is not provided, we try to read exactly
           'bytes' bytes.  If terminator is provided, we read until we
           encounter the terminator, but give up after 'bytes' bytes.
        """
        del self.__inbuf[:]
        self.__inbuflen = 0
        self.__expectReadLen = bytes
        self.__terminator = terminator

        self.__state = self.__readFn
        self.__server.registerReader(self)

    def beginWrite(self, str):
        """Begin writing a string to the underlying connection.  When the
           string is completely written, this object's "finished" method
           will be called.
        """
        self.__outbuf = str
        self.__state = self.__writeFn
        self.__server.registerWriter(self)

    def __acceptFn(self):
        """Hook to implement server-side handshake."""
        self.__con.accept() #may throw want*
        self.__server.unregister(self)
        self.finished()

    def __connectFn(self):
        """Hook to implement client-side handshake."""
        self.__con.connect() #may throw want*
        self.__server.unregister(self)
        self.__connecting = 0
        self.finished()

    def __shutdownFn(self):
        """Hook to implement shutdown."""

        # This is a bit subtle.  The underlying 'shutdown' method
        # needs to be retried till the other guy sends an 'ack'
        # back... but we don't want to keep retrying indefinitely, or
        # else we can deadlock on a connection from ourself to
        # ourself.
        if self.__con.shutdown() == 1: #may throw want*
            #trace("Got a 1 on shutdown (fd %s)", self.fd)
            self.__sock.close()
            self.__state = None
            self.shutdownFinished()
            return

        # If we don't get any response on shutdown, stop blocking; the other
        # side may be hostile, confused, or deadlocking.
        #trace("Got a 0 on shutdown (fd %s)", self.fd)
        # ???? Is 'wantread' always correct?
        # ???? Rather than waiting for a read, should we use a timer or
        # ????       something?
        raise _ml.TLSWantRead()

    def __readFn(self):
        """Hook to implement read"""
        while 1:
            r = self.__con.read(1024) #may throw want*
            if r == 0:
                trace("read returned 0 -- shutting down (fd %s)", self.fd)
                self.shutdown(err=0)
                return
            else:
                assert isinstance(r, StringType)
                trace("read got %s bytes (fd %s)", len(r), self.fd)
                self.__inbuf.append(r)
                self.__inbuflen += len(r)
                if not self.__con.pending():
                    break

        if self.__terminator and len(self.__inbuf) > 1:
            self.__inbuf = ["".join(self.__inbuf)]

        if self.__expectReadLen and self.__inbuflen > self.__expectReadLen:
            warn("Protocol violation: too much data. Closing connection to %s",
                 self.address)
            self.shutdown(err=1, retriable=0)
            return

        if self.__terminator and stringContains(self.__inbuf[0],
                                                self.__terminator):
            trace("read found terminator (fd %s)", self.fd)
            self.__server.unregister(self)
            self.finished()

        if self.__expectReadLen and (self.__inbuflen == self.__expectReadLen):
            trace("read got enough (fd %s)", self.fd)
            self.__server.unregister(self)
            self.finished()

    def __writeFn(self):
        """Hook to implement write"""
        out = self.__outbuf
        while len(out):
            r = self.__con.write(out) # may throw

            assert r > 0
            out = out[r:]

        self.__outbuf = out
        if len(out) == 0:
            self.finished()

    def __handshakeFn(self):
        """Callback used when we're renegotiating the connection key.  Must
           only be used from client mode."""
        assert not self.__serverMode
        self.__con.do_handshake() #may throw want*
        self.__server.unregister(self)
        self.finished()

    def startRenegotiate(self):
        """Begin renegotiation the connection key.  Must only be called from
           client mode."""
        self.__con.renegotiate() # Succeeds immediately.
        self.__state = self.__handshakeFn
        self.__server.registerBoth(self) #????

    def tryTimeout(self, cutoff):
        if self.lastActivity <= cutoff:
            warn("Connection to %s timed out", self.address)
            # ????     I'm not sure this is right.  Instead of just killing
            # ???? the socket, should we shut down the SSL too?
            self.__sock.close()
            if not self.__failed:
                self.__failed = 1
                self.handleFail(1)
            self.remove()

    def handleRead(self):
        self.__handleAll()

    def handleWrite(self):
        self.__handleAll()

    def __handleAll(self):
        """Underlying implementation of TLS connection: traverses as
           many states as possible until some operation blocks on
           reading or writing, or until the current __state becomes
           None.
        """
        self.lastActivity = time.time()

        try:
            # We have a while loop here so that, upon entering a new
            # state, we immediately see if we can go anywhere with it
            # without blocking.
            while self.__state is not None:
                self.__state()
        except _ml.TLSWantWrite:
            self.__server.registerWriter(self)
        except _ml.TLSWantRead:
            self.__server.registerReader(self)
        except _ml.TLSClosed:
            if self.__connecting:
                warn("Couldn't connect to server %s", self.address)
            else:
                warn("Unexpectedly closed connection to %s", self.address)
            self.__sock.close()
            if not self.__failed:
                self.__failed = 1
                self.handleFail(retriable=1)
            self.remove()
        except _ml.TLSError, e:
            if self.__state != self.__shutdownFn:
                warn("Unexpected error: %s. Closing connection to %s.",
                     e, self.address)
                self.shutdown(err=1, retriable=1)
                self.__handleAll() # Try another round of the loop.
            else:
                warn("Error while shutting down: closing connection to %s",
                     self.address)
                self.__sock.close()
                if not self.__failed:
                    self.__failed = 1
                    self.handleFail(1)
                self.remove()
        else:
            # We are in no state at all; disconnect
            self.remove()

    def finished(self):
        """Called whenever a connect, accept, read, or write is finished."""
        pass

    def shutdownFinished(self):
        """Called when this connection is successfully shut down."""
        pass

    def shutdownFailed(self):
        """Called when this connection goes down hard."""
        pass

    def shutdown(self, err=0, retriable=0):
        """Begin a shutdown on this connection"""
        if err and not self.__failed:
            self.handleFail(retriable)
            #self.__sock.close()
            #self.__state = None
            #return
            
        self.__state = self.__shutdownFn

    def fileno(self):
        return self.fd

    def getInput(self):
        """Returns the current contents of the input buffer."""
        return "".join(self.__inbuf)

    def pullInput(self):
        """Returns the current contents of the input buffer, and clears the
           input buffer."""
        inp = "".join(self.__inbuf)
        del self.__inbuf[:]
        self.__inbuflen = 0
        return inp

    def getTLSConnection(self):
        return self.__con

    def handleFail(self, retriable=0):
        """Called when we shutdown with an error."""
        pass

    def remove(self):
        """Called when this connection is shut down successfully or closed
           with an error.  Removes all state associated with this connection.
           """
        self.__server.unregister(self)
        self.__server = None

        # Under heavy loads, having circular references through __state and
        # __finished can keep the connection object alive for many garbage
        # collections.  Let's nuke those so it is deleted right away.
        self.__state = None
        self.finished = None


#----------------------------------------------------------------------
# Implementation for MMTP.

# The protocol string to send.
PROTOCOL_STRING      = "MMTP 0.3\r\n"
# The protocol specification to expect.
PROTOCOL_RE          = re.compile("MMTP ([^\s\r\n]+)\r\n")
# Control line for sending a message.
SEND_CONTROL         = "SEND\r\n"
# Control line for sending padding.
JUNK_CONTROL         = "JUNK\r\n"
# Control line for acknowledging a message
RECEIVED_CONTROL     = "RECEIVED\r\n"
# Control line for refusing a message
REJECTED_CONTROL     = "REJECTED\r\n"
SEND_CONTROL_LEN     = len(SEND_CONTROL)
RECEIVED_CONTROL_LEN = len(RECEIVED_CONTROL)
SEND_RECORD_LEN      = len(SEND_CONTROL) + MESSAGE_LEN + DIGEST_LEN
RECEIVED_RECORD_LEN  = RECEIVED_CONTROL_LEN + DIGEST_LEN

class MMTPServerConnection(SimpleTLSConnection):
    '''An asynchronous implementation of the receiving side of an MMTP
       connection.'''
    ## Fields:
    # messageConsumer: a function to call with all received messages.
    # finished: callback when we're done with a read or write; see
    #     SimpleTLSConnection.
    # protocol: The MMTP protocol version we're currently using, or None
    #     if negotiation hasn't completed.
    # PROTOCOL_VERSIONS: (static) a list of protocol versions we allow,
    #     in decreasing order of preference.
    # junkCallback: a no-arguments function called when we receive a
    #     junk packet.
    # rejectCallback: a no-arguments function called when we reject a packet.
    # rejectPackets: a flag: should we reject incoming packets?
    PROTOCOL_VERSIONS = [ '0.3' ]
    def __init__(self, sock, tls, consumer, rejectPackets=0):
        """Create an MMTP connection to receive messages sent along a given
           socket.  When valid packets are received, pass them to the
           function 'consumer'.  If rejectPackets is true, then instead of
           accepting packets, we refuse them instead--for example, if the
           because the disk is full."""
        SimpleTLSConnection.__init__(self, sock, tls, 1,
                                     "%s:%s"%sock.getpeername())
        
        EventStats.log.receivedConnection() #FFFF addr

        self.messageConsumer = consumer
        self.junkCallback = lambda : None
        self.rejectCallback = lambda : None
        self.finished = self.__setupFinished
        self.protocol = None
        self.rejectPackets = rejectPackets

    def __setupFinished(self):
        """Called once we're done accepting.  Begins reading the protocol
           string.
        """
        self.finished = self.__receivedProtocol
        self.expectRead(1024, '\n')

    def __receivedProtocol(self):
        """Called once we're done reading the protocol string.  Either
           rejects, or sends our response.
        """
        trace("done w/ client sendproto to %s", self.address)
        inp = self.pullInput()
        m = PROTOCOL_RE.match(inp)

        if not m:
            warn("Bad protocol list: %r.  Closing connection to %s", inp,
                 self.address)
            self.shutdown(err=1)
            return
        protocols = m.group(1).split(",")
        for p in self.PROTOCOL_VERSIONS:
            if p in protocols:
                trace("Using protocol %s with %s", p, self.address)
                self.protocol = p
                self.finished = self.__sentProtocol
                self.beginWrite("MMTP %s\r\n"% p)
                return

        warn("Unsupported protocol list.  Closing connection to %s",
             self.address)
        self.shutdown(err=1)
        return

    def __sentProtocol(self):
        """Called once we're done sending our protocol response.  Begins
           reading a packet from the line.
        """
        trace("done w/ server sendproto to %s", self.address)
        self.finished = self.__receivedMessage
        self.expectRead(SEND_RECORD_LEN)

    def __receivedMessage(self):
        """Called once we've read a message from the line.  Checks the
           digest, and either rejects or begins sending an ACK."""
        data = self.pullInput()
        msg = data[SEND_CONTROL_LEN:-DIGEST_LEN]
        digest = data[-DIGEST_LEN:]

        if data.startswith(JUNK_CONTROL):
            expectedDigest = sha1(msg+"JUNK")
            replyDigest = sha1(msg+"RECEIVED JUNK")
            replyControl = RECEIVED_CONTROL
            isJunk = 1
        elif data.startswith(SEND_CONTROL):
            expectedDigest = sha1(msg+"SEND")
            if self.rejectPackets:
                replyDigest = sha1(msg+"REJECTED")
                replyControl = REJECTED_CONTROL
            else:
                replyDigest = sha1(msg+"RECEIVED")
                replyControl = RECEIVED_CONTROL
            isJunk = 0
        else:
            warn("Unrecognized command (%r) from %s.  Closing connection.",
                 data[:4], self.address)
            self.shutdown(err=1)
            return
        if expectedDigest != digest:
            warn("Invalid checksum from %s. Closing connection",
                 self.address)
            self.shutdown(err=1)
            return
        else:
            if isJunk:
                debug("Link padding received from %s; Checksum valid.",
                      self.address)
            else:
                debug("Packet received from %s; Checksum valid.", self.address)
            self.finished = self.__sentAck
            self.beginWrite(replyControl+replyDigest)
            if isJunk:
                self.junkCallback()
            elif self.rejectPackets:
                self.rejectCallback()
            else:
                self.messageConsumer(msg)

    def __sentAck(self):
        """Called once we're done sending an ACK.  Begins reading a new
           message."""
        debug("Send ACK for message from %s", self.address)
        self.finished = self.__receivedMessage
        self.expectRead(SEND_RECORD_LEN)

    def remove(self):
        self.messageConsumer = None
        self.finished = None
        self.junkCallback = None
        self.rejectCallback = None
        
        SimpleTLSConnection.remove(self)

#----------------------------------------------------------------------

NULL_KEYID = "\x00"*20

class DeliverableMessage:
    """Interface to be implemented by messages deliverable by MMTP """
    def __init__(self):
        pass
    def getContents(self):
        raise NotImplementedError
    def succeeded(self):
        raise NotImplementedError
    def failed(self,retriable=0):
        raise NotImplementedError

class DeliverablePacket(DeliverableMessage):
    """Implementation of DeliverableMessage.

       Wraps a ServerQueue.PendingMessage object for a queue holding
       PacketHandler.RelayPacket objects."""
    def __init__(self, pending):
        DeliverableMessage.__init__(self)
        self.pending = pending
    def succeeded(self):
        self.pending.succeeded()
    def failed(self,retriable=0):
        self.pending.failed(retriable=retriable)
    def getContents(self):
        return self.pending.getMessage().getPacket()

class MMTPClientConnection(SimpleTLSConnection):
    """Asynchronous implementation of the sending ("client") side of a
       mixminion connection."""
    ## Fields:
    # ip, port, keyID, messageList, finishedCallback, certCache:
    #   As described in the docstring for __init__ below.  We remove entries
    #   from the front of messageList/handleList as we begin sending them.
    # _curMessage, _curHandle: Correspond to the message that we are
    #     currently trying to deliver.  If _curHandle is None, _curMessage
    #     is a control string.  If _curHandle is a DeliverableMessage,
    #     _curMessage is the corresponding 32KB string.
    # junk: A list of 32KB padding chunks that we're going to send.  We
    #   pregenerate these to avoid timing attacks.  They correspond to
    #   the 'JUNK' entries in messageList.
    # isJunk: flag.  Is the current chunk padding?
    # expectedDigest: The digest we expect to receive in response to the
    #   current chunk.
    # protocol: The MMTP protocol version we're currently using, or None
    #     if negotiation hasn't completed.
    # PROTOCOL_VERSIONS: (static) a list of protocol versions we allow,
    #     in the order we offer them.
    # active: Are we currently able to send messages to a server?  Boolean.

    PROTOCOL_VERSIONS = [ '0.3' ]
    def __init__(self, context, ip, port, keyID, messageList,
                 finishedCallback=None, certCache=None):
        """Create a connection to send messages to an MMTP server.
           Raises socket.error if the connection fails.

           ip -- The IP of the destination server.
           port -- The port to connect to.
           keyID -- None, or the expected SHA1 hash of the server's public key
           messageList -- a list of message payloads and control strings.
               Message payloads must implement the DeliverableMessage
               interface above; allowable control strings are either
               string "JUNK", which sends 32KB of padding; or the control
               string "RENEGOTIATE" which renegotiates the connection key.
           finishedCallback -- None, or a function to be called when this
              connection is closed.
           certCache -- an instance of PeerCertificateCache to use for
              checking server certificates.
        """
        # Generate junk before connecting to avoid timing attacks
        self.junk = []
        self.messageList = []
        self.active = 1

        self.addMessages(messageList)

        if certCache is None:
            certCache = PeerCertificateCache()
        self.certCache = certCache

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(0)
        self.keyID = keyID
        self.ip = ip
        self.port = port
        try:
            sock.connect((ip, port))
        except socket.error, e:
            # This will always raise an error, since we're nonblocking.  That's
            # okay... but it had better be EINPROGRESS or the local equivalent.
            if e[0] not in IN_PROGRESS_ERRNOS:
                raise e

        tls = context.sock(sock)

        SimpleTLSConnection.__init__(self, sock, tls, 0, "%s:%s"%(ip,port))
        self.finished = self.__setupFinished
        self.finishedCallback = finishedCallback
        self.protocol = None
        self._curMessage = self._curHandle = None

        EventStats.log.attemptedConnect() #FFFF addr        
        debug("Opening client connection to %s", self.address)

    def isActive(self):
        """Return true iff messages added to this connection via addMessages
           will be delivered.  isActive() will return false if, for example,
           the connection is currently shutting down."""
        return self.active

    def addMessages(self, messages):
        """Given a list of messages and control strings, as given to
           MMTPServer.__init__, cause this connection to deliver that new
           set of messages after it's done with those it's currently
           sending.
        """
        assert self.active
        for m in messages:
            if m == "JUNK":
                self.junk.append(getCommonPRNG().getBytes(MESSAGE_LEN))
            elif m == 'RENEGOTIATE':
                pass
            else:
                EventStats.log.attemptedRelay() #FFFF addr
        self.messageList.extend(messages)

    def getAddr(self):
        """Return an (ip,port,keyID) tuple for this connection"""
        return self.ip, self.port, self.keyID

    def __setupFinished(self):
        """Called when we're done with the client side negotations.
           Begins sending the protocol string.
        """
        try:
            self.certCache.check(self.getTLSConnection(), self.keyID,
                                 self.address)
        except MixProtocolError, e:
            warn("Certificate error: %s.  Shutting down connection to %s",
                 e, self.address)
            self.shutdown(err=1,retriable=1)
            return
        else:
            debug("KeyID is valid from %s", self.address)

        EventStats.log.successfulConnect()

        self.beginWrite("MMTP %s\r\n"%(",".join(self.PROTOCOL_VERSIONS)))
        self.finished = self.__sentProtocol

    def __sentProtocol(self):
        """Called when we're done sending the protocol string.  Begins
           reading the server's response.
        """
        self.expectRead(1024, '\n')
        self.finished = self.__receivedProtocol

    def __receivedProtocol(self):
        """Called when we're done receiving the protocol string.  Begins
           sending a packet, or exits if we're done sending.
        """
        inp = self.pullInput()

        for p in self.PROTOCOL_VERSIONS:
            if inp == 'MMTP %s\r\n'%p:
                trace("Speaking MMTP version %s with %s", p, self.address)
                self.protocol = inp
                self.beginNextMessage()
                return

        warn("Invalid protocol.  Closing connection to %s", self.address)
             
        # This isn't retriable; we don't talk to servers we don't
        # understand.
        self.shutdown(err=1,retriable=0)
        return

    def beginNextMessage(self):
        """Start writing a message to the connection."""
        if not self.messageList:
            self.shutdown(0)
            return
        
        self._getNextMessage()
        msg = self._curMessage
        if msg == 'RENEGOTIATE':
            self.finished = self.beginNextMessage
            self.startRenegotiate()
            return
        elif msg == 'JUNK':
            msg = self.junk[0]
            del self.junk[0]
            self.expectedDigest = sha1(msg+"RECEIVED JUNK")
            self.rejectDigest = sha1(msg+"REJECTED")
            msg = JUNK_CONTROL+msg+sha1(msg+"JUNK")
            self.isJunk = 1
        else:
            self.expectedDigest = sha1(msg+"RECEIVED")
            self.rejectDigest = sha1(msg+"REJECTED")
            msg = SEND_CONTROL+msg+sha1(msg+"SEND")
            self.isJunk = 0
        
        assert len(msg) == SEND_RECORD_LEN
        self.beginWrite(msg)
        self.finished = self.__sentMessage

    def _getNextMessage(self):
        """Helper function: pull the next _curHandle, _curMessage pair from
           self.messageList."""
        m = self.messageList[0]
        del self.messageList[0]
        if hasattr(m, 'getContents'):
            self._curHandle = m
            self._curMessage = m.getContents()
        else:
            self._curHandle = None
            self._curMessage = m

    def __sentMessage(self):
        """Called when we're done sending a message.  Begins reading the
           server's ACK."""

        debug("Message delivered to %s", self.address)
        self.finished = self.__receivedAck
        self.expectRead(RECEIVED_RECORD_LEN)

    def __receivedAck(self):
       """Called when we're done reading the ACK.  If the ACK is bad,
          closes the connection.  If the ACK is correct, removes the
          just-sent message from the connection's internal queue, and
          calls sentCallback with the sent message.

          If there are more messages to send, begins sending the next.
          Otherwise, begins shutting down.
       """
       trace("received ack from %s", self.address)
       inp = self.pullInput()
       rejected = 0
       if inp == REJECTED_CONTROL+self.rejectDigest:
           debug("Message rejected from %s", self.address)
           rejected = 1
       elif inp != (RECEIVED_CONTROL+self.expectedDigest):
           # We only get bad ACKs if an adversary somehow subverts TLS's
           # checksumming.  That's not fixable.
           self.shutdown(err=1,retriable=0)
           return
       else:
           debug("Received valid ACK for message from %s", self.address)

       if not self.isJunk:
           if not rejected:
               self._curHandle.succeeded()
               EventStats.log.successfulRelay() #FFFF addr
           else:
               self._curHandle.failed(retriable=1)
               EventStats.log.failedRelay() #FFFF addr

       self._curMessage = self._curHandle = None

       self.beginNextMessage()

    def handleFail(self, retriable):
        """Invoked when we shutdown with an error."""
        if retriable:
            statFn = EventStats.log.failedRelay
        else:
            statFn = EventStats.log.unretriableRelay
        if self.finished is self.__setupFinished:
            EventStats.log.failedConnect() #FFFF addr
        if self._curHandle is not None:
            self._curHandle.failed(retriable)
            statFn()
        for msg in self.messageList:
            try:
                msg.failed(retriable)
                statFn()
            except AttributeError:
                pass
        self._messageList = []
        self._curMessage = self._curHandle = None

    def shutdown(self, err=0, retriable=0):
        self.active = 0
        SimpleTLSConnection.shutdown(self, err=err, retriable=retriable)

    def remove(self):
        self.active = 0
        if self.finishedCallback is not None:
            self.finishedCallback()
        self.finishedCallback = None
        
        SimpleTLSConnection.remove(self)


LISTEN_BACKLOG = 128
class MMTPAsyncServer(AsyncServer):
    """A helper class to invoke AsyncServer, MMTPServerConnection, and
       MMTPClientConnection, with a function to add new connections, and
       callbacks for message success and failure."""
    ##
    # context: a TLSContext object to use for newly received connections.
    # clientConByAddr: A map from 3-tuples returned by MMTPClientConnection.
    #     getAddr, to MMTPClientConnection objects.
    # certificateCache: A PeerCertificateCache object.
    # listener: A ListenConnection object.
    # _timeout: The number of seconds of inactivity to allow on a connection
    #     before formerly shutting it down.
    def __init__(self, config, tls):
        AsyncServer.__init__(self)

        self.context = tls
        # FFFF Don't always listen; don't always retransmit!
        # FFFF Support listening on multiple IPs

        IP = config['Incoming/MMTP'].get('ListenIP')
        if IP is None:
            IP = config['Incoming/MMTP']['IP']

        port =  config['Incoming/MMTP'].get('ListenPort')
        if port is None:
            port = config['Incoming/MMTP']['Port']

        self.listener = ListenConnection(IP, port,
                                         LISTEN_BACKLOG,
                                         self._newMMTPConnection)
        #self.config = config
        self.listener.register(self)
        self._timeout = config['Server']['Timeout'].getSeconds()
        self.clientConByAddr = {}
        self.certificateCache = PeerCertificateCache()

    def setContext(self, context):
        """Change the TLS context used for newly received connections.
           Used to rotate keys."""
        self.context = context

    def getNextTimeoutTime(self, now=None):
        """Return the time at which we next purge connections, if we have
           last done so at time 'now'."""
        if now is None:
            now = time.time()
        return now + self._timeout

    def _newMMTPConnection(self, sock):
        """helper method.  Creates and registers a new server connection when
           the listener socket gets a hit."""
        # FFFF Check whether incoming IP is allowed!
        tls = self.context.sock(sock, serverMode=1)
        sock.setblocking(0)
        con = MMTPServerConnection(sock, tls, self.onMessageReceived)
        con.register(self)
        return con

    def stopListening(self):
        self.listener.shutdown()

    def sendMessages(self, ip, port, keyID, deliverable):
        """Begin sending a set of messages to a given server.

           deliverable is a list of objects obeying the DeliverableMessage
           interface.
        """

        try:
            # Is there an existing connection open to the right server?
            con = self.clientConByAddr[(ip,port,keyID)]
            # If so, is that connection currently sending messages?
            if con.isActive():
                LOG.debug("Queueing %s messages on open connection to %s",
                          len(deliverable), con.address)
                con.addMessages(deliverable)
                return
        except KeyError:
            pass

        try:
            # There isn't any connection to the right server. Open one...
            addr = (ip, port, keyID)
            finished = lambda addr=addr, self=self: self.__clientFinished(addr)
            con = MMTPClientConnection(self.context,
                                     ip, port, keyID, deliverable,
                                     finishedCallback=finished,
                                     certCache=self.certificateCache)
            con.register(self)
            # ...and register it in clientConByAddr
            assert addr == con.getAddr()
            self.clientConByAddr[addr] = con
        except socket.error, e:
            LOG.error("Unexpected socket error connecting to %s:%s: %s",
                      ip, port, e)
            EventStats.log.failedConnect() #FFFF addr
            for m in self.messageList:
                try:
                    m.failed(1)
                except AttributeError:
                    pass

    def __clientFinished(self, addr):
        """Called when a client connection runs out of messages to send."""
        try:
            del self.clientConByAddr[addr]
        except KeyError:
            warn("Didn't find client connection to %s in address map",
                 addr)

    def onMessageReceived(self, msg):
        """Abstract function.  Called when we get a message"""
        pass


