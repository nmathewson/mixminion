# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPServer.py,v 1.63 2003/12/13 19:10:16 nickm Exp $
"""mixminion.MMTPServer

   This package implements the Mixminion Transfer Protocol as described
   in the Mixminion specification.  It uses a select loop to provide
   a nonblocking implementation of *both* the client and the server sides
   of the protocol.

   If you just want to send packets into the system, use MMTPClient.
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
import sys
import time
from types import StringType

import mixminion._minionlib as _ml
from mixminion.Common import MixError, MixFatalError, MixProtocolError, \
     LOG, stringContains, MessageQueue, QueueEmpty
from mixminion.Crypto import sha1, getCommonPRNG
from mixminion.Packet import PACKET_LEN, DIGEST_LEN, IPV4Info, MMTPHostInfo
from mixminion.MMTPClient import PeerCertificateCache
from mixminion.NetUtils import IN_PROGRESS_ERRNOS, getProtocolSupport, AF_INET, AF_INET6
import mixminion.server.EventStats as EventStats
from mixminion.Filestore import CorruptedFile
from mixminion.ServerInfo import displayServer

__all__ = [ 'AsyncServer', 'ListenConnection', 'MMTPServerConnection',
            'MMTPClientConnection' ]

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
        self.wrExceptions = {}

    def process(self, timeout):
        """If any relevant file descriptors become available within
           'timeout' seconds, call the appropriate methods on their
           connections and return immediately after. Otherwise, wait
           'timeout' seconds and return.

           If we receive an unblocked signal, return immediately.
           """

        readfds = self.readers.keys()
        writefds = self.writers.keys()
        exfds = self.wrExceptions.keys()
        if not (readfds or writefds):
            # Windows 'select' doesn't timeout properly when we aren't
            # selecting on any FDs.  This should never happen to us,
            # but we'll check for it anyway.
            time.sleep(timeout)
            return

        try:
            readfds,writefds,exfds = select.select(readfds,writefds,exfds,
                                                   timeout)
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
            #DOCDOC -- for win32 connects.
            self.wrExceptions[fd].handleWrite()
            #if self.readers.has_key(fd): del self.readers[fd]
            #if self.writers.has_key(fd): del self.writers[fd]

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
            if self.wrExceptions.has_key(fd):
                del self.wrExceptions[fd]

    def registerWriter(self, writer, connecting=0):
        """Register a connection as a writer.  The connection's 'handleWrite'
           method will be called whenever the buffer is free for writing.
        """
        fd = writer.fileno()
        self.writers[fd] = writer
        if connecting and sys.platform == 'win32':
            #DOCDOC
            self.wrExceptions[fd] = writer
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
    def __init__(self, family, ip, port, backlog, connectionFactory):
        """Create a new ListenConnection"""
        self.ip = ip
        self.port = port
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setblocking(0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.ip, self.port))
        except socket.error, e:
            raise MixFatalError("Error while trying to bind to %s:%s: %s"%(
                self.ip, self.port, e))
        self.sock.listen(backlog)
        self.connectionFactory = connectionFactory
        LOG.info("Listening at %s on port %s (fd %s)",
                 ip, port, self.sock.fileno())

    def register(self, server):
        server.registerReader(self)
        self.server = server

    def handleRead(self):
        con, addr = self.sock.accept()
        LOG.debug("Accepted connection from %s (fd %s)", addr, con.fileno())
        rw = self.connectionFactory(con)
        rw.register(self.server)

    def shutdown(self):
        LOG.debug("Closing listener connection (fd %s)", self.sock.fileno())
        self.server.unregister(self)
        del self.server
        self.sock.close()
        LOG.info("Server connection closed")

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
           address -- A human-readable address for this server.
        """
        self.__sock = sock
        self.__con = tls
        self.fd = self.__con.fileno()
        self.lastActivity = time.time()
        self.__serverMode = serverMode
        self.__failed = 0
        self.__inbuf = []
        self.__inbuflen = 0
        self.__awaitingShutdown = 0

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
            server.registerWriter(self, connecting=1)

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
        # ourself.  Thus, we do the following:
        #

        # We try to shutdown.  This either acknowledges the other
        # side's attempt to close the stream, or sends a request to
        # close the stream.
        #      - If OpenSSL says we're finished, great!
        #      - If not, and we've already tried to shutdown, then freak out;
        #        that's not supposed to happen.
        #      - If we're not finished, and this *is* our first time trying,
        #        then start *reading* from the incoming socket.  We should
        #        get an acknowledgement for our close request soon when read
        #        returns a 0.  Then, calling shutdown again should mean we're
        #        done.

        while 1:
            done = self.__con.shutdown() # may throw want*
            if not done and self.__awaitingShutdown:
                LOG.error("Shutdown returned zero twice from %s -- bailing",
                          self.address)
                done = 1
            if done:
                LOG.debug("Got a completed shutdown from %s", self.address)
                self.__sock.close()
                self.__state = None
                self.shutdownFinished()
                return
            else:
                LOG.trace("Shutdown returned zero -- entering read mode")
                self.__awaitingShutdown = 1
                if 1:
                    self.finished = self.__readTooMuch
                    self.expectRead(128)
                raise _ml.TLSWantRead()

    def __readTooMuch(self):
        """Helper function -- called if we read too much data while we're
           shutting down."""
        LOG.error("Read over 128 bytes of unexpected data from closing "
                  "connection to %s", self.address)
        self.__sock.close()
        self.state = None

    def __readFn(self):
        """Hook to implement read"""
        while 1:
            r = self.__con.read(1024) #may throw want*
            if r == 0:
                if self.__awaitingShutdown:
                    LOG.debug("read returned 0: shutdown complete (fd %s)",
                              self.fd)
                else:
                    LOG.debug("read returned 0: shutting down (fd %s)",self.fd)
                self.shutdown(err=0)
                return
            else:
                assert isinstance(r, StringType)
                LOG.trace("read got %s bytes (fd %s)", len(r), self.fd)
                self.__inbuf.append(r)
                self.__inbuflen += len(r)
                if not self.__con.pending():
                    break

        if self.__terminator and len(self.__inbuf) > 1:
            self.__inbuf = ["".join(self.__inbuf)]

        if self.__expectReadLen and self.__inbuflen > self.__expectReadLen:
            LOG.warn("Protocol violation: too much data. Closing connection to %s",
                     self.address)
            self.shutdown(err=1, retriable=0)
            return

        if self.__terminator and stringContains(self.__inbuf[0],
                                                self.__terminator):
            LOG.trace("read found terminator (fd %s)", self.fd)
            self.__server.unregister(self)
            self.finished()

        if self.__expectReadLen and (self.__inbuflen == self.__expectReadLen):
            LOG.trace("read got enough (fd %s)", self.fd)
            self.__server.unregister(self)
            self.finished()

    def __writeFn(self):
        """Hook to implement write"""
        while len(self.__outbuf):
            r = self.__con.write(self.__outbuf) # may throw

            assert r > 0
            self.__outbuf = self.__outbuf[r:]

        if len(self.__outbuf) == 0:
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
            LOG.warn("Connection to %s timed out", self.address)
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
                LOG.warn("Couldn't connect to %s", self.address)
            else:
                LOG.warn("Unexpectedly closed connection to %s", self.address)
            self.__sock.close()
            if not self.__failed:
                self.__failed = 1
                self.handleFail(retriable=1)
            self.remove()
        except _ml.TLSError, e:
            if self.__state != self.__shutdownFn and (not self.__awaitingShutdown):
                e = str(e)
                if e == 'wrong version number':
                    e = 'wrong version number (or failed handshake)'
                LOG.warn("Unexpected TLS error: %s. Closing connection to %s.",
                         e, self.address)
                self.shutdown(err=1, retriable=1)
                self.__handleAll() # Try another round of the loop.
            else:
                LOG.warn("Error while shutting down: closing connection to %s",
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
# Control line for sending a packet
SEND_CONTROL         = "SEND\r\n"
# Control line for sending padding.
JUNK_CONTROL         = "JUNK\r\n"
# Control line for acknowledging a packet
RECEIVED_CONTROL     = "RECEIVED\r\n"
# Control line for refusing a packet
REJECTED_CONTROL     = "REJECTED\r\n"
SEND_CONTROL_LEN     = len(SEND_CONTROL)
RECEIVED_CONTROL_LEN = len(RECEIVED_CONTROL)
SEND_RECORD_LEN      = len(SEND_CONTROL) + PACKET_LEN + DIGEST_LEN
RECEIVED_RECORD_LEN  = RECEIVED_CONTROL_LEN + DIGEST_LEN

class MMTPServerConnection(SimpleTLSConnection):
    '''An asynchronous implementation of the receiving side of an MMTP
       connection.'''
    ## Fields:
    # packetConsumer: a function to call with all received packets.
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
        """Create an MMTP connection to receive packets sent along a given
           socket.  When valid packets are received, pass them to the
           function 'consumer'.  If rejectPackets is true, then instead of
           accepting packets, we refuse them instead--for example, if the
           because the disk is full."""
        SimpleTLSConnection.__init__(self, sock, tls, 1,
                                     "%s:%s"%sock.getpeername())

        EventStats.log.receivedConnection() #FFFF addr

        self.packetConsumer = consumer
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
        LOG.trace("done w/ client sendproto to %s", self.address)
        inp = self.pullInput()
        m = PROTOCOL_RE.match(inp)

        if not m:
            LOG.warn("Bad protocol list: %r.  Closing connection to %s", inp,
                     self.address)
            self.shutdown(err=1)
            return
        protocols = m.group(1).split(",")
        for p in self.PROTOCOL_VERSIONS:
            if p in protocols:
                LOG.trace("Using protocol %s with %s", p, self.address)
                self.protocol = p
                self.finished = self.__sentProtocol
                self.beginWrite("MMTP %s\r\n"% p)
                return

        LOG.warn("Unsupported protocol list.  Closing connection to %s",
                 self.address)
        self.shutdown(err=1)
        return

    def __sentProtocol(self):
        """Called once we're done sending our protocol response.  Begins
           reading a packet from the line.
        """
        LOG.trace("done w/ server sendproto to %s", self.address)
        self.finished = self.__receivedPacket
        self.expectRead(SEND_RECORD_LEN)

    def __receivedPacket(self):
        """Called once we've read a packet from the line.  Checks the
           digest, and either rejects or begins sending an ACK."""
        data = self.pullInput()
        pkt = data[SEND_CONTROL_LEN:-DIGEST_LEN]
        digest = data[-DIGEST_LEN:]

        if data.startswith(JUNK_CONTROL):
            expectedDigest = sha1(pkt+"JUNK")
            replyDigest = sha1(pkt+"RECEIVED JUNK")
            replyControl = RECEIVED_CONTROL
            isJunk = 1
        elif data.startswith(SEND_CONTROL):
            expectedDigest = sha1(pkt+"SEND")
            if self.rejectPackets:
                replyDigest = sha1(pkt+"REJECTED")
                replyControl = REJECTED_CONTROL
            else:
                replyDigest = sha1(pkt+"RECEIVED")
                replyControl = RECEIVED_CONTROL
            isJunk = 0
        else:
            LOG.warn("Unrecognized command (%r) from %s.  Closing connection.",
                     data[:4], self.address)
            self.shutdown(err=1)
            return
        if expectedDigest != digest:
            LOG.warn("Invalid checksum from %s. Closing connection",
                 self.address)
            self.shutdown(err=1)
            return
        else:
            if isJunk:
                LOG.debug("Link padding received from %s; Checksum valid.",
                          self.address)
            else:
                LOG.debug("Packet received from %s; Checksum valid.",
                          self.address)
            self.finished = self.__sentAck
            self.beginWrite(replyControl+replyDigest)
            if isJunk:
                self.junkCallback()
            elif self.rejectPackets:
                self.rejectCallback()
            else:
                self.packetConsumer(pkt)

    def __sentAck(self):
        """Called once we're done sending an ACK.  Begins reading a new
           packet."""
        LOG.debug("Send ACK for packet from %s", self.address)
        self.finished = self.__receivedPacket
        self.expectRead(SEND_RECORD_LEN)

    def remove(self):
        self.packetConsumer = None
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
        assert hasattr(pending, 'succeeded')
        assert hasattr(pending, 'failed')
        assert hasattr(pending, 'getMessage')
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
    # ip, port, keyID, packetList, finishedCallback, certCache:
    #   As described in the docstring for __init__ below.  We remove entries
    #   from the front of packetList/handleList as we begin sending them.
    # _curPacekt, _curHandle: Correspond to the packet that we are
    #     currently trying to deliver.  If _curHandle is None, _curPacket
    #     is a control string.  If _curHandle is a DeliverableMessage,
    #     _curPacket is the corresponding 32KB string.
    # junk: A list of 32KB padding chunks that we're going to send.  We
    #   pregenerate these to avoid timing attacks.  They correspond to
    #   the 'JUNK' entries in pacektList.
    # isJunk: flag.  Is the current chunk padding?
    # expectedDigest: The digest we expect to receive in response to the
    #   current chunk.
    # protocol: The MMTP protocol version we're currently using, or None
    #     if negotiation hasn't completed.
    # PROTOCOL_VERSIONS: (static) a list of protocol versions we allow,
    #     in the order we offer them.
    # active: Are we currently able to send packets to the server?  Boolean.

    PROTOCOL_VERSIONS = [ '0.3' ]
    def __init__(self, context, ip, port, keyID, packetList,
                 finishedCallback=None, certCache=None,
                 address=None):
        """Create a connection to send packets to an MMTP server.
           Raises socket.error if the connection fails.

           ip -- The IP of the destination server.
           port -- The port to connect to.
           keyID -- None, or the expected SHA1 hash of the server's public key
           packetList -- a list of packets and control strings.
               Packets must implement the DeliverableMessage
               interface above; allowable control strings are either
               string "JUNK", which sends 32KB of padding; or the control
               string "RENEGOTIATE" which renegotiates the connection key.
           finishedCallback -- None, or a function to be called when this
              connection is closed.
           certCache -- an instance of PeerCertificateCache to use for
              checking server certificates.
           address -- a human-readable description of the destination server.
        """
        # Generate junk before connecting to avoid timing attacks
        self.junk = []
        self.packetList = []
        self.active = 1

        self.addPackets(packetList)

        if certCache is None:
            certCache = PeerCertificateCache()
        self.certCache = certCache
        if ':' in ip:
            family = AF_INET6
        else:
            family = AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
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

        if address is None:
            address = "%s:%s"%(ip,port)
        SimpleTLSConnection.__init__(self, sock, tls, 0, address)
        self.finished = self.__setupFinished
        self.finishedCallback = finishedCallback
        self.protocol = None
        self._curPacket = self._curHandle = None

        EventStats.log.attemptedConnect() #FFFF addr
        LOG.debug("Opening client connection to %s", self.address)

    def isActive(self):
        """Return true iff packets added to this connection via addPackets
           will be delivered.  isActive() will return false if, for example,
           the connection is currently shutting down."""
        return self.active

    def addPackets(self, packets):
        """Given a list of packets and control strings, as given to
           MMTPServer.__init__, cause this connection to deliver that new
           set of packets after it's done with those it's currently
           sending.
        """
        assert self.active
        for pkt in packets:
            if pkt == "JUNK":
                self.junk.append(getCommonPRNG().getBytes(PACKET_LEN))
            elif pkt == 'RENEGOTIATE':
                pass
            else:
                EventStats.log.attemptedRelay() #FFFF addr
        self.packetList.extend(packets)

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
            LOG.warn("Certificate error: %s.  Shutting down connection to %s",
                     e, self.address)
            self.shutdown(err=1,retriable=1)
            return
        else:
            LOG.debug("KeyID is valid from %s", self.address)

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
                LOG.trace("Speaking MMTP version %s with %s", p, self.address)
                self.protocol = inp
                self.beginNextPacket()
                return

        LOG.warn("Invalid protocol.  Closing connection to %s", self.address)

        # This isn't retriable; we don't talk to servers we don't
        # understand.
        self.shutdown(err=1,retriable=0)
        return

    def beginNextPacket(self):
        """Start writing a packet to the connection."""
        self._getNextPacket()
        if not self._curPacket:
            self.shutdown(0)
            return

        pkt = self._curPacket
        if pkt == 'RENEGOTIATE':
            self.finished = self.beginNextPacket
            self.startRenegotiate()
            return
        elif pkt == 'JUNK':
            pkt = self.junk[0]
            del self.junk[0]
            self.expectedDigest = sha1(pkt+"RECEIVED JUNK")
            self.rejectDigest = sha1(pkt+"REJECTED")
            pkt = JUNK_CONTROL+pkt+sha1(pkt+"JUNK")
            self.isJunk = 1
        else:
            self.expectedDigest = sha1(pkt+"RECEIVED")
            self.rejectDigest = sha1(pkt+"REJECTED")
            pkt = SEND_CONTROL+pkt+sha1(pkt+"SEND")
            self.isJunk = 0

        assert len(pkt) == SEND_RECORD_LEN
        self.beginWrite(pkt)
        self.finished = self.__sentPacket

    def _getNextPacket(self):
        """Helper function: pull the next _curHandle, _curPacket pair from
           self.packetList."""
        while self.packetList:
            m = self.packetList[0]
            del self.packetList[0]
            if hasattr(m, 'getContents'):
                self._curHandle = m
                try:
                    self._curPacket = m.getContents()
                except CorruptedFile:
                    pass
                return
            else:
                self._curHandle = None
                self._curPacket = m
                return
        self._curHandle = self._curPacket = None

    def __sentPacket(self):
        """Called when we're done sending a packet.  Begins reading the
           server's ACK."""

        LOG.debug("Packet delivered to %s", self.address)
        self.finished = self.__receivedAck
        self.expectRead(RECEIVED_RECORD_LEN)

    def __receivedAck(self):
       """Called when we're done reading the ACK.  If the ACK is bad,
          closes the connection.  If the ACK is correct, removes the
          just-sent packet from the connection's internal queue, and
          calls sentCallback with the sent packet.

          If there are more packets to send, begins sending the next.
          Otherwise, begins shutting down.
       """
       LOG.trace("received ack from %s", self.address)
       inp = self.pullInput()
       rejected = 0
       if inp == REJECTED_CONTROL+self.rejectDigest:
           LOG.debug("Packet rejected from %s", self.address)
           rejected = 1
       elif inp != (RECEIVED_CONTROL+self.expectedDigest):
           # We only get bad ACKs if an adversary somehow subverts TLS's
           # checksumming.  That's not fixable.
           self.shutdown(err=1,retriable=0)
           return
       else:
           LOG.debug("Received valid ACK for packet sent to %s", self.address)

       if not self.isJunk:
           if not rejected:
               self._curHandle.succeeded()
               EventStats.log.successfulRelay() #FFFF addr
           else:
               self._curHandle.failed(retriable=1)
               EventStats.log.failedRelay() #FFFF addr

       self._curPacket = self._curHandle = None

       self.beginNextPacket()

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
        for pkt in self.packetList:
            try:
                pkt.failed(retriable)
                statFn()
            except AttributeError:
                pass
        self.packetList = []
        self._curPacket = self._curHandle = None

    def shutdown(self, err=0, retriable=0):
        self.active = 0
        if err and self.finished == self.__setupFinished:
            EventStats.log.failedConnect()
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
       callbacks for packet success and failure."""
    ##
    # serverContext: a TLSContext object to use for newly received connections.
    # clientContext: a TLSContext object to use for initiated connections.
    # clientConByAddr: A map from 3-tuples returned by MMTPClientConnection.
    #     getAddr, to MMTPClientConnection objects.
    # certificateCache: A PeerCertificateCache object.
    # listeners: A list of ListenConnection objects.
    # _timeout: The number of seconds of inactivity to allow on a connection
    #     before formerly shutting it down.
    # dnsCache: An instance of mixminion.server.DNSFarm.DNSCache.
    # msgQueue: An instance of MessageQueue to receive notification from DNS
    #     DNS threads.  See _queueSendablePackets for more information.

    def __init__(self, config, servercontext):
        AsyncServer.__init__(self)

        self.serverContext = servercontext
        self.clientContext = _ml.TLSContext_new()
        # FFFF Don't always listen; don't always retransmit!
        # FFFF Support listening on multiple IPs

        ip4_supported, ip6_supported = getProtocolSupport()
        IP, IP6 = None, None
        if ip4_supported:
            IP = config['Incoming/MMTP'].get('ListenIP')
            if IP is None:
                IP = config['Incoming/MMTP'].get('IP')
            if IP is None:
                IP = "0.0.0.0"
        # FFFF Until we get the non-clique situation is supported, we don't
        # FFFF listen on IPv6.
        #if ip6_supported:
        #    IP6 = config['Incoming/MMTP'].get('ListenIP6')
        #    if IP6 is None:
        #        IP6 = "::"

        port =  config['Incoming/MMTP'].get('ListenPort')
        if port is None:
            port = config['Incoming/MMTP']['Port']

        self.listeners = []
        for (supported, addr, family) in [(ip4_supported,IP,AF_INET),
                                          (ip6_supported,IP6,AF_INET6)]:
            if not supported or not addr:
                continue
            listener = ListenConnection(family, addr, port,
                                        LISTEN_BACKLOG,
                                        self._newMMTPConnection)
            self.listeners.append(listener)
            listener.register(self)

        self._timeout = config['Server']['Timeout'].getSeconds()
        self.clientConByAddr = {}
        self.certificateCache = PeerCertificateCache()
        self.dnsCache = None
        self.msgQueue = MessageQueue()

    def connectDNSCache(self, dnsCache):
        """Use the DNSCache object 'DNSCache' to resolve DNS queries for
           this server.
        """
        self.dnsCache = dnsCache

    def setServerContext(self, servercontext):
        """Change the TLS context used for newly received connections.
           Used to rotate keys."""
        self.serverContext = servercontext

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
        tls = self.serverContext.sock(sock, serverMode=1)
        sock.setblocking(0)
        con = MMTPServerConnection(sock, tls, self.onPacketReceived)
        con.register(self)
        return con

    def stopListening(self):
        """Shut down all the listeners for this server.  Does not close open
           connections.
        """
        for listener in self.listeners:
            listener.shutdown()
        self.listeners = []

    def sendPacketsByRouting(self, routing, deliverable):
        """Given a RoutingInfo object (either an IPV4Info or an MMTPHostInfo),
           and a list of DeliverableMessage objects, start sending all the
           corresponding packets to the corresponding sever, doing a DNS
           lookup first if necessary.
        """
        serverName = displayServer(routing)
        if isinstance(routing, IPV4Info):
            self._sendPackets(AF_INET, routing.ip, routing.port,
                              routing.keyinfo, deliverable, serverName)
        else:
            assert isinstance(routing, MMTPHostInfo)
            # This function is a callback for when the DNS lookup is over.
            def lookupDone(name, (family, addr, when),
                           self=self, routing=routing, deliverable=deliverable,
                           serverName=serverName):
                if addr == "NOENT":
                    # The lookup failed, so tell all of the message objects.
                    for m in deliverable:
                        try:
                            m.failed(1)
                        except AttributeError:
                            pass
                else:
                    # We've got an IP address: tell the MMTPServer to start
                    # sending the deliverable packets to that address.
                    self._queueSendablePackets(family, addr,
                                         routing.port, routing.keyinfo,
                                         deliverable, serverName)

            # Start looking up the hostname for the destination, and call
            # 'lookupDone' when we're done.  This is a little fiddly, since
            # 'lookupDone' might get invoked from this thread (if the result
            # is in the cache) or from a DNS thread.
            self.dnsCache.lookup(routing.hostname, lookupDone)

    def _queueSendablePackets(self, family, addr, port, keyID, deliverable,
                              serverName):
        """Helper function: insert the DNS lookup results and list of
           deliverable packets onto self.msgQueue.  Subsequent invocations
           of _sendQueuedPackets will begin sending those packets to their
           destination.

           It is safe to call this function from any thread.
           """
        self.msgQueue.put((family,addr,port,keyID,deliverable,serverName))

    def _sendQueuedPackets(self):
        """Helper function: Find all DNS lookup results and packets in
           self.msgQueue, and begin sending packets to the resulting servers.

           This function should only be called from the main thread.
        """
        while 1:
            try:
                family,addr,port,keyID,deliverable,serverName = \
                                                self.msgQueue.get(block=0)
            except QueueEmpty:
                return
            self._sendPackets(family,addr,port,keyID,deliverable,serverName)

    def _sendPackets(self, family, ip, port, keyID, deliverable, serverName):
        """Begin sending a set of packets to a given server.

           'deliverable' is a list of objects obeying the DeliverableMessage
           interface.
        """
        try:
            # Is there an existing connection open to the right server?
            con = self.clientConByAddr[(ip,port,keyID)]
        except KeyError:
            pass
        else:
            # No exception: There is an existing connection.  But is that
            # connection currently sending packets?
            if con.isActive():
                LOG.debug("Queueing %s packets on open connection to %s",
                          len(deliverable), con.address)
                con.addPackets(deliverable)
                return

        try:
            # There isn't any connection to the right server. Open one...
            addr = (ip, port, keyID)
            finished = lambda addr=addr, self=self: self.__clientFinished(addr)
            con = MMTPClientConnection(self.clientContext,
                                     ip, port, keyID, deliverable,
                                     finishedCallback=finished,
                                     certCache=self.certificateCache,
                                     address=serverName)
        except socket.error, e:
            LOG.error("Unexpected socket error connecting to %s: %s",
                      serverName, e)
            EventStats.log.failedConnect() #FFFF addr
            for m in deliverable:
                try:
                    m.failed(1)
                except AttributeError:
                    pass
        else:
            # No exception: We created the connection successfully.
            # Thus, register it in clientConByAddr
            assert addr == con.getAddr()
            con.register(self)
            self.clientConByAddr[addr] = con

    def __clientFinished(self, addr):
        """Called when a client connection runs out of packets to send."""
        try:
            del self.clientConByAddr[addr]
        except KeyError:
            LOG.warn("Didn't find client connection to %s in address map",
                     addr)

    def onPacketReceived(self, pkt):
        """Abstract function.  Called when we get a packet"""
        pass

    def process(self, timeout):
        """overrides asyncserver.process to call sendQueuedPackets before
           checking fd status.
        """
        self._sendQueuedPackets()
        AsyncServer.process(self, timeout)
