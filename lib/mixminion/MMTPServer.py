# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPServer.py,v 1.8 2002/08/06 16:09:21 nickm Exp $
"""mixminion.MMTPServer

   This package implements the Mixminion Transfer Protocol as described
   in the Mixminion specification.  It uses a select loop to provide
   a nonblocking implementation of *both* the client and the server sides
   of the protocol.

   If you just want to send messages into the system, use MMTPClient.

   XXXX As yet unsupported are: Session resumption, key renegotiation,
   XXXX checking KeyID.

   XXXX: Also unsupported: timeouts."""

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
from mixminion.Common import MixError, MixFatalError, getLog
from mixminion.Crypto import sha1
from mixminion.Packet import MESSAGE_LEN, DIGEST_LEN

__all__ = [ 'AsyncServer', 'ListenConnection', 'MMTPServerConnection',
            'MMTPClientConnection' ]

trace = getLog().trace
info = getLog().info
debug = getLog().info
warn = getLog().warn
error = getLog().error

class AsyncServer:
    """AsyncServer is the core of a general-purpose asynchronous
       select-based server loop.  AsyncServer maintains two lists of
       Connection objects that are waiting for reads and writes
       (respectively), and waits for their underlying sockets to be
       available for the desired operations.
       """
    def __init__(self):
        """Create a new AsyncServer with no readers or writers."""
        self.writers = {}
        self.readers = {}

    def process(self, timeout):
        """If any relevant file descriptors become available within
           'timeout' seconds, call the appropriate methods on their
           connections and return immediately after. Otherwise, wait
           'timeout' seconds and return.

           If we receive an unblocked signal, return immediately.
           """

        trace("%s readers, %s writers" % (len(self.readers),
                                          len(self.writers)))
        
        readfds = self.readers.keys()
        writefds = self.writers.keys()
        try:
            readfds,writefds,exfds = select.select(readfds,writefds,[],timeout)
        except select.error, e:
            if e[0] == errno.EINTR:
                return
            else:
                raise e

        for fd in readfds:
            trace("Got a read on "+str(fd))
            self.readers[fd].handleRead()
        for fd in writefds:
            trace("Got a write on"+str(fd))
            self.writers[fd].handleWrite()
        for fd in exfds:
            trace("Got an exception on"+str(fd))
            if self.readers.has_key(fd): del self.readers[fd]
            if self.writers.has_key(fd): del self.writers[fd]

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

class ListenConnection(Connection):
    """A ListenConnection listens on a given port/ip combination, and calls
       a 'connectionFactory' method whenever a new connection is made to that
       port."""
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
        info("Listening at %s on port %s", ip, port)

    def register(self, server):
        server.registerReader(self)
        self.server = server

    def handleRead(self):
        con, addr = self.sock.accept()
        debug("Accepted connection from %s", addr)
        rw = self.connectionFactory(con)
        rw.register(self.server)

    def shutdown(self):
        debug("Closing server connection")
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
       Reads procede until either a given number of bytes have been received,
       or until a provided terminator has been found.  Writes procede until
       a buffer is exhausted.

       After leaving states 1,2,3,or 4, the connection's "finished" method
       is called.  After leaving state 5, the connection's "shutdownFinished"
       method is called.
    """
    # Fields:
    #    lastActivity: the last time when we had a read or a write.
    #    __con: an underlying TLS object
    #    __state: a callback to use whenever we get a read or a write. May
    #           throw _ml.TLSWantRead or _ml.TLSWantWrite.
    #    __server: an AsyncServer.
    #    __inbuf: A list of strings that we've read since the last expectRead. 
    #    __inbuflen: The total length of all the strings in __inbuf
    #    __expectReadLen: None, or the number of bytes to read before
    #           the current read succeeds.
    #    __terminator: None, or a string which will terminate the current read.
    #    __outbuf: None, or the remainder of the string we're currently
    #           writing.
    
    def __init__(self, sock, tls, serverMode):
        """Create a new SimpleTLSConnection.

           tls -- An underlying TLS connection.
           serverMode -- If true, we start with a server-side negotatiation.
                         otherwise, we start with a client-side negotatiation.
        """
        self.__sock = sock
        self.__con = tls

        if serverMode:
            self.__state = self.__acceptFn
        else:
            self.__state = self.__connectFn

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
        self.__inbuf = []
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
        self.finished()

    def __shutdownFn(self):
        """Hook to implement shutdown."""
        r = self.__con.shutdown() #may throw want*
        if r == 1:
            trace("Got a 1 on shutdown")
            self.__server.unregister(self)
            self.__state = None
            self.__sock.close()
            self.shutdownFinished()
        else:
            trace("Got a 0 on shutdown")

    def __readFn(self):
        """Hook to implement read"""
        while 1:
            r = self.__con.read(1024) #may throw want*
            if r == 0:
                trace("read returned 0.")
                self.shutdown()
                return
            else:
                assert isinstance(r, StringType)
                trace("read got %s bytes" % len(r))
                self.__inbuf.append(r)
                self.__inbuflen += len(r)
                if not self.__con.pending():
                    break

        if self.__terminator and len(self.__inbuf) > 1:
            self.__inbuf = ["".join(self.__inbuf)]

        if self.__expectReadLen and self.__inbuflen > self.__expectReadLen:
            warn("Protocol violation: too much data. Closing connection.")
            self.shutdown(err=1)
            return
         
        if self.__terminator and self.__inbuf[0].find(self.__terminator) > -1:
            trace("read found terminator")
            self.__server.unregister(self)
            self.finished()

        if self.__expectReadLen and (self.__inbuflen == self.__expectReadLen):
            trace("read got enough.")
            self.__server.unregister(self)
            self.finished()

    def __writeFn(self):
        """Hook to implement write"""
        out = self.__outbuf
        while len(out):
            r = self.__con.write(out) # may throw

            if r == 0:
                self.shutdown() #XXXX
                return

            out = out[r:]

        self.__outbuf = out
        if len(out) == 0:
            self.finished()
        
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
            warn("Unexpectedly closed connection")

            self.__sock.close()
            self.__server.unregister(self) 
        except _ml.TLSError:
            if self.__state != self.__shutdownFn:
                warn("Unexpected error: closing connection.")
                self.shutdown(1)
            else:
                warn("Error while shutting down: closing connection.")
                self.__server.unregister(self)
        else:
            # We are in no state at all.
            self.__server.unregister(self)
              
    def finished(self):
        """Called whenever a connect, accept, read, or write is finished."""
        pass

    def shutdownFinished(self):
        """Called when this connection is successfully shut down."""
        pass

    def shutdown(self, err=0):
        """Begin a shutdown on this connection"""
        
        self.__state = self.__shutdownFn
        #self.__server.registerWriter(self)
        
    def fileno(self):
        return self.__con.fileno()

    def getInput(self):
        """Returns the current contents of the input buffer."""
        return "".join(self.__inbuf)

    def getPeerPK(self):
        return self.__con.get_peer_cert_pk()
    
#----------------------------------------------------------------------
PROTOCOL_STRING      = "MMTP 1.0\r\n"
PROTOCOL_RE = re.compile("MMTP ([^\s\r\n]+)\r\n")
SEND_CONTROL         = "SEND\r\n"
JUNK_CONTROL         = "JUNK\r\n"
RECEIVED_CONTROL     = "RECEIVED\r\n"
SEND_CONTROL_LEN     = len(SEND_CONTROL)
RECEIVED_CONTROL_LEN = len(RECEIVED_CONTROL)
SEND_RECORD_LEN      = len(SEND_CONTROL) + MESSAGE_LEN + DIGEST_LEN
RECEIVED_RECORD_LEN  = RECEIVED_CONTROL_LEN + DIGEST_LEN

class MMTPServerConnection(SimpleTLSConnection):
    '''An asynchronous implementation of the receiving side of an MMTP
       connection.'''
    def __init__(self, sock, tls, consumer):
        SimpleTLSConnection.__init__(self, sock, tls, 1)
        self.messageConsumer = consumer
        self.finished = self.__setupFinished

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
        trace("done w/ client sendproto")
        inp = self.getInput()
        m =PROTOCOL_RE.match(inp)

        if not m:
            warn("Bad protocol list.  Closing connection.")
            self.shutdown(err=1)
        protocols = m.group(1).split(",")
        if "1.0" not in protocols:
            warn("Unsupported protocol list.  Closing connection.")
            self.shutdown(err=1); return #XXXX
        else:
            trace("proto ok.")
            self.finished = self.__sentProtocol
            self.beginWrite(PROTOCOL_STRING)

    def __sentProtocol(self):
        """Called once we're done sending our protocol response.  Begins
           reading a packet from the line.
        """
        trace("done w/ server sendproto")
        self.finished = self.__receivedMessage
        self.expectRead(SEND_RECORD_LEN)

    def __receivedMessage(self):
        """Called once we've read a message from the line.  Checks the
           digest, and either rejects or begins sending an ACK."""
        data = self.getInput()
        msg = data[SEND_CONTROL_LEN:-DIGEST_LEN]
        digest = data[-DIGEST_LEN:]

        if data.startswith(JUNK_CONTROL):
            expectedDigest = sha1(msg+"JUNK")
            replyDigest = sha1(msg+"RECEIVED JUNK")
        elif data.startswith(SEND_CONTROL):
            expectedDigest = sha1(msg+"SEND")
            replyDigest = sha1(msg+"RECEIVED")
        else:
            warn("Unrecognized command.  Closing connection.")
            self.shutdown(err=1)
            return
        if expectedDigest != digest:
            warn("Invalid checksum. Closing connection.")
            self.shutdown(err=1)
            return
        else:
            debug("Packet received; Checksum valid.")
            self.finished = self.__sentAck
            self.beginWrite(RECEIVED_CONTROL+replyDigest)
            self.messageConsumer(msg)

    def __sentAck(self):
        """Called once we're done sending an ACK.  Begins reading a new
           message."""
        trace("done w/ send ack")
        #XXXX Rehandshake
        self.finished = self.__receivedMessage
        self.expectRead(SEND_RECORD_LEN)

#----------------------------------------------------------------------
        
class MMTPClientConnection(SimpleTLSConnection):
    def __init__(self, context, ip, port, keyID, messageList,
                 sentCallback=None):
        trace("CLIENT CON")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(0)
        self.keyID = keyID
        self.ip = ip
        try:
            sock.connect((ip, port))
        except socket.error:
            # This will always raise an error, since we're nonblocking.  That's
            # okay.
            pass
        tls = context.sock(sock)

        SimpleTLSConnection.__init__(self, sock, tls, 0)
        self.messageList = messageList
        self.finished = self.__setupFinished
        self.sentCallback = sentCallback

    def __setupFinished(self):
        """Called when we're done with the client side negotations.
           Begins sending the protocol string.
        """
        keyID = sha1(self.getPeerPK().encode_key(public=1))
        if self.keyID is not None:
            if keyID != self.keyID:
                warn("Got unexpected Key ID from %s", self.ip)
                self.shutdown(err=1)
            else:
                debug("KeyID is valid")

        self.beginWrite(PROTOCOL_STRING)
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
        inp = self.getInput()
        if inp != PROTOCOL_STRING:
            warn("Invalid protocol.  Closing connection")
            self.shutdown(err=1)
            return

        self.beginNextMessage()

    def beginNextMessage(self):
        """Start writing a message to the connection."""
        if not self.messageList:
            self.shutdown(0)
            return
        msg = self.messageList[0]
        self.expectedDigest = sha1(msg+"RECEIVED")
        msg = SEND_CONTROL+msg+sha1(msg+"SEND")

        self.beginWrite(msg)
        self.finished = self.__sentMessage

    def __sentMessage(self):
        """Called when we're done sending a message.  Begins reading the
           server's ACK."""

        trace("message sent")
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
       trace("received ack")
       #XXXX Rehandshake
       inp = self.getInput()
       if inp != (RECEIVED_CONTROL+self.expectedDigest):
           self.shutdown(1)
           return

       debug("Received valid ACK for message.")
       justSent = self.messageList[0]
       del self.messageList[0]
       if self.sentCallback is not None:
           self.sentCallback(justSent)

       self.beginNextMessage()

class MMTPServer(AsyncServer):
    "XXXX"
    def __init__(self, config):
        self.context = config.getTLSContext(server=1)
        self.listener = ListenConnection("127.0.0.1",
                                         config['Outgoing/MMTP']['Port']
                                         10, self._newMMTPConnection)
        self.config = config
        self.listener.register(self)

    def _newMMTPConnection(self, sock):
        "XXXX"
        # XXXX Check whether incoming IP is valid XXXX
        tls = self.context.sock(sock, serverMode=1)
        sock.setblocking(0)
        con = MMTPServerConnection(sock, tls, self.onMessageReceived)
        con.register(self)
        
    def sendMessages(self, ip, port, keyID, messages):
        con = MMTPClientConnection(ip, port, keyID, messages,
                                   self.onMessageSent)
        con.register(self)

    def onMessageReceived(self, msg):
        pass

    def onMessageSent(self, msg):
        pass
    
