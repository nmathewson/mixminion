# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPServer.py,v 1.1 2002/06/24 20:28:19 nickm Exp $
"""mixminion.MMTPServer

   This package implements the Mixminion Transfer Protocol as described
   in the Mixminion specification.  It uses a select loop to provide
   an nonblocking implementation of *both* the client and the server sides
   of the protocol.

   If you just want to send messages into the system, use MMTPClient.

   XXXX As yet unsupported are: Session resumption, key renegotiation,
   XXXX checking KeyID."""

import socket, select, re
import mixminion._minionlib as _ml
from types import StringType
from mixminion.Common import MixError, MixFatalError, log
from mixminion.Crypto import sha1
from mixminion.Packet import MESSAGE_LEN, DIGEST_LEN

__all__ = [ 'AsyncServer', 'ListenConnection', 'MMTPServerConnection',
            'MMTPClientConnection' ]

def debug(s):
    #print s
    pass

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
        ## Defunct code for poll-based implementation.
        #self.p = select.poll()

    def process(self, timeout):
        """If any relevant file descriptors become available within
           'timeout' seconds, call the appropriate methods on their
           connections and return immediately after. Otherwise, wait
           'timeout' seconds and return."""

        debug("%s readers, %s writers" % (len(self.readers),
                                          len(self.writers)))
        
### Defunct code for for poll-based implementation
#          res = self.p.poll(timeout*1000)
#          for fd, event in res:
#              if event == select.POLLIN:
#                  print "Got a read on", fd
#                  self.readers[fd].handleRead()
#              elif event == select.POLLOUT:
#                  print "Got a write on", fd 
#                  self.writers[fd].handleWrite()
#              elif event == select.POLLNVAL:
#                  #XXXX Should never happen
#                  print "Bad FD: ",fd, "unregistered."
#                  self.p.unregister(fd)
#              else:
#                  # XXXX Should never happen
#                  print "????", fd,event

        readfds = self.readers.keys()
        writefds = self.writers.keys()
        readfds, writefds, exfds = select.select(readfds, writefds,[], timeout)
        for fd in readfds:
            debug("Got a read on "+str(fd))
            self.readers[fd].handleRead()
        for fd in writefds:
            debug("Got a write on"+str(fd))
            self.writers[fd].handleWrite()
        for fd in exfds:
            debug("Got an exception on"+str(fd))
            if self.readers.has_key(fd): del self.readers[fd]
            if self.writers.has_key(fd): del self.writers[fd]

    def registerReader(self, reader):
        """Register a connection as a reader.  The connection's 'handleRead'
           method will be called whenever data is available for reading."""
        fd = reader.fileno()
        #self.p.register(fd, select.POLLIN)
        self.readers[fd] = reader
        if self.writers.has_key(fd):
            del self.writers[fd]

    def registerWriter(self, writer):
        """Register a connection as a writer.  The connection's 'handleWrite'
           method will be called whenever the buffer is free for writing.
        """
        fd = writer.fileno()
        #self.p.register(fd, select.POLLOUT)
        self.writers[fd] = writer
        if self.readers.has_key(fd):
            del self.readers[fd]

    def registerBoth(self, connection):
        """Register a connection as a reader and a writer.  The
           connection's 'handleRead' and 'handleWrite' methods will be
           called as appropriate.
        """ 
        fd = connection.fileno()
        #self.p.register(fd, select.POLLIN | select.POLLOUT)
        self.readers[fd] = self.writers[fd] = connection

    def unregister(self, connection):
        """Removes a connection from this server."""
        fd = connection.fileno()
        w = self.writers.has_key(fd)
        r = self.readers.has_key(fd)
        #if r or w:
        #    self.p.unregister(fd)
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
        self.sock.setsockopt(0, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(backlog)
        # FFFF LOG
        self.connectionFactory = connectionFactory

    def register(self, server):
        server.registerReader(self)
        self.server = server

    def handleRead(self):
        con, addr = self.sock.accept()
        debug("Accepted connection from "+str(addr)+" on "+str(con.fileno()))
        rw = self.connectionFactory(con)
        rw.register(self.server)

    def shutdown(self):
        self.server.unregister(self)
        del self.server
        self.sock.close()

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
       is called.  After leaving state 5, the connection's "shutdownFinishied"
       method is called.
    """
    # Fields:
    #    __con: an underlying TLS object
    #    __state: a callback to use whenever we get a read or a write. May
    #           throw _ml.TLSWantRead or _ml.TLSWantWrite.
    #    __server: an AsyncServer.
    #    __inbuf: A list of strings that we've read since the last expectRead. 
    #    __inbuflen: The total length of alll the strings in __inbuf
    #    __expectReadLen: None, or the number of bytes to read before
    #           the current read succeeds.
    #    __maxReadLen: None, or a number of bytes above which the current
    #           read must fail.
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
        return self.__state == None

    def register(self, server):
        self.__server = server
        if self.__state == self.__acceptFn:
            server.registerReader(self)
        else:
            assert self.__state == self.__connectFn
            server.registerWriter(self)
        
    def expectRead(self, bytes=None, bytesMax=None, terminator=None):
        """Begin reading from the underlying TLS connection.

           After the read is finished, this object's finished method
           is invoked.  A call to 'getInput' will retrieve the contents
           of the input buffer since the last call to 'expectRead'.

           bytes -- If provided, a number of bytes to read before
                    exiting the read state.
           bytesMax -- If provided, a maximal number of bytes to read
                    before exiting the read state.
           terminator -- If provided, a character sequence to read
                    before exiting the read state.
        """
        self.__inbuf = []
        self.__inbuflen = 0
        self.__expectReadLen = bytes
        self.__maxReadLen = bytesMax
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
        # may throw wantread, wantwrite.
        self.__con.accept()
        self.__server.unregister(self)
        self.finished()

    def __connectFn(self):
        self.__con.connect()
        self.__server.unregister(self)
        self.finished()

    def __shutdownFn(self):
        r = self.__con.shutdown()
        if r == 1:
            debug("Got a 1 on shutdown")
            self.__server.unregister(self)
            self.__state = None
            self.__sock.close()
            self.shutdownFinished()
        else:
            debug("Got a 0 on shutdown")

    def __readFn(self):
        while 1:
            r = self.__con.read(1024)
            if r == 0:
                debug("read returned 0.")
                self.shutdown()
                return
            else:
                assert type(r) == StringType
                debug("read got %s bytes" % len(r))
                self.__inbuf.append(r)
                self.__inbuflen += len(r)
                if not self.__con.pending():
                    break

        if self.__terminator and len(self.__inbuf) > 1:
            self.__inbuf = [ "".join(self.__inbuf) ]

        if self.__maxReadLen and self.__inbuflen > self.__maxReadLen:
            debug("Read got too much.")
            self.shutdown(err=1)
            return
         
        if (self.__terminator and self.__inbuf[0].find(self.__terminator)>-1):
            debug("read found terminator")
            self.__server.unregister(self)
            self.finished()

        if (self.__expectReadLen and 
            (self.__inbuflen >= self.__expectReadLen)):
            
            debug("read got enough.")
            self.__server.unregister(self)
            self.finished()

    def __writeFn(self):
        out = self.__outbuf
        while len(out):
            # may throw
            r = self.__con.write(out)

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
          try:
              while self.__state is not None:
                  self.__state()
          except _ml.TLSWantWrite:
              self.__server.registerWriter(self)
          except _ml.TLSWantRead:
              self.__server.registerReader(self)
          except _ml.TLSError:
              if self.__state != self.__shutdownFn:
                  debug("Unexpected error: closing connection.")
                  self.shutdown(1)
              else:
                  debug("Error while shutting down: closing connection.")
                  self.__server.unregister(self)
          else:
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
    
#----------------------------------------------------------------------
# XXXX Need to support future protos.
PROTOCOL_STRING      = "PROTOCOL 1.0\n"
PROTOCOL_RE = re.compile("PROTOCOL ([^\s\r\n]+)\n")
SEND_CONTROL         = "SEND\n" #XXXX Not as in spec
RECEIVED_CONTROL     = "RECEIVED\n" #XXXX Not as in spec
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
        self.expectRead(None, 1024, '\n')

    def __receivedProtocol(self):
        """Called once we're done reading the protocol string.  Either
           rejects, or sends our response.
        """
        debug("done w/ client sendproto")
        inp = self.getInput()
        m = PROTOCOL_RE.match(inp)
        protocols = m.group(1).split(",")
        if "1.0" not in protocols:
            debug("proto bad. Dying.")
            self.shutdown(err=1); return #XXXX
        else:
            debug("proto ok.")
            self.finished = self.__sentProtocol
            self.beginWrite(PROTOCOL_STRING)

    def __sentProtocol(self):
        """Called once we're done sending our protocol response.  Begins
           reading a packet from the line.
        """
        debug("done w/ server sendproto")
        self.finished = self.__receivedMessage
        self.expectRead(SEND_RECORD_LEN, SEND_RECORD_LEN)

    def __receivedMessage(self):
        """Called once we've read a message from the line.  Checks the
           digest, and either rejects or begins sending an ACK."""
        data = self.getInput()
        msg = data[SEND_CONTROL_LEN:-DIGEST_LEN]
        digest = data[-DIGEST_LEN:]

        if (not (data.startswith(SEND_CONTROL) and
                 sha1(msg+"SEND") == digest)):
            debug("Data is bad.")
            self.shutdown(err=1)
        else:
            debug("Data is ok.")
            self.finished = self.__sentAck
            self.beginWrite(RECEIVED_CONTROL+sha1(msg+"RECEIVED"))
            self.messageConsumer(msg)

    def __sentAck(self):
        """Called once we're done sending an ACK.  Begins reading a new
           message."""
        debug("done w/ send ack")
        #XXXX Rehandshake
        self.finished = self.__receivedMessage
        self.expectRead(SEND_RECORD_LEN, SEND_RECORD_LEN)

#----------------------------------------------------------------------
        
class MMTPClientConnection(SimpleTLSConnection):
    def __init__(self, context, ip, port, keyId, messageList,
                 sentCallback=None):
        debug("CLIENT CON")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(0)
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
        '''Called when we're done with the client side negotations.
           Begins sending the protocol string.'''
        self.beginWrite(PROTOCOL_STRING)
        self.finished = self.__sentProtocol

    def __sentProtocol(self):    
        '''Called when we're done sending the protocol string.  Begins
           reading the server's response.'''
        self.expectRead(len(PROTOCOL_STRING), len(PROTOCOL_STRING))
        self.finished = self.__receivedProtocol

    def __receivedProtocol(self):
        """Called when we're done receiving the protocol string.  Begins
           sending a packet, or exits if we're done sending.
        """
        inp = self.getInput()
        if inp != PROTOCOL_STRING:
            self.shutdown(err=1); return

        self.beginNextMessage()

    def beginNextMessage(self):
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

        debug("message sent")
        self.finished = self.__receivedAck
        self.expectRead(RECEIVED_RECORD_LEN)

    def __receivedAck(self):
       """Called when we're done reading the ACK.  If the ACK is bad,
          closes the connection.  If the ACK is correct, removes the
          just-sent message from the queue, and calls sentCallback.

          If there are more messages to send, begins sending the next.
          Otherwise, begins shutting down.
       """
       debug("received ack")
       #XXXX Rehandshake
       inp = self.getInput()
       if inp != (RECEIVED_CONTROL+self.expectedDigest):
           self.shutdown(1)
           return

       debug("ack ok")
       del self.messageList[0]
       if self.sentCallback is not None:
           self.sentCallback()

       self.beginNextMessage()

# ----------------------------------------------------------------------
# Old defunct testing code.  Will remove 

## if __name__=='__main__':
##   import sys
##   if len(sys.argv) == 1:
##     d = "/home/nickm/src/ssl_sandbox/"
##     for f in (d+"server.cert",d+"server.pk",d+"dh"):
##         assert os.path.exists(f)
##     context = _ml.TLSContext_new(d+"server.cert",d+"server.pk",d+"dh")

##     _server = AsyncServer()
##     def receiveMessage(pkt):
##         print "Received packet beginning with %r" % pkt[:16]
##     def conFactory(con,context=context,receiveMessage=receiveMessage):
##         tls = context.sock(con)
##         con.setblocking(0)
##         return MMTPServerConnection(con, tls, receiveMessage)

##     listener = ListenConnection("127.0.0.1", 9002, 5, conFactory)
##     listener.register(_server)
##     try:
##         while 1:
##             print "."
##             _server.process(10)
##     finally:
##         listener.shutdown()
##   else:
##     context = _ml.TLSContext_new()
##     _server = AsyncServer()
##     def sentMessage():
##         print "Done sending a message"
##     msg = "helloxxx"*4096
##     clientDone = 0
##     def onSend():
##         global clientDone
##         clientDone = 1
##     sender = MMTPClientConnection(context, "127.0.0.1", 9002, None,
##                                   [msg], onSend)
##     sender.register(_server)
##     while 1 and not clientDone:
##         print "."
##         _server.process(10)
