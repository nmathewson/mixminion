# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: TLSConnection.py,v 1.17 2004/04/01 15:36:27 nickm Exp $
"""mixminion.TLSConnection

   Generic functions for wrapping bidirectional asynchronous TLS connections.
"""

#XXXX implement renegotiate
import sys
import time

import mixminion._minionlib as _ml
from mixminion.Common import LOG, stringContains

# Number of bytes to try reading at once.
_READLEN = 1024

class _Closing(Exception):
    """Helper class: exception raised by state functions that want the
       TLS connection to be closed."""
    pass

class TLSConnection:
    """Common abstract class to implement asynchronous bidirectional
       TLS connections.  This is still not a completely generic TLS
       class--it's designed to be simple enough to implement MMTP properly,
       and nothing more.

       Conceptually, a TLSConnection wraps a _minionlib.TLS object, and
       transitions between a number of logical states.  These states
       are: 'handshaking', 'exchanging data', 'shutting down',
       and 'closed.'  State transitions are either expliticly initiated
       by invocation of the class's control functions, or caused by the
       class itself based on errors or network events.
    """
    ## Fields:
    # sock -- the underlying socket.socket object.
    # tls -- an instance of mixminion._minionlib.TLSConnection, wrapping
    #   self.sock.
    # address -- the name of the host on the other side; used in log
    #   messages.
    # wantRead, wantWrite -- flags: is this connection interested in read/write
    #   events on self.sock?  (As a special case, if wantWrite is 2, we're
    #   currently waiting for socket.connect.)
    # lastActivity -- When did this connection last get any activity?
    #
    # inbuf -- a list of strings received from self.tls
    # inbuflen -- the total length of the strings in self.inbuf
    # outbuf -- a list of strings to write to self.tls
    # outbuflen -- the total length of the strings in self.outbuf
    #
    # __setup -- have we finished the TLS handshake.
    # __stateFn -- a function that should be invoked when this connection
    #   receives a read/write event.  One of __connectFn, __acceptFn,
    #   __dataFn, __shutdownFn.
    # __reading -- flag: are we trying to read bytes from self.tls?
    # __awaitingShutdown -- flag: have we already called shutdown once?
    # __bytesReadOnShutdown -- the number of bytes we've received since
    #   the first time we called shutdown.
    # __readBlockedOnWrite, __writeBlockedOnRead -- flags: has a read/write
    #   operation blocked on the opposite event type?
    # __blockedWriteLen -- if the last call to 'write' blocked, how much
    #   did we try to write?  (OpenSSL requires that we retry using exactly
    #   the same length as the time before.)  0 if the last write was
    #   successful.

    def __init__(self, tls, sock, address):
        """Create a new TLSConnection."""
        self.tls = tls
        self.sock = sock
        self.address = address
        self.wantRead = self.wantWrite = 0
        self.lastActivity = time.time()

        self.__stateFn = None
        self.__setup = 0
        self.__reading = 0

        self.__blockedWriteLen = 0

        self.inbuf = []
        self.inbuflen = 0
        self.outbuf = []
        self.outbuflen = 0

        self.__awaitingShutdown = 0
        self.__bytesReadOnShutdown = 0
        self.__readBlockedOnWrite = 0
        self.__writeBlockedOnRead = 0
    #####
    # Control functions
    #####
    def fileno(self):
        """Return the fd underlying this connection."""
        return self.sock.fileno()

    def beginConnecting(self):
        """Start connecting to a remote server.  This method should be invoked
           after self.sock.connect has first been called.  When the tls
           connection is done handshaking, onConnected will be invoked."""
        self.__stateFn = self.__connectFn
        self.wantRead = 0
        # We special-case wantWrite here because Win32 treats connects as
        # exceptions, but everybody else treats them as writes.
        self.wantWrite = 2
        self.__setup = 0

    def beginAccepting(self):
        """Start TLS handshaking with a remote client.  When the tls connection
           is done handshaking, onConnected will be invoked."""
        self.__stateFn = self.__acceptFn
        self.wantRead = 1
        self.wantWrite = 0
        self.__setup = 0

    def beginReading(self):
        """Start reading bytes from self.tls; when any are received, they
           are added to self.tls and onRead is invoked."""
        self.__reading = 1
        self.__stateFn = self.__dataFn
        if not self.__readBlockedOnWrite:
            self.wantRead = 1

    def stopReading(self):
        """Stop reading bytes from self.tls."""
        assert self.__stateFn == self.__dataFn
        self.__readBlockedOnWrite = 0
        if not self.__writeBlockedOnRead:
            self.wantRead = 0
        self.__reading = 0

    def beginWriting(self, data):
        """Queue 'data' to be written to self.tls.  When any is written,
           onWrite is invoked."""
        self.__stateFn = self.__dataFn
        self.outbuf.append(data)
        self.outbuflen += len(data)
        if not self.__writeBlockedOnRead:
            self.wantWrite = 1

    def stopWriting(self):
        """Stop writing data to self.tls; clear any currently pending data."""
        self.__stateFn = self.__dataFn
        self.outbuf = []
        self.outbuflen = 0
        self.__writeBlockedOnRead = 0
        if not self.__readBlockedOnWrite:
            self.wantWrite = 0

    def startShutdown(self):
        """Start shutting down the TLS connection; clear any data we're
           currently waiting to write.  When we're done, onShutdown is
           invoked."""
        self.__stateFn = self.__shutdownFn
        self.outbuf = []
        self.outbuflen = 0
        self.__reading = 0
        self.__writeBlockedOnRead = self.__readBlockedOnWrite = 0
        self.wantRead = self.wantWrite = 1

    def tryTimeout(self, cutoff):
        """Close self.sock if the last activity on this connection was
           before 'cutoff'.  Returns true iff the connection is timed out.
        """
        if self.lastActivity <= cutoff:
            LOG.warn("Connection to %s timed out: %.2f seconds without activity",
                     self.address, time.time()-self.lastActivity)
            self.onTimeout()
            self.__close()
            return 1
        return 0

    def getInbuf(self, maxBytes=None, clear=0):
        """Return up to 'maxBytes' bytes from the front of the input buffer.
           If 'maxBytes' is not provided, return a string containing the
           entire input buffer.  If 'clear' is true, remove the bytes from
           the input buffer.
           """
        if maxBytes is None or maxBytes >= self.inbuflen:
            # We're returning the entire input buffer.
            if len(self.inbuf) > 1:
                self.inbuf = [ "".join(self.inbuf) ]
            elif len(self.inbuf) == 0:
                return ""
            r = self.inbuf[0]
            if clear:
                del self.inbuf[:]
                self.inbuflen = 0
            return r
        else:
            # maxBytes < self.inbuflen; There are more bytes than we
            # asked for.
            n = 0
            ln = 0
            while 1:
                # Expand until self.inbuf[:n] is ln bytes long, and
                # ln is long enough to return maxBytes bytes.
                ln += len(self.inbuf[n])
                n += 1
                if ln >= maxBytes:
                    self.inbuf[:n] = [ "".join(self.inbuf[:n]) ]
                    assert len(self.inbuf[0]) == ln
                    r = self.inbuf[0][:maxBytes]
                    if clear:
                        if ln > maxBytes:
                            self.inbuf[0] = self.inbuf[0][maxBytes:]
                        else:
                            del self.inbuf[0]
                        self.inbuflen -= maxBytes
                    return r

            raise AssertionError # unreached; appease pychecker

    def getInbufLine(self, maxBytes=None, terminator="\r\n", clear=0,
                     allowExtra=0):
        """Return the first prefix of the current inbuf that ends with the
           'terminator' string.

           Returns the string on success, None if no such string is
           found, and -1 on error.  Errors occur when: there are 'maxBytes'
           bytes available but the terminator is not found; or when
           'allowExtra' is false and there is data on the input buffer
           following the terminator."""
        s = self.getInbuf(maxBytes)
        idx = s.find(terminator)
        if idx < 0:
            if len(s) == maxBytes:
                LOG.warn("Too much data without EOL from %s",self.address)
                return -1
            else:
                return None
        if not allowExtra and idx+len(terminator) < self.inbuflen:
            LOG.warn("Trailing data after EOL from %s",self.address)
            return -1

        return self.getInbuf(idx+len(terminator), clear=clear)

    def clearInbuf(self):
        """Remove all pending data from the input buffer."""
        del self.inbuf[:]
        self.inbuflen = 0

    def isShutdown(self):
        """Return true iff this TLSConnection has been completely shut down,
           and the underlying socket has been closed."""
        return self.sock is None

    #####
    # Implementation
    #####
    def __close(self, gotClose=0):
        """helper: close the underlying socket without cleaning up the TLS
           connection."""
        if gotClose:
            if self.__stateFn == self.__connectFn:
                LOG.warn("Couldn't connect to %s",self.address)
            else:
                LOG.warn("Unexpectedly closed connection to %s", self.address)
            self.onTLSError()
        self.sock.close()
        self.sock = None
        self.tls = None
        self.__stateFn = self.__closedFn
        self.onClosed()

    def __connectFn(self, r, w, cap):
        """state function: client-side TLS handshaking"""
        self.tls.connect() # might raise TLS*
        self.__setup = 1
        self.onConnected()
        return 1 # We may be ready for the next state.

    def __acceptFn(self, r, w, cap):
        """state function: server-side TLS handshaking"""
        self.tls.accept() # might raise TLS*
        self.__setup = 1
        self.onConnected()
        return 1 # We may be ready for the next state.

    def __shutdownFn(self, r, w, cap):
        """state function: TLS shutdonw"""
        while 1:
            if self.__awaitingShutdown:
                # We've already sent a 'shutdown' once.  Read until we
                # get another shutdown, or until we get enough data to
                # give up.
                s = "x"
                while s != 0:
                    #XXXX007 respect cap.
                    s = self.tls.read(_READLEN) # might raise TLSWant*
                    if s == 0:
                        LOG.debug("Read returned 0; shutdown to %s done",
                                  self.address)
                    else:
                        self.__bytesReadOnShutdown += len(s)
                        if self.__bytesReadOnShutdown > 128:
                            self.__readTooMuch()
                            return 0

            done = self.tls.shutdown()

            if not done and self.__awaitingShutdown:
                # This should neer actually happen, but let's cover the
                # possibility.
                LOG.error("Shutdown returned zero twice from %s--bailing",
                          self.address)
                done = 1
            if done:
                LOG.debug("Got a completed shutdown from %s", self.address)
                self.shutdownFinished()
                raise _Closing()
            else:
                LOG.trace("Shutdown returned zero -- entering read mode.")
                self.__awaitingShutdown = 1
                self.__bytesReadOnShutdown = 0
                self.wantRead = 1
                return 1

        raise AssertionError() # unreached; appease pychecker

    def __closedFn(self,r,w, cap):
        """state function: called when the connection is closed"""
        self.__sock = None
        return 0

    def __readTooMuch(self):
        """Helper function -- called if we read too much data while we're
           shutting down."""
        LOG.error("Read over 128 bytes of unexpected data from closing "
                  "connection to %s", self.address)
        self.onTLSError()
        raise _Closing()

    def __dataFn(self, r, w, cap):
        """state function: read or write data as appropriate"""
        if r:
            if self.__writeBlockedOnRead:
                cap = self.__doWrite(cap)
            if self.__reading and not self.__writeBlockedOnRead:
                cap = self.__doRead(cap)
        if w:
            if self.__reading and self.__readBlockedOnWrite:
                cap = self.__doRead(cap)
            if self.outbuf and not self.__readBlockedOnWrite:
                cap = self.__doWrite(cap)
        return 0

    def __doWrite(self, cap):
        "Helper function: write as much data from self.outbuf as we can."
        self.__writeBlockedOnRead = 0
        while self.outbuf and cap > 0:
            if self.__blockedWriteLen:
                # If the last write blocked, we must retry the exact same
                # length, or else OpenSSL will give an error.
                span = self.__blockedWriteLen
            else:
                # Otherwise, we try to write as much of the first string on
                # the output buffer as our bandwidth cap will allow.
                span = min(len(self.outbuf[0]),cap)
            try:
                n = self.tls.write(self.outbuf[0][:span])
            except _ml.TLSWantRead:
                self.__blockedWriteLen = span
                self.__writeBlockedOnRead = 1
                self.wantWrite = 0
                self.wantRead = 1
                return cap
            except _ml.TLSWantWrite:
                self.__blockedWriteLen = span
                self.wantWrite = 1
                return cap
            else:
                # We wrote some data: remove it from the buffer.
                assert n >= 0
                self.__blockedWriteLen = 0
                LOG.trace("Wrote %s bytes to %s", n, self.address)
                if n == len(self.outbuf[0]):
                    del self.outbuf[0]
                else:
                    self.outbuf[0] = self.outbuf[0][n:]
                self.outbuflen -= n
                cap -= n
                self.onWrite(n)
        if not self.outbuf:
            # There's no more data to write.  We only want write events now if
            # read is blocking on write.
            self.wantWrite = self.__readBlockedOnWrite
            self.doneWriting()
        return cap

    def __doRead(self, cap):
        "Helper function: read as much data as we can."
        self.__readBlockedOnWrite = 0
        # Keep reading until we decide to stop or run out of bandwidth
        #    (or break because we [1] need to wait for network events or
        #     [2] we get a shutdown.)
        while self.__reading and cap > 0:
            try:
                s = self.tls.read(min(_READLEN,cap))
                if s == 0:
                    # The other side sent us a shutdown; we'll shutdown too.
                    self.receivedShutdown()
                    LOG.trace("read returned 0: shutting down connection to %s"
                              , self.address)
                    self.startShutdown()
                    break
                else:
                    # We got some data; add it to the inbuf.
                    LOG.trace("Read got %s bytes from %s",len(s), self.address)
                    self.inbuf.append(s)
                    self.inbuflen += len(s)
                    cap -= len(s)
                    if (not self.tls.pending()) and cap > 0:
                        # Only call onRead when we've got all the pending
                        # data from self.tls, or we've just run out of
                        # allocated bandwidth.
                        self.onRead()
            except _ml.TLSWantRead:
                self.wantRead = 1
                break
            except _ml.TLSWantWrite:
                self.wantRead = 0
                self.wantWrite = 1
                self.__readBlockedOnWrite = 1
                break
        return cap

    def process(self, r, w, x, maxBytes=None):
        """Given that we've received read/write events as indicated in r/w,
           advance the state of the connection as much as possible, but try to
           use no more than 'maxBytes' bytes of bandwidth. Return
           is as in 'getStatus', with an extra 'bandwidth used' field
           appended."""
        if x and (self.sock is not None):
            self.__close(gotClose=1)
            return 0,0,0,0
        if not (r or w):
            return self.wantRead, self.wantWrite, (self.sock is not None),0

        bytesAtStart = bytesNow = self.tls.get_num_bytes_raw()
        if maxBytes is None:
            bytesCutoff = sys.maxint
            maxBytes = sys.maxint-bytesNow
        else:
            bytesCutoff = bytesNow+maxBytes
        try:
            self.lastActivity = time.time()
            while bytesNow < bytesCutoff and self.__stateFn(r, w, maxBytes):
                # If __stateFn returns 1, then the state has changed, and
                # we should try __stateFn again.
                if self.tls is not None:
                    bytesNow = self.tls.get_num_bytes_raw()
                    maxBytes = bytesCutoff-bytesNow
        except _ml.TLSWantRead:
            self.wantRead = 1
            self.wantWrite = 0
        except _ml.TLSWantWrite:
            self.wantRead = 0
            if self.__stateFn == self.__connectFn:
                self.wantWrite = 2
            else:
                self.wantWrite = 1
        except _Closing:
            # state functions that want to close the connection should
            # raise '_Closing', so we can count the bytes used before we
            # call 'close'.
            if self.tls is not None:
                bytesNow = self.tls.get_num_bytes_raw()
            self.__close()
        except _ml.TLSClosed:
            # We get this error if the socket unexpectedly closes underneath
            # the TLS connection.
            self.__close(gotClose=1)
        except _ml.TLSError, e:
            if self.tls is not None:
                bytesNow = self.tls.get_num_bytes_raw()
            if not (self.__awaitingShutdown or self.__stateFn == self.__shutdownFn):
                e = str(e)
                if stringContains(e, 'wrong version number'):
                    e = 'wrong version number (or failed handshake)'
                LOG.warn("Unexpected TLS error: %s.  Closing connection to %s",
                         e, self.address)
                self.onTLSError()
                self.startShutdown()
            else:
                LOG.warn("Error while shutting down: closing connection to %s",
                         self.address)
                self.onTLSError()
                self.__close()

        return (self.wantRead, self.wantWrite, (self.sock is not None),
                bytesNow-bytesAtStart)

    def getStatus(self):
        """Return a 3-tuple of wantRead, wantWrite, and isOpen."""
        return self.wantRead, self.wantWrite, (self.sock is not None)

    #####
    # HOOKS
    #####
    def onConnected(self):
        """Called when we're done negotiating a TLS connection with the
           other side."""
        raise NotImplemented()

    def onWrite(self, nBytes):
        """Called when n bytes have been written from the output buffer."""
        raise NotImplemented()

    def onRead(self):
        """Called when new data is available on the input buffer"""
        raise NotImplemented()

    def onTLSError(self):
        """Called when we get an error on the connection."""
        raise NotImplemented()

    def onTimeout(self):
        """Called when the connection gets timed out."""
        raise NotImplemented()

    def onClosed(self):
        """Called when the underlying socket is closed."""
        raise NotImplemented()

    def doneWriting(self):
        """Called when we have written all the data pending on the output
           buffer"""
        raise NotImplemented()

    def receivedShutdown(self):
        """Called when the other side has requested a shutdown."""
        raise NotImplemented()

    def shutdownFinished(self):
        """Called when a shutdown operation has finished."""
        raise NotImplemented()

