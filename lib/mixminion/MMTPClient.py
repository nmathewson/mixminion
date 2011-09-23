# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.
"""mixminion.MMTPClient

   This module contains a single, synchronous implementation of the client
   side of the Mixminion Transfer protocol.  You can use this client to
   upload packets to any conforming Mixminion server.

   (We don't use this module for transferring packets between servers;
   in fact, MMTPServer makes it redundant.  We only keep this module
   around [A] so that clients have an easy (blocking) interface to
   introduce packets into the system, and [B] so that we've got an
   easy-to-verify reference implementation of the protocol.)
   """

__all__ = [ "MMTPClientConnection", "sendPackets", "DeliverableMessage" ]

import socket
import sys
import time
import mixminion._minionlib as _ml
import mixminion.NetUtils
import mixminion.ServerInfo
import mixminion.TLSConnection
from mixminion.Crypto import sha1, getCommonPRNG
from mixminion.Common import MixProtocolError, MixProtocolReject, \
     MixProtocolBadAuth, LOG, MixError, formatBase64, stringContains, \
     TimeoutError
from mixminion.Packet import IPV4Info, MMTPHostInfo

def _noop(*k,**v): pass
class EventStatsDummy:
    def __getattr__(self,a):
        return _noop
EventStats = EventStatsDummy()
EventStats.log = EventStats

def useEventStats():
    import mixminion.server.EventStats
    global EventStats
    EventStats = mixminion.server.EventStats

class DeliverableMessage:
    """Interface to be implemented by messages deliverable by MMTP"""
    def getContents(self):
        raise NotImplementedError
    def isJunk(self):
        raise NotImplementedError
    def succeeded(self):
        raise NotImplementedError
    def failed(self,retriable=0):
        raise NotImplementedError

class MMTPClientConnection(mixminion.TLSConnection.TLSConnection):
    """A nonblocking MMTP connection sending packets and padding to a single
       server."""
    # Which MMTP versions do we understand?
    PROTOCOL_VERSIONS = ['0.3']
    # If we've written WRITEAHEAD packets without receiving any acks, we wait
    # for an ack before sending any more.
    WRITEAHEAD = 6
    # Length of a single transmission unit (control string, packet, checksum)
    MESSAGE_LEN = 6 + (1<<15) + 20
    # Length of a single acknowledgment (control string, digest)
    ACK_LEN = 10+20

    ## Fields:
    # targetAddr, targetPort, targetKeyID: the address and keyid of the
    #   server we're trying to connect to.
    # certCache: an instance of PeerCertificateCache to use to check the
    #   peer server's certificate
    # packets: a list of DeliverableMessage objects that have not yet been
    #   sent to the TLS connection, in the order they should be sent.
    # pendingPackets: a list of DeliverableMessage objects that have been
    #   sent to the TLS connection, but which have not yet been acknowledged.
    # nPacketsTotal: total number of packets we've ever been asked to send.
    # nPacketsSent: total number of packets sent across the TLS connection
    # nPacketsAcked: total number of acks received from the TLS connection
    # expectedAcks: list of acceptAck,rejectAck tuples for the packets
    #   that we've sent but haven't gotten acks for.
    # _isConnected: flag: true if the TLS connection been completed,
    #   and no errors have been encountered.
    # _isFailed: flag: has this connection encountered any errors?
    # _isAlive: flag: if we put another packet on this connection, will the
    #   packet maybe get delivered?

    ####
    # External interface
    ####
    def __init__(self, targetFamily, targetAddr, targetPort, targetKeyID,
                 serverName=None, context=None, certCache=None):
        """Initialize a new MMTPClientConnection."""
        assert targetFamily in (mixminion.NetUtils.AF_INET,
                                mixminion.NetUtils.AF_INET6)
        if context is None:
            context = _ml.TLSContext_new()
        if serverName is None:
            serverName = mixminion.ServerInfo.displayServerByRouting(
                IPV4Info(targetAddr, targetPort, targetKeyID))
        if certCache is None:
            certCache = PeerCertificateCache()

        self.targetAddr = targetAddr
        self.targetPort = targetPort
        sock = socket.socket(targetFamily, socket.SOCK_STREAM)
        serverName += " (fd %s)"%sock.fileno()
        sock.setblocking(0)
        try:
            sock.connect((targetAddr, targetPort))
        except socket.error, e:
            # This will always raise an error, since we're nonblocking.  That's
            # okay... but it had better be EINPROGRESS or the local equivalent.
            if e[0] not in mixminion.NetUtils.IN_PROGRESS_ERRNOS:
                raise e

        tls = context.sock(sock)
        mixminion.TLSConnection.TLSConnection.__init__(self, tls, sock,
                                                       serverName)

        if targetKeyID != '\x00' * 20:
            self.targetKeyID = targetKeyID
        else:
            self.targetKeyID = None
        self.certCache = certCache

        self.packets = []
        self.pendingPackets = []
        self.expectedAcks = []
        self.nPacketsSent = self.nPacketsAcked = self.nPacketsTotal =0
        self._isConnected = 0
        self._isFailed = 0
        self._isAlive = 1
        EventStats.log.attemptedConnect()
        LOG.debug("Opening client connection to %s",self.address)
        self.beginConnecting()

    def addPacket(self, deliverableMessage):
        """Queue 'deliverableMessage' for transmission.  When it has been
           acknowledged, deliverableMessage.succeeded will be called.  On
           failure, deliverableMessage.failed will be called."""
        assert hasattr(deliverableMessage, 'getContents')
        self.packets.append(deliverableMessage)
        self.nPacketsTotal += 1
        # If we're connected, maybe start sending the packet we just added.
        self._updateRWState()

    ####
    # Implementation
    ####
    def _startSendingNextPacket(self):
        "Helper: begin transmitting the next available packet."
        # There _is_ a next available packet, right?
        assert self.packets and self._isConnected
        pkt = self.packets.pop(0)

        if pkt.isJunk():
            control = "JUNK\r\n"
            serverControl = "RECEIVED\r\n"
            hashExtra = "JUNK"
            serverHashExtra = "RECEIVED JUNK"
        else:
            control = "SEND\r\n"
            serverControl = "RECEIVED\r\n"
            hashExtra = "SEND"
            serverHashExtra = "RECEIVED"
            EventStats.log.attemptedRelay()

        m = pkt.getContents()
        if m == 'RENEGOTIATE':
            # Renegotiate has been removed from the spec.
            return

        data = "".join([control, m, sha1(m+hashExtra)])
        assert len(data) == self.MESSAGE_LEN
        acceptedAck = serverControl + sha1(m+serverHashExtra)
        rejectedAck = "REJECTED\r\n" + sha1(m+"REJECTED")
        assert len(acceptedAck) == len(rejectedAck) == self.ACK_LEN
        self.expectedAcks.append( (acceptedAck, rejectedAck) )
        self.pendingPackets.append(pkt)
        self.beginWriting(data)
        self.nPacketsSent += 1

    def _updateRWState(self):
        """Helper: if we have any queued packets that haven't been sent yet,
           and we aren't waiting for WRITEAHEAD acks, and we're connected,
           start sending the pending packets.
        """
        if not self._isConnected: return

        while self.nPacketsSent < self.nPacketsAcked + self.WRITEAHEAD:
            if not self.packets:
                break
            LOG.trace("Queueing new packet for %s",self.address)
            self._startSendingNextPacket()

        if self.nPacketsAcked == self.nPacketsSent:
            LOG.debug("Successfully relayed all packets to %s",self.address)
            self.allPacketsSent()
            self._isConnected = 0
            self._isAlive = 0
            self.startShutdown()

    def _failPendingPackets(self):
        "Helper: tell all unacknowledged packets to fail."
        self._isConnected = 0
        self._isFailed = 1
        self._isAlive = 0
        pkts = self.pendingPackets + self.packets
        self.pendingPackets = []
        self.packets = []
        for p in pkts:
            if p.isJunk():
                EventStats.log.failedRelay()
            p.failed(1)

    ####
    # Implementation: hooks
    ####
    def onConnected(self):
        LOG.debug("Completed MMTP client connection to %s",self.address)
        # Is the certificate correct?
        try:
            self.certCache.check(self.tls, self.targetKeyID, self.address)
        except MixProtocolBadAuth, e:
            LOG.warn("Certificate error: %s. Shutting down connection.", e)
            self._failPendingPackets()
            self.startShutdown()
            return
        else:
            LOG.debug("KeyID is valid from %s", self.address)

        EventStats.log.successfulConnect()

        # The certificate is fine; start protocol negotiation.
        self.beginWriting("MMTP %s\r\n" % ",".join(self.PROTOCOL_VERSIONS))
        self.onWrite = self.onProtocolWritten

    def onProtocolWritten(self,n):
        if self.outbuf:
            # Not done writing outgoing data.
            return

        LOG.debug("Sent MMTP protocol string to %s", self.address)
        self.stopWriting()
        self.beginReading()
        self.onRead = self.onProtocolRead

    def onProtocolRead(self):
        # Pull the contents of the buffer up to the first CRLF
        s = self.getInbufLine(4096,clear=1)
        if s is None:
            # We have <4096 bytes, and no CRLF yet
            return
        elif s == -1:
            # We got 4096 bytes with no CRLF, or a CRLF with more data
            # after it.
            self._failPendingPackets()
            self.startShutdown()
            return

        # Find which protocol the server chose.
        self.protocol = None
        for p in self.PROTOCOL_VERSIONS:
            if s == "MMTP %s\r\n"%p:
                self.protocol = p
                break
        if not self.protocol:
            LOG.warn("Protocol negotiation failed with %s", self.address)
            self._failPendingPackets()
            self.startShutdown()
            return

        LOG.debug("MMTP protocol negotiated with %s: version %s",
                  self.address, self.protocol)

        # Now that we're connected, optimize for throughput.
        mixminion.NetUtils.optimizeThroughput(self.sock)

        self.onRead = self.onDataRead
        self.onWrite = self.onDataWritten
        self.beginReading()

        self._isConnected = 1
        # Now that we're connected, start sending packets.
        self._updateRWState()

    def onDataRead(self):
        # We got some data from the server: it'll be 0 or more acks.
        if self.inbuflen < self.ACK_LEN:
            # If we have no acks at all, do nothing.
            return

        while self.inbuflen >= self.ACK_LEN:
            if not self.expectedAcks:
                LOG.warn("Received acknowledgment from %s with no corresponding message", self.address)
                self._failPendingPackets()
                self.startShutdown()
                return
            ack = self.getInbuf(self.ACK_LEN, clear=1)
            good, bad = self.expectedAcks.pop(0)
            if ack == good:
                LOG.debug("Packet delivered to %s",self.address)
                self.nPacketsAcked += 1
                if not self.pendingPackets[0].isJunk():
                    EventStats.log.successfulRelay()
                self.pendingPackets[0].succeeded()
                del self.pendingPackets[0]
            elif ack == bad:
                LOG.warn("Packet rejected by %s", self.address)
                self.nPacketsAcked += 1
                if not self.pendingPackets[0].isJunk():
                    EventStats.log.failedRelay()
                self.pendingPackets[0].failed(1)
                del self.pendingPackets[0]
            else:
                # The control string and digest are wrong for an accepted
                # or rejected packet!
                LOG.warn("Bad acknowledgement received from %s",self.address)
                self._failPendingPackets()
                self.startShutdown()
                return
        # Start sending more packets, if we were waiting for an ACK to do so.
        self._updateRWState()

    def onDataWritten(self,n):
        # If we wrote some data, maybe we'll be ready to write more.
        self._updateRWState()
    def onTLSError(self):
        # If we got an error, fail all our packets and don't accept any more.
        if not self._isConnected:
            EventStats.log.failedConnect()
        self._isConnected = 0
        self._failPendingPackets()
    def onTimeout(self):
        self.onTLSError()
    def onClosed(self): pass
    def doneWriting(self): pass
    def receivedShutdown(self):
        LOG.warn("Received unexpected shutdown from %s", self.address)
        self._failPendingPackets()
    def shutdownFinished(self): pass

    def allPacketsSent(self):
        """Hook: called when we've received acks for all our pending packets"""
        pass

    def getAddr(self):
        """Return a 3-tuple of address,port,keyid for this connection"""
        return self.targetAddr, self.targetPort, self.targetKeyID

    def isActive(self):
        """Return true iff packets sent with this connection may be delivered.
        """
        return self._isAlive

class DeliverableString(DeliverableMessage):
    """Subclass of DeliverableMessage suitable for use by ClientMain and
       sendPackets.  Sends str(s) for some object s; invokes a callback on
       success."""
    def __init__(self, s=None, isJunk=0, callback=None):
        if isJunk:
            self.s = getCommonPRNG().getBytes(1<<15)
        else:
            self.s = s
        self.j = isJunk
        self.cb = callback
        self._failed = 0
        self._succeeded = 0
    def getContents(self):
        return str(self.s)
    def isJunk(self):
        return self.j
    def succeeded(self):
        self.s = None
        if self.cb is not None:
            self.cb()
        self._succeeded = 1
    def failed(self,retriable):
        self.s = None
        self._failed = 1

def sendPackets(routing, packetList, timeout=300, callback=None):
    """Sends a list of packets to a server.  Raise MixProtocolError on
       failure.

       routing -- an instance of mixminion.Packet.IPV4Info or
                  mixminion.Packet.MMTPHostInfo.
                  If routing.keyinfo == '\000'*20, we ignore the server's
                  keyid.
       packetList -- a list of 32KB packets and control strings.  Control
           strings must be one of "JUNK" to send a 32KB padding chunk,
           or "RENEGOTIATE" to renegotiate the connection key.
       connectTimeout -- None, or a number of seconds to wait for data
           on the connection before raising TimeoutError.
       callback -- None, or a function to call with a index into packetList
           after each successful packet delivery.
    """
    # Find out where we're connecting to.
    serverName = mixminion.ServerInfo.displayServerByRouting(routing)
    if isinstance(routing, IPV4Info):
        family, addr = socket.AF_INET, routing.ip
    else:
        assert isinstance(routing, MMTPHostInfo)
        LOG.trace("Looking up %s...",routing.hostname)
        family, addr, _ = mixminion.NetUtils.getIP(routing.hostname)
        if family == "NOENT":
            raise MixProtocolError("Couldn't resolve hostname %s: %s" % (
                                   routing.hostname, addr))

    # Create an MMTPClientConnection
    try:
        con = MMTPClientConnection(
            family, addr, routing.port, routing.keyinfo, serverName=serverName)
    except socket.error, e:
        raise MixProtocolError(str(e))

    # Queue the items on the list.
    deliverables = []
    for idx in xrange(len(packetList)):
        p = packetList[idx]
        if p == 'JUNK':
            pkt = DeliverableString(isJunk=1)
        elif p == 'RENEGOTIATE':
            continue #XXXX no longer supported.
        else:
            if callback is not None:
                def cb(idx=idx,callback=callback): callback(idx)
            else:
                cb = None
            pkt = DeliverableString(s=p,callback=cb)
        deliverables.append(pkt)
        con.addPacket(pkt)

    # Use select to run the connection until it's done.
    import select
    fd = con.fileno()
    wr,ww,isopen = con.getStatus()
    while isopen:
        if wr:
            rfds = [fd]
        else:
            rfds = []
        if ww:
            wfds = [fd]
        else:
            wfds = []
        if ww==2:
            xfds = [fd]
        else:
            xfds = []

        rfds,wfds,xfds=select.select(rfds,wfds,xfds,3)
        now = time.time()
        wr,ww,isopen,_=con.process(fd in rfds, fd in wfds, 0)
        if isopen:
            if con.tryTimeout(now-timeout):
                isopen = 0

    # If anything wasn't delivered, raise MixProtocolError.
    for d in deliverables:
        if d._failed:
            raise MixProtocolError("Error occurred while delivering packets to %s"%
                                   serverName)

    # If the connection failed, raise MixProtocolError.
    if con._isFailed:
        raise MixProtocolError("Error occurred on connection to %s"%serverName)

def pingServer(routing, timeout=60):
    """Try to connect to a server and send a junk packet.

       May raise MixProtocolBadAuth, or other MixProtocolError if server
       isn't up."""
    sendPackets(routing, ["JUNK"], timeout=timeout)

class PeerCertificateCache:
    """A PeerCertificateCache validates certificate chains from MMTP servers,
       and remembers which chains we've already seen and validated."""
    ## Fields
    # cache: A map from peer (temporary) KeyID's to a (signing) KeyID.
    def __init__(self):
        self.cache = {}

    def check(self, tls, targetKeyID, serverName):
        """Check whether the certificate chain on the TLS connection 'tls'
           is valid, current, and matches the keyID 'targetKeyID'.  If so,
           return.  If not, raise MixProtocolBadAuth.  Display all messages
           using the server 'serverName'.
        """

        # First, make sure the certificate is neither premature nor expired.
        try:
            tls.check_cert_alive()
        except _ml.TLSError, e:
            s = str(e)
            skewed=0
            notBefore,notAfter = tls.get_cert_lifetime()
            # XXXX 'stringContains' is not the best possible check here...
            if stringContains(s, "expired"):
                s += " [expired at %s]"%notAfter
                skewed = 1
            elif stringContains(s,"not yet valid"):
                s += " [not valid until %s]"%notBefore
                skewed = 1
            if skewed:
                s +=" (One of you may have a skewed clock or wrong time zone)"
            raise MixProtocolBadAuth("Invalid certificate from %s: %s " % (
                serverName, s))

        # If we don't care whom we're talking to, we don't need to check
        # them out.
        if targetKeyID is None:
            return

        # Get the KeyID for the peer (temporary) key.
        hashed_peer_pk = sha1(tls.get_peer_cert_pk().encode_key(public=1))

        # Before 0.0.4alpha, a server's keyID was a hash of its current
        # TLS public key.  In 0.0.4alpha, we allowed this for backward
        # compatibility.  As of 0.0.4alpha2, since we've dropped backward
        # compatibility with earlier packet formats, we drop certificate
        # compatibility as well.
        if targetKeyID == hashed_peer_pk:
            raise MixProtocolBadAuth(
               "Pre-0.0.4 (non-rotatable) certificate from %s" % serverName)

        try:
            if targetKeyID == self.cache[hashed_peer_pk]:
                # We recognize the key, and have already seen it to be
                # signed by the target identity.
                LOG.trace("Got a cached certificate from %s", serverName)
                return # All is well.
            else:
                # We recognize the key, but some other identity signed it.
                raise MixProtocolBadAuth(
                    "Mismatch between expected and actual key ID")
        except KeyError:
            pass

        # We haven't found an identity for this pk yet.  Try to check the
        # signature on it.
        try:
            identity = tls.verify_cert_and_get_identity_pk()
        except _ml.TLSError, e:
            raise MixProtocolBadAuth("Invalid KeyID (allegedly) from %s: %s"
                                   %serverName)

        # Okay, remember who has signed this certificate.
        hashed_identity = sha1(identity.encode_key(public=1))
        LOG.trace("Remembering valid certificate for %s", serverName)
        self.cache[hashed_peer_pk] = hashed_identity

        # Note: we don't need to worry about two identities signing the
        # same certificate.  While this *is* possible to do, it's useless:
        # You could get someone else's certificate and sign it, but you
        # couldn't start up a TLS connection with that certificate without
        # stealing their private key too.

        # Was the signer the right person?
        if hashed_identity != targetKeyID:
            raise MixProtocolBadAuth("Invalid KeyID for %s" % serverName)
