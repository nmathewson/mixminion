# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPClient.py,v 1.25 2003/03/28 15:36:22 nickm Exp $
"""mixminion.MMTPClient

   This module contains a single, synchronous implementation of the client
   side of the Mixminion Transfer protocol.  You can use this client to
   upload messages to any conforming Mixminion server.

   (We don't use this module for tranferring packets between servers;
   in fact, MMTPServer makes it redundant.  We only keep this module
   around [A] so that clients have an easy (blocking) interface to
   introduce messages into the system, and [B] so that we've got an
   easy-to-verify reference implementation of the protocol.)

   FFFF: As yet unsupported are: Session resumption and key renegotiation.
   FFFF: Also unsupported: timeouts."""

__all__ = [ "BlockingClientConnection", "sendMessages" ]

import errno
import signal
import socket
import mixminion._minionlib as _ml
from mixminion.Crypto import sha1, getCommonPRNG
from mixminion.Common import MixProtocolError, LOG, MixError

class TimeoutError(MixProtocolError):
    """Exception raised for protocol timeout."""
    pass

class BlockingClientConnection:
    """A BlockingClientConnection represents a MMTP connection to a single
       server.
    """
    ## Fields:
    # targetIP -- the dotted-quad, IPv4 address of our server.
    # targetPort -- the port on the server
    # targetKeyID -- sha1 hash of the ASN1 encoding of the public key we
    #   expect the server to use, or None if we don't care.
    # context: a TLSContext object; used to create connections.
    # sock: a TCP socket, open to the server.
    # tls: a TLS socket, wrapping sock.
    # protocol: The MMTP protocol version we're currently using, or None
    #     if negotiation hasn't completed.
    # PROTOCOL_VERSIONS: (static) a list of protocol versions we allow,
    #     in decreasing order of preference.
    PROTOCOL_VERSIONS = ['0.2', '0.1']
    def __init__(self, targetIP, targetPort, targetKeyID):
        """Open a new connection."""
        self.targetIP = targetIP
        self.targetPort = targetPort
        if targetKeyID != '\x00' *20:
            self.targetKeyID = targetKeyID
        else:
            self.targetKeyID = None
        self.context = _ml.TLSContext_new()
        self.tls = None
        self.sock = None
        self.certCache = PeerCertificateCache()

    def connect(self, connectTimeout=None):
        """Connect to the server, perform the TLS handshake, check the server
           key, and negotiate a protocol version.  If connectTimeout is set,
           wait no more than connectTimeout seconds for TCP handshake to
           complete.

           Raises TimeoutError on timeout, and MixProtocolError on all other
           errors."""
        try:
            self._connect(connectTimeout)
        except (socket.error, _ml.TLSError), e:
            self._raise(e, "connecting")

    def _raise(self, err, action):
        """Helper method: given an exception (err) and an action string (e.g.,
           'connecting'), raises an appropriate MixProtocolError.
        """
        if isinstance(err, socket.error):
            tp = "Socket"
        elif isinstance(err, _ml.TLSError):
            tp = "TLS"
        else:
            tp = str(type(err))
        raise MixProtocolError("%s error while %s to %s:%s: %s",
             tp, action, self.targetIP, self.targetPort, err)

    def _connect(self, connectTimeout=None):
        """Helper method; implements _connect."""
        # FFFF There should be a way to specify timeout for communication.
        def sigalarmHandler(sig, _):
            assert sig == signal.SIGALRM
        if connectTimeout:
            signal.signal(signal.SIGALRM, sigalarmHandler)
        
        # Connect to the server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(1)
        LOG.debug("Connecting to %s:%s", self.targetIP, self.targetPort)

        # Do the TLS handshaking
        if connectTimeout:
            signal.alarm(connectTimeout)
        try:
            try:
                self.sock.connect((self.targetIP,self.targetPort))
            except socket.error, e:
                if e[0] == errno.EINTR:
                    raise TimeoutError("Connection timed out")
                else:
                    raise MixProtocolError("Error connecting: %s" % e)
        finally:
            if connectTimeout:
                signal.alarm(0)
            
        LOG.debug("Handshaking with %s:%s",self.targetIP, self.targetPort)
        self.tls = self.context.sock(self.sock.fileno())
        # FFFF session resumption
        self.tls.connect()
        LOG.debug("Connected.")

        # Check the public key of the server to prevent man-in-the-middle
        # attacks.
        self.certCache.check(self.tls, self.targetKeyID,
                             "%s:%s"%(self.targetIP,self.targetPort))

        ####
        # Protocol negotiation
        # For now, we only support 1.0, but we call it 0.1 so we can
        # change our mind between now and a release candidate, and so we
        # can obsolete betas come release time.
        LOG.debug("Negotiatiating MMTP protocol")
        self.tls.write("MMTP %s\r\n" % ",".join(self.PROTOCOL_VERSIONS))
        # This is ugly, but we have no choice if we want to read up to the
        # first newline.
        # we don't really want 100; we just want up to the newline.
        inp = self.tls.read(100)
        while "\n" not in inp and len(inp) < 100:
            inp += self.tls.read(100)
        self.protocol = None
        for p in self.PROTOCOL_VERSIONS:
            if inp == 'MMTP %s\r\n'%p:
                self.protocol = p
                break
        if not self.protocol:
            raise MixProtocolError("Protocol negotiation failed")
        LOG.debug("MMTP protocol negotated: version %s", self.protocol)

    def renegotiate(self):
        """Re-do the TLS handshake to renegotiate a new connection key."""
        try:
            self.tls.renegotiate()
            self.tls.do_handshake()
        except (socket.error, _ml.TLSError), e:
            self._raise(e, "renegotiating connection")

    def sendPacket(self, packet):
        """Send a single 32K packet to the server."""
        self._sendPacket(packet)

    def sendJunkPacket(self, packet):
        """Send a single 32K junk packet to the server."""
        if self.protocol == '0.1':
            LOG.debug("Not sending junk to a v0.1 server")
            return
        self._sendPacket(packet,
                         control="JUNK\r\n", serverControl="RECEIVED\r\n",
                         hashExtra="JUNK", serverHashExtra="RECEIVED JUNK")
        
    def _sendPacket(self, packet,
                    control="SEND\r\n", serverControl="RECEIVED\r\n",
                    hashExtra="SEND",serverHashExtra="RECEIVED"):
        """Helper method: implements sendPacket and sendJunkPacket.
              packet -- a 32K string to send
              control -- a 6-character string ending with CRLF to
                  indicate the type of message we're sending.
              serverControl -- a 10-character string ending with CRLF that
                  we expect to receive if we've sent correctly.
              hashExtra -- a string to append to the packet when computing
                  the hash we send.
              serverHashExtra -- the string we expect the server to append
                  to the packet when computing the hash it sends in reply.
           """
        assert len(packet) == 1<<15
        LOG.debug("Sending packet")
        try:
            ##
            # We write: "SEND\r\n", 28KB of data, and sha1(packet|"SEND").
            self.tls.write(control)
            self.tls.write(packet)
            self.tls.write(sha1(packet+hashExtra))
            LOG.debug("Packet sent; waiting for ACK")

            # And we expect, "RECEIVED\r\n", and sha1(packet|"RECEIVED")
            inp = self.tls.read(len(serverControl)+20)
            if inp != serverControl+sha1(packet+serverHashExtra):
                raise MixProtocolError("Bad ACK received")
            LOG.debug("ACK received; packet successfully delivered")
        except (socket.error, _ml.TLSError), e:
            self._raise(e, "sending packet")
            
    def shutdown(self):
        """Close this connection."""
        LOG.debug("Shutting down connection to %s:%s",
                       self.targetIP, self.targetPort)
        try:
            if self.tls is not None:
                self.tls.shutdown()
            if self.sock is not None:
                self.sock.close()
        except (socket.error, _ml.TLSError), e:
            self._raise(e, "closing connection")
        LOG.debug("Connection closed")

def sendMessages(routing, packetList, connectTimeout=None, callback=None):
    """Sends a list of messages to a server.  Raise MixProtocolError on
       failure.

       routing -- an instance of mixminion.Packet.IPV4Info.
                  If routing.keyinfo == '\000'*20, we ignore the server's
                  keyid.
       packetList -- a list of 32KB packets and control strings.  Control
           strings must be one of "JUNK" to send a 32KB padding chunk,
           or "RENEGOTIATE" to renegotiate the connection key.
       connectTimeout -- None, or a number of seconds to wait for the
           TCP handshake to finish before raising TimeoutError.
       callback -- None, or a function to call with a index into packetList
           after each successful packet delivery.
    """
    # Generate junk before opening connection to avoid timing attacks
    packets = []
    for p in packetList:
        if p == 'JUNK':
            packets.append(("JUNK", getCommonPRNG().getBytes(1<<15)))
        elif p == 'RENEGOTIATE':
            packets.append(("RENEGOTIATE", None))
        else:
            packets.append(("MSG", p))

    con = BlockingClientConnection(routing.ip,routing.port,routing.keyinfo)
    try:
        con.connect(connectTimeout=connectTimeout)
        for idx in xrange(len(packets)):
            t,p = packets[idx]
            if t == "JUNK":
                con.sendJunkPacket(p)
            elif t == "RENEGOTIATE":
                con.renegotiate()
            else:
                con.sendPacket(p)
            if callback is not None:
                callback(idx)
    finally:
        con.shutdown()

class PeerCertificateCache:
    #XXXX004 use this properly; flush it to disk.
    "DOCDOC"
    def __init__(self):
        self.cache = {} # hashed peer pk -> identity keyid that it is valid for

    def check(self, tls, targetKeyID, address):
        "DOCDOC"
        if targetKeyID is None:
            return

        peer_pk = tls.get_peer_cert_pk()
        hashed_peer_pk = sha1(peer_pk.encode_key(public=1))
        #XXXX Remove this option
        if targetKeyID == hashed_peer_pk:
            LOG.warn("Non-rotatable keyid from server at %s", address)
            return # raise MixProtocolError

        try:
            if self.cache[hashed_peer_pk] == targetKeyID:
                return # All is well.
            else:
                raise MixProtocolError("Mismatch between expected and actual key id")
        except KeyError:
            # We haven't found an identity for this pk yet.
            pass

        try:
            identity = tls.verify_cert_and_get_identity_pk()
        except _ml.TLSError, e:
            raise MixProtocolError("Invalid KeyID from server at %s: %s"
                                   %(address, e))

        hashed_identity = sha1(peer_pk.encode_key(public=1))
        self.cache[hashed_peer_pk] = hashed_identity
        if hashed_identity != targetKeyID:
            raise MixProtocolError("Invalid KeyID for server at %s", address)

