# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPClient.py,v 1.37.2.1 2003/10/19 03:36:49 nickm Exp $
"""mixminion.MMTPClient

   This module contains a single, synchronous implementation of the client
   side of the Mixminion Transfer protocol.  You can use this client to
   upload messages to any conforming Mixminion server.

   (We don't use this module for transferring packets between servers;
   in fact, MMTPServer makes it redundant.  We only keep this module
   around [A] so that clients have an easy (blocking) interface to
   introduce messages into the system, and [B] so that we've got an
   easy-to-verify reference implementation of the protocol.)
   """

__all__ = [ "BlockingClientConnection", "sendMessages" ]

import errno
import signal
import socket
import mixminion._minionlib as _ml
from mixminion.Crypto import sha1, getCommonPRNG
from mixminion.Common import MixProtocolError, MixProtocolReject, \
     MixProtocolBadAuth, LOG, MixError, formatBase64

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
    PROTOCOL_VERSIONS = ['0.3']
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
        except (socket.error, _ml.TLSError, _ml.TLSClosed,
                _ml.TLSWantRead, _ml.TLSWantWrite), e:
            self._raise(e, "connecting")

    def _raise(self, err, action):
        """Helper method: given an exception (err) and an action string (e.g.,
           'connecting'), raises an appropriate MixProtocolError.
        """
        if isinstance(err, socket.error):
            tp = "Socket"
        elif isinstance(err, _ml.TLSError):
            tp = "TLS"
        elif isinstance(err, _ml.TLSClosed):
            tp = "TLSClosed"
        elif isinstance(err, _ml.TLSWantRead):
            tp = "Unexpected TLSWantRead"
        elif isinstance(err, _ml.TLSWantWrite):
            tp = "Unexpected TLSWantWrite"
        else:
            tp = str(type(err))
        e = MixProtocolError("%s error while %s to %s:%s: %s" %(
                             tp, action, self.targetIP, self.targetPort, err))
        e.base = err
        raise e

    def _connect(self, connectTimeout=None):
        """Helper method; implements _connect."""
        # FFFF There should be a way to specify timeout for communication.
        if not hasattr(signal, 'alarm'): #WWWW
            connectTimeout = None

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
        self.tls.connect()
        LOG.debug("Connected.")

        # Check the public key of the server to prevent man-in-the-middle
        # attacks.
        self.certCache.check(self.tls, self.targetKeyID,
                             "%s:%s"%(self.targetIP,self.targetPort))

        ####
        # Protocol negotiation
        # For now, we only support 1.0, but we call it 0.3 so we can
        # change our mind between now and a release candidate, and so we
        # can obsolete betas come release time.
        LOG.debug("Negotiating MMTP protocol")
        self.tls.write("MMTP %s\r\n" % ",".join(self.PROTOCOL_VERSIONS))
        # This is ugly, but we have no choice if we want to read up to the
        # first newline.
        # we don't really want 100; we just want up to the newline.
        inp = self.tls.read(100)
        if inp in (0, None):
            raise MixProtocolError("Connection closed during protocol negotiation.")
        while "\n" not in inp and len(inp) < 100:
            inp += self.tls.read(100)
        self.protocol = None
        for p in self.PROTOCOL_VERSIONS:
            if inp == 'MMTP %s\r\n'%p:
                self.protocol = p
                break
        if not self.protocol:
            raise MixProtocolError("Protocol negotiation failed")
        LOG.debug("MMTP protocol negotiated: version %s", self.protocol)

    def renegotiate(self):
        """Re-do the TLS handshake to renegotiate a new connection key."""
        try:
            self.tls.renegotiate()
            self.tls.do_handshake()
        except (socket.error, _ml.TLSError, _ml.TLSClosed), e:
            self._raise(e, "renegotiating connection")

    def sendPacket(self, packet):
        """Send a single 32K packet to the server."""
        self._sendPacket(packet)

    def sendJunkPacket(self, packet):
        """Send a single 32K junk packet to the server."""
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
            written = control+packet+sha1(packet+hashExtra)
            self.tls.write(written)
            LOG.debug("Packet sent; waiting for ACK")

            # And we expect, "RECEIVED\r\n", and sha1(packet|"RECEIVED")
            inp = self.tls.read(len(serverControl)+20)
            if inp == "REJECTED\r\n"+sha1(packet+"REJECTED"):
                raise MixProtocolReject()
            elif inp != serverControl+sha1(packet+serverHashExtra):
                LOG.warn("Received bad ACK from server")
                raise MixProtocolError("Bad ACK received")
            LOG.debug("ACK received; packet successfully delivered")
        except (socket.error, _ml.TLSError, _ml.TLSClosed, _ml.TLSWantRead,
                _ml.TLSWantWrite, _ml.TLSClosed), e:
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
        except (socket.error, _ml.TLSError, _ml.TLSClosed, _ml.TLSWantRead,
                _ml.TLSWantWrite, _ml.TLSClosed), e:
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

def pingServer(routing, connectTimeout=5):
    """Try to connect to a server and send a junk packet.

       May raise MixProtocolBadAuth, or other MixProtocolError if server
       isn't up."""
    sendMessages(routing, ["JUNK"], connectTimeout=connectTimeout)

class PeerCertificateCache:
    """A PeerCertificateCache validates certificate chains from MMTP servers,
       and remembers which chains we've already seen and validated."""
    ## Fields
    # cache: A map from peer (temporary) KeyID's to a (signing) KeyID.
    def __init__(self):
        self.cache = {}


    def check(self, tls, targetKeyID, address):
        """Check whether the certificate chain on the TLS connection 'tls'
           is valid, current, and matches the keyID 'targetKeyID'.  If so,
           return.  If not, raise MixProtocolBadAuth.
        """
        # First, make sure the certificate is neither premature nor expired.
        try:
            tls.check_cert_alive()
        except _ml.TLSError, e:
            raise MixProtocolBadAuth("Invalid certificate: %s", str(e))

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
               "Pre-0.0.4 (non-rotatable) certificate from server at %s",
               address)

        try:
            if targetKeyID == self.cache[hashed_peer_pk]:
                # We recognize the key, and have already seen it to be
                # signed by the target identity.
                LOG.trace("Got a cached certificate from server at %s",
                          address)
                return # All is well.
            else:
                # We recognize the key, but some other identity signed it.
                raise MixProtocolBadAuth(
                    "Mismatch between expected and actual key id")
        except KeyError:
            pass

        # We haven't found an identity for this pk yet.  Try to check the
        # signature on it.
        try:
            identity = tls.verify_cert_and_get_identity_pk()
        except _ml.TLSError, e:
            raise MixProtocolBadAuth("Invalid KeyID from server at %s: %s"
                                   %(address, e))

        # Okay, remember who has signed this certificate.
        hashed_identity = sha1(identity.encode_key(public=1))
        LOG.trace("Remembering valid certificate for server at %s",
                  address)
        self.cache[hashed_peer_pk] = hashed_identity

        # Note: we don't need to worry about two identities signing the
        # same certificate.  While this *is* possible to do, it's useless:
        # You could get someone else's certificate and sign it, but you
        # couldn't start up a TLS connection with that certificate without
        # stealing their private key too.

        # Was the signer the right person?
        if hashed_identity != targetKeyID:
            raise MixProtocolBadAuth("Invalid KeyID for server at %s" %address)
