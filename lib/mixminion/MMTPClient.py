# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPClient.py,v 1.15 2003/01/12 04:27:19 nickm Exp $
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

import socket
import mixminion._minionlib as _ml
from mixminion.Crypto import sha1, getCommonPRNG
from mixminion.Common import MixProtocolError, LOG

class BlockingClientConnection:
    """A BlockingClientConnection represents a MMTP connection to a single
       server.
    """
    ## Fields:
    # targetIP -- the dotted-quad, IPv4 address of our server.
    # targetPort -- the port on the server
    # targetKeyID -- sha1 hash of the ASN1 encoding of the public key we
    #   expect the server to use.
    # context: a TLSContext object; used to create connections.
    # sock: a TCP socket, open to the server.
    # tls: a TLS socket, wrapping sock.
    #DOCDOC protocol
    PROTOCOL_VERSIONS = ['0.2', '0.1']
    def __init__(self, targetIP, targetPort, targetKeyID):
        """Open a new connection."""
        self.targetIP = targetIP
        self.targetPort = targetPort
        self.targetKeyID = targetKeyID
        self.context = _ml.TLSContext_new()
        self.tls = None
        self.sock = None

    def connect(self):
        """Negotiate the handshake and protocol."""
        # Connect to the server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(1)
        LOG.debug("Connecting to %s:%s", self.targetIP, self.targetPort)

        # Do the TLS handshaking
        self.sock.connect((self.targetIP,self.targetPort))
        LOG.debug("Handshaking with %s:%s",self.targetIP, self.targetPort)
        self.tls = self.context.sock(self.sock.fileno())
        # FFFF session resumption
        self.tls.connect()
        LOG.debug("Connected.")

        # Check the public key of the server to prevent man-in-the-middle
        # attacks.
        peer_pk = self.tls.get_peer_cert_pk()
        keyID = sha1(peer_pk.encode_key(public=1))
        if self.targetKeyID is not None and (keyID != self.targetKeyID):
            raise MixProtocolError("Bad Key ID: Expected %r but got %r" % (
                self.targetKeyID, keyID))

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
        self.tls.renegotiate()
        self.tls.do_handshake()

    def sendPacket(self, packet,
                   control="SEND\r\n", serverControl="RECEIVED\r\n",
                   hashExtra="SEND",serverHashExtra="RECEIVED"):
        """Send a single packet to a server."""
        assert len(packet) == 1<<15
        LOG.debug("Sending packet")
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

    def sendJunkPacket(self, packet):
        if self.protocol == '0.1':
            LOG.debug("Not sending junk to a v0.1 server")
            return
        self.sendPacket(packet,
                        control="JUNK\r\n", serverControl="RECEIVED\r\n",
                        hashExtra="JUNK", serverHashExtra="RECEIVED JUNK")
        
    def shutdown(self):
        """Close this connection."""
        LOG.debug("Shutting down connection to %s:%s",
                       self.targetIP, self.targetPort)
        if self.tls is not None:
            self.tls.shutdown()
        if self.sock is not None:
            self.sock.close()
        LOG.debug("Connection closed")

def sendMessages(targetIP, targetPort, targetKeyID, packetList):
    """Sends a list of messages to a server.
        DOCDOC arguments
        DOCDOC "JUNK", "RENEGOTIATE"
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
    
    con = BlockingClientConnection(targetIP, targetPort, targetKeyID)
    try:
        con.connect()
        for t,p in packets:
            if t == "JUNK":
                con.sendJunkPacket(p)
            elif t == "RENEGOTIATE":
                con.renegotiate()
            else:
                con.sendPacket(p)
    finally:
        con.shutdown()
