# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPClient.py,v 1.11 2002/12/07 04:03:35 nickm Exp $
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

import socket
import mixminion._minionlib as _ml
from mixminion.Crypto import sha1
from mixminion.Common import MixProtocolError, getLog

class BlockingClientConnection:
    """A BlockingClientConnection represents a MMTP connection to a single
       server.
    """
    def __init__(self, targetIP, targetPort, targetKeyID):
        """Open a new connection.""" 
        self.targetIP = targetIP
        self.targetPort = targetPort
        self.targetKeyID = targetKeyID
        self.context = _ml.TLSContext_new()

    def connect(self):
        """Negotiate the handshake and protocol."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(1)
	getLog().debug("Connecting to %s:%s", self.targetIP, self.targetPort) 
        self.sock.connect((self.targetIP,self.targetPort))
        getLog().debug("Handshaking with %s:%s",self.targetIP, self.targetPort)

        self.tls = self.context.sock(self.sock.fileno())
        # FFFF session resumption
        self.tls.connect()
	getLog().debug("Connected.")

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
	getLog().debug("Negotiatiating MMTP protocol")
        self.tls.write("MMTP 0.1\r\n")
        inp = self.tls.read(len("MMTP 0.1\r\n"))
        if inp != "MMTP 0.1\r\n":
            raise MixProtocolError("Protocol negotiation failed")
	getLog().debug("MMTP protocol negotated: version 0.1")
        
    def sendPacket(self, packet):
        """Send a single packet to a server."""
        assert len(packet) == 1<<15
	getLog().debug("Sending packet")
        self.tls.write("SEND\r\n")
        self.tls.write(packet)
        self.tls.write(sha1(packet+"SEND"))
	getLog().debug("Packet sent; waiting for ACK")
        
        inp = self.tls.read(len("RECEIVED\r\n")+20)
        if inp != "RECEIVED\r\n"+sha1(packet+"RECEIVED"):
            raise MixProtocolError("Bad ACK received")
	getLog().debug("ACK received; packet successfully delivered")

    def shutdown(self):
        """Close this connection."""
	getLog().debug("Shutting down connection to %s:%s",
		       self.targetIP, self.targetPort)
        self.tls.shutdown()
        self.sock.close()
	getLog().debug("Connection closed")

def sendMessages(targetIP, targetPort, targetKeyID, packetList):
    """Sends a list of messages to a server."""
    con = BlockingClientConnection(targetIP, targetPort, targetKeyID)
    try:
        con.connect()
        for p in packetList:
            con.sendPacket(p)
    finally:
        con.shutdown()
