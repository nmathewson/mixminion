# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPClient.py,v 1.3 2002/07/01 18:03:05 nickm Exp $
"""mixminion.MMTPClient

   This module contains a single, synchronous implementation of the client
   side of the Mixminion Transfer protocol.  You can use this client to 
   upload messages to any conforming Mixminion server.

   (We don't use this module for tranferring packets between servers;
   in fact, MMTPServer makes it redundant.  We only keep this module
   around [A] so that clients have an easy (blocking) interface to
   introduce messages into the system, and [B] so that we've got an
   easy-to-verify reference implementation of the protocol.)

   XXXX We don't yet check for the correct keyid.

   XXXX: As yet unsupported are: Session resumption and key renegotiation.

   XXXX: Also unsupported: timeouts."""

import socket
import mixminion._minionlib as _ml
from mixminion.Crypto import sha1
from mixminion.Common import MixProtocolError

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
        self.sock.connect((self.targetIP,self.targetPort))
        
        self.tls = self.context.sock(self.sock.fileno())
        #XXXX session resumption
        self.tls.connect()
        peer_pk = self.tls.get_peer_cert_pk()
        # XXXX Check the key ... how exactly is this to be hashed?
        
        ####
        # Protocol negotiation
        # For now, we only support 1.0
        self.tls.write("PROTOCOL 1.0\n")
        inp = self.tls.read(len("PROTOCOL 1.0\n"))
        if inp != "PROTOCOL 1.0\n":
            raise MixProtocolError("Protocol negotiation failed")
        
    def sendPacket(self, packet):
        """Send a single packet to a server."""
        assert len(packet) == 1<<15
        self.tls.write("SEND\n")
        self.tls.write(packet)
        self.tls.write(sha1(packet+"SEND"))
        
        inp = self.tls.read(len("RECEIVED\n")+20)
        if inp != "RECEIVED\n"+sha1(packet+"RECEIVED"):
            raise MixProtocolError("Bad ACK received")

    def shutdown(self):
        """Close this connection."""
        self.tls.shutdown()
        self.sock.close()

def sendMessages(targetIP, targetPort, targetKeyID, packetList):
    """Sends a list of messages to a server."""
    con = BlockingClientConnection(targetIP, targetPort, targetKeyID)
    con.connect()
    for p in packetList:
        con.sendPacket(p)
    con.shutdown()
