# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPClient.py,v 1.1 2002/06/24 20:28:19 nickm Exp $
"""mixminion.MMTPClient

   This module contains a single, synchronous implementation of the client
   side of the Mixminion Transfer protocol.  You can use this client to 
   upload messages to any conforming Mixminion server.

   XXXX (We don't want to use this module for tranferring packets
   XXXX between servers; once we have async IO working in MMTPServer, we'll
   XXXX use that.)

   XXXX We don't yet check for the correct keyid.

   XXXX: As yet unsupported are: Session resumption and key renegotiation."""

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
        
        self.ssl = self.context.sock(self.sock.fileno())
        #XXXX session resumption
        self.ssl.connect()
        # XXXX CHECK KEY XXXX rsa = ssl.get_peer_cert_pk()
        ####
        # Protocol negotiation

        self.ssl.write("PROTOCOL 1.0\n")
        inp = self.ssl.read(len("PROTOCOL 1.0\n"))
        if inp != "PROTOCOL 1.0\n":
            raise MixProtocolError("Protocol negotiation failed")
        
    def sendPacket(self, packet):
        """Send a single packet to a server."""
        assert len(packet) == 1<<15
        self.ssl.write("SEND\n")
        self.ssl.write(packet)
        self.ssl.write(sha1(packet+"SEND"))
        
        inp = self.ssl.read(len("RECEIVED\n")+20)
        if inp != "RECEIVED\n"+sha1(packet+"RECEIVED"):
            raise MixProtocolError("Bad ACK received")

    def shutdown(self):
        """Close this connection."""
        self.ssl.shutdown()
        self.sock.close()

def sendMessages(targetIP, targetPort, targetKeyID, packetList):
    """Sends a list of messages to a server."""
    con = BlockingClientConnection(targetIP, targetPort, targetKeyID)
    con.connect()
    for p in packetList:
        con.sendPacket(p)
    con.shutdown()

# ----------------------------------------------------------------------
# Old defunct testing code.  Will remove.

## if __name__=='__main__':
##     msg = "helloxxx"*4096
##     assert len(msg) == (1<<15)
##     sendMessages("127.0.0.1",9001,None,[msg])
