# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInfo.py,v 1.5 2002/06/24 20:28:19 nickm Exp $

"""mixminion.ServerInfo

   Data structures to represent a server's information, and functions to
   martial and unmarshal it.

   ???? Since we don't have an interchange format yet, we only have
   an object with the minimal info."""

__all__ = [ 'ServerInfo' ]

from mixminion.Modules import SWAP_FWD_TYPE, FWD_TYPE
from mixminion.Packet import IPV4Info

#
# Stub class till we have the real thing
#
class ServerInfo:
    """Represents a Mixminion server, and the information needed to send
       messages to it."""
    def __init__(self, addr, port, modulus, keyid):
        self.addr = addr
        self.port = port
        self.modulus = modulus
        self.keyid = keyid

    def getAddr(self): return self.addr
    def getPort(self): return self.port
    def getModulus(self): return self.modulus
    def getKeyID(self): return self.keyid
    
    def getRoutingInfo(self):
        """Returns a mixminion.Packet.IPV4Info object for routing messages
           to this server."""
        return IPV4Info(self.addr, self.port, self.keyid)

