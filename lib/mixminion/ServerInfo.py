# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInfo.py,v 1.3 2002/05/31 12:47:58 nickm Exp $

"XXXX"

__all__ = [ 'ServerInfo' ]

from mixminion.Modules import SWAP_FWD_TYPE, FWD_TYPE
from mixminion.Formats import IPV4Info

#
# Stub class till we have the real thing
#
class ServerInfo:
    "XXXX"
    def __init__(self, addr, port, modulus, keyid):
        "XXXX"
        self.addr = addr
        self.port = port
        self.modulus = modulus
        self.keyid = keyid

    def getAddr(self): return self.addr
    def getPort(self): return self.port
    def getModulus(self): return self.modulus
    def getKeyID(self): return self.keyid
    
    def getRoutingInfo(self, swap=0):
        return IPV4Info(self.addr, self.port, self.keyid)
    
