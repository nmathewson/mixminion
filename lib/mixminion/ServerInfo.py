# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInfo.py,v 1.1 2002/05/29 03:52:13 nickm Exp $

#XXXX DOC

__all__ = [ 'ServerInfo' ]

#
# Stub class till we have the real thing
#
class ServerInfo:
    def __init__(self, addr, port, modulus, keyid):
        self.addr = addr
        self.port = port
        self.modulus = modulus
        self.keyid = keyid

    def getAddr(self): return self.addr
    def getPort(self): return self.port
    def getModulus(self): return self.modulus
    return getKeyID(self): return self.keyid
    
