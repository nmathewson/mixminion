# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Formats.py,v 1.3 2002/05/29 22:51:58 nickm Exp $
"""mixminion.Formats

   Functions, classes, and constants to parse and unparse Mixminion messages
   and related structures."""

__all__ = [ 'ParseError', 'Message', 'Header', 'Subheader',
            'parseMessage', 'parseHeader', 'parseSubheader',
            'getTotalBlocksForRoutingInfoLen',
            'IPV4Info', 'SMTPInfo',
            'parseIPV4Info', 'parseSMTPInfo',
            'ENC_SUBHEADER_LEN', 'HEADER_LEN',
            'PAYLOAD_LEN', 'MAJOR_NO', 'MINOR_NO',
            'SECRET_LEN']

import types, struct, unittest
import mixminion.Common

MAJOR_NO, MINOR_NO = 0,1

# Length of a Mixminion message
MESSAGE_LEN = 1 << 15
# Length of a header section
HEADER_LEN  = 128 * 16
# Length of a single payload
PAYLOAD_LEN = MESSAGE_LEN - HEADER_LEN*2

# Smallest possible size for a subheader
MIN_SUBHEADER_LEN = 42
# Most information we can fit into a subheader
MAX_SUBHEADER_LEN = 86
# Longest routing info that will fit in the main subheader
MAX_ROUTING_INFO_LEN = MAX_SUBHEADER_LEN - MIN_SUBHEADER_LEN

# Length of a subheader, once RSA-encoded.
ENC_SUBHEADER_LEN = 128

# Length of a digest
DIGEST_LEN = 20
# Length of a secret key
SECRET_LEN = 16

# Most info that fits in a single ERI block
ROUTING_INFO_PER_EXTENDED_SUBHEADER = ENC_SUBHEADER_LEN

class ParseError(mixminion.Common.MixError):
    """Thrown when a message or portion thereof is incorrectly formatted."""
    pass

def parseMessage(s):
    """parseMessage(s) -> Message

       Given a 32K string, returns a Message object that breaks it into
       two headers and a payload."""
    if len(s) != MESSAGE_LEN:
        raise ParseError("Bad message length")
        
    return Message(s[:HEADER_LEN],
                   s[HEADER_LEN:HEADER_LEN*2],
                   s[HEADER_LEN*2:])

class Message:
    """Represents a complete Mixminion packet

       Fields: header1, header2, payload"""
    def __init__(self, header1, header2, payload):
        """Message(header1, header2, payload) -> msg

           Creates a new Message object from three strings."""
        self.header1 = header1
        self.header2 = header2
        self.payload = payload

    def pack(self):
        """Returns the 32K string value of this message."""
        return "".join([self.header1,self.header2,self.payload])

def parseHeader(s):
    """parseHeader(s) -> Header

       Converts a 2K string into a Header object"""
    if len(s) != HEADER_LEN:
        raise ParseError("Bad header length")

    return Header(s)

class Header:
    """Represents a 2K Mixminion header"""
    def __init__(self, contents):
        self.contents = contents

    def __getitem__(self, i):
        """header[i] -> str

           Returns the i'th encoded subheader of this header, for i in 0..15"""
        return self.contents[i*ENC_SUBHEADER_LEN:
                             (i+1)*ENC_SUBHEADER_LEN]

    def __getslice__(self, i, j):
        """header[i] -> str

           Returns a slice of the i-j'th subheaders of this header."""
        if j > 16: j = 16
        if i < 0: i=16+i
        if j < 0: j=16-j   
        return self.contents[i*ENC_SUBHEADER_LEN:
                             j*ENC_SUBHEADER_LEN]

SH_UNPACK_PATTERN = "!BB%ds%dsHH" % (SECRET_LEN, DIGEST_LEN)

def parseSubheader(s):
    """parseSubheader(s) -> Subheader

       Converts a decoded Mixminion subheader into a Subheader object"""
    if len(s) < MIN_SUBHEADER_LEN:
        raise ParseError("Header too short")

    major, minor, secret, digest, rlen, rt = \
           struct.unpack(SH_UNPACK_PATTERN, s[:MIN_SUBHEADER_LEN])
    ri = s[MIN_SUBHEADER_LEN:]
    if rlen < len(ri):
        ri = ri[:rlen]
    return Subheader(major,minor,secret,digest,rt,ri,rlen)

def getTotalBlocksForRoutingInfoLen(bytes):
    if bytes <= MAX_ROUTING_INFO_LEN:
        return 1
    else:
        extraBytes = bytes - MAX_ROUTING_INFO_LEN
        return 2 + (extraBytes // ROUTING_INFO_PER_EXTENDED_SUBHEADER)
    
class Subheader:
    """Represents a decoded Mixminion header

       Fields: major, minor, secret, digest, routinglen, routinginfo,
               routingtype."""
    def __init__(self, major, minor, secret, digest, routingtype,
                 routinginfo, routinglen=None):
        self.major = major
        self.minor = minor
        self.secret = secret
        self.digest = digest
        if routinglen == None:
            self.routinglen = len(routinginfo)
        else:
            self.routinglen = routinglen
        self.routingtype = routingtype
        self.routinginfo = routinginfo

    def __repr__(self):
        return ("Subheader(major=%(major)r, minor=%(minor)r, "+
                "secret=%(secret)r, digest=%(digest)r, "+
                "routingtype=%(routingtype)r, routinginfo=%(routinginfo)r, "+
                "routinglen=%(routinglen)r)")% self.__dict__
                
    def setRoutingInfo(self, info):
        """Changes the routinginfo, and the routinglength to correspond."""
        self.routinginfo = info
        self.routinglen = len(info)

    def isExtended(self):
        """Returns true iff the routinginfo is too long to fit in a single
           subheader."""
        return self.routinglen > MAX_ROUTING_INFO_LEN

    def getNExtraBlocks(self):
        """Returns the number of extra blocks that will be needed to fit
           the routinginfo."""
        return getTotalBlocksForRoutingInfoLen(self.routinglen)-1

    def appendExtraBlocks(self, data):
        """appendExtraBlocks(str)

           Given additional (decoded) blocks of routing info, adds them
           to the routinginfo of this object."""
        nBlocks = self.getNExtraBlocks()
        assert len(data) == nBlocks * ENC_SUBHEADER_LEN
        raw = [self.routinginfo]
        for i in range(nBlocks):
            block = data[i*ENC_SUBHEADER_LEN:(i+1)*ENC_SUBHEADER_LEN]
            raw.append(block)
        self.routinginfo = ("".join(raw))[:self.routinglen]
        
    def pack(self):
        """Returns the (unencrypted) string representation of this Subhead"""
        assert self.routinglen == len(self.routinginfo)
        assert len(self.digest) == DIGEST_LEN
        assert len(self.secret) == SECRET_LEN
        info = self.routinginfo[:MAX_ROUTING_INFO_LEN]

        return struct.pack(SH_UNPACK_PATTERN, 
                           self.major,self.minor,self.secret,self.digest,
                           self.routinglen, self.routingtype)+info
    
    def getExtraBlocks(self):
        """getExtraBlocks() -> [ str, ...]

           Returns a list of (unencrypted) blocks of extra routing info."""
        if not self.isExtended():
            return []
        else:
            info = self.routinginfo[MAX_ROUTING_INFO_LEN:]
            result = []
            for i in range(self.getNExtraBlocks()):
                content = info[i*ROUTING_INFO_PER_EXTENDED_SUBHEADER:
                               (i+1)*ROUTING_INFO_PER_EXTENDED_SUBHEADER]
                missing = ROUTING_INFO_PER_EXTENDED_SUBHEADER-len(content)
                if missing > 0:
                    content += '\000'*missing                
                result.append(content)
            return result

IPV4_PAT = "!4sH%ds" % DIGEST_LEN

def _packIP(s):
    "xxxx"
    addr = s.split(".")
    if len(addr) != 4:
        raise ParseError("Malformed IP address")
    try:
        addr = map(int, addr)
    except ValueError:
        raise ParseError("Malformed IP address")
    for i in addr:
        if not (0 <= i <= 255): raise ParseError("Malformed IP address")
    return struct.pack("!BBBB", *addr)

def _unpackIP(s):
    "XXXX"
    if len(s) != 4: raise ParseError("Malformed IP")
    return ".".join(map(str, struct.unpack("!BBBB", s)))

def parseIPV4Info(s):
    """parseIP4VInfo(s) -> IPV4Info

       Converts routing info for an IPV4 address into an IPV4Info object."""
    if len(s) != 4+2+DIGEST_LEN:
        raise ParseError("IPV4 information with wrong length")
    ip, port, keyinfo = struct.unpack(IPV4_PAT, s)
    ip = _unpackIP(ip)
    return IPV4Info(ip, port, keyinfo)

class IPV4Info:
    "XXXX"
    def __init__(self, ip, port, keyinfo):
        self.ip = ip
        self.port = port
        self.keyinfo = keyinfo

    def pack(self):
        assert len(self.keyinfo) == DIGEST_LEN
        return struct.pack(IPV4_PAT, _packIP(self.ip), self.port, self.keyinfo)

def parseSMTPInfo(s):
    "XXXX"
    lst = s.split("\000",1)
    if len(lst) == 1:
        return SMTPInfo(s,None)
    else:
        return SMTPInfo(lst[0], lst[1])

class SMTPInfo:
    "XXXX"
    def __init__(self, email, tag):
        self.email = email
        self.tag = tag

    def pack(self):
        if self.tag != None:
            return self.email+"\000"+self.tag
        else:
            return self.email
        
def parseLocalInfo(s):
    "XXXX"
    nil = s.find('\000')
    user = s[:nil]
    tag = s[nil+1]
    return LocalInfo(user,tag)
    
class LocalInfo:
    "XXXX"
    def __init__(self, user, tag):
        self.user = user
        assert user.find('\000') == -1
        self.tag = tag

    def pack(self):
        return self.user+"\000"+self.tag
