# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Packet.py,v 1.9 2002/09/10 14:45:30 nickm Exp $
"""mixminion.Packet

   Functions, classes, and constants to parse and unparse Mixminion
   messages and related structures."""

__all__ = [ 'ParseError', 'Message', 'Header', 'Subheader',
            'parseMessage', 'parseHeader', 'parseSubheader',
            'getTotalBlocksForRoutingInfoLen', 'ReplyBlock',
            'IPV4Info', 'SMTPInfo', 'MBOXInfo', 'parseIPV4Info',
            'parseSMTPInfo', 'parseMBOXInfo', 'ReplyBlock',
            'parseReplyBlock', 'ENC_SUBHEADER_LEN',
            'HEADER_LEN', 'PAYLOAD_LEN', 'MAJOR_NO', 'MINOR_NO',
            'SECRET_LEN']

import struct
from socket import inet_ntoa, inet_aton
from mixminion.Common import MixError, floorDiv

# Major and minor number for the understood packet format.
# ???? The spec needs to specify this.
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

# Most info that fits in a single extened subheader
ROUTING_INFO_PER_EXTENDED_SUBHEADER = ENC_SUBHEADER_LEN

class ParseError(MixError):
    """Thrown when a message or portion thereof is incorrectly formatted."""
    pass

def parseMessage(s):
    """Given a 32K string, returns a Message object that breaks it into
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
        """Create a new Message object from three strings."""
        self.header1 = header1
        self.header2 = header2
        self.payload = payload

    def pack(self):
        """Return the 32K string value of this message."""
        return "".join([self.header1,self.header2,self.payload])

def parseHeader(s):
    """Convert a 2K string into a Header object"""
    if len(s) != HEADER_LEN:
        raise ParseError("Bad header length")

    return Header(s)

class Header:
    """Represents a 2K Mixminion header"""
    def __init__(self, contents):
        """Initialize a new header from its contents"""
        self.contents = contents

    def __getitem__(self, i):
        """header[i] -> str

           Returns the i'th encoded subheader of this header, for i in 0..15"""
        if i < 0: i = 16+i
        return self.contents[i*ENC_SUBHEADER_LEN:
                             (i+1)*ENC_SUBHEADER_LEN]

    def __getslice__(self, i, j):
        """header[i:j] -> str

           Returns a slice of the i-j'th subheaders of this header."""
        if j > 16: j = 16
        if i < 0: i += 16
        if j < 0: j += 16 
        return self.contents[i*ENC_SUBHEADER_LEN:
                             j*ENC_SUBHEADER_LEN]

    def __len__(self):
        """Return the number of subheaders in this header (always 16)"""
        return 16

# A subheader begins with: a major byte, a minor byte, SECRET_LEN secret
# bytes, DIGEST_LEN digest bytes, a routing_len short, and a routing_type
# short.
SH_UNPACK_PATTERN = "!BB%ds%dsHH" % (SECRET_LEN, DIGEST_LEN)

def parseSubheader(s):
    """Convert a decoded Mixminion subheader into a Subheader object"""
    if len(s) < MIN_SUBHEADER_LEN:
        raise ParseError("Header too short")
    if len(s) > MAX_SUBHEADER_LEN:
        raise ParseError("Header too long")

    try:
        major, minor, secret, digest, rlen, rt = \
               struct.unpack(SH_UNPACK_PATTERN, s[:MIN_SUBHEADER_LEN])
    except struct.error:
        raise ParseError("Misformatted subheader")
    ri = s[MIN_SUBHEADER_LEN:]
    if rlen < len(ri):
        ri = ri[:rlen]
    return Subheader(major,minor,secret,digest,rt,ri,rlen)

def getTotalBlocksForRoutingInfoLen(bytes):
    """Return the number of subheaders that will be needed for a hop
       whose routinginfo is (bytes) long."""
    if bytes <= MAX_ROUTING_INFO_LEN:
        return 1
    else:
        extraBytes = bytes - MAX_ROUTING_INFO_LEN
        return 2 + floorDiv(extraBytes,ROUTING_INFO_PER_EXTENDED_SUBHEADER)

class Subheader:
    """Represents a decoded Mixminion header

       Fields: major, minor, secret, digest, routinglen, routinginfo,
               routingtype.

       A Subheader can exist in a half-initialized state where routing
       info has been read from the first header, but not from the
       extened headers.  If this is so, routinglen will be > len(routinginfo).
       """

    def __init__(self, major, minor, secret, digest, routingtype,
                 routinginfo, routinglen=None):
        """Initialize a new subheader"""
        self.major = major
        self.minor = minor
        self.secret = secret
        self.digest = digest
        if routinglen is None:
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
        """Change the routinginfo, and the routinglength to correspond."""
        self.routinginfo = info
        self.routinglen = len(info)

    def isExtended(self):
        """Return true iff the routinginfo is too long to fit in a single
           subheader."""
        return self.routinglen > MAX_ROUTING_INFO_LEN

    def getNExtraBlocks(self):
        """Return the number of extra blocks that will be needed to fit
           the routinginfo."""
        return getTotalBlocksForRoutingInfoLen(self.routinglen)-1

    def appendExtraBlocks(self, data):
        """Given a string containing additional (decoded) blocks of
           routing info, add them to the routinginfo of this
           object.
        """
        nBlocks = self.getNExtraBlocks()
        assert len(data) == nBlocks * ENC_SUBHEADER_LEN
        raw = [self.routinginfo]
        for i in range(nBlocks):
            block = data[i*ENC_SUBHEADER_LEN:(i+1)*ENC_SUBHEADER_LEN]
            raw.append(block)
        self.routinginfo = ("".join(raw))[:self.routinglen]

    def pack(self):
        """Return the (unencrypted) string representation of this Subhead.

           Does not include extra blocks"""
        assert self.routinglen == len(self.routinginfo)
        assert len(self.digest) == DIGEST_LEN
        assert len(self.secret) == SECRET_LEN
        info = self.routinginfo[:MAX_ROUTING_INFO_LEN]

        return struct.pack(SH_UNPACK_PATTERN,
                           self.major,self.minor,self.secret,self.digest,
                           self.routinglen, self.routingtype)+info

    def getExtraBlocks(self):
        """Return a list of (unencrypted) blocks of extra routing info."""
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


RB_UNPACK_PATTERN = "!4sBBL%ssHH" % (HEADER_LEN)
MIN_RB_LEN = 14+HEADER_LEN

def parseReplyBlock(s):
    """Return a new ReplyBlock object for an encoded reply block"""
    if len(s) < MIN_RB_LEN:
        raise ParseError("Reply block too short")

    try:
        magic, major, minor, timestamp, header, rlen, rt = \
               struct.unpack(RB_UNPACK_PATTERN, s[:MIN_RB_LEN])
    except struct.error:
        raise ParseError("Misformatted reply block")

    if magic != 'SURB':
        raise ParseError("Misformatted reply block")

    if major != 0x00 or minor != 0x01:
        raise ParseError("Unrecognized version on reply block %s.%s",
			 major,minor)

    ri = s[MIN_RB_LEN:]
    if len(ri) != rlen:
        raise ParseError("Misformatted reply block")

    return ReplyBlock(header, timestamp, rt, ri)

class ReplyBlock:
    """A mixminion reply block, including the address of the first hop
       on the path, and the RoutingType and RoutingInfo for the server."""
    def __init__(self, header, useBy, rt, ri):
        """Construct a new Reply Block."""
        assert len(header) == HEADER_LEN
        self.header = header
        self.timestamp = useBy
        self.routingType = rt
        self.routingInfo = ri

    def pack(self):
        """Returns the external representation of this reply block"""
        return struct.pack(RB_UNPACK_PATTERN,
                           "SURB", 0x00, 0x01, self.timestamp,
                           self.header, len(self.routingInfo),
                           self.routingType)+self.routingInfo

# An IPV4 address (Used by SWAP_FWD and FWD) is packed as: four bytes
# of IP address, a short for the portnum, and DIGEST_LEN bytes of keyid.
IPV4_PAT = "!4sH%ds" % DIGEST_LEN

def parseIPV4Info(s):
    """Converts routing info for an IPV4 address into an IPV4Info object,
       suitable for use by FWD or SWAP_FWD modules."""
    if len(s) != 4+2+DIGEST_LEN:
        raise ParseError("IPV4 information with wrong length")
    try:
        ip, port, keyinfo = struct.unpack(IPV4_PAT, s)
    except struct.error:
        raise ParseError("Misformatted IPV4 routing info")
    ip = inet_ntoa(ip)
    return IPV4Info(ip, port, keyinfo)

class IPV4Info:
    """An IPV4Info object represents the routinginfo for a FWD or SWAP_FWD hop.

       Fields: ip (a dotted quad string), port (an int from 0..65535), and keyinfo
       (a digest)."""
    def __init__(self, ip, port, keyinfo):
        """Construct a new IPV4Info"""
        assert 0 <= port <= 65535
        self.ip = ip
        self.port = port
        self.keyinfo = keyinfo

    def pack(self):
        """Return the routing info for this address"""
        assert len(self.keyinfo) == DIGEST_LEN
        return struct.pack(IPV4_PAT, inet_aton(self.ip), 
			   self.port, self.keyinfo)
    
    def __hash__(self):
	return hash(self.pack())

    def __eq__(self, other):
	return (type(self) == type(other) and self.ip == other.ip and
		self.port == other.port and self.keyinfo == other.keyinfo)

def parseSMTPInfo(s):
    """Convert the encoding of an SMTP routinginfo into an SMTPInfo object."""
    lst = s.split("\000",1)
    if len(lst) == 1:
        return SMTPInfo(s,None)
    else:
        return SMTPInfo(lst[0], lst[1])

class SMTPInfo:
    """Represents the routinginfo for an SMTP hop.

       Fields: email (an email address), tag (an arbitrary tag, optional)."""
    def __init__(self, email, tag):
        self.email = email
        self.tag = tag

    def pack(self):
        """Returns the wire representation of this SMTPInfo"""
        if self.tag != None:
            return self.email+"\000"+self.tag
        else:
            return self.email

def parseMBOXInfo(s):
    """Convert the encoding of an MBOX routinginfo into an MBOXInfo
       object."""
    lst = s.split("\000",1)
    if len(lst) == 1:
        return MBOXInfo(s,None)
    else:
        return MBOXInfo(lst[0], lst[1])

class MBOXInfo:
    """Represents the routinginfo for an MBOX hop.

       Fields: user (a user identifier), tag (an arbitrary tag, optional)."""
    def __init__(self, user, tag):
        self.user = user
        assert user.find('\000') == -1
        self.tag = tag

    def pack(self):
        """Return the external representation of this routing info."""
        if self.tag:
            return self.user+"\000"+self.tag
        else:
            return self.user
