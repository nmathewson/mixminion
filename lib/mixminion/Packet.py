# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Packet.py,v 1.73 2004/02/02 07:05:49 nickm Exp $
"""mixminion.Packet

   Functions, classes, and constants to parse and unparse Mixminion
   messages, packets, and related structures.

   For functions that handle client-side generation and decoding of
   packets, see BuildMessage.py.  For functions that handle
   server-side processing of packets, see PacketHandler.py."""

__all__ = [ 'compressData', 'CompressedDataTooLong', 'DROP_TYPE',
            'ENC_FWD_OVERHEAD', 'ENC_SUBHEADER_LEN',
            'encodeMailHeaders', 'encodeMessageHeaders',
            'FRAGMENT_PAYLOAD_OVERHEAD', 'FWD_HOST_TYPE', 'FWD_IPV4_TYPE',
            'FragmentPayload',
            'FRAGMENT_MESSAGEID_LEN', 'FRAGMENT_TYPE',
            'HEADER_LEN', 'IPV4Info', 'MAJOR_NO', 'MBOXInfo',
            'MBOX_TYPE', 'MINOR_NO', 'MIN_EXIT_TYPE',
            'MIN_SUBHEADER_LEN', 'MMTPHostInfo', 'Packet',
            'OAEP_OVERHEAD', 'PAYLOAD_LEN', 'ParseError', 'ReplyBlock',
            'ReplyBlock', 'SECRET_LEN', 'SINGLETON_PAYLOAD_OVERHEAD',
            'SMTPInfo', 'SMTP_TYPE', 'SWAP_FWD_IPV4_TYPE',
            'SWAP_FWD_HOST_TYPE', 'SingletonPayload',
            'Subheader', 'TAG_LEN', 'TextEncodedMessage',
            'parseHeader', 'parseIPV4Info', 'parseMMTPHostInfo',
            'parseMBOXInfo', 'parsePacket', 'parseMessageAndHeaders',
            'parsePayload', 'parseRelayInfoByType', 'parseReplyBlock',
            'parseReplyBlocks', 'parseSMTPInfo', 'parseSubheader',
            'parseTextEncodedMessages', 'parseTextReplyBlocks',
            'uncompressData'
            ]

import binascii
import re
import struct
import sys
import types
import zlib
from socket import inet_ntoa, inet_aton
from mixminion.Common import MixError, MixFatalError, encodeBase64, \
     floorDiv, formatTime, isSMTPMailbox, LOG, armorText, unarmorText, \
     isPlausibleHostname
from mixminion.Crypto import sha1

if sys.version_info[:3] < (2,2,0):
    import mixminion._zlibutil as zlibutil

# Major and minor number for the understood packet format.
MAJOR_NO, MINOR_NO = 0,3
PACKET_VERSION = "%s.%s"%(MAJOR_NO,MINOR_NO)

# Length of a Mixminion packet
PACKET_LEN = 1 << 15
# Length of a header section
HEADER_LEN  = 128 * 16
# Length of a single payload
PAYLOAD_LEN = PACKET_LEN - HEADER_LEN*2

# Bytes taken up by OAEP padding in RSA-encrypted data
OAEP_OVERHEAD = 42

# Length of a subheader, once RSA-encoded.
ENC_SUBHEADER_LEN = 256
# Smallest possible size for a subheader
MIN_SUBHEADER_LEN = 42
# Most information we can fit into a subheader before padding
MAX_SUBHEADER_LEN = ENC_SUBHEADER_LEN - OAEP_OVERHEAD
# Longest routing info that will fit into the RSA-encrypted portion of
# the subheader.
MAX_ROUTING_INFO_LEN = MAX_SUBHEADER_LEN - MIN_SUBHEADER_LEN

# Length of a digest
DIGEST_LEN = 20
# Length of a secret key
SECRET_LEN = 16
# Length of end-to-end message tag
TAG_LEN = 20

#----------------------------------------------------------------------
# Values for the 'Routing type' subheader field
# Mixminion types
DROP_TYPE          = 0x0000 # Drop the packet
FWD_IPV4_TYPE      = 0x0001 # Forward the packet to an IPV4 addr via MMTP
SWAP_FWD_IPV4_TYPE = 0x0002 # SWAP, then FWD_IPV4
FWD_HOST_TYPE      = 0x0003 # Forward the pkt to a hostname, via MMTP.
SWAP_FWD_HOST_TYPE = 0x0004 # SWAP, then FWD_HOST

# Exit types
MIN_EXIT_TYPE  = 0x0100  # The numerically first exit type.
SMTP_TYPE      = 0x0100  # Mail the message
MBOX_TYPE      = 0x0101  # Send the message to one of a fixed list of addresses
NEWS_TYPE      = 0x0102  # Post the message to some ngs, and maybe mail it too
FRAGMENT_TYPE  = 0x0103  # Find the actual delivery info in the message payload
MAX_EXIT_TYPE  = 0xFFFF

# Set of exit types that don't get tag fields.
# XXXX007 This interface is really brittle; it needs to change.  I added it
# XXXX007 in order to allow 'fragment' to be an exit type without adding a
# XXXX007 needless tag field to every fragment routing info.
_TYPES_WITHOUT_TAGS = { FRAGMENT_TYPE : 1 }

def typeIsSwap(tp):
    return tp in (SWAP_FWD_IPV4_TYPE,SWAP_FWD_HOST_TYPE)

class ParseError(MixError):
    """Thrown when a message or portion thereof is incorrectly formatted."""
    pass

#----------------------------------------------------------------------
# PACKET-LEVEL STRUCTURES

def parsePacket(s):
    """Given a 32K string, returns a Packet object that breaks it into
       two headers and a payload."""
    if len(s) != PACKET_LEN:
        raise ParseError("Bad packet length")

    return Packet(s[:HEADER_LEN],
                   s[HEADER_LEN:HEADER_LEN*2],
                   s[HEADER_LEN*2:])

class Packet:
    """Represents a complete Mixminion packet

       Fields: header1, header2, payload"""
    def __init__(self, header1, header2, payload):
        """Create a new Packet object from three strings."""
        self.header1 = header1
        self.header2 = header2
        self.payload = payload

    def pack(self):
        """Return the 32K string value of this packet."""
        return "".join([self.header1,self.header2,self.payload])

def parseHeader(s):
    """Convert a 2K string into a Header object"""
    if len(s) != HEADER_LEN:
        raise ParseError("Bad header length")

    return s

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
    underflow = ""
    if rlen < len(ri):
        ri, underflow = ri[:rlen], ri[rlen:]
    if rt >= MIN_EXIT_TYPE and not _TYPES_WITHOUT_TAGS.get(rt) and rlen < TAG_LEN:
        raise ParseError("Subheader missing tag")
    return Subheader(major,minor,secret,digest,rt,ri,rlen,underflow)

class Subheader:
    """Represents a decoded Mixminion subheader.

       Fields: major, minor, secret, digest, routinglen, routinginfo,
               routingtype.

       A Subheader can exist in a half-initialized state where routing
       info has been read from the first RSA-encrypted data, but not
       from the symmetrically encrypted data in the rest of the
       header.  If this is so, routinglen will be > len(routinginfo).

       If 'underflow' is present, it contains material that does not
       belong to this subheader that was provided to 'parseSubheader'
       anyway.
       """
    def __init__(self, major, minor, secret, digest, routingtype,
                 routinginfo, routinglen=None, underflow=""):
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
        self.underflow = underflow

    def __repr__(self):
        return ("Subheader(major=%(major)r, minor=%(minor)r, "+
                "secret=%(secret)r, digest=%(digest)r, "+
                "routingtype=%(routingtype)r, routinginfo=%(routinginfo)r, "+
                "routinglen=%(routinglen)r)")% self.__dict__

    def getExitAddress(self):
        """Return the part of the routingInfo that contains the delivery
           address.  (Requires that routingType is an exit type.)"""
        assert self.routingtype >= MIN_EXIT_TYPE
        #XXXX007 This interface is completely insane.  Change it.
        if _TYPES_WITHOUT_TAGS.get(self.routingtype):
            return self.routinginfo
        else:
            assert len(self.routinginfo) >= TAG_LEN
            return self.routinginfo[TAG_LEN:]

    def getTag(self):
        """Return the part of the routingInfo that contains the decoding
           tag. (Requires that routingType is an exit type.)"""
        assert self.routingtype >= MIN_EXIT_TYPE
        #XXXX007 This interface is completely insane.  Change it.
        if _TYPES_WITHOUT_TAGS.get(self.routingtype):
            return ""
        else:
            assert len(self.routinginfo) >= TAG_LEN
            return self.routinginfo[:TAG_LEN]

    def setRoutingInfo(self, info):
        """Change the routinginfo, and the routinglength to correspond."""
        self.routinginfo = info
        self.routinglen = len(info)

    def appendOverflow(self, data):
        """Given a string containing additional routing info, add it
           to the routinginfo of this object.  """
        self.routinginfo += data
        assert len(self.routinginfo) <= self.routinglen

    def getUnderflowLength(self):
        """Return the number of bytes from the rest of the header that should
           be included in the RSA-encrypted part of the header.
        """
        return max(0, MAX_ROUTING_INFO_LEN - self.routinglen)

    def getOverflowLength(self):
        """Return the length of the data from routinginfo that will
           not fit in the RSA-encrypted part of the header.
        """
        return max(0, self.routinglen - MAX_ROUTING_INFO_LEN)

    def getOverflow(self):
        """Return the portion of routinginfo that doesn't fit into the
           RSA-encrypted part of the header.
        """
        return self.routinginfo[MAX_ROUTING_INFO_LEN:]

    def pack(self):
        """Return the (unencrypted) string representation of this Subhead.

           Does not include overflow or underflow"""
        assert self.routinglen == len(self.routinginfo)
        assert len(self.digest) == DIGEST_LEN
        assert len(self.secret) == SECRET_LEN
        info = self.routinginfo[:MAX_ROUTING_INFO_LEN]

        return struct.pack(SH_UNPACK_PATTERN,
                           self.major,self.minor,self.secret,self.digest,
                           self.routinglen, self.routingtype)+info

#----------------------------------------------------------------------
# UNENCRYPTED PAYLOADS

# Length of the 'MessageID' field in a fragment payload
FRAGMENT_MESSAGEID_LEN = 20
# Maximum number of fragments associated with a given message
MAX_N_FRAGMENTS = 0x7ffffff

# Number of bytes taken up by header fields in a singleton payload.
SINGLETON_PAYLOAD_OVERHEAD = 2 + DIGEST_LEN
# Number of bytes taken up by header fields in a fragment payload.
FRAGMENT_PAYLOAD_OVERHEAD = 3 + DIGEST_LEN + FRAGMENT_MESSAGEID_LEN + 4
# Number of bytes taken up from OAEP padding in an encrypted forward
# payload, minus bytes saved by spilling the RSA-encrypted block into the
# tag, minus the bytes taken by the session key.
ENC_FWD_OVERHEAD = OAEP_OVERHEAD - TAG_LEN + SECRET_LEN

def parsePayload(payload):
    """Convert a decoded mixminion payload into a SingletonPayload or a
       FragmentPayload object.  Raise ParseError on failure or data
       corruption."""
    if len(payload) not in (PAYLOAD_LEN, PAYLOAD_LEN-ENC_FWD_OVERHEAD):
        raise ParseError("Payload has bad length")
    bit0 = ord(payload[0]) & 0x80
    if bit0:
        # We have a fragment
        idxhi, idxlo, digest, msgID, msgLen = \
               struct.unpack(FRAGMENT_UNPACK_PATTERN,
                             payload[:FRAGMENT_PAYLOAD_OVERHEAD])
        idx = ((idxhi & 0x7f) << 16) + idxlo
        contents = payload[FRAGMENT_PAYLOAD_OVERHEAD:]
        if msgLen <= len(contents):
            raise ParseError("Payload has an invalid size field")
        return FragmentPayload(idx,digest,msgID,msgLen,contents)
    else:
        # We have a singleton
        size, digest = struct.unpack(SINGLETON_UNPACK_PATTERN,
                                   payload[:SINGLETON_PAYLOAD_OVERHEAD])
        contents = payload[SINGLETON_PAYLOAD_OVERHEAD:]
        if size > len(contents):
            raise ParseError("Payload has invalid size field")
        return SingletonPayload(size,digest,contents)

# A singleton payload starts with a 0 bit, 15 bits of size, and a 20-byte hash
SINGLETON_UNPACK_PATTERN = "!H%ds" % (DIGEST_LEN)

# A fragment payload starts with a 1 bit, a 23-bit packet index, a
# 20-byte hash, a 20-byte message ID, and 4 bytes of message size.
FRAGMENT_UNPACK_PATTERN = "!BH%ds%dsL" % (DIGEST_LEN, FRAGMENT_MESSAGEID_LEN)

class _Payload:
    pass

class SingletonPayload(_Payload):
    """Represents the payload for a standalone mixminion message.
       Fields:  size, hash, data.  (Note that data is padded.)"""
    def __init__(self, size, digest, data):
        self.size = size
        self.hash = digest
        self.data = data

    def computeHash(self):
        """Update the hash field of this payload to correspond to the hash
           of the data."""
        self.hash = sha1(self.data)

    def isSingleton(self):
        """Returns true; this is a singleton payload."""
        return 1

    def getContents(self):
        """Returns the non-padding portion of this payload's data"""
        return self.data[:self.size]

    def getUncompressedContents(self, force=None):
        """Return the original message from this payload's data, removing
           compression.  Raise CompressedDataTooLong if the data is too
           long, and force is not true."""
        d = self.data[:self.size]
        if force:
            return uncompressData(d)
        else:
            maxLen = max(20*1024, 20*len(d))
            return uncompressData(d, maxLen)

    def pack(self):
        """Check for reasonable values of fields, and return a packed payload.
        """
        assert (0x8000 & self.size) == 0
        assert 0 <= self.size <= len(self.data)
        assert len(self.hash) == DIGEST_LEN
        assert (PAYLOAD_LEN - SINGLETON_PAYLOAD_OVERHEAD - len(self.data)) in \
               (0, ENC_FWD_OVERHEAD)
        header = struct.pack(SINGLETON_UNPACK_PATTERN, self.size, self.hash)
        return "%s%s" % (header, self.data)

class FragmentPayload(_Payload):
    """Represents the fields of a decoded fragment payload.
    """
    def __init__(self, index, digest, msgID, msgLen, data):
        self.index = index
        self.hash = digest
        self.msgID = msgID
        self.msgLen = msgLen
        self.data = data

    def computeHash(self):
        """Update the hash field of this payload to correspond to the hash
           of the data."""
        self.hash = "X"*DIGEST_LEN
        p = self.pack()
        self.hash = sha1(p[23:])

    def isSingleton(self):
        """Return false; not a singleton"""
        return 0

    def pack(self):
        """Returns the string value of this payload."""
        assert 0 <= self.index <= MAX_N_FRAGMENTS
        assert len(self.hash) == DIGEST_LEN
        assert len(self.msgID) == FRAGMENT_MESSAGEID_LEN
        assert len(self.data) < self.msgLen < 0x100000000L
        assert (PAYLOAD_LEN - FRAGMENT_PAYLOAD_OVERHEAD - len(self.data)) in \
               (0, ENC_FWD_OVERHEAD)
        idxhi = ((self.index & 0xff0000) >> 16) | 0x80
        idxlo = self.index & 0x00fffff
        header = struct.pack(FRAGMENT_UNPACK_PATTERN, idxhi, idxlo,
                             self.hash, self.msgID, self.msgLen)
        return "%s%s" % (header, self.data)

    def getOverhead(self):
        return PAYLOAD_LEN - FRAGMENT_PAYLOAD_OVERHEAD - len(self.data)

#----------------------------------------------------------------------
# Encoding of messages fragmented for reassembly by the exit server.
#
# Such messages are encoded by adding routing-type, routing-len, and
# routing-info fields at the start of the payload before fragmentation,
# so that the server doesn't recover the delivery address before it's time
# to deliver the message.

SSF_UNPACK_PATTERN = "!HH"
SSF_PREFIX_LEN = 4

def parseServerSideFragmentedMessage(s):
    if len(s) < SSF_PREFIX_LEN:
        raise ParseError("Server-side fragmented message too short")

    rt, rl = struct.unpack(SSF_UNPACK_PATTERN, s[:SSF_PREFIX_LEN])
    if len(s) < SSF_PREFIX_LEN + rl:
        raise ParseError("Server-side fragmented message too short")
    ri = s[SSF_PREFIX_LEN:SSF_PREFIX_LEN+rl]
    comp = s[SSF_PREFIX_LEN+rl:]
    return ServerSideFragmentedMessage(rt, ri, comp)

class ServerSideFragmentedMessage:
    def __init__(self, routingtype, routinginfo, compressedContents):
        self.routingtype = routingtype
        self.routinginfo = routinginfo
        self.compressedContents = compressedContents
    def pack(self):
        return "%s%s%s" % (struct.pack(SSF_UNPACK_PATTERN, self.routingtype,
                                       len(self.routinginfo)),
                           self.routinginfo,
                           self.compressedContents)

#----------------------------------------------------------------------
# REPLY BLOCKS

# A reply block is: the string "SURB", a major number, a minor number,
#   a 4-byte "valid-until" timestamp, a 2K header, 2 bytes of routingLen for
#   the last server in the first leg; 2 bytes of routingType for the last
#   server in the first leg; a 16-byte shared end-to-end key, and the
#   routingInfo for the last server.
RB_UNPACK_PATTERN = "!4sBBL%dsHH%ss" % (HEADER_LEN, SECRET_LEN)
MIN_RB_LEN = 30+HEADER_LEN
RB_ARMOR_NAME = "TYPE III REPLY BLOCK"

def parseTextReplyBlocks(s):
    """Given a string holding one or more text-encoded reply blocks,
       return a list containing the reply blocks.  Raise ParseError on
       failure."""

    try:
        res = unarmorText(s, (RB_ARMOR_NAME,), base64=1)
    except ValueError, e:
        raise ParseError(str(e))
    blocks = []
    for tp, fields, value in res:
        d = {}
        for k,v in fields:
            d[k]=v
        if not d.get("Version") == '0.2':
            LOG.warn("Skipping SURB with bad version: %r", d.get("Version"))
        blocks.append(parseReplyBlock(value))
    return blocks

def parseReplyBlocks(s):
    """Given a string containing a list of concatenated encoded reply blocks,
       return list of reply blocks corresponding to those in the string.
       Raise ParseError on failure.
    """
    blocks = []
    while 1:
        # Skip over any whitespace before or after the reply blocks.
        while s and s[0] in ' \t\r\n':
            s = s[1:]
        if not s:
            break
        block, length = _parseReplyBlock(s)
        blocks.append(block)
        s = s[length:]
    return blocks

def parseReplyBlock(s):
    """Return a new ReplyBlock object for an encoded reply block.

       Raise ParseError on failure.
    """
    block, length = _parseReplyBlock(s)
    if length > len(s):
        raise ParseError("Misformatted reply block: extra data.")
    return block

def _parseReplyBlock(s):
    """Helper function: Given a string containing one or more (binary) reply
       blocks, extract the first one.  On success, return a tuple containing
       a ReplyBlock, and the length of 's' taken up by the reply block."""
    if len(s) < MIN_RB_LEN:
        raise ParseError("Reply block too short")
    try:
        magic, major, minor, timestamp, header, rlen, rt, key = \
               struct.unpack(RB_UNPACK_PATTERN, s[:MIN_RB_LEN])
    except struct.error:
        raise ParseError("Misformatted reply block")

    if magic != 'SURB':
        raise ParseError("Misformatted reply block")

    if major != 0x00 or minor != 0x01:
        raise ParseError("Unrecognized version on reply block %s.%s"
                         %(major,minor))

    ri = s[MIN_RB_LEN:]
    length = rlen + MIN_RB_LEN
    ri = ri[:rlen]

    surb =  ReplyBlock(header, timestamp, rt, ri, key)
    return surb, length

class ReplyBlock:
    """A mixminion reply block, including the address of the first hop
       on the path, and the RoutingType and RoutingInfo for the server."""
    def __init__(self, header, useBy, rt, ri, key):
        """Construct a new Reply Block."""
        assert len(header) == HEADER_LEN
        self.header = header
        self.timestamp = useBy
        self.routingType = rt
        self.routingInfo = ri
        self.encryptionKey = key

    def format(self):
        import mixminion.ServerInfo
        digest = binascii.b2a_hex(sha1(self.pack()))
        expiry = formatTime(self.timestamp)
        if self.routingType == SWAP_FWD_IPV4_TYPE:
            routing = parseIPV4Info(self.routingInfo)
        elif self.routingType == SWAP_FWD_HOST_TYPE:
            routing = parseMMTPHostInfo(self.routingInfo)
        else:
            routing = None
        server = mixminion.ServerInfo.displayServerByRouting(routing)
        return """Reply block hash: %s
Expires at: %s GMT
First server is: %s""" % (digest, expiry, server)

    def pack(self):
        """Returns the external representation of this reply block"""
        return struct.pack(RB_UNPACK_PATTERN,
                           "SURB", 0x00, 0x01, self.timestamp, self.header,
                           len(self.routingInfo), self.routingType,
                           self.encryptionKey) + self.routingInfo

    def packAsText(self):
        """Returns the external text representation of this reply block"""
        return armorText(self.pack(), RB_ARMOR_NAME,
                         headers=(("Version", "0.2"),))

#----------------------------------------------------------------------
# Routing info

def parseRelayInfoByType(routingType,routingInfo):
    """Parse the routingInfo contained in the string 'routinginfo',
       according to the type in 'routingType'.  Only relay types are
       supported."""
    if routingType in (FWD_IPV4_TYPE, SWAP_FWD_IPV4_TYPE):
        parseFn = parseIPV4Info
        parsedType = IPV4Info
    elif routingType in (FWD_HOST_TYPE, SWAP_FWD_HOST_TYPE):
        parseFn = parseMMTPHostInfo
        parsedType = MMTPHostInfo
    else:
        raise MixFatalError("Unrecognized relay type 0x%04X"%routingType)
    if type(routingInfo) == types.StringType:
        routingInfo = parseFn(routingInfo)
    assert isinstance(routingInfo, parsedType)
    return routingInfo

# An IPV4 address (Used by SWAP_FWD and FWD) is packed as: four bytes
# of IP address, a short for the portnum, and DIGEST_LEN bytes of keyid.
IPV4_PAT = "!4sH%ds" % DIGEST_LEN

def parseIPV4Info(s):
    """Converts routing info for an IPV4 address into an IPV4Info object,
       suitable for use by FWD_IPV4 or SWAP_FWD_IPV4 modules."""
    if len(s) != 4+2+DIGEST_LEN:
        raise ParseError("IPV4 information with wrong length (%d)" % len(s))
    try:
        ip, port, keyinfo = struct.unpack(IPV4_PAT, s)
    except struct.error:
        raise ParseError("Misformatted IPV4 routing info")
    ip = inet_ntoa(ip)
    return IPV4Info(ip, port, keyinfo)

class IPV4Info:
    """An IPV4Info object represents the routinginfo for a FWD_IPV4 or
       SWAP_FWD_IPV4 hop.  This kind of routing is only used with older
       servers that don't support hostname-based routing.

       Fields: ip (a dotted quad string), port (an int from 0..65535),
       and keyinfo (a digest)."""
    #XXXX007/8 phase this out.
    def __init__(self, ip, port, keyinfo):
        """Construct a new IPV4Info"""
        assert 0 <= port <= 65535
        self.ip = ip
        self.port = port
        self.keyinfo = keyinfo

    def format(self):
        return "%s:%s (keyid=%s)"%(self.ip, self.port,
                                   binascii.b2a_hex(self.keyinfo))


    def pack(self):
        """Return the routing info for this address"""
        assert len(self.keyinfo) == DIGEST_LEN
        return struct.pack(IPV4_PAT, inet_aton(self.ip),
                           self.port, self.keyinfo)

    def __repr__(self):
        return "IPV4Info(%r, %r, %r)"%(self.ip, self.port, self.keyinfo)

    def __hash__(self):
        return hash(self.pack())

    def __cmp__(self, other):
        r = cmp(type(self), type(other))
        if r: return r
        r = cmp(self.ip, other.ip)
        if r: return r
        r = cmp(self.port, other.port)
        if r: return r
        return cmp(self.keyinfo, other.keyinfo)

MMTP_HOST_PAT = "!H%ds" % DIGEST_LEN

def parseMMTPHostInfo(s):
    """Converts routing info for a hostname address into an MMTPHostInfo
    object, suitable for use by FWD_HOST or SWAP_FWD_HOST modules."""
    if len(s) < 2+DIGEST_LEN+1:
        raise ParseError("Routing information is too short.")
    try:
        port, keyinfo = struct.unpack(MMTP_HOST_PAT, s[:2+DIGEST_LEN])
    except struct.error:
        raise ParseError("Misformatted routing info")
    host = s[2+DIGEST_LEN:]
    if not isPlausibleHostname(host):
        raise ParseError("Nonsensical hostname")
    return MMTPHostInfo(s[2+DIGEST_LEN:], port, keyinfo)

class MMTPHostInfo:
    """An MMTPHostInfo object represents the routinginfo for a FWD_HOST or
       SWAP_FWD_HOST hop.

       Fields: hostname, port (an int from 0..65535), and keyinfo (a
       digest)."""
    def __init__(self, hostname, port, keyinfo):
        assert 0 <= port <= 65535
        self.hostname = hostname.lower()
        self.port = port
        self.keyinfo = keyinfo

    def format(self):
        return "%s:%s (keyid=%s)"%(self.hostname, self.port,
                                   binascii.b2a_hex(self.keyinfo))

    def pack(self):
        """Return the routing info for this address"""
        assert len(self.keyinfo) == DIGEST_LEN
        return struct.pack(MMTP_HOST_PAT,self.port,self.keyinfo)+self.hostname

    def __repr__(self):
        return "MMTPHostInfo(%r, %r, %r)"%(
            self.hostname,self.port,self.keyinfo)

    def __hash__(self):
        return hash(self.pack())

    def __cmp__(self, other):
        r = cmp(type(self), type(other))
        if r: return r
        r = cmp(self.hostname, other.hostname)
        if r: return r
        r = cmp(self.port, other.port)
        if r: return r
        return cmp(self.keyinfo, other.keyinfo)

def parseSMTPInfo(s):
    """Convert the encoding of an SMTP exitinfo into an SMTPInfo object."""
    if not isSMTPMailbox(s):
        raise ParseError("Invalid rfc822 mailbox %r" % s)
    return SMTPInfo(s)

class SMTPInfo:
    """Represents the exit address for an SMTP hop.

       Fields: email (an email address)"""
    def __init__(self, email):
        self.email = email

    def pack(self):
        """Returns the wire representation of this SMTPInfo"""
        return self.email

def parseMBOXInfo(s):
    """Convert the encoding of an MBOX exitinfo into an MBOXInfo address"""
    if not s:
        raise ParseError("Empty mbox")
    return MBOXInfo(s)

class MBOXInfo:
    """Represents the exitinfo for an MBOX hop.

       Fields: user (a user identifier)"""
    def __init__(self, user):
        self.user = user

    def pack(self):
        """Return the external representation of this routing info."""
        return self.user

#----------------------------------------------------------------------
# Ascii-encoded packets
#
# A packet is an ASCII-armored object, with the following headers:
#     Message-type: (plaintext|encrypted|binary|overcompressed)
#    [Decoding-handle: base64-encoded-stuff]
#
# If Message-type is 'plaintext', the body is dash-escaped.  Otherwise,
# the body is base64-encoded.

MESSAGE_ARMOR_NAME = "TYPE III ANONYMOUS MESSAGE"

def parseTextEncodedMessages(msg,force=0):
    """Given a text-encoded Type III packet, return a list of
       TextEncodedMessage objects or raise ParseError.

          force -- uncompress the message even if it's overcompressed.
    """

    def isBase64(t,f):
        for k,v in f:
            if k == "Message-type":
                if v != 'plaintext':
                    return 1
        return 0

    unarmored = unarmorText(msg, (MESSAGE_ARMOR_NAME,), base64fn=isBase64)
    res = []
    for tp,fields,val in unarmored:
        d = {}
        for k,v in fields:
            d[k] = v
        if d.get("Message-type", "plaintext") == "plaintext":
            msgType = 'TXT'
        elif d['Message-type'] == 'overcompressed':
            msgType = "LONG"
        elif d['Message-type'] == 'binary':
            msgType = "BIN"
        elif d['Message-type'] == 'encrypted':
            msgType = "ENC"
        elif d['Message-type'] == 'fragment':
            msgType = "FRAG"
        else:
            raise ParseError("Unknown message type: %r"%d["Message-type"])

        ascTag = d.get("Decoding-handle")
        if ascTag:
            msgType = "ENC"

        if msgType == 'LONG' and force:
            msg = uncompressData(msg)

        if msgType in ('TXT','BIN','LONG','FRAG'):
            res.append(TextEncodedMessage(val, msgType))
        else:
            assert msgType == 'ENC'
            try:
                tag = binascii.a2b_base64(ascTag)
            except (TypeError, binascii.Incomplete, binascii.Error), e:
                raise ParseError("Error in base64 encoding: %s"%e)
            if len(tag) != TAG_LEN:
                raise ParseError("Impossible tag length: %s"%len(tag))
            res.append(TextEncodedMessage(val, 'ENC', tag))

    return res

class TextEncodedMessage:
    """A TextEncodedMessage object holds a Type III message as delivered
       over a text-based medium."""
    def __init__(self, contents, messageType, tag=None):
        """Create a new TextEncodedMessage given a set of contents, a
           messageType ('TXT', 'ENC', 'LONG', 'FRAG' or 'BIN'), and optionally
           a tag.
           """
        assert messageType in ('TXT', 'ENC', 'LONG', 'BIN', 'FRAG')
        assert tag is None or (messageType == 'ENC' and len(tag) == TAG_LEN)
        self.contents = contents
        self.messageType = messageType
        self.tag = tag
    def isBinary(self):
        """Return true iff this is a binary plaintext packet."""
        return self.messageType == 'BIN'
    def isText(self):
        """Return true iff this is a text plaintext packet."""
        return self.messageType == 'TXT'
    def isEncrypted(self):
        """Return true iff this is an encrypted packet."""
        return self.messageType == 'ENC'
    def isOvercompressed(self):
        """Return true iff this is an overcompressed plaintext packet."""
        return self.messageType == 'LONG'
    def isFragment(self):
        """Return true iff this is a fragment packet."""
        return self.messageType == 'FRAG'
    def getContents(self):
        """Return the (unencoded) contents of this packet."""
        return self.contents
    def getTag(self):
        """Return the (unencoded) decoding handle for this packet, or None."""
        return self.tag
    def pack(self):
        """Return the text representation of this message."""
        c = self.contents
        fields = [("Message-type",
                   { 'TXT' : "plaintext",
                     'LONG' : "overcompressed",
                     'BIN' : "binary",
                     'ENC' : "encrypted",
                     'FRAG' : 'fragment' }[self.messageType]),
                  ]
        if self.messageType == 'ENC':
            fields.append(("Decoding-handle",
                           binascii.b2a_base64(self.tag).strip()))

        return armorText(c, MESSAGE_ARMOR_NAME, headers=fields,
                         base64=(self.messageType!='TXT'))

#----------------------------------------------------------------------
# Header encoding

# Longest allowed length of a single header.
MAX_HEADER_LEN = 900

def encodeMailHeaders(subject=None, fromAddr=None, inReplyTo=None,
                      references=None):
    """Given (optionally) any of the headers permissible for email
       messages, return a string to be prepended to a message before
       encoding.  Raise MixError on failure."""
    headers = {}
    if subject:
        headers['SUBJECT'] = subject
    if fromAddr:
        for badchar in ('"', '[', ']', ':'):
            if badchar in fromAddr:
                raise MixError("Forbidden character %r in from address"%
                               badchar)
        headers['FROM'] = fromAddr
    if inReplyTo:
        headers['IN-REPLY-TO'] = inReplyTo
    if references:
        headers['REFERENCES'] = references
    return encodeMessageHeaders(headers)

def encodeMessageHeaders(headers):
    """Given a dictionary of (header,header-value) entries, encode the
       entries and return a string to be prepended to a message before
       encoding.  Requires that headers are in acceptable format.
       Raises MixError on failure.
    """
    items = []
    hitems = headers.items()
    hitems.sort()
    for k,v in hitems:
        item = "%s:%s\n"%(k,v)
        if not HEADER_RE.match(item) or "\n" in k or "\n" in v:
            raise ParseError("Invalid value for %s header"%k)
        if len(v) > 900:
            raise ParseError("The %s header is too long"%k.lower())
        items.append(item)
    items.append("\n")
    return "".join(items)

HEADER_RE = re.compile(r'^([!-9;-~]+):([ -~]*)\n')

def parseMessageAndHeaders(message):
    """Given a message with encoded headers, return a 2-tuple containing
       the message, and a dictionary mapping header names to header values.
       Skips improperly formatted headers."""
    headers = {}
    msg = message
    while 1:
        if msg[0] == '\n':
            return msg[1:], headers
        m = HEADER_RE.match(msg)
        if m:
            k,v = m.groups()
            if len(v) > MAX_HEADER_LEN:
                LOG.warn("Rejecting overlong exit header %r:%r...",k,v[:30])
            else:
                headers[k] = v
            msg = msg[m.end():]
        else:
            LOG.warn("Could not parse headers on message; not using them.")
            return message, headers

    raise AssertionError # Unreached; appease pychecker

#----------------------------------------------------------------------
# COMPRESSION FOR PAYLOADS

# Global: contains 0 if we haven't validated zlib; 1 if we have, and 0.5
#    if we're in the middle of validation.
_ZLIB_LIBRARY_OK = 0

def compressData(payload):
    """Given a string 'payload', compress it with the 'deflate' method
       as specified in the remailer spec and in RFC1951."""
    if not _ZLIB_LIBRARY_OK:
        _validateZlib()

    # Don't change any of these options; if different Mixminion clients
    # compress their data differently, an adversary could distinguish
    # messages generated by them.
    zobj = zlib.compressobj(zlib.Z_BEST_COMPRESSION, zlib.DEFLATED,
                            zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL,
                            zlib.Z_DEFAULT_STRATEGY)
    s1 = zobj.compress(payload)
    s2 = zobj.flush()
    s = s1 + s2

    # Now we check the 2 bytes of zlib header.  Strictly speaking,
    # these are irrelevant, as are the 4 bytes of adler-32 checksum at
    # the end.  Still, we can afford 6 bytes per payload, and
    # reconstructing the checksum to keep zlib happy is a bit of a pain.
    assert s[0] == '\x78' # deflate, 32K window
    assert s[1] == '\xda' # no dict, max compression
    return s

class CompressedDataTooLong(MixError):
    """Exception: raised when try to uncompress data that turns out to be
       longer than we had expected."""
    pass

def uncompressData(payload, maxLength=None):
    """Uncompress a string 'payload'; raise ParseError if it is not
       valid compressed data.  If the expanded data is longer than
       maxLength, we raise 'CompressedDataTooLong'."""

    if len(payload) < 6 or payload[0:2] != '\x78\xDA':
        raise ParseError("Invalid zlib header")

    # This code is necessary because versions of Python before 2.2 didn't
    # support limited-size versions of zlib.decompress.  We use a helper
    # function helpfully submitted by Zooko.
    if sys.version_info[:3] < (2,2,0) and maxLength is not None:
        try:
            return zlibutil.safe_zlib_decompress_to_retval(payload,
                                                      maxLength,
                                                  max(maxLength*3, 1<<20))
        except zlibutil.TooBigError:
            raise CompressedDataTooLong()
        except zlibutil.DecompressError, e:
            raise ParseError("Error in compressed data: %s"%e)
        except (IOError, ValueError), e:
            raise ParseError("Error in compressed data: %s"%e)

    try:
        # We can't just call zlib.decompress(payload), since we may
        # want to limit the output size.

        zobj = zlib.decompressobj(zlib.MAX_WBITS)
        # Decompress the payload.
        if maxLength is None:
            d = zobj.decompress(payload)
        else:
            # If we _do_ have Python 2.2, this is the easy way to do it.  It
            # also uses less RAM in the failing case.
            d = zobj.decompress(payload, maxLength)
            if zobj.unconsumed_tail:
                raise CompressedDataTooLong()

        # Get any leftovers, which shouldn't exist.
        nil = zobj.flush()
        if nil != '':
            raise ParseError("Error in compressed data")
        return d
    except zlib.error:
        raise ParseError("Error in compressed data")
    except (IOError, ValueError), e:
        raise ParseError("Error in compressed data: %s"%e)

def _validateZlib():
    """Internal function:  Make sure that zlib is a recognized version, and
       that it compresses things as expected.  (This check is important,
       because using a zlib version that compressed differently from zlib1.1.4
       would make senders partitionable by payload compression.)
    """
    global _ZLIB_LIBRARY_OK
    ver = getattr(zlib, "ZLIB_VERSION", None)
    if ver and ver < "1.1.2":
        raise MixFatalError("Zlib version %s is not supported"%ver)

    _ZLIB_LIBRARY_OK = 0.5
    if ver in ("1.1.2", "1.1.3", "1.1.4", "1.2.0", "1.2.0.1", "1.2.0.2",
               "1.2.0.3", "1.2.0.4", "1.2.0.5", "1.2.0.6", "1.2.0.7", 
               "1.2.0.8", "1.2.1"):
        _ZLIB_LIBRARY_OK = 1
        return

    LOG.warn("Unrecognized zlib version: %r. Spot-checking output", ver)
    # This test is inadequate, but it _might_ catch future incompatible
    # changes.
    _ZLIB_LIBRARY_OK = 0.5
    good = '\x78\xda\xed\xc6A\x11\x00 \x08\x00\xb0l\xd4\xf0\x87\x02\xf6o'+\
           '`\x0e\xef\xb6\xd7r\xed\x88S=7\xcd\xcc\xcc\xcc\xcc\xcc\xcc'+\
           '\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xbe\xdd\x03'+\
           'q\x8d\n\x93'
    if compressData("aZbAAcdefg"*1000) == good:
        _ZLIB_LIBRARY_OK = 1
    else:
        _ZLIB_LIBRARY_OK = 0
        raise MixFatalError("Zlib output not as exected.")
