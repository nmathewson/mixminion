# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Packet.py,v 1.36 2003/02/20 00:31:12 nickm Exp $
"""mixminion.Packet

   Functions, classes, and constants to parse and unparse Mixminion
   messages and related structures.

   For functions that handle client-side generation and decoding of
   packets, see BuildMessage.py.  For functions that handle
   server-side processing of packets, see PacketHandler.py."""

__all__ = [ 'compressData', 'CompressedDataTooLong', 'DROP_TYPE',
            'ENC_FWD_OVERHEAD', 'ENC_SUBHEADER_LEN',
            'FRAGMENT_PAYLOAD_OVERHEAD', 'FWD_TYPE', 'FragmentPayload',
            'HEADER_LEN', 'Header', 'IPV4Info', 'MAJOR_NO', 'MBOXInfo',
            'MBOX_TYPE', 'MINOR_NO', 'MIN_EXIT_TYPE', 'Message',
            'OAEP_OVERHEAD', 'PAYLOAD_LEN', 'ParseError', 'ReplyBlock',
            'ReplyBlock', 'SECRET_LEN', 'SINGLETON_PAYLOAD_OVERHEAD',
            'SMTPInfo', 'SMTP_TYPE', 'SWAP_FWD_TYPE', 'SingletonPayload',
            'Subheader', 'TAG_LEN', 'TextEncodedMessage',
            'getTotalBlocksForRoutingInfoLen', 'parseHeader', 'parseIPV4Info',
            'parseMBOXInfo', 'parseMessage', 'parsePayload', 'parseReplyBlock',
            'parseReplyBlocks', 'parseSMTPInfo', 'parseSubheader',
            'parseTextEncodedMessage', 'parseTextReplyBlocks', 'uncompressData'
            ]

import binascii
import re
import struct
import sys
import zlib
from socket import inet_ntoa, inet_aton
from mixminion.Common import MixError, MixFatalError, encodeBase64, \
     floorDiv, formatTime, isSMTPMailbox, LOG
from mixminion.Crypto import sha1

if sys.version_info[:3] < (2,2,0):
    import mixminion._zlibutil as zlibutil

# Major and minor number for the understood packet format.
MAJOR_NO, MINOR_NO = 0,2

# Length of a Mixminion message
MESSAGE_LEN = 1 << 15
# Length of a header section
HEADER_LEN  = 128 * 16
# Length of a single payload
PAYLOAD_LEN = MESSAGE_LEN - HEADER_LEN*2

# Bytes taken up by OAEP padding in RSA-encrypted data
OAEP_OVERHEAD = 42

# Length of a subheader, once RSA-encoded.
ENC_SUBHEADER_LEN = 128
# Smallest possible size for a subheader
MIN_SUBHEADER_LEN = 42
# Most information we can fit into a subheader before padding
MAX_SUBHEADER_LEN = ENC_SUBHEADER_LEN - OAEP_OVERHEAD
# Longest routing info that will fit in the main subheader
MAX_ROUTING_INFO_LEN = MAX_SUBHEADER_LEN - MIN_SUBHEADER_LEN

# Length of a digest
DIGEST_LEN = 20
# Length of a secret key
SECRET_LEN = 16
# Length of end-to-end message tag
TAG_LEN = 20

# Most info that fits in a single extened subheader
ROUTING_INFO_PER_EXTENDED_SUBHEADER = ENC_SUBHEADER_LEN

#----------------------------------------------------------------------
# Values for the 'Routing type' subheader field
# Mixminion types
DROP_TYPE      = 0x0000  # Drop the current message
FWD_TYPE       = 0x0001  # Forward the msg to an IPV4 addr via MMTP
SWAP_FWD_TYPE  = 0x0002  # SWAP, then forward the msg to an IPV4 addr via MMTP

# Exit types
MIN_EXIT_TYPE  = 0x0100  # The numerically first exit type.
SMTP_TYPE      = 0x0100  # Mail the message
MBOX_TYPE      = 0x0101  # Send the message to one of a fixed list of addresses
MAX_EXIT_TYPE  = 0xFFFF

class ParseError(MixError):
    """Thrown when a message or portion thereof is incorrectly formatted."""
    pass

#----------------------------------------------------------------------
# PACKET-LEVEL STRUCTURES

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
    """Represents a 2K Mixminion header, containing up to 16 subheaders."""
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
    if rt >= MIN_EXIT_TYPE and rlen < 20:
        raise ParseError("Subheader missing tag")
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
    """Represents a decoded Mixminion subheader

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

    def getExitAddress(self):
        """Return the part of the routingInfo that contains the delivery
           address.  (Requires that routingType is an exit type.)"""
        assert self.routingtype >= MIN_EXIT_TYPE
        assert len(self.routinginfo) >= TAG_LEN
        return self.routinginfo[TAG_LEN:]

    def getTag(self):
        """Return the part of the routingInfo that contains the decoding
           tag. (Requires that routingType is an exit type.)"""
        assert self.routingtype >= MIN_EXIT_TYPE
        assert len(self.routinginfo) >= TAG_LEN
        return self.routinginfo[:TAG_LEN]

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

#----------------------------------------------------------------------
# UNENCRYPTED PAYLOADS

# Length of the 'MessageID' field in a fragment payload
FRAGMENT_MESSAGEID_LEN = 20
# Maximum number of fragments associated with a given message
MAX_N_FRAGMENTS = 0x7ffff

# Number of bytes taken up by header fields in a singleton payload.
SINGLETON_PAYLOAD_OVERHEAD = 2 + DIGEST_LEN
# Number of bytes taken up by header fields in a fragment payload.
FRAGMENT_PAYLOAD_OVERHEAD = 2 + DIGEST_LEN + FRAGMENT_MESSAGEID_LEN + 4
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
        idx, hash, msgID, msgLen = struct.unpack(FRAGMENT_UNPACK_PATTERN,
                                         payload[:FRAGMENT_PAYLOAD_OVERHEAD])
        idx &= 0x7f
        contents = payload[FRAGMENT_PAYLOAD_OVERHEAD:]
        if msgLen <= len(contents):
            raise ParseError("Payload has an invalid size field")
        return FragmentPayload(idx,hash,msgID,msgLen,contents)
    else:
        # We have a singleton
        size, hash = struct.unpack(SINGLETON_UNPACK_PATTERN,
                                   payload[:SINGLETON_PAYLOAD_OVERHEAD])
        contents = payload[SINGLETON_PAYLOAD_OVERHEAD:]
        if size > len(contents):
            raise ParseError("Payload has invalid size field")
        return SingletonPayload(size,hash,contents)

# A singleton payload starts with a 0 bit, 15 bits of size, and a 20-byte hash
SINGLETON_UNPACK_PATTERN = "!H%ds" % (DIGEST_LEN)

# A fragment payload starts with a 1 bit, a 15-bit paket index, a 20-byte hash,
# a 20-byte message ID, and 4 bytes of message size.
FRAGMENT_UNPACK_PATTERN = "!H%ds%dsL" % (DIGEST_LEN, FRAGMENT_MESSAGEID_LEN)

class _Payload:
    pass

class SingletonPayload(_Payload):
    """Represents the payload for a standalone mixminion message.
       Fields:  size, hash, data.  (Note that data is padded.)"""
    def __init__(self, size, hash, data):
        self.size = size
        self.hash = hash
        self.data = data

    def isSingleton(self):
        """Returns true; this is a singleton payload."""
        return 1

    def getContents(self):
        """Returns the non-padding portion of this payload's data"""
        return self.data[:self.size]

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

       FFFF Fragments are not yet fully supported; there's no code to generate
            or decode them.
    """
    def __init__(self, index, hash, msgID, msgLen, data):
        self.index = index
        self.hash = hash
        self.msgID = msgID
        self.msgLen = msgLen
        self.data = data

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
        idx = self.index | 0x8000
        header = struct.pack(FRAGMENT_UNPACK_PATTERN, idx, self.hash,
                             self.msgID, self.msgLen)
        return "%s%s" % (header, self.data)

#----------------------------------------------------------------------
# REPLY BLOCKS

# A reply block is: the string "SURB", a major number, a minor number,
#   a 4-byte "valid-until" timestamp, a 2K header, 2 bytes of routingLen for
#   the last server in the first leg; 2 bytes of routingType for the last
#   server in the first leg; a 16-byte shared end-to-end key, and the
#   routingInfo for the last server.
RB_UNPACK_PATTERN = "!4sBBL%dsHH%ss" % (HEADER_LEN, SECRET_LEN)
MIN_RB_LEN = 30+HEADER_LEN
RB_TEXT_START = "======= BEGIN TYPE III REPLY BLOCK ======="
RB_TEXT_END   = "======== END TYPE III REPLY BLOCK ========"
# XXXX Use a better pattern here.
RB_TEXT_RE = re.compile(r"==+ BEGIN TYPE III REPLY BLOCK ==+"+
                        r'[\r\n]+Version: (\d+\.\d+)\s*[\r\n]+(.*?)'+
                        r"==+ END TYPE III REPLY BLOCK ==+", re.M|re.DOTALL) 

def parseTextReplyBlocks(s):
    """Given a string holding one or more text-encoded reply blocks,
       return a list containing the reply blocks.  Raise ParseError on
       failure."""
    idx = 0
    blocks = []
    while 1:
        m = RB_TEXT_RE.search(s[idx:])
        if m is None:
            # FFFF Better errors on malformatted reply blocks.
            break
        version, text = m.group(1), m.group(2)
        idx += m.end()
        if version != '0.1':
            LOG.warn("Skipping reply block with unrecognized version: %s",
                     version)
            continue
        try:
            val = binascii.a2b_base64(text)
        except (TypeError, binascii.Incomplete, binascii.Error), e:
            raise ParseError("Bad reply block encoding: %s"%e)
        blocks.append(parseReplyBlock(val))
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
        block, length = parseReplyBlock(s, allowMore=1, returnLen=1)
        blocks.append(block)
        s = s[length:]
    return blocks

def parseReplyBlock(s, allowMore=0, returnLen=0):
    """Return a new ReplyBlock object for an encoded reply block.
       If allowMore is true, accept a string that only begins with a
       reply block.  If returnLen is true, return a 2-tuple of the
       reply block, and its length when encoded.

       Raise ParseError on failure.
    """

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
        raise ParseError("Unrecognized version on reply block %s.%s",
                         major,minor)

    ri = s[MIN_RB_LEN:]
    length = rlen + MIN_RB_LEN
    if allowMore:
        ri = ri[:rlen]
    elif len(ri) != rlen:
        raise ParseError("Misformatted reply block")

    surb =  ReplyBlock(header, timestamp, rt, ri, key)
    if returnLen:
        return surb, length
    else:
        return surb

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
        hash = binascii.b2a_hex(sha1(self.pack()))
        expiry = formatTime(self.timestamp)
        if self.routingType == SWAP_FWD_TYPE:
            server = parseIPV4Info(self.routingInfo).format()
        else:
            server = "????"
        return """Reply block hash: %s
Expires at: %s GMT
First server is: %s""" % (hash, expiry, server)

    def pack(self):
        """Returns the external representation of this reply block"""
        return struct.pack(RB_UNPACK_PATTERN,
                           "SURB", 0x00, 0x01, self.timestamp, self.header,
                           len(self.routingInfo), self.routingType,
                           self.encryptionKey) + self.routingInfo

    def packAsText(self):
        """Returns the external text representation of this reply block"""
        text = encodeBase64(self.pack())
        if not text.endswith("\n"):
            text += "\n"
        return "%s\nVersion: 0.1\n\n%s%s\n"%(RB_TEXT_START,text,RB_TEXT_END)
    
#----------------------------------------------------------------------
# Routing info

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
    """An IPV4Info object represents the routinginfo for a FWD or
       SWAP_FWD hop.

       Fields: ip (a dotted quad string), port (an int from 0..65535),
       and keyinfo (a digest)."""
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
        if r: return n
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
# The format is HeaderLine, TagLine?, Body, FooterLine.
#     TagLine is one of /Message-type: (overcompressed|binary)/
#                    or /Decoding-handle: (base64-encoded-stuff)/.
MESSAGE_START_LINE = "======= TYPE III ANONYMOUS MESSAGE BEGINS ======="
MESSAGE_END_LINE   = "======== TYPE III ANONYMOUS MESSAGE ENDS ========"
_MESSAGE_START_RE  = re.compile(r"==+ TYPE III ANONYMOUS MESSAGE BEGINS ==+")
_MESSAGE_END_RE    = re.compile(r"==+ TYPE III ANONYMOUS MESSAGE ENDS ==+")
#XXXX004 disable "decoding handle" format
_FIRST_LINE_RE = re.compile(r'''^Decoding[- ]handle:\s(.*)\r*\n|
                                 Message-type:\s(.*)\r*\n''', re.X+re.S)
_LINE_RE = re.compile(r'[^\r\n]*\r*\n', re.S+re.M)

def _nextLine(s, idx):
    """Helper method.  Return the index of the first character of the first
       line of s to follow <idx>."""
    m = _LINE_RE.match(s[idx:])
    if m is None:
        return len(s)
    else:
        return m.end()+idx

def parseTextEncodedMessage(msg,force=0,idx=0):
    """Given a text-encoded Type III packet, return a TextEncodedMessage
       object or raise ParseError.
          force -- uncompress the message even if it's overcompressed.
          idx -- index within <msg> to search.
    """
    #idx = msg.find(MESSAGE_START_PAT, idx)
    m = _MESSAGE_START_RE.search(msg[idx:])
    if m is None:
        return None, None
    idx += m.start()
    m = _MESSAGE_END_RE.search(msg[idx:])
    if m is None:
        raise ParseError("No end line found")
    msgEndIdx = idx+m.start()
    idx = _nextLine(msg, idx)
    firstLine = msg[idx:_nextLine(msg, idx)]
    m = _FIRST_LINE_RE.match(firstLine)
    if m is None:
        msgType = 'TXT'
    elif m.group(1):
        ascTag = m.group(1)
        msgType = "ENC" 
        idx = _nextLine(msg, idx)
    elif m.group(2):
        if m.group(2) == 'overcompressed':
            msgType = 'LONG' 
        elif m.group(2) == 'binary':
            msgType = 'BIN'
        else:
            raise ParseError("Unknown message type: %r"%m.group(2))
        idx = _nextLine(msg, idx)

    endIdx = _nextLine(msg, msgEndIdx)
    msg = msg[idx:msgEndIdx]

    if msgType == 'TXT':
        return TextEncodedMessage(msg, 'TXT'), endIdx

    try:
        msg = binascii.a2b_base64(msg)
    except (TypeError, binascii.Incomplete, binascii.Error), e:
        raise ParseError("Error in base64 encoding: %s"%e)

    if msgType == 'BIN':
        return TextEncodedMessage(msg, 'BIN'), endIdx
    elif msgType == 'LONG':
        if force:
            msg = uncompressData(msg) # May raise ParseError
        return TextEncodedMessage(msg, 'LONG'), endIdx
    elif msgType == 'ENC':
        try:
            tag = binascii.a2b_base64(ascTag)
        except (TypeError, binascii.Incomplete, binascii.Error), e:
            raise ParseError("Error in base64 encoding: %s"%e)
        if len(tag) != TAG_LEN:
            raise ParseError("Impossible tag length: %s"%len(tag))
        return TextEncodedMessage(msg, 'ENC', tag), endIdx
    else:
        raise MixFatalError("unreached")

class TextEncodedMessage:
    """A TextEncodedMessage object holds a Type-III message as delivered
       over a text-based medium."""
    def __init__(self, contents, messageType, tag=None):
        """Create a new TextEncodedMessage given a set of contents, a
           messageType ('TXT', 'ENC', 'LONG', or 'BIN'), and optionally
           a tag."""
        assert messageType in ('TXT', 'ENC', 'LONG', 'BIN')
        assert tag is None or (messageType == 'ENC' and len(tag) == 20)
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
    def getContents(self):
        """Return the (unencoded) contents of this packet."""
        return self.contents
    def getTag(self):
        """Return the (unencoded) decoding handle for this packet, or None."""
        return self.tag
    def pack(self):
        """Return the text representation of this message."""
        c = self.contents
        preNL = postNL = ""

        if self.messageType != 'TXT':
            c = encodeBase64(c)
        else:
            #XXXX004 disable "decoding handle" format
            if (c.startswith("Decoding-handle:") or
                c.startswith("Decoding handle:") or
                c.startswith("Message-type:")):
                preNL = "\n"
                
        if self.messageType == 'TXT':
            tagLine = ""
        elif self.messageType == 'ENC':
            ascTag = binascii.b2a_base64(self.tag).strip()
            tagLine = "Decoding-handle: %s\n\n" % ascTag
        elif self.messageType == 'LONG':
            tagLine = "Message-type: overcompressed\n\n"
        elif self.messageType == 'BIN':
            tagLine = "Message-type: binary\n\n"

        if c and c[-1] != '\n':
            postNL = "\n"

        return "%s\n%s%s%s%s%s\n" % (
            MESSAGE_START_LINE, tagLine, preNL, c, postNL, MESSAGE_END_LINE)

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
    ver = getattr(zlib, "ZLIB_VERSION")
    if ver and ver < "1.1.2":
        raise MixFatalError("Zlib version %s is not supported"%ver)

    _ZLIB_LIBRARY_OK = 0.5
    if ver in ("1.1.2", "1.1.3", "1.1.4"):
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
