# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Packet.py,v 1.24 2003/02/04 02:38:23 nickm Exp $
"""mixminion.Packet

   Functions, classes, and constants to parse and unparse Mixminion
   messages and related structures.

   For functions that handle client-side generation and decoding of
   packets, see BuildMessage.py.  For functions that handle
   server-side processing of packets, see PacketHandler.py."""

__all__ = [ 'ParseError', 'Message', 'Header', 'Subheader', 'parseMessage',
            'parseHeader', 'parseSubheader',
            'getTotalBlocksForRoutingInfoLen', 'parsePayload',
            'SingletonPayload', 'FragmentPayload', 'ReplyBlock', 'IPV4Info',
            'SMTPInfo', 'MBOXInfo', 'parseIPV4Info', 'parseSMTPInfo',
            'parseMBOXInfo', 'ReplyBlock', 'parseReplyBlock',
            'parseTextReplyBlocks', 'ENC_SUBHEADER_LEN', 'HEADER_LEN',
            'PAYLOAD_LEN', 'MAJOR_NO', 'MINOR_NO', 'SECRET_LEN', 'TAG_LEN',
            'SINGLETON_PAYLOAD_OVERHEAD', 'OAEP_OVERHEAD',
            'FRAGMENT_PAYLOAD_OVERHEAD', 'ENC_FWD_OVERHEAD', 'DROP_TYPE',
            'FWD_TYPE', 'SWAP_FWD_TYPE', 'SMTP_TYPE', 'MBOX_TYPE',
            'MIN_EXIT_TYPE'
          ]

import base64
import binascii
import re
import struct
from socket import inet_ntoa, inet_aton
import mixminion.BuildMessage
from mixminion.Common import MixError, floorDiv, isSMTPMailbox, LOG

# Major and minor number for the understood packet format.
MAJOR_NO, MINOR_NO = 0,1  #XXXX003 Bump minor_no for 0.0.3

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
RB_TEXT_START = "======= BEGIN TYPE III REPLY BLOCK ========"
RB_TEXT_END   = "======== END TYPE III REPLY BLOCK ========="
RB_TEXT_RE = re.compile(RB_TEXT_START+
                        r'[\r\n]+Version: (\d+.\d+)\s*[\r\n]+(.*)[\r\n]+'+
                        RB_TEXT_END, re.M) 

def parseTextReplyBlocks(s):
    """DOCDOC"""
    idx = 0
    blocks = []
    while 1:
        idx = s.find(RB_TEXT_START, idx)
        if idx == -1:
            break
        m = RB_TEXT_RE.match(s, idx)
        if not m:
            raise ParseError("Misformatted reply block")
        version, text = m.group(1), m.group(2)
        if version != '0.1':
            LOG.warn("Unrecognized reply block version: %s", version)
        val = binascii.a2b_base64(text)
        blocks.append(parseReplyBlock(val))
        idx = m.end()
    return blocks

def parseReplyBlock(s):
    """Return a new ReplyBlock object for an encoded reply block."""        
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
    if len(ri) != rlen:
        raise ParseError("Misformatted reply block")

    return ReplyBlock(header, timestamp, rt, ri, key)

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

    def pack(self):
        """Returns the external representation of this reply block"""
        return struct.pack(RB_UNPACK_PATTERN,
                           "SURB", 0x00, 0x01, self.timestamp, self.header,
                           len(self.routingInfo), self.routingType,
                           self.encryptionKey) + self.routingInfo

    def packAsText(self):
        text = binascii.b2a_base64(self.pack())
        if not text.endswith("\n"):
            text += "\n"
        return "%s\nVersion: 0.1\n%s%s\n"%(RB_TEXT_START,text,RB_TEXT_END)
    
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

MESSAGE_START_LINE = "======= TYPE III ANONYMOUS MESSAGE BEGINS ========"
MESSAGE_END_LINE   = "======== TYPE III ANONYMOUS MESSAGE ENDS ========="
_FIRST_LINE_RE = re.compile(r'''^Decoding-handle:\s(.*)\r*\n|
                                 Message-type:\s(.*)\r*\n''', re.X+re.S)
_LINE_RE = re.compile(r'[^\r\n]+\r*\n', re.S)

def _nextLine(s, idx):
    m = _LINE_RE.match(s)
    if m is None:
        return len(s)
    else:
        return m.end()

def getMessageContents(msg,force=0,idx=0):
    """ Returns
            ( 'TXT'|'ENC'|'LONG'|'BIN', tag|None, message, end-idx )
    """
    idx = msg.find(MESSAGE_START_LINE)
    if idx < 0:
        raise ParseError("No begin line found")
    endIdx = msg.find(MESSAGE_END_LINE, idx)
    if endIdx < 0:
        raise ParseError("No end line found")
    idx = _nextLine(msg, idx)
    firstLine = msg[idx:_nextLine(msg, idx)]
    m = _FIRST_LINE_RE.match(firstLine)
    if m is None:
        msgType = 'TXT'
    elif m.group(1):
        ascTag = m.group(1)
        msgType = "ENC" #XXXX003 refactor
        idx = firstLine
    elif m.group(2):
        if m.group(2) == 'overcompressed':
            msgType = 'LONG' #XXXX003 refactor
        elif m.group(2) == 'binary':
            msgType = 'BIN' #XXXX003 refactor
        else:
            raise ParseError("Unknown message type: %r"%m.group(2))
        idx = firstLine

    msg = msg[idx:endIdx]
    endIdx = _nextLine(endIdx)

    if msgType == 'TXT':
        return 'TXT', None, msg, endIdx

    msg = binascii.a2b_base64(msg) #XXXX May raise
    if msgType == 'BIN':
        return 'BIN', None, msg, endIdx
    elif msgType == 'LONG':
        if force:
            msg = mixminion.BuildMessage.uncompressData(msg) #XXXX may raise
        return 'LONG', None, msg, endIdx
    elif msgType == 'ENC':
        tag = binascii.a2b_base64(ascTag)
        return 'ENC', tag, msg, endIdx
    else:
        raise MixFatalError("unreached")

class AsciiEncodedMessage:
    def __init__(self, contents, messageType, tag=None):
        assert messageType in ('TXT', 'ENC', 'LONG', 'BIN')
        assert tag is None or (messageType == 'ENC' and len(tag) == 20)
        self.contents = contents
        self.messageType = messageType
        self.tag = tag
    def isBinary(self):
        return self.messageType == 'BIN'
    def isText(self):
        return self.messageType == 'TXT'
    def isEncrypted(self):
        return self.messageType == 'ENC'
    def isOvercompressed(self):
        return self.messageType == 'LONG'
    def getContents(self):
        return self.contents
    def getTag(self):
        return self.tag
    def pack(self):
        c = self.contents
        preNL = ""

        if self.messageType != 'TXT':
            c = base64.encodestring(c)
        else:
            if (c.startswith("Decoding-handle:") or
                c.startswith("Message-type:")):
                preNL = "\n"
                
        preNL = postNL = ""
        if self.messageType == 'TXT':
            tagLine = ""
        elif self.messageType == 'ENC':
            ascTag = binascii.b2a_base64(self.tag).strip()
            tagLine = "Decoding-handle: %s\n" % ascTag
        elif self.messageType == 'LONG':
            tagLine = "Message-type: overcompressed\n"
        elif self.messageType == 'BIN':
            tagLine = "Message-type: binary\n"

        if c[-1] != '\n':
            postNL = "\n"

        return "%s\n%s%s%s%s%s\n" % (
            MESSAGE_START_LINE, tagLine, preNL, c, postNL, MESSAGE_END_LINE)
