# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInfo.py,v 1.29 2003/01/03 05:14:47 nickm Exp $

"""mixminion.ServerInfo

   Implementation of server descriptors (as described in the mixminion
   spec).  Includes logic to parse, validate, and generate server
   descriptors.
   """

__all__ = [ 'ServerInfo', 'ServerDirectory' ]

import gzip
import re
import time

import mixminion.Config
import mixminion.Crypto

from mixminion.Common import IntervalSet, LOG, MixError, createPrivateDir, \
    formatBase64, formatDate, formatTime
from mixminion.Config import ConfigError
from mixminion.Packet import IPV4Info
from mixminion.Crypto import CryptoError, DIGEST_LEN, pk_check_signature

# Longest allowed Contact email
MAX_CONTACT = 256
# Longest allowed Comments field
MAX_COMMENTS = 1024
# Shortest permissible identity key
MIN_IDENTITY_BYTES = 2048 >> 3
# Longest permissible identity key
MAX_IDENTITY_BYTES = 4096 >> 3
# Length of packet key
PACKET_KEY_BYTES = 1024 >> 3

# tmp alias to make this easier to spell.
C = mixminion.Config
class ServerInfo(mixminion.Config._ConfigFile):
    ## Fields: (as in ConfigFile, plus)
    # _isValidated: flag.  Has this serverInfo been fully validated?
    """A ServerInfo object holds a parsed server descriptor."""
    _restrictFormat = 1
    _syntax = {
        "Server" : { "__SECTION__": ("REQUIRE", None, None),
                     "Descriptor-Version": ("REQUIRE", None, None),
                     "IP": ("REQUIRE", C._parseIP, None),
                     "Nickname": ("REQUIRE", C._parseNickname, None),
                     "Identity": ("REQUIRE", C._parsePublicKey, None),
                     "Digest": ("REQUIRE", C._parseBase64, None),
                     "Signature": ("REQUIRE", C._parseBase64, None),
                     "Published": ("REQUIRE", C._parseTime, None),
                     "Valid-After": ("REQUIRE", C._parseDate, None),
                     "Valid-Until": ("REQUIRE", C._parseDate, None),
                     "Contact": ("ALLOW", None, None),
                     "Comments": ("ALLOW", None, None),
                     "Packet-Key": ("REQUIRE", C._parsePublicKey, None),
                     },
        "Incoming/MMTP" : {
                     "Version": ("REQUIRE", None, None),
                     "Port": ("REQUIRE", C._parseInt, None),
                     "Key-Digest": ("REQUIRE", C._parseBase64, None),
                     "Protocols": ("REQUIRE", None, None),
                     "Allow": ("ALLOW*", C._parseAddressSet_allow, None),
                     "Deny": ("ALLOW*", C._parseAddressSet_deny, None),
                     },
        "Outgoing/MMTP" : {
                     "Version": ("REQUIRE", None, None),
                     "Protocols": ("REQUIRE", None, None),
                     "Allow": ("ALLOW*", C._parseAddressSet_allow, None),
                     "Deny": ("ALLOW*", C._parseAddressSet_deny, None),
                     },
        "Delivery/MBOX" : {
                     "Version": ("REQUIRE", None, None),
                     },
        "Delivery/SMTP" : {
                     "Version": ("REQUIRE", None, None),
                     }
        }

    def __init__(self, fname=None, string=None, assumeValid=0):
        self._isValidated = 0
        mixminion.Config._ConfigFile.__init__(self, fname, string, assumeValid)
        LOG.trace("Reading server descriptor %s from %s",
                       self['Server']['Nickname'],
                       fname or "<string>")

    def validate(self, sections, entries, lines, contents):
        ####
        # Check 'Server' section.
        server = sections['Server']
        if server['Descriptor-Version'] != '0.1':
            raise ConfigError("Unrecognized descriptor version %r",
                              server['Descriptor-Version'])
        identityKey = server['Identity']
        identityBytes = identityKey.get_modulus_bytes()
        if not (MIN_IDENTITY_BYTES <= identityBytes <= MAX_IDENTITY_BYTES):
            raise ConfigError("Invalid length on identity key")
        if server['Published'] > time.time() + 600:
            raise ConfigError("Server published in the future")
        if server['Valid-Until'] <= server['Valid-After']:
            raise ConfigError("Server is never valid")
        if server['Contact'] and len(server['Contact']) > MAX_CONTACT:
            raise ConfigError("Contact too long")
        if server['Comments'] and len(server['Comments']) > MAX_COMMENTS:
            raise ConfigError("Comments too long")
        packetKeyBytes = server['Packet-Key'].get_modulus_bytes()
        if packetKeyBytes != PACKET_KEY_BYTES:
            raise ConfigError("Invalid length on packet key")

        ####
        # Check Digest of file
        digest = getServerInfoDigest(contents)
        if digest != server['Digest']:
            raise ConfigError("Invalid digest")

        # Check signature
        try:
            signedDigest = pk_check_signature(server['Signature'], identityKey)
        except CryptoError:
            raise ConfigError("Invalid signature")
        
        if digest != signedDigest:
            raise ConfigError("Signed digest is incorrect")

        ## Incoming/MMTP section
        inMMTP = sections['Incoming/MMTP']
        if inMMTP:
            if inMMTP['Version'] != '0.1':
                raise ConfigError("Unrecognized MMTP descriptor version %s"%
                                  inMMTP['Version'])
            if len(inMMTP['Key-Digest']) != DIGEST_LEN:
                raise ConfigError("Invalid key digest %s"%
                                  formatBase64(inMMTP['Key-Digest']))

        ## Outgoing/MMTP section
        outMMTP = sections['Outgoing/MMTP']
        if outMMTP:
            if outMMTP['Version'] != '0.1':
                raise ConfigError("Unrecognized MMTP descriptor version %s"%
                                  inMMTP['Version'])

        # FFFF When a better client module system exists, check the
        # FFFF module descriptors.

        self._isValidated = 1

    def getNickname(self):
        """Returns this server's nickname"""
        return self['Server']['Nickname']

    def getAddr(self):
        """Returns this server's IP address"""
        return self['Server']['IP']

    def getPort(self):
        """Returns this server's IP port"""
        return self['Incoming/MMTP']['Port']

    def getPacketKey(self):
        """Returns the RSA key this server uses to decrypt messages"""
        return self['Server']['Packet-Key']

    def getKeyID(self):
        """Returns a hash of this server's MMTP key"""
        return self['Incoming/MMTP']['Key-Digest']

    def getRoutingInfo(self):
        """Returns a mixminion.Packet.IPV4Info object for routing messages
           to this server."""
        return IPV4Info(self.getAddr(), self.getPort(), self.getKeyID())

    def getIdentity(self):
        return self['Server']['Identity']

    def getCaps(self):
        # FFFF refactor this once we have client addresses.
        caps = []
        if not self['Incoming/MMTP'].get('Version',None):
            return caps
        if self['Delivery/MBOX'].get('Version', None):
            caps.append('mbox')
        if self['Delivery/SMTP'].get('Version', None):
            caps.append('smtp')
        # XXXX This next check is highly bogus.
        if self['Outgoing/MMTP'].get('Version',None):
            caps.append('relay')
        return caps

    def isValidated(self):
        """Return true iff this ServerInfo has been validated"""
        return self._isValidated

    def getIntervalSet(self):
        """Return an IntervalSet covering all the time at which this
           ServerInfo is valid."""
        #XXXX002 test
        return IntervalSet([(self['Server']['Valid-After'],
                             self['Server']['Valid-Until'])])

    def isExpiredAt(self, when):
        """Return true iff this ServerInfo expires before time 'when'."""
        #XXXX002 test
        return self['Server']['Valid-Until'] < when

    def isValidAt(self, when):
        """Return true iff this ServerInfo is valid at time 'when'."""
        #XXXX002 test
        return (self['Server']['Valid-After'] <= when <=
                self['Server']['Valid-Until'])

    def isValidFrom(self, startAt, endAt):
        """Return true iff this ServerInfo is valid at all time from 'startAt'
           to 'endAt'."""
        #XXXX002 test
        return (startAt <= self['Server']['Valid-After'] and
                self['Server']['Valid-Until'] <= endAt)

    def isValidAtPartOf(self, startAt, endAt):
        """Return true iff this ServerInfo is valid at some time between
           'startAt' and 'endAt'."""
        #XXXX002 test
        va = self['Server']['Valid-After']
        vu = self['Server']['Valid-Until']
        return ((startAt <= va and va <= endAt) or
                (startAt <= vu and vu <= endAt) or
                (va <= startAt and endAt <= vu))

    def isNewerThan(self, other):
        """Return true iff this ServerInfo was published after 'other',
           where 'other' is either a time or a ServerInfo."""
        #XXXX002 test
        if isinstance(other, ServerInfo):
            other = other['Server']['Published']
        return self['Server']['Published'] > other

#----------------------------------------------------------------------

#DOCDOC 
_server_header_re = re.compile(r'^\[\s*Server\s*\]\s*\n', re.M)
class ServerDirectory:
    #DOCDOC
    """Minimal client-side implementation of directory parsing.  This will
       become very inefficient when directories get big, but we won't have
       that problem for a while."""
   
    def __init__(self, string=None, fname=None):
        if string:
            contents = string
        elif fname.endswith(".gz"):
            # XXXX test!
            f = gzip.GzipFile(fname, 'r')
            contents = f.read()
            f.close()
        else:
            f = open(fname)
            contents = f.read()
            f.close()
        
        contents = _abnormal_line_ending_re.sub("\n", contents)

        # First, get the digest.  Then we can break everything up.
        digest = _getDirectoryDigestImpl(contents)
        
        # This isn't a good way to do this, but what the hey.
        sections = _server_header_re.split(contents)
        del contents
        headercontents = sections[0]
        servercontents = [ "[Server]\n%s"%s for s in sections[1:] ]

        self.header = _DirectoryHeader(headercontents, digest)
        self.servers = [ ServerInfo(string=s) for s in servercontents ]

    def getServers(self):
        return self.servers

    def __getitem__(self, item):
        return self.header[item]

class _DirectoryHeader(mixminion.Config._ConfigFile):
    "DOCDOC"
    _restrictFormat = 1
    _syntax = {
        'Directory': { "__SECTION__": ("REQUIRE", None, None),
                       "Version": ("REQUIRE", None, None),
                       "Published": ("REQUIRE", C._parseTime, None),
                       "Valid-After": ("REQUIRE", C._parseDate, None),
                       "Valid-Until": ("REQUIRE", C._parseDate, None),
                       },
        'Signature': {"__SECTION__": ("REQUIRE", None, None),
                 "DirectoryIdentity": ("REQUIRE", C._parsePublicKey, None),
                 "DirectoryDigest": ("REQUIRE", C._parseBase64, None),
                 "DirectorySignature": ("REQUIRE", C._parseBase64, None),
                      }
        }

    def __init__(self, contents, expectedDigest):
        self.expectedDigest = expectedDigest
        mixminion.Config._ConfigFile.__init__(self, string=contents)

    def validate(self, sections, entries, lines, contents):
        direc = sections['Directory']
        if direc['Version'] != "0.1":
            raise ConfigError("Unrecognized directory version")
        if direc['Published'] > time.time() + 600:
            raise ConfigError("Directory published in the future")
        if direc['Valid-Until'] <= direc['Valid-After']:
            raise ConfigError("Directory is never valid")

        sig = sections['Signature']
        identityKey = sig['DirectoryIdentity']
        identityBytes = identityKey.get_modulus_bytes()
        if not (MIN_IDENTITY_BYTES <= identityBytes <= MAX_IDENTITY_BYTES):
            raise ConfigError("Invalid length on identity key")
        
        # Now, at last, we check the digest
        if self.expectedDigest != sig['DirectoryDigest']:
            raise ConfigError("Invalid digest")

        try:
            signedDigest = pk_check_signature(sig['DirectorySignature'], 
                                              identityKey)
        except CryptoError:
            raise ConfigError("Invalid signature")
        if self.expectedDigest != signedDigest:
            raise ConfigError("Signed digest was incorrect")

#----------------------------------------------------------------------
def getServerInfoDigest(info):
    """Calculate the digest of a server descriptor"""
    return _getServerInfoDigestImpl(info, None)

def signServerInfo(info, rsa):
    """Sign a server descriptor.  <info> should be a well-formed server
       descriptor, with Digest: and Signature: lines present but with
       no values."""
    return _getServerInfoDigestImpl(info, rsa)

_leading_whitespace_re = re.compile(r'^[ \t]+', re.M)
_trailing_whitespace_re = re.compile(r'[ \t]+$', re.M)
_abnormal_line_ending_re = re.compile(r'\r\n?')
def _cleanForDigest(s):
    "DOCDOC"
    # should be shared with config, serverinfo.
    s = _abnormal_line_ending_re.sub("\n", s)
    s = _trailing_whitespace_re.sub("", s)
    s = _leading_whitespace_re.sub("", s)
    if s[-1] != "\n":
        s += "\n"
    return s

def _getDigestImpl(info, regex, digestField=None, sigField=None, rsa=None):
    """Helper method.  Calculates the correct digest of a server descriptor
       (as provided in a string).  If rsa is provided, signs the digest and
       creates a new descriptor.  Otherwise just returns the digest.

       DOCDOC: NO LONGER QUITE TRUE
       """
    info = _cleanForDigest(info)
    def replaceFn(m):
        s = m.group(0)
        return s[:s.index(':')+1]
    info = regex.sub(replaceFn, info, 2)
    digest = mixminion.Crypto.sha1(info)

    if rsa is None:
        return digest
    
    signature = mixminion.Crypto.pk_sign(digest,rsa)
    digest = formatBase64(digest)
    signature = formatBase64(signature)
    def replaceFn2(s, digest=digest, signature=signature,
                   digestField=digestField, sigField=sigField):
        if s.group(0).startswith(digestField):
            return "%s: %s" % (digestField, digest)
        else:
            assert s.group(0).startswith(sigField)
            return "%s: %s" % (sigField, signature)

    info = regex.sub(replaceFn2, info, 2)
    return info

_special_line_re = re.compile(r'^(?:Digest|Signature):.*$', re.M)
def _getServerInfoDigestImpl(info, rsa=None):
    return _getDigestImpl(info, _special_line_re, "Digest", "Signature", rsa)

_dir_special_line_re = re.compile(r'^Directory(?:Digest|Signature):.*$', re.M)
def _getDirectoryDigestImpl(directory, rsa=None):
    return _getDigestImpl(directory, _dir_special_line_re, 
                          "DirectoryDigest", "DirectorySignature", rsa)
