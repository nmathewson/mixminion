# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInfo.py,v 1.26 2002/12/16 02:40:11 nickm Exp $

"""mixminion.ServerInfo

   Implementation of server descriptors (as described in the mixminion
   spec).  Includes logic to parse, validate, and generate server
   descriptors.
   """

__all__ = [ 'ServerInfo' ]

import mixminion.Config
import mixminion.Crypto

from mixminion.Common import LOG, MixError, createPrivateDir, formatBase64, \
    formatDate, formatTime
from mixminion.Config import ConfigError
from mixminion.Packet import IPV4Info
from mixminion.Crypto import DIGEST_LEN

# Longest allowed Nickname
MAX_NICKNAME = 128
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
    """A ServerInfo object holds a parsed server descriptor."""
    _restrictFormat = 1
    _syntax = {
        "Server" : { "__SECTION__": ("REQUIRE", None, None),
                     "Descriptor-Version": ("REQUIRE", None, None),
                     "IP": ("REQUIRE", C._parseIP, None),
                     "Nickname": ("REQUIRE", None, None),
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
        if len(server['Nickname']) > MAX_NICKNAME:
            raise ConfigError("Nickname too long")
        identityKey = server['Identity']
        identityBytes = identityKey.get_modulus_bytes()
        if not (MIN_IDENTITY_BYTES <= identityBytes <= MAX_IDENTITY_BYTES):
            raise ConfigError("Invalid length on identity key")
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
        if digest != mixminion.Crypto.pk_check_signature(server['Signature'],
                                                         identityKey):
            raise ConfigError("Invalid signature")

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

#----------------------------------------------------------------------
def getServerInfoDigest(info):
    """Calculate the digest of a server descriptor"""
    return _getServerInfoDigestImpl(info, None)

def signServerInfo(info, rsa):
    """Sign a server descriptor.  <info> should be a well-formed server
       descriptor, with Digest: and Signature: lines present but with
       no values."""
    return _getServerInfoDigestImpl(info, rsa)

def _getServerInfoDigestImpl(info, rsa=None):
    """Helper method.  Calculates the correct digest of a server descriptor
       (as provided in a string).  If rsa is provided, signs the digest and
       creates a new descriptor.  Otherwise just returns the digest."""

    # The algorithm's pretty easy.  We just find the Digest and Signature
    # lines, replace each with an 'Empty' version, and calculate the digest.
    infoLines = info.split("\n")
    if not infoLines[0] == "[Server]":
        raise ConfigError("Must begin with server section")
    digestLine = None
    signatureLine = None
    infoLines = info.split("\n")
    for lineNo in range(len(infoLines)):
        line = infoLines[lineNo]
        if line.startswith("Digest:") and digestLine is None:
            digestLine = lineNo
        elif line.startswith("Signature:") and signatureLine is None:
            signatureLine = lineNo

    assert digestLine is not None and signatureLine is not None

    infoLines[digestLine] = 'Digest:'
    infoLines[signatureLine] = 'Signature:'
    info = "\n".join(infoLines)

    digest = mixminion.Crypto.sha1(info)

    if rsa is None:
        return digest
    # If we got an RSA key, we need to add the digest and signature.

    signature = mixminion.Crypto.pk_sign(digest,rsa)
    digest = formatBase64(digest)
    signature = formatBase64(signature)
    infoLines[digestLine] = 'Digest: '+digest
    infoLines[signatureLine] = 'Signature: '+signature

    return "\n".join(infoLines)

