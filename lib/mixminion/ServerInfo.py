# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerInfo.py,v 1.6 2002/07/26 20:52:17 nickm Exp $

"""mixminion.ServerInfo

   Data structures to represent a server's information, and functions to
   martial and unmarshal it.

   """

__all__ = [ 'ServerInfo' ]

import time

from mixminion.Modules import SWAP_FWD_TYPE, FWD_TYPE
from mixminion.Packet import IPV4Info
import mixminion.Config
import mixminion.Crypto

ConfigError = mixminion.Config.ConfigError

# tmp variable to make this easier to spell.
C = mixminion.Config

MAX_NICKNAME = 128
MAX_CONTACT = 256
MAX_COMMENT = 1024
MIN_IDENTITY_BYTES = 2048 >> 3
MAX_IDENTITY_BYTES = 4096 >> 3
PACKET_KEY_BYTES = 1024 >> 3

class ServerInfo(mixminion.Config._ConfigFile):
    _restrictFormat = 1
    _syntax = {
	"Server" : { "__SECTION__": ("REQUIRE", None, None),
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
		     },
	"Modules/MMTP" : {
 	             "Version": ("REQUIRE", None, None),
		     "Protocols": ("REQUIRE", None, None),
		     },
	"Modules/MBOX" : {
   	             "Version": ("REQUIRE", None, None),
		     },
	"Modules/SMTP" : {
           	     "Version": ("REQUIRE", None, None),
		     }
	}

    def __init__(self, fname, string):
	mixminion.Config._ConfigFile.__init__(self, fname, string)

    def validate(self, sections, entries, lines, contents):
	####
	# Check 'Server' section.

	server = sections['Server']
	if server['Descriptor-Version'] != '1.0':
	    raise ConfigError("Unrecognized descriptor version")
	if len(server['Nickname']) > MAX_NICKNAME:
	    raise ConfigError("Nickname too long")
	identityKey = server['Identity-Key']
	identityBytes = identityKey.get_modulus_bytes()
	if not (MIN_IDENTITY_BYTES <= identityBytes <= MAX_IDENTITY_BYTES):
	    raise ConfigError("Invalid length on identity key")
	if server['Valid-Until'] <= server['Valid-After']:
	    raise ConfigError("Server is never valid")
	if len(server['Contact']) > MAX_CONTACT:
	    raise ConfigError("Contact too long")
	if len(sever['Comments']) > MAX_COMMENTS:
	    raise ConfigError("Comments too long")
	packetKeyBytes = server['Packet-Key'].get_modulus_bytes()
	if packetKeyBytes != PACKET_KEY_BYTES:
	    raise ConfigError("Invalid length on packet key")

	####
	# Check Digest of file
	digest = getServerInfoDigest(contents)
	if digest != server['Digest']:
	    raise ConfigError("Invalid digest")
	
	signature = server['']
	if digest != mixminion.Crypto.pk_check_signature(server['Signature'],
							 identityKey):
	    raise ConfigError("Invalid signature")

	#### XXXX CHECK OTHER SECTIONS

    def getAddr(self):
	return self['Server']['IP']
    
    def getPort(self):
	return self['Incoming/MMTP']['Port']
    
    def getPacketKey(self):
	return self['Server']['Packet-Key']

    def getKeyID(self):
	return self['Incoming/MMTP']['Key-Digest']

    def getRoutingInfo(self):
        """Returns a mixminion.Packet.IPV4Info object for routing messages
           to this server."""
        return IPV4Info(self.getAddr(), self.getPort(), self.getKeyID())

#----------------------------------------------------------------------
# This should go in a different file.
class ServerKeys:
    "XXXX"
    def __init__(self, keyroot, keyname, hashroot):
	self.keydir = os.path.join(keyroot, "key_"+keyname)
	self.hashlogFile = os.path.join(hashroot, "hash_"+keyname)
	self.packetKeyFile = os.path.join(keydir, "mix.key")
	self.mmtpKeyFile = os.path.join(keydir, "mmtp.key")
	self.certFile = os.path.join(keydir, "mmtp.cert")

    def load(self, password=None):
	r = mixminion.Crypto.PEM_read_key
	if password:
	    self.packetKey = r(self.packetKeyFile,0,password)
	    self.mmtpKey = r(self.mmtpKeyFile,0,password)
	else:
	    self.packetKey = r(self.packetKeyFile,0)
	    self.mmtpKey = r(self.mmtpKeyFile,0)

    def save(self, pasword=None):
	if password:
	    self.packetKey.PEM_write_key(self.packetKeyFile,0,password)
	    self.mmtpKey.PEM_write_key(self.mmtpKeyFile,0,password)
	else:
	    self.packetKey.PEM_write_key(self.packetKeyFile,0)
	    self.mmtpKey.PEM_write_key(self.mmtpKeyFile,0)

    def getCertFileName(self): return self.certFile
    def getHashLogFileName(self): return self.hashlogFile
    def getPacketKey(self): return self.packetKey
    def getMMTPKey(self): return self.mmtpKey
    def getMMTPKeyID(self): 
	return sha1(self.mmtpKey.encode_key(1))

def _base64(s):
    return binascii.b2a_base64(s).replace("\n","")

def _time(t):
    gmt = time.gmtime(t)
    return "%02d/%02s/%04d %02d:%02d:%02d" % (
	gmt[2],gmt[1],gmt[0],  gmt[3],gmt[4],gmt[5])

def _date(t):
    gmt = time.gmtime(t+1)
    return "%02d/%02s/%04d" % (gmt[2],gmt[1],gmt[0])

def generateNewServerInfoAndKeys(config, identityKey, keydir, keyname):
    packetKey = mixminion.Crypto.pk_generate(PACKET_KEY_BYTES*8)
    mmtpKey = mixminion.Crypto.pk_generate(PACKET_KEY_BYTES*8)
    
    serverKeys = ServerKeys(keydir, keyname)
    serverKeys.packetKey = packetKey
    serverKeys.mmtpKey = mmtpKey
    serverKeys.save()

    nickname = "XXXX" #XXXX"
    contact = "XXXX"
    comment = "XXXX"
    validAt = time.time() #XXXX
    validUntil = time.time()+365*24*60*60 #XXXX
    lifespan = ceilDiv(validUntil-validAt , 24*60*60)#XXXX
    
    mixminion.Crypto.generate_cert(serverKeys.getCertFileName(),
				   mmtpKey,
				   lifespan, 
				   "MMTP certificate for %s" %nickname)
    
    if not config['Server']['Incoming/MMTP']:
	# Don't generate a serverInfo if we don't allow connections in.
	return

    fields = {
	"IP": config['Incoming/MMTP']['IP'],
	"Port": config['Incoming/MMTP']['Port'],
	"Nickname": nickname,
	"Identity": 
	   _base64(mixminion.Crypto.pk_encode_public_key(identityKey)),
	"Published": _time(time.time()),
	"ValidAfter": _date(validAt),
	"ValidUntil": _date(validUntil),
	"PacketKey":
  	   _base64(mixminion.Crypto.pk_encode_public_key(publicKey)),
	"KeyID":
	   _base64(serverKeys.getMMTPKeyID()),
	}
	
    info = """\
        [Server]
	Descriptor-Version: 1.0
        IP: %(IP)s
        Port: %(Port)s
	Identity: %(Identity)s
	Digest:
        Signature:
        Published: %(Published)s
        Valid-After: %(ValidAfter)s
	Valid-Until: %(ValidUntil)s
	Packet-Key: %(PacketKey)s
        """ %(fields)
    if contact:
	info += "Contact %s\n"%contact
    if comment:
	info += "Contact %s\n"%comment
            
    if ALLOW_INCOMING_MMTP: #XXXX
	info += """\
            [Incoming/MMTP]
            Version: 1.0
            Port: %(Port)s
	    Key-Digest: %(KeyID)s
	    Protocols: 1.0
            """
    if ALLOW_OUTGOING_MMTP: #XXXX
	info += """\
            [Modules/MMTP]
	    Version: 1.0
            Protocols: 1.0
            """
        for k,v in config.getSectionItems("Outgoing/MMTP"):
	    # XXXX write the rule
	    pass
    if ALLOW_DELIVERY_MBOX: #XXXX
	info += """\
            [Modules/MBOX]
            Version: 1.0
            """
	    
    # Remove extra (leading) whitespace.
    lines = [ line.strip() for line in info.split("\n") ]
    # Remove empty lines
    lines = filter(None, lines)
    info = "\n".join(lines)
    info = signServerInfo(info, identityKey)
    
    # debug XXXX
    ServerInfo(string=info)

    return info
    

#----------------------------------------------------------------------
def getServerInfoDigest(info):
    return _getServerInfoDiggestImpl(info, None)

def signServerInfo(info, rsa):
    return _getServerInfoDiggestImpl(info, rsa)

def _getServerInfoDigestImpl(info, rsa=None):
    infoLines = info.split("\n")
    if not infoLines[0] == "[Server]":
	raise ConfigError("Must begin with server section")
    digestLine = None
    signatureLine = None
    infoLines = info.split("\n")
    for lineno in range(len(infoLines)):
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
    if pk is None:
	return digest

    #### Signature case.
    signature = mixminion.Crypto.pk_sign(digest,rsa)
    digest = _base64(digest)
    signature = binascii.b2a_base64(signature).replace("\n","")
    infoLines[digestLine] = 'Digest: '+digest
    infoLines[signatureLine] = 'Signature: '+signature

    return "\n".join(infoLines)
