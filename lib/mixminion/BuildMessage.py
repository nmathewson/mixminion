# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: BuildMessage.py,v 1.15 2002/10/14 03:03:42 nickm Exp $

"""mixminion.BuildMessage

   Code to construct messages and reply blocks."""

import zlib
import operator
from mixminion.Packet import *
from mixminion.Common import MixError, MixFatalError, getLog
import mixminion.Crypto as Crypto
import mixminion.Modules as Modules

__all__ = [ 'Address', 
           'buildForwardMessage', 'buildEncryptedMessage', 'buildReplyMessage',
           'buildStatelessReplyBlock', 'buildReplyBlock', 'decodePayload',
	   'decodeForwardPayload', 'decodeEncryptedForwardPayload', 
	   'decodeReplyPayload', 'decodeStatelessReplyPayload' ]

def buildForwardMessage(payload, exitType, exitInfo, path1, path2, 
			paddingPRNG=None):
    """Construct a forward message.
            payload: The payload to deliver.  Must compress to under 28K-22b.
            exitType: The routing type for the final node
            exitInfo: The routing info for the final node, not including tag.
            path1: Sequence of ServerInfo objects for the first leg of the path
            path2: Sequence of ServerInfo objects for the 2nd leg of the path
	    paddingPRNG

        Note: If either path is empty, the message is vulnerable to tagging 
         attacks! (FFFF we should check this.)
    """
    if paddingPRNG is None: paddingPRNG = Crypto.AESCounterPRNG()

    payload = _encodePayload(payload, 0, paddingPRNG)
    tag = _getRandomTag(paddingPRNG)
    exitInfo = tag + exitInfo 
    return _buildMessage(payload, exitType, exitInfo, path1, path2,paddingPRNG)

def buildEncryptedForwardMessage(payload, exitType, exitInfo, path1, path2, 
				 key, paddingPRNG=None, secretRNG=None):
    """XXXX
    """
    if paddingPRNG is None: paddingPRNG = Crypto.AESCounterPRNG()
    if secretRNG is None: secretRNG = paddingPRNG

    payload = _encodePayload(payload, ENC_FWD_OVERHEAD, paddingPRNG)

    sessionKey = secretRNG.getBytes(SECRET_LEN)
    payload = sessionKey+payload
    rsaDataLen = key.get_modulus_bytes()-OAEP_OVERHEAD
    rsaPart = payload[:rsaDataLen]
    lionessPart = payload[rsaDataLen:]
    # XXXX DOC
    while 1:
	encrypted = Crypto.pk_encrypt(rsaPart, key)
	if not (ord(encrypted[0]) & 0x80):
	    break
    #XXXX doc mode 'End-to-end encrypt'
    k = Crypto.Keyset(sessionKey).getLionessKeys("End-to-end encrypt")
    lionessPart = Crypto.lioness_encrypt(lionessPart, k)
    payload = encrypted + lionessPart
    tag = payload[:TAG_LEN]
    payload = payload[TAG_LEN:]
    exitInfo = tag + exitInfo 
    assert len(payload) == 28*1024
    return _buildMessage(payload, exitType, exitInfo, path1, path2,paddingPRNG)

def buildReplyMessage(payload, path1, replyBlock, paddingPRNG=None):
    """Build a message using a reply block.  'path1' is a sequence of
       ServerInfo for the nodes on the first leg of the path.
    """
    if paddingPRNG is None: paddingPRNG = Crypto.AESCounterPRNG()

    payload = _encodePayload(payload, 0, paddingPRNG)
   
    # XXXX Document this mode
    k = Crypto.Keyset(replyBlock.encryptionKey).getLionessKeys(
	                 Crypto.PAYLOAD_ENCRYPT_MODE)
    # XXXX Document why this is decrypt
    payload = Crypto.lioness_decrypt(payload, k)

    return _buildMessage(payload, None, None,
                         path1=path1, path2=replyBlock)

def buildReplyBlock(path, exitType, exitInfo, expiryTime=0, secretPRNG=None, 
                    tag=None):
    """Return a 3-tuple containing (1) a newly-constructed reply block, (2)
       a list of secrets used to make it, (3) a tag.
       
              path: A list of ServerInfo
              exitType: Routing type to use for the final node
              exitInfo: Routing info for the final node, not including tag.
              expiryTime: The time at which this block should expire.
              secretPRNG: A PRNG to use for generating secrets.  If not
                 provided, uses an AES counter-mode stream seeded from our
                 entropy source.  Note: the secrets are generated so that they
                 will be used to encrypt the message in reverse order.
              tag: If provided, a 159-bit tag.  If not provided, a new one 
                 is generated.
       """
    if secretPRNG is None:
        secretPRNG = Crypto.AESCounterPRNG()

    # The message is encrypted first by the end-to-end key, then by
    # each of the path keys in order. We need to reverse these steps, so we
    # generate the path keys back-to-front, followed by the end-to-end key.
    secrets = [ secretPRNG.getBytes(SECRET_LEN) for _ in range(len(path)+1) ]

    headerSecrets = secrets[:-1]
    headerSecrets.reverse()
    sharedKey = secrets[-1]

    if tag is None:
	tag = _getRandomTag(secretPRNG)

    header = _buildHeader(path, headerSecrets, exitType, tag+exitInfo, 
                          paddingPRNG=Crypto.AESCounterPRNG())

    return ReplyBlock(header, expiryTime,
                      Modules.SWAP_FWD_TYPE,
                      path[0].getRoutingInfo().pack(), sharedKey), secrets, tag

# Maybe we shouldn't even allow this to be called with userKey==None.
def buildStatelessReplyBlock(path, exitType, exitInfo, userKey, 
			     expiryTime=0, secretRNG=None):
    """XXXX DOC IS NOW WRONG HERE
       Construct a 'stateless' reply block that does not require the
       reply-message recipient to remember a list of secrets.
       Instead, all secrets are generated from an AES counter-mode
       stream, and the seed for the stream is stored in the 'tag'
       field of the final block's routing info.

       If the user provides a 'userkey', that key is used to encrypt
       the seed before storing it in the tag field.  Otherwise, the
       seed is stored in the clear.  USERS SHOULD ALWAYS SET 'userkey'
       IF THE EXIT INFORMATION WILL BE TRAVELING OVER THE NETWORK, OR
       IF THEY DO NOT PERSONALLY CONTROL THE EXIT NODE.  Otherwise,
       their anonymity can be completely broken.

                  path: a list of ServerInfo objects
                  user: the user's username/email address
                  userKey: an AES key to encrypt the seed, or None.
                  email: If true, delivers via SMTP; else delivers via MBOX
       """
    #XXXX Out of sync with the spec.
    if secretRNG is None: secretRNG = Crypto.AESCounterPRNG()
    
    while 1:
	seed = _getRandomTag(secretRNG)
	if Crypto.sha1(seed+userKey+"Validate")[-1] == '\x00':
	    break
	
    prng = Crypto.AESCounterPRNG(Crypto.sha1(seed+userKey+"Generate")[:16])

    return buildReplyBlock(path, exitType, exitInfo, expiryTime, prng, seed)[0]

#----------------------------------------------------------------------
# MESSAGE DECODING

def decodePayload(payload, tag, key=None, storedKeys=None, userKey=None):
    """ DOCDOC XXXX
        Contract: return payload on success; raise MixError on certain failure,
          return None if neither.
    """
    if _checkPayload(payload):
	return decodeForwardPayload(payload)

    if storedKeysFn is not None:
	secrets = storedKeys.get(tag)
	if secrets is not None:
	    del storedKeys[tag]
	    return decodeReplyPayload(payload, secrets)

    if userKey is not None:
	if Crypto.sha1(tag+userKey+"Validate")[-1] == '\x00': 
	    try:
		return decodeStatelessReplyPayload(payload, tag, userKey)
	    except MixError, _:
		pass

    if key is not None:
	p = decodeEncryptedForwardPayload(payload, tag, key)
	if p is not None:
	    return p
	
    return None

def decodeForwardPayload(payload):
    "XXXX"
    return _decodePayload(payload)

def decodeEncryptedForwardPayload(payload, tag, key):
    "XXXX"
    msg = tag+payload
    try:
	rsaPart = Crypto.pk_decrypt(msg[:key.get_modulus_bytes()], key)
    except Crypto.CryptoError, _:
	return None
    rest = msg[key.get_modulus_bytes():]
    #XXXX magic string
    k = Crypto.Keyset(rsaPart[:SECRET_LEN]).getLionessKeys("End-to-end encrypt")
    rest = rsaPart[SECRET_LEN:] + Crypto.lioness_decrypt(rest, k)
    return _decodePayload(rest)

def decodeReplyPayload(payload, secrets, check=0):
    "XXXX"
    for sec in secrets:
	k = Crypto.Keyset(sec).getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE)
	# XXXX document why this is encrypt
	payload = Crypto.lioness_encrypt(payload, k)
	if check and _checkPayload(payload):
	    break

    return _decodePayload(payload)

def decodeStatelessReplyPayload(payload, tag, userKey):
    "XXXX"
    seed = Crypto.sha1(tag+userKey+"Generate")[:16]
    prng = Crypto.AESCounterPRNG(seed)
    secrets = [ prng.getBytes(SECRET_LEN) for _ in xrange(17) ]
			 
    return decodeReplyPayload(payload, secrets, check=1)

#----------------------------------------------------------------------
def _buildMessage(payload, exitType, exitInfo,
                  path1, path2, paddingPRNG=None, paranoia=0):
    """Helper method to create a message.

    The following fields must be set:
       payload: the intended exit payload.  Must be 28K.
       (exitType, exitInfo): the routing type and info for the final node.
              (Ignored for reply messages)
       path1: a sequence of ServerInfo objects, one for each of the nodes
          on the first leg of the path.

    The following fields must be set for a forward message:
       path2: EITHER
             a sequence of ServerInfo objects, one for each of the nodes
             on the second leg of the path.
         OR
             a replyBlock object.

    The following fields are optional:
       paddingPRNG: A pseudo-random number generator used to pad the headers.
         If not provided, we use a counter-mode AES stream seeded from our 
         entropy source. 
         
       paranoia: If this is false, we use the padding PRNG to generate
         header secrets too.  Otherwise, we read all of our header secrets
         from the true entropy source. 
    """
    assert len(payload) == PAYLOAD_LEN
    reply = None
    if isinstance(path2, ReplyBlock):
        reply = path2
        path2 = None

    ### SETUP CODE: let's handle all the variant cases.

    # Set up the random number generators.
    if paddingPRNG is None:
        paddingPRNG = Crypto.AESCounterPRNG()
    if paranoia:
        nHops = len(path1)
        if path2: nHops += len(path2)
        secretRNG = Crypto.TrueRNG(SECRET_LEN*len(nHops))
    else:
        secretRNG = paddingPRNG

    # Determine exit routing for path1.
    if reply:
        path1exittype = reply.routingType
        path1exitinfo = reply.routingInfo
    else:
        path1exittype = Modules.SWAP_FWD_TYPE
        path1exitinfo = path2[0].getRoutingInfo().pack()

    # Generate secrets for path1.
    secrets1 = [ secretRNG.getBytes(SECRET_LEN) for _ in path1 ]
    
    if path2:
        # Make secrets for header 2, and construct header 2.  We do this before
        # making header1 so that our rng won't be used for padding yet.
        secrets2 = [ secretRNG.getBytes(SECRET_LEN) for _ in range(len(path2))]
        header2 = _buildHeader(path2,secrets2,exitType,exitInfo,paddingPRNG)
    else:
        secrets2 = None
        header2 = reply.header

    # Construct header1.
    header1 = _buildHeader(path1,secrets1,path1exittype,path1exitinfo,
                           paddingPRNG)

    return _constructMessage(secrets1, secrets2, header1, header2, payload)

def _buildHeader(path,secrets,exitType,exitInfo,paddingPRNG):
    """Helper method to construct a single header.
           path: A sequence of serverinfo objects.
           secrets: A list of 16-byte strings to use as master-secrets for
               each of the subheaders.
           exitType: The routing type for the last node in the header
           exitInfo: The routing info for the last node in the header
           paddingPRNG: A pseudo-random number generator to generate padding
    """
    assert len(path) == len(secrets)
    if len(path) * ENC_SUBHEADER_LEN > HEADER_LEN:
        raise MixError("Too many nodes in path")

    # Construct a list 'routing' of exitType, exitInfo.  
    routing = [ (Modules.FWD_TYPE, node.getRoutingInfo().pack()) for
                node in path[1:] ]
    routing.append((exitType, exitInfo))
    
    # sizes[i] is size, in blocks, of subheaders for i.
    sizes =[ getTotalBlocksForRoutingInfoLen(len(ri)) for _, ri in routing]
    
    # totalSize is the total number of blocks.
    totalSize = reduce(operator.add, sizes)
    if totalSize * ENC_SUBHEADER_LEN > HEADER_LEN:
        raise MixError("Routing info won't fit in header")

    # headerKey[i]==the AES key object node i will use to decrypt the header
    headerKeys = [ Crypto.Keyset(secret).get(Crypto.HEADER_SECRET_MODE)
                       for secret in secrets ]
    
    # Calculate junk.  
    #   junkSeen[i]==the junk that node i will see, before it does any
    #                encryption.   Note that junkSeen[0]=="", because node 0
    #                sees no junk.
    junkSeen = [""]
    for secret, headerKey, size in zip(secrets, headerKeys, sizes):
        # Here we're calculating the junk that node i+1 will see.
        #
        # Node i+1 sees the junk that node i saw, plus the junk that i appends,
        # all encrypted by i.
        prngKey = Crypto.Keyset(secret).get(Crypto.RANDOM_JUNK_MODE)
        # NewJunk is the junk that node i will append. (It's as long as
        #   the subheaders that i removes.)
        newJunk = Crypto.prng(prngKey,size*128)
        lastJunk = junkSeen[-1]
        nextJunk = lastJunk + newJunk
        # Node i encrypts starting with its first extended subheader.  By
        #   the time it reaches the junk, it's traversed:
        #          All of its extended subheaders    [(size-1)*128]
        #          Non-junk parts of the header      [HEADER_LEN-len(nextJunk)]
        #
        # Simplifying, we find that the PRNG index for the junk is
        #    HEADER_LEN-len(lastJunk)-128.
        startIdx = HEADER_LEN-len(lastJunk)-128
        nextJunk = Crypto.ctr_crypt(nextJunk, headerKey, startIdx)
        junkSeen.append(nextJunk)

    # We start with the padding.
    header = paddingPRNG.getBytes(HEADER_LEN - totalSize*128)

    # Now, we build the subheaders, iterating through the nodes backwards.
    for i in range(len(path)-1, -1, -1):
        rt, ri = routing[i]

        # Create a subheader object for this node, but don't fill in the
        # digest until we've constructed the rest of the header.
        subhead = Subheader(MAJOR_NO, MINOR_NO,
                            secrets[i],
                            None, #placeholder for as-yet-uncalculated digest
                            rt, ri)

        extHeaders = "".join(subhead.getExtraBlocks())
        rest = Crypto.ctr_crypt(extHeaders+header, headerKeys[i])
        subhead.digest = Crypto.sha1(rest+junkSeen[i])
        pubkey = path[i].getPacketKey()
        esh = Crypto.pk_encrypt(subhead.pack(), pubkey)
        header = esh + rest

    return header

def _constructMessage(secrets1, secrets2, header1, header2, payload):
    """Helper method: Builds a message, given both headers, all known
       secrets, and the padded payload.

       If using a reply block, secrets2 should be null.
    """
    assert len(payload) == PAYLOAD_LEN
    assert len(header1) == len(header2) == HEADER_LEN
    
    if secrets2:
        # (Copy secrets2 so we don't reverse the original)
        secrets2 = secrets2[:]

        # If we're not using a reply block, encrypt the payload for
        # each key in the second path, in reverse order.
        secrets2.reverse()
        for secret in secrets2:
            ks = Crypto.Keyset(secret)
            key = ks.getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE)
            payload = Crypto.lioness_encrypt(payload, key)

    # Encrypt header2 with a hash of the payload.
    key = Crypto.lioness_keys_from_payload(payload)
    header2 = Crypto.lioness_encrypt(header2, key)

    # Encrypt payload with a hash of header2.  Now tagging either will make
    # both unrecoverable.
    key = Crypto.lioness_keys_from_header(header2)
    payload = Crypto.lioness_encrypt(payload, key)

    # Copy secrets1 so we don't reverse the original.
    secrets1 = secrets1[:]

    # Now, encrypt header2 and the payload for each node in path1, reversed.
    secrets1.reverse()    
    for secret in secrets1:
        ks = Crypto.Keyset(secret)
        hkey = ks.getLionessKeys(Crypto.HEADER_ENCRYPT_MODE)
        pkey = ks.getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE)
        header2 = Crypto.lioness_encrypt(header2,hkey)
        payload = Crypto.lioness_encrypt(payload,pkey)

    return Message(header1, header2, payload).pack()

#----------------------------------------------------------------------
# Payload-related helpers

def _encodePayload(payload, overhead, paddingPRNG):
    """Helper: compress a payload, pad it, and add extra fields (size and hash)
              payload: the initial payload
	      overhead: number of bytes to omit from result
	                (0 or ENC_FWD_OVERHEAD)
              paddingPRNG: generator for padding.

       BUG: This should eventually support K-of-N.
    """
    assert overhead in (0, ENC_FWD_OVERHEAD)
    payload = compressData(payload)

    length = len(payload)
    paddingLen = PAYLOAD_LEN - SINGLETON_PAYLOAD_OVERHEAD - overhead - length
    if paddingLen < 0:
	raise MixError("Payload too long for singleton message")
    
    payload += paddingPRNG.getBytes(paddingLen)

    return SingletonPayload(length, Crypto.sha1(payload), payload).pack()

def _getRandomTag(rng):
    "Helper: Return a 20-byte string with the MSB of byte 0 set to 0."
    b = ord(rng.getBytes(1)) & 0x7f
    return chr(b) + rng.getBytes(TAG_LEN-1)

def _decodePayload(payload):
    if not _checkPayload(payload):
	raise MixError("Hash doesn't match")
    payload = parsePayload(payload)

    if not payload.isSingleton():
	raise MixError("Message fragments not yet supported")

    return uncompressData(payload.getContents())

def _checkPayload(payload):
    'Return true iff the hash on the given payload seems valid'
    return payload[2:22] == Crypto.sha1(payload[22:])

#----------------------------------------------------------------------
# COMPRESSION FOR PAYLOADS

_ZLIB_LIBRARY_OK = 0

def compressData(payload):
    """Given a string 'payload', compress it with zlib as specified in the
       remailer spec."""
    if not _ZLIB_LIBRARY_OK:
	_validateZlib()
    # Don't change any of these options; they're all mandated.  
    zobj = zlib.compressobj(zlib.Z_BEST_COMPRESSION, zlib.DEFLATED,
			    zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 
			    zlib.Z_DEFAULT_STRATEGY)
    s1 = zobj.compress(payload)
    s2 = zobj.flush()
    return s1 + s2

def uncompressData(payload):
    """Uncompress a string 'payload'; raise ParseError if it is not valid
       compressed data."""
    try:
	return zlib.decompress(payload)
    except zlib.error, _:
	raise ParseError("Error in compressed data")

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
    if ver in ("1.1.2", "1.1.3", "1.1.4"):
	_ZLIB_LIBRARY_OK = 1
	return

    getLog().warn("Unrecognized zlib version: %r. Spot-checking output", ver)
    # This test is inadequate, but it _might_ catch future incompatible
    # changes.
    _ZLIB_LIBRARY_OK = 0.5
    good = 'x\xda\xed\xc6A\x11\x00 \x08\x00\xb0l\xd4\xf0\x87\x02\xf6o'+\
	   '`\x0e\xef\xb6\xd7r\xed\x88S=7\xcd\xcc\xcc\xcc\xcc\xcc\xcc'+\
	   '\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xbe\xdd\x03q'+\
	   '\x8d\n\x93'
    if compressData("aZbAAcdefg"*1000) == good:
	_ZLIB_LIBRARY_OK = 1
    else:
	_ZLIB_LIBRARY_OK = 0
	raise MixFatalError("Zlib output not as exected.")
