# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: BuildMessage.py,v 1.27 2002/12/31 17:47:41 nickm Exp $

"""mixminion.BuildMessage

   Code to construct messages and reply blocks, and to decode received
   message payloads."""

import sys
import zlib
import operator
import mixminion.Crypto as Crypto
from mixminion.Packet import *
from mixminion.Common import MixError, MixFatalError, LOG

if sys.version_info[:3] < (2,2,0):
    import mixminion._zlibutil as zlibutil

__all__ = ['buildForwardMessage', 'buildEncryptedMessage', 'buildReplyMessage',
           'buildReplyBlock', 'decodePayload' ]

def buildForwardMessage(payload, exitType, exitInfo, path1, path2,
                        paddingPRNG=None):
    """Construct a forward message.
            payload: The payload to deliver.  Must compress to under 28K-22b.
                  If it does not, MixError is raised.
            exitType: The routing type for the final node. (2 bytes, >=0x100)
            exitInfo: The routing info for the final node, not including tag.
            path1: Sequence of ServerInfo objects for the first leg of the path
            path2: Sequence of ServerInfo objects for the 2nd leg of the path
            paddingPRNG: random number generator used to generate padding.
                  If None, a new PRNG is initialized.

        Neither path1 nor path2 may be empty.
    """
    if paddingPRNG is None: 
        paddingPRNG = Crypto.getCommonPRNG()
    assert path1 and path2

    LOG.debug("Encoding forward message for %s-byte payload",len(payload))
    LOG.debug("  Using path %s/%s",
                   [s.getNickname() for s in path1],
                   [s.getNickname() for s in path2])
    LOG.debug("  Delivering to %04x:%r", exitType, exitInfo)

    # Compress, pad, and checksum the payload.
    payload = _encodePayload(payload, 0, paddingPRNG)

    # Choose a random decoding tag.
    tag = _getRandomTag(paddingPRNG)
    exitInfo = tag + exitInfo
    return _buildMessage(payload, exitType, exitInfo, path1, path2,paddingPRNG)

def buildEncryptedForwardMessage(payload, exitType, exitInfo, path1, path2,
                                 key, paddingPRNG=None, secretRNG=None):
    """Construct a forward message encrypted with the public key of a
       given user.
            payload: The payload to deliver.  Must compress to under 28K-60b.
                  If it does not, MixError is raised.
            exitType: The routing type for the final node. (2 bytes, >=0x100)
            exitInfo: The routing info for the final node, not including tag.
            path1: Sequence of ServerInfo objects for the first leg of the path
            path2: Sequence of ServerInfo objects for the 2nd leg of the path
            key: Public key of this message's recipient.
            paddingPRNG: random number generator used to generate padding.
                  If None, a new PRNG is initialized.
    """
    if paddingPRNG is None: 
        paddingPRNG = Crypto.getCommonPRNG()
    if secretRNG is None: secretRNG = paddingPRNG

    LOG.debug("Encoding encrypted forward message for %s-byte payload",
                   len(payload))
    LOG.debug("  Using path %s/%s",
                   [s.getNickname() for s in path1],
                   [s.getNickname() for s in path2])
    LOG.debug("  Delivering to %04x:%r", exitType, exitInfo)

    # Compress, pad, and checksum the payload.
    # (For encrypted-forward messages, we have overhead for OAEP padding
    #   and the session  key, but we save 20 bytes by spilling into the tag.)
    payload = _encodePayload(payload, ENC_FWD_OVERHEAD, paddingPRNG)

    # Generate the session key, and prepend it to the payload.
    sessionKey = secretRNG.getBytes(SECRET_LEN)
    payload = sessionKey+payload

    # We'll encrypt the first part of the new payload with RSA, and the
    # second half with Lioness, based on the session key.
    rsaDataLen = key.get_modulus_bytes()-OAEP_OVERHEAD
    rsaPart = payload[:rsaDataLen]
    lionessPart = payload[rsaDataLen:]

    # RSA encryption: To avoid leaking information about our RSA modulus,
    # we keep trying to encrypt until the MSBit of our encrypted value is
    # zero.
    while 1:
        encrypted = Crypto.pk_encrypt(rsaPart, key)
        if not (ord(encrypted[0]) & 0x80):
            break
    # Lioness encryption.
    k= Crypto.Keyset(sessionKey).getLionessKeys(Crypto.END_TO_END_ENCRYPT_MODE)
    lionessPart = Crypto.lioness_encrypt(lionessPart, k)

    # Now we re-divide the payload into the part that goes into the tag, and
    # the 28K of the payload proper...
    payload = encrypted + lionessPart
    tag = payload[:TAG_LEN]
    payload = payload[TAG_LEN:]
    exitInfo = tag + exitInfo
    assert len(payload) == 28*1024

    # And now, we can finally build the message.
    return _buildMessage(payload, exitType, exitInfo, path1, path2,paddingPRNG)

def buildReplyMessage(payload, path1, replyBlock, paddingPRNG=None):
    """Build a message using a reply block.  'path1' is a sequence of
       ServerInfo for the nodes on the first leg of the path.
    """
    if paddingPRNG is None:
        paddingPRNG = Crypto.getCommonPRNG()

    LOG.debug("Encoding reply message for %s-byte payload",
                   len(payload))
    LOG.debug("  Using path %s/??",[s.getNickname() for s in path1])

    # Compress, pad, and checksum the payload.
    payload = _encodePayload(payload, 0, paddingPRNG)

    # Encrypt the payload so that it won't appear as plaintext to the
    #  crossover note.  (We use 'decrypt' so that the message recipient can
    #  simply use 'encrypt' to reverse _all_ the steps of the reply path.)
    k = Crypto.Keyset(replyBlock.encryptionKey).getLionessKeys(
                         Crypto.PAYLOAD_ENCRYPT_MODE)
    payload = Crypto.lioness_decrypt(payload, k)

    return _buildMessage(payload, None, None,
                         path1=path1, path2=replyBlock)

def _buildReplyBlockImpl(path, exitType, exitInfo, expiryTime=0,
                         secretPRNG=None, tag=None):
    """Helper function: makes a reply block, given a tag and a PRNG to
       generate secrets. Returns a 3-tuple containing (1) a
       newly-constructed reply block, (2) a list of secrets used to
       make it, (3) a tag.

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
        secretPRNG = Crypto.getCommonPRNG()

    LOG.debug("Building reply block for path %s",
                   [s.getNickname() for s in path])
    LOG.debug("  Delivering to %04x:%r", exitType, exitInfo)

    # The message is encrypted first by the end-to-end key, then by
    # each of the path keys in order. We need to reverse these steps, so we
    # generate the path keys back-to-front, followed by the end-to-end key.
    secrets = [ secretPRNG.getBytes(SECRET_LEN) for _ in range(len(path)+1) ]
    headerSecrets = secrets[:-1]
    headerSecrets.reverse()
    sharedKey = secrets[-1]

    # (This will go away when we deprecate 'stateful' reply blocks
    if tag is None:
        tag = _getRandomTag(secretPRNG)

    header = _buildHeader(path, headerSecrets, exitType, tag+exitInfo,
                          paddingPRNG=Crypto.getCommonPRNG())

    return ReplyBlock(header, expiryTime,
                      SWAP_FWD_TYPE,
                      path[0].getRoutingInfo().pack(), sharedKey), secrets, tag

# Maybe we shouldn't even allow this to be called with userKey==None.
def buildReplyBlock(path, exitType, exitInfo, userKey,
                    expiryTime=0, secretRNG=None):
    """Construct a 'state-carrying' reply block that does not require the
       reply-message recipient to remember a list of secrets.
       Instead, all secrets are generated from an AES counter-mode
       stream, and the seed for the stream is stored in the 'tag'
       field of the final block's routing info.   (See the spec for more
       info).

               path: a list of ServerInfo objects
               exitType,exitInfo: The address to deliver the final message.
               userKey: a string used to encrypt the seed.

       NOTE: We used to allow another kind of 'non-state-carrying' reply
       block that stored its secrets on disk, and used an arbitrary tag to
       determine
       """
    if secretRNG is None: 
        secretRNG = Crypto.getCommonPRNG()

    # We need to pick the seed to generate our keys.  To make the decoding
    # step a little faster, we find a seed such that H(seed|userKey|"Validate")
    # ends with 0.  This way, we can detect whether we really have a reply
    # message with 99.6% probability.  (Otherwise, we'd need to repeatedly
    # lioness-decrypt the payload in order to see whether the message was
    # a reply.)

    # XXXX D'oh!  This enables an offline password guessing attack for
    # XXXX anybody who sees multiple tags.  We need to make sure that userKey
    # XXXX is stored on disk, and isn't a password.  This needs more thought.
    while 1:
        seed = _getRandomTag(secretRNG)
        if Crypto.sha1(seed+userKey+"Validate")[-1] == '\x00':
            break

    prng = Crypto.AESCounterPRNG(Crypto.sha1(seed+userKey+"Generate")[:16])

    return _buildReplyBlockImpl(path, exitType, exitInfo, expiryTime, prng,
                                seed)[0]

#----------------------------------------------------------------------
# MESSAGE DECODING

def decodePayload(payload, tag, key=None,
                  #storedKeys=None, # 'Stateful' reply blocks are disabled.
                  userKey=None):
    """Given a 28K payload and a 20-byte decoding tag, attempt to decode and
       decompress the original message.

           key: an RSA key to decode encrypted forward messages, or None
           userKey: our encryption key for reply blocks, or None.

       If we can successfully decrypt the payload, we return it.  If we
       might be able to decrypt the payload given more/different keys,
       we return None.  If the payload is corrupt, we raise MixError.
    """
    # FFFF Take a list of keys?
    # FFFF Allow callbacks?

    if len(payload) != PAYLOAD_LEN or len(tag) != TAG_LEN:
        raise MixError("Wrong payload or tag length")

    # If the payload already contains a valid checksum, it's a forward
    # message.
    if _checkPayload(payload):
        return _decodeForwardPayload(payload)

    # ('Stateful' reply blocks are disabled.)

##    # If we have a list of keys associated with the tag, it's a reply message
##    # using those keys.

##     if storedKeys is not None:
##      secrets = storedKeys.get(tag)
##      if secrets is not None:
##          del storedKeys[tag]
##          return _decodeReplyPayload(payload, secrets)

    # If H(tag|userKey|"Validate") ends with 0, then the message _might_
    # be a reply message using H(tag|userKey|"Generate") as the seed for
    # its master secrets.  (There's a 1-in-256 chance that it isn't.)
    if userKey is not None:
        if Crypto.sha1(tag+userKey+"Validate")[-1] == '\x00':
            try:
                return _decodeStatelessReplyPayload(payload, tag, userKey)
            except MixError:
                pass

    # If we have an RSA key, and none of the above steps get us a good
    # payload, then we may as well try to decrypt the start of tag+key with
    # our RSA key.
    if key is not None:
        p = _decodeEncryptedForwardPayload(payload, tag, key)
        if p is not None:
            return p

    return None

def _decodeForwardPayload(payload):
    """Helper function: decode a non-encrypted forward payload. Return values
       are the same as decodePayload."""
    return _decodePayloadImpl(payload)

def _decodeEncryptedForwardPayload(payload, tag, key):
    """Helper function: decode an encrypted forward payload.  Return values
       are the same as decodePayload.
             payload: the payload to decode
             tag: the decoding tag
             key: the RSA key of the payload's recipient."""
    assert len(tag) == TAG_LEN
    assert len(payload) == PAYLOAD_LEN

    # Given an N-byte RSA key, the first N bytes of tag+payload will be
    # encrypted with RSA, and the rest with a lioness key given in the
    # first N.  Try decrypting...
    msg = tag+payload
    try:
        rsaPart = Crypto.pk_decrypt(msg[:key.get_modulus_bytes()], key)
    except Crypto.CryptoError:
        return None
    rest = msg[key.get_modulus_bytes():]

    k = Crypto.Keyset(rsaPart[:SECRET_LEN]).getLionessKeys(
        Crypto.END_TO_END_ENCRYPT_MODE)
    rest = rsaPart[SECRET_LEN:] + Crypto.lioness_decrypt(rest, k)

    # ... and then, check the checksum and continue.
    return _decodePayloadImpl(rest)

def _decodeReplyPayload(payload, secrets, check=0):
    """Helper function: decode a reply payload, given a known list of packet
         master secrets. If 'check' is true, then 'secerets' may be overlong.
         Return values are the same as decodePayload.
      [secrets must be in _reverse_ order]
    """
    # Reverse the 'decrypt' operations of the reply mixes, and the initial
    # 'decrypt' of the originating user...
    for sec in secrets:
        k = Crypto.Keyset(sec).getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE)
        payload = Crypto.lioness_encrypt(payload, k)
        if check and _checkPayload(payload):
            break

    # ... and then, check the checksum and continue.
    return _decodePayloadImpl(payload)

def _decodeStatelessReplyPayload(payload, tag, userKey):
    """Decode a (state-carrying) reply payload."""
    # Reconstruct the secrets we used to generate the reply block (possibly
    # too many)
    seed = Crypto.sha1(tag+userKey+"Generate")[:16]
    prng = Crypto.AESCounterPRNG(seed)
    secrets = [ prng.getBytes(SECRET_LEN) for _ in xrange(17) ]

    return _decodeReplyPayload(payload, secrets, check=1)

#----------------------------------------------------------------------
def _buildMessage(payload, exitType, exitInfo,
                  path1, path2, paddingPRNG=None, paranoia=0):
    """Helper method to create a message.

    The following fields must be set:
       payload: the intended exit payload.  Must be 28K.
       (exitType, exitInfo): the routing type and info for the final
              node.  (Ignored for reply messages; 'exitInfo' should
              include the 20-byte decoding tag.)
       path1: a sequence of ServerInfo objects, one for each node on
          the first leg of the path.
       path2:
        EITHER
             a sequence of ServerInfo objects, one for each node
             on the second leg of the path.
         OR
             a ReplyBlock object.

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
    else:
        if len(exitInfo) < TAG_LEN:
            raise MixError("Implausibly short exit info: %r"%exitInfo)
        if exitType < MIN_EXIT_TYPE and exitType != DROP_TYPE:
            raise MixError("Invalid exit type: %4x"%exitType)

    ### SETUP CODE: let's handle all the variant cases.

    # Set up the random number generators.
    if paddingPRNG is None:
        paddingPRNG = Crypto.getCommonPRNG()
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
        path1exittype = SWAP_FWD_TYPE
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
           exitInfo: The routing info for the last node in the header.
               (Must include 20-byte decoding tag.)
           paddingPRNG: A pseudo-random number generator to generate padding
    """
    assert len(path) == len(secrets)
    if len(path) * ENC_SUBHEADER_LEN > HEADER_LEN:
        raise MixError("Too many nodes in path")

    # Construct a list 'routing' of exitType, exitInfo.
    routing = [ (FWD_TYPE, node.getRoutingInfo().pack()) for
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

       If using a reply block for header2, secrets2 should be null.
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

    # Compress the data, and figure out how much padding we'll need.
    origLength = len(payload)
    payload = compressData(payload)
    length = len(payload)
    
    # FFFF This is an ugly workaround for too-compressable data, so we don't
    # FFFF create messages that will necessarily be dropped.  We should be
    # FFFF more sensible on the output side.
    if length > 1024 and length*20 <= origLength:
        LOG.warn("Double-compressing message so it won't look like a z-bomb")
        payload = compressData(payload)
        length = len(payload)

    paddingLen = PAYLOAD_LEN - SINGLETON_PAYLOAD_OVERHEAD - overhead - length

    # If the compressed payload doesn't fit in 28K, then we need to bail out.
    if paddingLen < 0:
        raise MixError("Payload too long for singleton message")

    # Otherwise, we pad the payload, and construct a new SingletonPayload,
    # including this payload's size and checksum.
    payload += paddingPRNG.getBytes(paddingLen)
    return SingletonPayload(length, Crypto.sha1(payload), payload).pack()

def _getRandomTag(rng):
    "Helper: Return a 20-byte string with the MSB of byte 0 set to 0."
    b = ord(rng.getBytes(1)) & 0x7f
    return chr(b) + rng.getBytes(TAG_LEN-1)

def _decodePayloadImpl(payload):
    """Helper: try to decode an encoded payload: checks only encoding,
       not encryption."""
    # Is the hash ok?
    if not _checkPayload(payload):
        raise MixError("Hash doesn't match")

    # Parse the payload into its size, checksum, and body.
    payload = parsePayload(payload)

    if not payload.isSingleton():
        raise MixError("Message fragments not yet supported")

    # Uncompress the body.
    contents = payload.getContents()
    # FFFF - We should make this rule configurable.
    maxLen = max(20*1024, 20*len(contents))
    # FFFF - On encountering an overcompressed piece of data, we should
    # FFFF   deliver it, still compressed, with a warning -- not merely
    # FFFF   drop it as a _definite_ bomb.
    return uncompressData(payload.getContents(), maxLength=maxLen)

def _checkPayload(payload):
    'Return true iff the hash on the given payload seems valid'
    return payload[2:22] == Crypto.sha1(payload[22:])

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
            raise ParseError("Error in compressed data")
    
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
