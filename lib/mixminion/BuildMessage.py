# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: BuildMessage.py,v 1.6 2002/06/24 20:28:19 nickm Exp $

"""mixminion.BuildMessage

   Code to construct messages and reply blocks."""

from mixminion.Packet import *
from mixminion.Common import MixError
import mixminion.Crypto as Crypto
import mixminion.Modules as Modules
import operator

__all__ = [ 'buildForwardMessage', 'buildReplyBlock', 'buildReplyMessage',
            'buildStatelessReplyBlock' ]

def buildForwardMessage(payload, exitType, exitInfo, path1, path2):
    """buildForwardMessage(payload, exitType, exitInfo, path1, path2) ->str

       Constructs a forward message.
            payload: The payload to deliver.
            exitType: The routing type for the final node
            exitType: The routing info for the final node
            path1: Sequence of ServerInfo objects for the first leg of the path
            path1: Sequence of ServerInfo objects for the 2nd leg of the path
        """
    return _buildMessage(payload, exitType, exitInfo, path1, path2)

def buildReplyMessage(payload, path1, replyBlock):
    """buildReplyMessage(payload, path1, replyBlock) ->str

       Builds a message using a reply block.  'path1' is a sequence of
       ServerInfo for the nodes on the first leg of the path."""
    return _buildMessage(payload, None, None,
                         path1=path1,
                         reply=replyBlock)

def buildReplyBlock(path, exitType, exitInfo, secretPRNG=None):
    """buildReplyBlock(path, exitType, exitInfo, secretPRNG=None) 
                                                  -> (Reply block, secret list)

       Returns a newly-constructed reply block and a list of secrets used
       to make it.
       
              path: A list of ServerInfo
              exitType: Routing type to use for the final node
              exitInfo: Routing info for the final node
              secretPRNG: A PRNG to use for generating secrets.  If not
                 provided, uses an AES counter-mode stream seeded from our
                 entropy source.
       """
    if secretPRNG == None:
        secretPRNG = Crypto.AESCounterPRNG()
    secrets = [ secretPRNG.getBytes(SECRET_LEN) for _ in path ]
    header = _buildHeader(path, secrets, exitType, exitInfo, 
                          paddingPRNG=Crypto.AESCounterPRNG())
    return ReplyBlock(header, path[0]), secrets

# Maybe we shouldn't even allow this to be called with userKey==None.
def buildStatelessReplyBlock(path, user, userKey, email=0):
    """buildStatelessReplyBlock(path, user, userKey, email=0) -> ReplyBlock

       Constructs a 'stateless' reply block that does not require the
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
                  user: the users username/email address
                  userKey: an AES key to encrypt the seed, or None.
                  email: If true, delivers via SMTP; else delivers via LOCAL.
       """
    if email and userKey:
        raise MixError("Requested EMail delivery without password-protection")

    seed = Crypto.trng(16)
    if userKey:
        tag = Crypto.ctr_crypt(seed,userKey)
    else:
        tag = seed
        
    if email:
        exitType = Modules.SMTP_TYPE
        exitInfo = SMTPInfo(user, "RTRN"+tag).pack()
    else:
        exitType = Modules.LOCAL_TYPE
        exitInfo = LocalInfo(user, "RTRN"+tag).pack()

    prng = Crypto.AESCounterPRNG(seed)
    return buildReplyBlock(path, exitType, exitInfo, prng)[0]

#----------------------------------------------------------------------
def _buildMessage(payload, exitType, exitInfo,
                  path1, path2=None, reply=None, paddingPRNG=None, paranoia=0):
    """_buildMessage(payload, exitType, exitInfo, path1, path2=None,
                     reply=None, paddingPRNG=None, paranoia=0) -> str
    
    Helper method to create a message.

    The following fields must be set:
       payload: the intended exit payload.
       (exitType, exitInfo): the routing type and info for the final node.
              (Ignored for reply messages)
       path1: a sequence of ServerInfo objects, one for each of the nodes
          on the first leg of the path.

    The following fields must be set for a forward message:
       path2: a sequence of ServerInfo objects, one for each of the nodes
          on the second leg of the path.

    The following fields must be set for a reply message:
       reply: a ReplyBlock object

    The following fields are optional:
       paddingPRNG: A pseudo-random number generator used to pad the headers
         and the payload.  If not provided, we use a counter-mode AES stream
         seeded from our entropy source.
       paranoia: If this is false, we use the padding PRNG to generate
         header secrets too.  Otherwise, we read all of our header secrets
         from the true entropy source. 
    """
    assert path2 or reply
    assert not (path2 and reply)

    ### SETUP CODE: let's handle all the variant cases.

    # Set up the random number generators.
    if paddingPRNG == None:
        paddingPRNG = Crypto.AESCounterPRNG()
    if paranoia:
        nHops = len(path1)
        if path2: nHops += len(path2)
        secretRNG = Crypto.TrueRNG(SECRET_LEN*len(nHops))
    else:
        secretRNG = paddingPRNG

    # Determine exit routing for path1 and path2.
    if reply:
        path1exitinfo = reply.addr.getRoutingInfo().pack()
    else:
        path1exitinfo = path2[0].getRoutingInfo().pack()

    # Pad the payload, as needed.
    if len(payload) < PAYLOAD_LEN:
        # ???? Payload padding/sizing must be handled in spec.
        payload += paddingPRNG.getBytes(PAYLOAD_LEN-len(payload))

    # Generate secrets for path1.
    secrets1 = [ secretRNG.getBytes(SECRET_LEN) for _ in path1 ]
    
    if path2:
        # Make secrets for header 2, and construct header 2.  We do the before
        # making header1 so that our rng won't be used for padding yet.
        secrets2 = [ secretRNG.getBytes(SECRET_LEN) for _ in range(len(path2))]
        header2 = _buildHeader(path2,secrets2,exitType,exitInfo,paddingPRNG)
    else:
        secrets2 = None
        header2 = reply.header

    # Construct header1.
    header1 = _buildHeader(path1,secrets1,Modules.SWAP_FWD_TYPE,path1exitinfo,
                           paddingPRNG)

    return _constructMessage(secrets1, secrets2, header1, header2, payload)

def _buildHeader(path,secrets,exitType,exitInfo,paddingPRNG):
    """_buildHeader(path, secrets, exitType, exitInfo, paddingPRNG) -> str

       Helper method to construct a single header.
           path: A sequence of serverinfo objects.
           secrets: A list of 16-byte strings to use as master-secrets for
               each of the subeaders.
           exitType: The routing for the last node in the header
           exitInfo: The routing info for the last node in the header
           paddingPRNG: A pseudo-random number generator to generate padding"""

    assert len(path) == len(secrets)
    if len(path) * ENC_SUBHEADER_LEN > HEADER_LEN:
        raise MixError("Too many nodes in path")

    # Construct a list 'routing' of exitType, exitInfo.  
    routing = [ (Modules.FWD_TYPE, node.getRoutingInfo().pack()) for
                node in path[1:] ]
    routing.append( (exitType, exitInfo) )
    
    # sizes[i] is size, in blocks, of subheaders for i.
    sizes =[ getTotalBlocksForRoutingInfoLen(len(info)) for t, info in routing]
    
    # totalSize is number total number of blocks.
    totalSize = reduce(operator.add, sizes)
    if totalSize * ENC_SUBHEADER_LEN >  HEADER_LEN:
        raise MixError("Routing info won't fit in header")

    # headerKey[i]==the AES key object node i will use to decrypt the header
    headerKeys = [ Crypto.Keyset(secret).get(Crypto.HEADER_SECRET_MODE)
                       for secret in secrets ]
    
    # Calculate junk.  
    #   junkSeen[i]==the junk that node i will see, before it does any
    #                encryption.   Note that junkSeen[0]=="", because node 0
    #                sees no junk.
    junkSeen = [ "" ]
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
                            secrets[i], " "*20,
                            rt, ri)

        extHeaders = "".join(subhead.getExtraBlocks())
        rest = Crypto.ctr_crypt(extHeaders+header, headerKeys[i])
        subhead.digest = Crypto.sha1(rest+junkSeen[i])
        pubkey = Crypto.pk_from_modulus(path[i].getModulus())
        esh = Crypto.pk_encrypt(subhead.pack(), pubkey)
        header = esh + rest

    return header

def _constructMessage(secrets1, secrets2, header1, header2, payload):
    """Helper method: Builds a message, given both headers, all known
       secrets, and the padded payload.

       If using a reply block, secrets2 should be null."""
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
