# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: BuildMessage.py,v 1.4 2002/05/31 12:47:58 nickm Exp $

from mixminion.Formats import *
import mixminion.Crypto as Crypto
import mixminion.Modules as Modules
import operator

__all__ = [ 'buildForwardMessage', 'buildReplyBlock', 'buildReplyMessage',
            'buildStatelessReplyBlock' ]

def buildForwardMessage(payload, exitType, exitInfo, path1, path2):
    "XXXX"
    return _buildMessage(payload, exitType, exitInfo, path1, path2)

def buildReplyMessage(payload, path1, replyBlock):
    # Bad iface; shouldn't take a tuple
    "XXXX"
    return _buildMessage(payload, None, None,
                         path1=path1,
                         reply=replyBlock)

# Bad interface: this shouldn't return a tuple. 
def buildReplyBlock(path, exitType, exitInfo, secretPRNG=None):
    "XXXX"
    if secretPRNG == None:
        secretPRNG = Crypto.AESCounterPRNG()
    secrets = [ secretPRNG.getBytes(SECRET_LEN) for node in path ]
    header = _buildHeader(path, secrets, exitType, exitInfo, 
                          paddingPRNG=Crypto.AESCounterPRNG())
    return (header, path[0]), secrets

# Bad interface: userkey should only be None if we trust the final node
# a lot.
def buildStatelessReplyBlock(path, user, userKey=None, email=0):
    "XXXX"
    # COMMENT
    if email:
        assert userKey
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
# needs a more informative name
def _buildMessage(payload, exitType, exitInfo,
                  path1, path2=None, reply=None, paddingPRNG=None, paranoia=0):
    "XXXX"
    assert path2 or reply
    assert not (path2 and reply)
    if paddingPRNG == None:
        paddingPRNG = Crypto.AESCounterPRNG()

    # ???? Payload padding/sizing must be handled in spec.
    if len(payload) < PAYLOAD_LEN:
        payload += paddingPRNG.getBytes(PAYLOAD_LEN-len(payload))

    nHops = len(path1)
    if path2: nHops += len(path2)

    if paranoia:
        secretRNG = Crypto.TrueRNG(SECRET_LEN*len(nHops))
    else:
        secretRNG = paddingPRNG

    if reply:
        path1exitnode = reply[1]
        path2exit = None
        reply = reply[0]
    else:
        path1exitnode = path2[0]
        path2exit = ( exitType, exitInfo )
    
    path1exit = ( Modules.SWAP_FWD_TYPE,
                  path1exitnode.getRoutingInfo().pack() )
    
    return _buildMessage_impl(payload, path1, path1exit, path2, path2exit,
                              reply, nHops, secretRNG, paddingPRNG)

#needs a more informative name
def _buildMessage_impl(payload, path1, path1exit, path2, path2exit,
                       reply, nHops, secretRNG, paddingRNG):
    "XXXX"
    # XXXX ???? Payload padding/sizing must be handled in spec.
    if len(payload) < PAYLOAD_LEN:
        payload += paddingRNG.getBytes(PAYLOAD_LEN-len(payload))

    secrets1 = [ secretRNG.getBytes(SECRET_LEN) for x in range(len(path1)) ]
    
    if path2:
        # Make secrets2 before header1 so we don't use the RNG to pad 
        # the first header yet.
        secrets2 = [ secretRNG.getBytes(SECRET_LEN) for x in range(len(path2))]
        header2 = _buildHeader(path2,secrets2,path2exit[0],path2exit[1],
                                 paddingRNG)
    else:
        secrets2 = None
        header2 = reply

    header1 = _buildHeader(path1,secrets1,path1exit[0],path1exit[1],
                             paddingRNG)
    return _constructMessage(secrets1, secrets2, header1, header2, payload)

def _buildHeader(path,secrets,exitType,exitInfo,paddingPRNG):
    "XXXX"
    # XXXX insist on sane parameters, path lengths.
    routing = []
    for i in range(len(path)-1):
        nextNode = path[i+1]
        info = nextNode.getRoutingInfo()
        routing.append( (Modules.FWD_TYPE, info.pack() ) )
        
    routing.append( (exitType, exitInfo) )
    
    return _buildHeader_impl(path,secrets,routing,paddingPRNG)

#routing is list of (type,info)
def _buildHeader_impl(path, secrets, routing, paddingPRNG):
    "XXXX"
    hops = len(path)

    # sizes[i] is size, in blocks, of subheaders for i.
    sizes =[ getTotalBlocksForRoutingInfoLen(len(info)) for t, info in routing]
    # totalSize is number total number of blocks.
    totalSize = reduce(operator.add, sizes)

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
        nextJunk = junkSeen[-1] + newJunk
        # Node i encrypts starting with its first extended subheader.  By
        #   the time it reaches the junk, it's traversed:
        #          All of its extended subheaders            [(size-1)*128]
        #          The parts of the header that aren't junk.
        #                                           [HEADER_LEN-len(nextJunk)]
        #
        # Simplifying, we find that the PRNG index for the junk is
        #      HEADER_LEN-len(junkSeen[-1])-128*size+128*size-128
        #    = HEADER_LEN-len(junkSeen[-1])-128
        startIdx = HEADER_LEN-len(junkSeen[-1])-128
        nextJunk = Crypto.ctr_crypt(nextJunk, headerKey, startIdx)
        junkSeen.append(nextJunk)

    # We start with the padding.
    header = paddingPRNG.getBytes(HEADER_LEN - totalSize*128)

    # Now, we build the subheaders, iterating through the nodes backwards.
    for i in range(hops-1, -1, -1):
        rt, ri = routing[i]

        subhead = Subheader(MAJOR_NO, MINOR_NO,
                            secrets[i], " "*20,
                            rt, ri)

        extHeaders = "".join(subhead.getExtraBlocks())
        rest = Crypto.ctr_crypt("".join((extHeaders,header)), headerKeys[i])
        subhead.digest = Crypto.sha1(rest+junkSeen[i])
        pubkey = Crypto.pk_from_modulus(path[i].getModulus())
        esh = Crypto.pk_encrypt(subhead.pack(), pubkey)
        header = esh + rest

    return header

# For a reply, secrets2==None
def _constructMessage(secrets1, secrets2, header1, header2, payload):
    "XXXX"
    #XXXX comment    
    assert len(payload) == PAYLOAD_LEN
    assert len(header1) == len(header2) == HEADER_LEN
    secrets1 = secrets1[:]
    if secrets2:
        secrets2 = secrets2[:]
    
    if secrets2:
        secrets2.reverse()
        for secret in secrets2:
            ks = Crypto.Keyset(secret)
            key = ks.getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE)
            payload = Crypto.lioness_encrypt(payload, key)

    key = Crypto.lioness_keys_from_payload(payload)
    header2 = Crypto.lioness_encrypt(header2, key)

    secrets1.reverse()
    for secret in secrets1:
        ks = Crypto.Keyset(secret)
        hkey = ks.getLionessKeys(Crypto.HEADER_ENCRYPT_MODE)
        pkey = ks.getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE)
        header2 = Crypto.lioness_encrypt(header2,hkey)
        payload = Crypto.lioness_encrypt(payload,pkey)

    return Message(header1, header2, payload).pack()
