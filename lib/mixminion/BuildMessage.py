# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: BuildMessage.py,v 1.3 2002/05/29 22:51:58 nickm Exp $

from mixminion.Formats import *
import mixminion.Crypto as Crypto
import mixminion.Modules as Modules

__all__ = [ 'buildForwardMessage', 'buildReplyBlock', 'buildReplyMessage',
            'buildStatelessReplyBlock' ]

def buildForwardMessage(payload, exitType, exitInfo, path1, path2):
    "XXXX"
    return _buildMessage(payload, exitType, exitInfo, path1, path2)

def buildReplyMessage(payload, exitType, exitInfo, path1, replyBlock):
    "XXXX"
    return _buildMessage(payload, exitType, exitInfo, path1, reply=replyBlock)

# Bad interface: this shouldn't return a tuple. 
def buildReplyBlock(path, exitType, exitInfo, prng):
    "XXXX"
    secrets = [ prng.getBytes(SECRET_LEN) for node in path ]
    headers = _buildHeaders(path, secrets, exitType, exitInfo)
    return (headers, path[0]), secrets

# Bad interface: userkey should only be None if we trust the final node
# a lot.
def buildStatelessReplyBlock(path, prng, user, userKey=None, email=0):
    "XXXX"
    if email:
        assert userKey
    seed = Crypto.trng(16)
    if userKey:
        tag = Crypto.ctr_crypt(seed,userKey)
    else:
        tag = seed
    if emal:
        exitType = Modules.SMTP_TYPE
        exitInfo = SMTPInfo(user, "RTRN"+key).pack()
    else:
        exitType = Modules.LOCAL_TYPE
        exitInfo = LocalInfo(user, "RTRN"+key).pack()

    prng = Crypto.AESCounterPRNG(seed)
    return buildReplyBlock(path, exitType, exitInto, prng)

#----------------------------------------------------------------------
def _buildMessage(payload, exitType, exitInfo,
                  path1, path2=None, reply=None, prng=None, paranoia=0):
    "XXXX"
    assert path2 or reply
    if prng == None:
        prng = Crypto.AESCounterPRNG()

    # ???? Payload padding/sizing must be handled in spec.
    if len(payload) < PAYLOAD_LEN:
        payload += prng.getBytes(PAYLOAD_LEN-len(payload))

    if paranoia:
        secrets1 = [ Crypto.trng(SECRET_LEN) for node in path1 ]
        if path2: secrets2 = [ Crypto.trng(SECRET_LEN) for node in path2 ]
    else:
        secrets1 = [ prng.getBytes(SECRET_LEN) for node in path1 ]
        if path2: secrets2 = [ prng.getBytes(SECRET_LEN) for node in path2 ]

    if path2:
        node = path2[0]
    else:
        node = reply[1]
    info = IPV4Info(node.getAddr(), node.getPort(), node.getKeyID())
    headers1 = _buildHeaders(path1, secrets1, Modules.SWAP_FWD_TYPE, info,prng)
    if path2:
        headers2 = _buildHeaders(path2, secrets2, exitType, exitInfo, prng)
    else:
        headers2 = reply[0]
    return _constructMessage(secrets1, secrets2, headers1, headers2, payload)


def _buildHeaders(path, secrets, exitType, exitInfo, prng):
    "XXXX"
    hops = len(path)

    #Calculate all routing info
    routing = []
    for i in range(hops-1):
        nextNode = path[i+1]
        info = IPV4Info(nextNode.getAddr(), nextNode.getPort(),
                        nextNode.getKeyID())
        routing.append( (Modules.FWD_TYPE, info.pack() ) )
    
    routing.append( (exitType, exitInfo) )                   
    
    # size[i] is size, in blocks, of headers for i.
    size = [ getTotalBlocksForRoutingInfoLen(len(info)) for t, info in routing]

    totalSize = len(path)+size[-1]-1

    # Calculate masks, junk.  mask[i] == the mask used by node i.
    #   junkSeen[i]==the junk that node i will see, before encryption.
    #XXXX Comment better
    headerKeys = []
    junkSeen = [ "" ]
    for secret, size in zip(secrets, size):
        ks = Crypto.Keyset(secret)
        headerKey = Crypto.aes_key(ks.get(Crypto.HEADER_SECRET_MODE))
        sz = size*128
        newJunk = Crypto.prng(ks.get(Crypto.RANDOM_JUNK_MODE),sz)
        nextJunk = junkSeen[-1] + newJunk
        nextJunk = Crypto.ctr_crypt(nextJunk, headerKey,
                                    HEADER_LEN-len(nextJunk))
        junkSeen.append(nextJunk)
        headerKeys.append(headerKey)
        
    header = prng.getBytes(HEADER_LEN - totalSize*128)

    #XXXX comment better
    for i in range(hops-1, -1, -1):
        rest = Crypto.ctr_crypt(header, headerKeys[i])
        digest = Crypto.sha1(rest+junkSeen[i])
        pubkey = Crypto.pk_from_modulus(path[i].getModulus())
        rt, ri = routing[i]

        subhead = Subheader(MAJOR_NO, MINOR_NO,
                            secrets[i], digest,
                            rt, ri).pack()
        esh = Crypto.pk_encrypt(subhead, pubkey)
        header = esh + rest

    return header
 
# For a reply, secrets2==None
def _constructMessage(secrets1, secrets2, header1, header2, payload):
    "XXXX"
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
