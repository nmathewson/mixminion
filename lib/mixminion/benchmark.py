# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: benchmark.py,v 1.43 2003/07/08 18:38:24 nickm Exp $

"""mixminion.benchmark

   Performance tests for Mixminion functionality.

   Usage:
   >>> import mixminion.benchmark
   >>> mixminion.benchmark.timeAll()

   """
__pychecker__ = 'no-funcdoc no-reimport'
__all__ = [ 'timeAll', 'testLeaks1', 'testLeaks2' ]

import gc
import os
import stat
import cPickle
import threading
from time import time

import mixminion._minionlib as _ml
import mixminion.server.ServerQueue

from mixminion.BuildMessage import _buildHeader, buildForwardMessage, \
     compressData, uncompressData, _encodePayload, decodePayload
from mixminion.Common import secureDelete, installSIGCHLDHandler, \
     waitForChildren, formatBase64, Lockfile
from mixminion.Crypto import *
from mixminion.Crypto import OAEP_PARAMETER
from mixminion.Crypto import _add_oaep_padding, _check_oaep_padding
from mixminion.Packet import SMTP_TYPE, CompressedDataTooLong, IPV4Info
from mixminion.ServerInfo import ServerInfo
from mixminion.server.HashLog import HashLog
from mixminion.server.PacketHandler import PacketHandler
from mixminion.server.ServerConfig import ServerConfig
from mixminion.test import FakeServerInfo
from mixminion.testSupport import mix_mktemp

# If PRECISION_FACTOR is >1, we time everything for PRECISION_FACTOR times
# more iterations than ususal.
#
# If PRESISION_FACTOR is 0, we only try stuff once.  Good for testing this
# file in a hurry.
PRECISION_FACTOR = 1

# Dictionary holds cached values of time for no-op loops.
loop_overhead = {}
def timeit_(fn, iters, ov=1):
    """timeit_(fn, iters)

       returns the execution time for fn(), measures with iters sample
       iterations."""
    iters *= PRECISION_FACTOR
    if iters < 1: iters = 1
    nones = [None]*iters
    if ov:
        overhead = loop_overhead.get(iters)
        if overhead is None:
            overhead = loop_overhead[iters] = timeit_((
                lambda:(lambda:None)()), iters, 0)
    else:
        overhead = 0
    t = time()
    for _ in nones: fn()
    t2 = time()-t
    t_each = ((t2) / float(iters))-overhead
    return t_each

def timestr(t):
    """Given a time in seconds, returns a readable representation"""
    if abs(t) >= 1.0:
        return "%.3f sec" % t
    elif abs(t) >= .001:
        return "%.3f msec" % (t*1000)
    elif abs(t) >= (.000001):
        return "%.3f usec" % (t*1000000)
    else:
        return "%f psec" % (t*1000000000L)

def timeit(fn,times):
    """Same as timeit_, but returns a readable representation"""
    return timestr(timeit_(fn,times))

def spacestr(n):
    """Converts number of bytes to readable representation)"""
    if abs(n) < 1024:
        return "%d B" %n
    elif abs(n) < 1048576:
        return "%d KB" % (n >> 10)
    elif abs(n) < 1e10:
        return "%d MB" % (n >> 20)
    else:
        return "%d GB" % (n >> 30)

#----------------------------------------------------------------------

short = "Hello, Dali!"
s20b = "ABCDEFGHIJKLMNOPQRST"
s64b = "8charstr"*8
s128b = s64b*2
s70b = "10character"*7
s1K = "8charstr"*128
s2K = s1K*2
s4K = s2K*2
s8K = s4K*2
s28K = s1K*28
s32K = s8K*4

s120b = 'z'*120

def cryptoTiming():
    print "#==================== CRYPTO ======================="

    print "SHA1 (short)", timeit((lambda: sha1(short)), 100000)
    print "SHA1 (64b)", timeit((lambda: sha1(s64b)), 100000)
    print "SHA1 (2K)", timeit((lambda: sha1(s2K)), 10000)
    print "SHA1 (8K)", timeit((lambda: sha1(s8K)), 10000)
    print "SHA1 (28K)", timeit((lambda: sha1(s28K)), 1000)
    print "SHA1 (32K)", timeit((lambda: sha1(s32K)), 1000)

    shakey = "8charstr"*2
    print "Keyed SHA1 for lioness (28K, unoptimized)", timeit(
        (lambda shakey=shakey: _ml.sha1("".join((shakey,s28K,shakey)))), 1000)

    print "TRNG (20 byte)", timeit((lambda: trng(20)), 100)
    print "TRNG (128 byte)", timeit((lambda: trng(128)), 100)
    print "TRNG (1K)", timeit((lambda: trng(1024)), 100)

    print "xor (1K)", timeit((lambda: _ml.strxor(s1K,s1K)), 100000)
    print "xor (32K)", timeit((lambda: _ml.strxor(s32K,s32K)), 1000)

    key = "8charstr"*2
    print "aes (short)", timeit((lambda key=key: ctr_crypt(short,key)), 100000)
    print "aes (1K)", timeit((lambda key=key: ctr_crypt(s1K,key)), 10000)
    print "aes (2K)", timeit((lambda key=key: ctr_crypt(s2K,key)), 10000)
    print "aes (28K)", timeit((lambda key=key: ctr_crypt(s28K,key)), 100)
    print "aes (32K)", timeit((lambda key=key: ctr_crypt(s32K,key)), 100)

    key = _ml.aes_key(key)
    print "aes (short,pre-key)", \
          timeit((lambda key=key: ctr_crypt(short,key)), 100000)
    print "aes (1K,pre-key)", \
          timeit((lambda key=key: ctr_crypt(s1K,key)), 10000)
    print "aes (28K,pre-key)", \
          timeit((lambda key=key: ctr_crypt(s28K,key)), 100)
    print "aes (32K,pre-key)", \
          timeit((lambda key=key: ctr_crypt(s32K,key)), 100)

    print "aes (32K,pre-key,unoptimized)", timeit(
        (lambda key=key: _ml.strxor(prng(key,32768),s32K)), 100)

    print "prng (short)", timeit((lambda key=key: prng(key,8)), 100000)
    print "prng (128b)", timeit((
        lambda key=key: prng(key,18)), 10000)
    print "prng (1K)", timeit((
        lambda key=key: prng(key,1024)), 10000)
    print "prng (2K)", timeit((
        lambda key=key: prng(key,2048)), 10000)
    print "prng (28K)", timeit((
        lambda key=key: prng(key,28678)), 100)
    print "prng (32K)", timeit((lambda key=key: prng(key,32768)), 100)
    print "prng (32K, unoptimized)", timeit(
        (lambda key=key: ctr_crypt('\x00'*32768, key)), 100)

    c = AESCounterPRNG()
    print "aesprng.getInt (10)", \
          timeit((lambda c=c: c.getInt(10)), 10000)
    print "aesprng.getInt (1000)", \
          timeit((lambda c=c: c.getInt(1000)), 10000)
    print "aesprng.getInt (513)", \
          timeit((lambda c=c: c.getInt(513)), 10000)

    L10 = [ "x" ] * 10
    L1000 = [ "x" ] * 1000
    print "aesprng.shuffle (10/10)", \
          timeit((lambda c=c,L=L10: c.shuffle(L)), 1000)
    print "aesprng.shuffle (1000/1000)", \
          timeit((lambda c=c,L=L1000: c.shuffle(L)), 30)
    print "aesprng.shuffle (10/1000)", \
          timeit((lambda c=c,L=L1000: c.shuffle(L,10)), 1000)

    lkey = Keyset("keymaterial foo bar baz").getLionessKeys("T")
    print "lioness E (1K)", timeit((
        lambda lkey=lkey: lioness_encrypt(s1K, lkey)), 1000)
    print "lioness E (2K)", timeit((
        lambda lkey=lkey: lioness_encrypt(s1K, lkey)), 1000)
    print "lioness E (4K)", timeit((
        lambda lkey=lkey: lioness_encrypt(s4K, lkey)), 1000)
    print "lioness E (28K)", timeit((
        lambda lkey=lkey: lioness_encrypt(s28K, lkey)), 100)
    print "lioness E (32K)", timeit((
        lambda lkey=lkey: lioness_encrypt(s32K, lkey)), 100)
    print "lioness D (1K)", timeit((
        lambda lkey=lkey: lioness_decrypt(s1K, lkey)), 1000)
    print "lioness D (2K)", timeit((
        lambda lkey=lkey: lioness_decrypt(s1K, lkey)), 1000)
    print "lioness D (4K)", timeit((
        lambda lkey=lkey: lioness_decrypt(s4K, lkey)), 1000)
    print "lioness D (28K)", timeit((
        lambda lkey=lkey: lioness_decrypt(s28K, lkey)), 100)
    print "lioness D (32K)", timeit((
        lambda lkey=lkey: lioness_decrypt(s32K, lkey)), 100)

    bkey = Keyset("keymaterial foo bar baz").getBearKeys("T")
    print "bear E (1K)", timeit((
        lambda bkey=bkey: bear_encrypt(s1K, bkey)), 1000)
    print "bear E (2K)", timeit((
        lambda bkey=bkey: bear_encrypt(s1K, bkey)), 1000)
    print "bear E (4K)", timeit((
        lambda bkey=bkey: bear_encrypt(s4K, bkey)), 1000)
    print "bear E (28K)", timeit((
        lambda bkey=bkey: bear_encrypt(s28K, bkey)), 100)
    print "bear E (32K)", timeit((
        lambda bkey=bkey: bear_encrypt(s32K, bkey)), 100)
    print "bear D (1K)", timeit((
        lambda bkey=bkey: bear_decrypt(s1K, bkey)), 1000)
    print "bear D (2K)", timeit((
        lambda bkey=bkey: bear_decrypt(s1K, bkey)), 1000)
    print "bear D (4K)", timeit((
        lambda bkey=bkey: bear_decrypt(s4K, bkey)), 1000)
    print "bear D (28K)", timeit((
        lambda bkey=bkey: bear_decrypt(s28K, bkey)), 100)
    print "bear D (32K)", timeit((
        lambda bkey=bkey: bear_decrypt(s32K, bkey)), 100)

def rsaTiming():
    c = AESCounterPRNG()
    if hasattr(_ml, 'add_oaep_padding'):
        print "OAEP_add (70->128B) (C)",
        print timeit((lambda: _ml.add_oaep_padding(s70b,OAEP_PARAMETER,128)),
                     10000)
        r = _ml.add_oaep_padding(s70b, OAEP_PARAMETER,128)
        print "OAEP_check (128B->70B) (C)",
        print timeit((lambda r=r:
                      _ml.check_oaep_padding(r,OAEP_PARAMETER,128)),10000)

    print "OAEP_add (70->128B) (native python)",
    print timeit((lambda c=c: _add_oaep_padding(s70b,OAEP_PARAMETER,128,c)),
                 10000)
    r = _add_oaep_padding(s70b, OAEP_PARAMETER,128,c)
    print "OAEP_check (128B->70B) (native python)",
    print timeit((lambda r=r:
                  _check_oaep_padding(r,OAEP_PARAMETER,128)),10000)

    print "RSA generate (1024 bit)", timeit((lambda: pk_generate()),10)
    rsa = pk_generate()
    print "Pad+RSA public encrypt",
    print timeit((lambda rsa=rsa: pk_encrypt(s70b, rsa)),1000)

    enc = pk_encrypt(s70b, rsa)
    print "Pad+RSA private decrypt", \
          timeit((lambda enc=enc,rsa=rsa: pk_decrypt(enc, rsa)),100)

    print "RSA.get_public_key", timeit(rsa.get_public_key, 100)
    print "RSA.get_exponent", timeit(rsa.get_exponent, 100)
    print "RSA.get_modulus_bytes", timeit(rsa.get_modulus_bytes, 10000)
    print "RSA.encode_key(public)", \
          timeit(lambda rsa=rsa: rsa.encode_key(1), 100)
    print "RSA.encode_key(private)", \
          timeit(lambda rsa=rsa: rsa.encode_key(0), 100)
    modulus = rsa.get_public_key()[0]
    print "RSA from modulus", \
          timeit(lambda modulus=modulus: pk_from_modulus(modulus), 10000)
    asn1 = rsa.encode_key(1)
    print "RSA from ASN1 (public)", \
          timeit(lambda asn1=asn1: pk_decode_public_key(asn1), 10000)

    print "RSA generate (1024 bit,e=65535)", timeit((lambda: pk_generate(1024,
                                                                  65535)),10)
    rsa = pk_generate(1024,65535)
    print "Pad+RSA public encrypt",
    print timeit((lambda rsa=rsa: pk_encrypt(s70b, rsa)),1000)
    enc = pk_encrypt(s70b, rsa)
    print "Pad+RSA private decrypt", \
          timeit((lambda enc=enc,rsa=rsa: pk_decrypt(enc, rsa)),100)

    print "RSA generate (1024 bit,e=3)", timeit((lambda: pk_generate(1024,
                                                                  3)),10)
    rsa = pk_generate(1024,3)
    print "Pad+RSA public encrypt",
    print timeit((lambda rsa=rsa: pk_encrypt(s70b, rsa)),1000)
    enc = pk_encrypt(s70b, rsa)
    print "Pad+RSA private decrypt", \
          timeit((lambda enc=enc,rsa=rsa: pk_decrypt(enc, rsa)),100)

    print "RSA generate (1024 bit,e=100073471)", timeit(
        lambda: pk_generate(1024, 100073471), 10)
                             
    rsa = pk_generate(1024, 100073471)
    print "Pad+RSA public encrypt",
    print timeit((lambda rsa=rsa: pk_encrypt(s70b, rsa)),1000)
    enc = pk_encrypt(s70b, rsa)
    print "Pad+RSA private decrypt", \
          timeit((lambda enc=enc,rsa=rsa: pk_decrypt(enc, rsa)),100)

    for (bits,it) in ((1536,15), (2048,10),(4096,10)):
        t = time()
        print "[generating key...]"
        rsa2 = pk_generate(bits)
        t = time()-t
        print "RSA genrate (%d bit)"%bits, timestr(t)
        enc = pk_encrypt(s70b, rsa2)
        print "Pad+RSA public encrypt (%d bit)"%bits,
        print timeit((lambda rsa2=rsa2: pk_encrypt("zzz", rsa2)),it)
        print "Pad+RSA private decrypt (%d bit)"%bits,
        print timeit((lambda enc=enc,rsa2=rsa2: pk_decrypt(enc, rsa2)),it)

    o = loop_overhead.values()
    print "Timing overhead: %s...%s" % (timestr(min(o)),timestr(max(o)))

#----------------------------------------------------------------------

def hashlogTiming():
    print "#==================== HASH LOGS ======================="
    for load in (100, 1000, 10000, 100000):
        fname = mix_mktemp(".db")
        try:
            _hashlogTiming(fname,load)
        finally:
            for suffix in ("", ".dat", ".bak", ".dir"):
                try:
                    os.unlink(fname+suffix)
                except OSError:
                    pass

def _hashlogTiming(fname, load):

    # Try more realistic access patterns.
    prng = AESCounterPRNG("a"*16)

    print "Testing hash log (%s entries)"%load
    if load > 20000:
        print "This may take a few minutes..."
    h = HashLog(fname, "A")
    hashes = [ prng.getBytes(20) for _ in xrange(load) ]

    # XXXX Check under different circumstances -- different sync patterns.
    t = time()
    for n in xrange(len(hashes)):
        h.logHash(hashes[n])
    h.sync()
    t = time()-t
    print "Add entry (up to %s entries)" %load, timestr(t/float(load))

    t = time()
    for hash in hashes[0:1000]:
        h.seenHash(hash)
    t = time()-t
    print "Check entry [hit] (%s entries)" %load, timestr(t/1000.0)

    hashes =[ prng.getBytes(20) for _ in xrange(1000) ]
    t = time()
    for hash in hashes:
        h.seenHash(hash)
    t = time()-t
    print "Check entry [miss] (%s entries)" %load, timestr(t/1000.0)

    hashes =[ prng.getBytes(20) for _ in xrange(1000) ]
    t = time()
    for hash in hashes:
        h.seenHash(hash)
        h.logHash(hash)
    t = time()-t
    print "Check entry [miss+add] (%s entries)" %load, timestr(t/1000.0)

    h.close()
    size = 0
    for suffix in ("", ".dat", ".bak", ".dir"):
        if not os.path.exists(fname+suffix):
            continue
        size += os.stat(fname+suffix)[stat.ST_SIZE]

    print "File size (%s entries)"%load, spacestr(size)

#----------------------------------------------------------------------
def directoryTiming():
    print "#========== DESCRIPTORS AND DIRECTORIES =============="
    from mixminion.server.ServerKeys import ServerKeyring
    confStr = """
[Server]
EncryptIdentityKey: no
PublicKeyLifetime: 1 day
EncryptPrivateKey: no
Homedir: %s
Mode: relay
Nickname: The-Server
Contact-Email: a@b.c
[Incoming/MMTP]
Enabled: yes
IP: 1.1.1.1
""" % mix_mktemp()
    config = ServerConfig(string=confStr)
    keyring = ServerKeyring(config)
    keyring.getIdentityKey()
    print "Create and sign server descriptor", timeit(keyring.createKeys, 10)
    liveKey = keyring.getServerKeysets()[0]
    descFile = liveKey.getDescriptorFileName()
    desc = open(descFile).read()
##     for _ in xrange(2000):
##         ServerInfo(string=desc, assumeValid=0)
##     if 1: return

    print "Parse server descriptor (no validation)", \
          timeit(lambda desc=desc: ServerInfo(string=desc,assumeValid=1),
                 400)
    print "Parse server descriptor (full validation)", \
          timeit(lambda desc=desc: ServerInfo(string=desc,assumeValid=0),
                 400)
    info = ServerInfo(string=desc)
    dbin = cPickle.dumps(info, 1)
    print "Unpickle binary-pickled descriptor (%s/%s)"%(len(dbin),len(desc)), \
          timeit(lambda dbin=dbin: cPickle.loads(dbin), 400)
    dtxt = cPickle.dumps(info, 0)
    print "Unpickle text-pickled descriptor (%s/%s)"%(len(dtxt),len(desc)), \
          timeit(lambda dtxt=dtxt: cPickle.loads(dtxt), 400)

#----------------------------------------------------------------------

def buildMessageTiming():
    print "#================= BUILD MESSAGE ====================="
    pk = pk_generate(2048)

    for payload in "Hello!!!"*128, "Hello!!!"*(128*28):
        print "Compress %sK" % (len(payload)/1024), \
              timeit(lambda p=payload: compressData(p),
                     100)

    compressed = compressData("Hello!!!"*128)
    print "Uncompress (1K, no max)", \
          timeit(lambda c=compressed: uncompressData(c), 1000)
    compressed = compressData("Hello!!!"*(128*28))
    print "Unompress (28K, no max)", \
          timeit(lambda c=compressed: uncompressData(c), 1000)

    compressed = compressData("Hello!!!"*128)
    print "Uncompress (1K, 1K max)", \
          timeit(lambda c=compressed: uncompressData(c, 1024), 1000)
    compressed = compressData("Hello!!!"*(128*28))
    print "Unompress (28K, 28K max)", \
          timeit(lambda c=compressed: uncompressData(c, 28<<10), 1000)

    payload = ("Junky qoph flags vext crwd zimb."*1024)[:22*1024]
    serverinfo = [FakeServerInfo("127.0.0.1", 48099, pk,"x"*20)
                  ] * 16

    def bh(np,it, serverinfo=serverinfo):
        ctr = AESCounterPRNG()

        tm = timeit_(
              lambda np=np,it=it,serverinfo=serverinfo,ctr=ctr:
                         _buildHeader(serverinfo[:np], ["Z"*16]*np,
                                        99, "Hello", ctr), it)

        print "Build header (%s)" %(np), timestr(tm)

    bh(1,100)
    bh(4,40)
    bh(8,20)
    bh(16,10)

    def bm(np1,np2,it,serverinfo=serverinfo,payload=payload):
        tm = timeit_( \
              lambda np1=np1,np2=np2,it=it,serverinfo=serverinfo,
                      payload=payload: buildForwardMessage(payload,
                                               500,
                                               "Hello",
                                               serverinfo[:np1],
                                               serverinfo[:np2]), it)
        print "Build forward message (%sx%s)" %(np1,np2), timestr(tm)


    bm(1,1,100)
    bm(8,1,40)
    bm(8,8,20)
    bm(16,16,10)

#----------------------------------------------------------------------
def serverQueueTiming():
    print "#================= SERVER QUEUES ====================="
    Queue = mixminion.server.ServerQueue.Queue
    DeliveryQueue = mixminion.server.ServerQueue.DeliveryQueue
    d1 = mix_mktemp()
    q1 = Queue(d1, create=1)

    d2 = mix_mktemp()
    os.mkdir(d2,0700)
    getCommonPRNG().getBytes(1)
    
    #for ln,it in (32*1024,100),(128,400),(1024,400), (32*1024,100):
    for ln,it in ():
        msg = "z"*ln
        def y(msg=msg,idx=[0],d2=d2):
            fn = os.path.join(d2,"k_"+str(idx[0]))
            idx[0] += 1
            f = open(fn, 'wb')
            f.write(msg)
            f.close()
        def x(msg=msg,d2=d2):
            f,b=getCommonPRNG().openNewFile(d2,"k_",1)
            f.write(msg)
            f.close()
        print "Base: write %s file: %s" %(
            spacestr(ln), timestr(timeit_(y, it)))
        for p in os.listdir(d2):
            os.unlink(os.path.join(d2,p))
        print "Base: write %s file with random name: %s" %(
            spacestr(ln), timestr(timeit_(x, it)))
        for p in os.listdir(d2):
            os.unlink(os.path.join(d2,p))

        tm = timeit_(lambda q1=q1,msg=msg:q1.queueMessage(msg),  it)
        print "Queue %s message: %s" %(spacestr(ln), timestr(tm))
        t2 = time()
        q1.removeAll()
        q1.cleanQueue()
        t2 = time() - t2
        print "Scrub %s message: %s" %(spacestr(ln), timestr(t2/float(it)))

        msg = [ 123, 414, msg ]
        tm = timeit_(lambda q1=q1,msg=msg:q1.queueObject(msg), it)
        print "Pickle %s message: %s" %(spacestr(ln), timestr(tm))
        q1.removeAll()
        q1.cleanQueue()

    for ln,it in (128,400),(1024,400), (32*1024,100):
        q1 = DeliveryQueue(d1, [100,100,100,100])
        msg = "z"*ln
        print "Delivery queue: %s message: %s" %(
            spacestr(ln),
            timeit(lambda q1=q1,msg=msg: q1.queueDeliveryMessage(msg), it))
        print "            (repOK):", \
              timeit(lambda q1=q1: q1._repOk(), it*10)
#        q1._bs2()
#        print "          (set metadata 2):", \
#              timeit(lambda q1=q1: q1._saveState2(), it)

        for p in os.listdir(d1):
            os.unlink(os.path.join(d1,p))


#----------------------------------------------------------------------
class DummyLog:
    def seenHash(self,h): return 0
    def logHash(self,h): pass

def serverProcessTiming():
    print "#================= SERVER PROCESS ====================="

    pk = pk_generate(2048)
    server = FakeServerInfo("127.0.0.1", 1, pk, "X"*20)
    sp = PacketHandler([pk], [DummyLog()])

    m_noswap = buildForwardMessage("Hello world", SMTP_TYPE, "f@invalid",
                                   [server, server], [server, server])

    print "Server process (no swap, no log)", timeit(
        lambda sp=sp, m_noswap=m_noswap: sp.processMessage(m_noswap), 100)

    m_swap = buildForwardMessage("Hello world", SMTP_TYPE, "f@invalid",
                                 [server], [server, server])

    print "Server process (swap, no log)", timeit(
        lambda sp=sp, m_swap=m_swap: sp.processMessage(m_swap), 100)

def encodingTiming():
    print "#=============== END-TO-END ENCODING =================="
    shortP = "hello world"
    prng = AESCounterPRNG()
    p = _encodePayload(shortP, 0, prng)
    t = prng.getBytes(20)
    print "Decode short payload", timeit(
        lambda p=p,t=t: decodePayload(p, t), 1000)

    k20 = prng.getBytes(20*1024)
    p = _encodePayload(k20, 0, prng)
    t = prng.getBytes(20)
    print "Decode 20K payload", timeit(
        lambda p=p,t=t: decodePayload(p, t), 1000)

    comp = "x"*(20*1024)
    p = _encodePayload(comp, 0, prng)
    t = prng.getBytes(20)
    def decode(p=p,t=t):
        try:
            decodePayload(p,t)
        except CompressedDataTooLong:
            pass
    print "Decode overcompressed payload", timeit(decode, 1000)

#----------------------------------------------------------------------
def timeEfficiency():
    print "#================= ACTUAL v. IDEAL ====================="
    # Here we compare the time spent in an operation with the time we think
    # is required for its underlying operations, in order to try to measure
    # its efficiency.  If function X is pretty efficient, there's not much
    # reason to try to optimise its implementation; instead, we need to attack
    # the functions it uses.

    ##### LIONESS

    shakey = "z"*20
    aeskey = "p"*16
    # Lioness_encrypt is:
    # 2 28K SHA1's (keyed)
    # 2 20b SHA1's (keyed)
    # 2 20b string xors.
    # 2 28K aes_crypts.
    shastr = shakey+s28K+shakey
    sha1_keyed_28k = timeit_((lambda shastr=shastr: _ml.sha1(shastr)), 1000)
    shastr = shakey+s20b+shakey
    sha1_keyed_20b = timeit_((lambda shastr=shastr: _ml.sha1(shastr)), 100000)
    strxor_20b = timeit_((lambda s=s20b: _ml.strxor(s,s)), 100000)
    aes_28k = timeit_((lambda s=s28K,k=aeskey: ctr_crypt(s,k)), 100)

    lionesskey = ("p"*20,)*4
    lioness_e = timeit_((lambda s=s28K,k=lionesskey: lioness_encrypt(s,k)),100)

    expected = 2*(strxor_20b+aes_28k+sha1_keyed_28k+sha1_keyed_20b)
    print "LIONESS TOOK:", timestr(lioness_e)
    print "    expected:", timestr(expected)
    print "  difference:", timestr(lioness_e-expected)
    print "    goodness: %3.2f%%" % (100*expected/lioness_e)
    print "   breakdown:       aes: %3.1f%%" % (100*2*aes_28k/lioness_e)
    print "              long sha1: %3.1f%%" % (100*2*sha1_keyed_28k/lioness_e)
    print "             short sha1: %3.1f%%" % (100*2*sha1_keyed_20b/lioness_e)
    print "              short xor: %3.1f%%" % (100*2*strxor_20b/lioness_e)

    ##### SERVER PROCESS
    pk = pk_generate(2048)

    # Typical (no swap) server process is:
    #  pk_decrypt (128b)
    #  sha1       (2K-128b)
    #5*sha1       (16b+~16b) [HEADER_SEC,HEADER_ENC,PRNG,PAYLOAD_ENC,REPLAY]
    #  hashlog.seen **omit
    #  hashlog.log  **omit
    #  ctr_crypt  (2K)
    #  lioness_D  (28K)
    #  prng       (128b)
    #  lioness_D  (2K)

    # With swap, add:
    #  keys_from_payload=HASH(28K)
    #  lioness_D  (2K)

    enc = pk_encrypt(s70b, pk)
    rsa_128b = timeit_((lambda pk=pk,enc=enc: pk_decrypt(enc,pk)), 100)
    shastr = s2K[2048-128]
    sha1_hdr = timeit_((lambda shastr=shastr: sha1(shastr)), 10000)
    shastr = s64b[:32]
    sha1_key = timeit_((lambda shastr=shastr: sha1(shastr)), 10000)
    aes_2k = timeit_((lambda k=aeskey: ctr_crypt(s2K,k)), 1000)
    lioness_28k = lioness_e
    lioness_2k = timeit_((
        lambda s=s2K,k=lionesskey: lioness_encrypt(s,k)),1000)
    prng_128b = timeit_((lambda k=aeskey: prng(k,128)),10000)

    server = FakeServerInfo("127.0.0.1", 1, pk, "X"*20)
    sp = PacketHandler([pk], [DummyLog()])

    m_noswap = buildForwardMessage("Hello world", SMTP_TYPE, "f@invalid",
                                   [server, server], [server, server])

    sp_ns = timeit_(
        lambda sp=sp, m_noswap=m_noswap: sp.processMessage(m_noswap), 100)

    expected = rsa_128b+sha1_hdr+sha1_key*5+aes_2k+lioness_28k+prng_128b
    expected += lioness_2k
    print "SERVERPROCESS TOOK:", timestr(sp_ns)
    print "          expected:", timestr(expected)
    print "        difference:", timestr(sp_ns-expected)
    print "          goodness: %3.2f%%" % (100*expected/sp_ns)
    print "         breakdown:         rsa: %3.1f%%" % (100*rsa_128b/sp_ns)
    print "                    28K lioness: %3.1f%%" % (100*lioness_28k/sp_ns)
    print "                     2K lioness: %3.1f%%" % (100*lioness_2k/sp_ns)
    print "                     header aes: %3.1f%%" % (100*aes_2k/sp_ns)
    print "                    header sha1: %3.1f%%" % (100*sha1_hdr/sp_ns)
    print "                    keygen sha1: %3.1f%%" % (500*sha1_key/sp_ns)
    print " (logs not included)"
    # FFFF Time, including the hashlogs too.
    # FFFF Time BuildMessage efficiency too.

#----------------------------------------------------------------------

def fileOpsTiming():
    print "#================= File ops ====================="
    installSIGCHLDHandler()
    dname = mix_mktemp(".d")

    os.mkdir(dname)

    lockfile = Lockfile(os.path.join("dname"))
    t1 = time()
    for _ in xrange(2000):
        lockfile.acquire(blocking=1)
        lockfile.release()
    t = time()-t1
    print "Lockfile: lock+unlock", timestr(t/2000.)

    for i in xrange(200):
        f = open(os.path.join(dname, str(i)), 'wb')
        f.write(s32K)
        f.close()
    lst = [os.path.join(dname,str(i)) for i in range(100) ]
    t1 = time()
    secureDelete(lst)
    t = time()-t1
    print "secureDelete (100x32)", timestr(t)

    waitForChildren()
    t = time()-t1
    print "               (sync)", timestr(t)

    lst = [ os.path.join(dname,str(i)) for i in range(100,200) ]
    t1 = time()
    for file in lst:
        secureDelete(file)
    t = time()-t1
    print "secureDelete (1)", timestr(t/100)

    waitForChildren()
    t = time()-t1
    print "          (sync)", timestr(t/100)

#----------------------------------------------------------------------
def fecTiming():
    print "#================= FEC =========================="

    r = getCommonPRNG()
    for k,n,it in [(5,10,1000),
                   (20,25,300),
                   (30,40,100),
                   (40,50,100)
                   ]:
        print "FEC (%s/%s)"%(k,n)
        msg = [ r.getBytes(28*1024) for i in xrange(k) ]
        fec = _ml.FEC_generate(k,n)
        tm = timeit_(lambda f=fec, m=msg,k=k: f.encode(k+1,m), it)
        print "Encode a single 28KB check block:", timestr(tm)
        print "                (time/(k*28KB)) =", timestr(tm/(k*28)), "/ KB"
        missing_1 = [ (i, fec.encode(i,msg)) for i in xrange(1,k+1) ]
        missing_max = [ (i, fec.encode(i,msg)) for i in xrange(n-k,n) ]
        tm = timeit_(lambda f=fec, m=missing_1: f.decode(m), it)
        print "              Decode (1 missing):", timestr(tm)
        print "              (time/(k*28KB*1)) =", timestr(tm/(k*28)), "/ KB"
        tm = timeit_(lambda f=fec, m=missing_max: f.decode(m), it)
        print "            Decode (k-n missing):", timestr(tm)
        print "          (time/(k*28KB*(n-k))) =", timestr(tm/(k*28*(n-k))), "/ KB"
#----------------------------------------------------------------------
def testLeaks1():
    print "Trying to leak (sha1,aes,xor,seed,oaep)"
    s20k="a"*20*1024
    keytxt="a"*16
    key = _ml.aes_key(keytxt)
    while 1:
        _ml.aes_key(keytxt)
        _ml.sha1(s20k)
        _ml.aes_ctr128_crypt(key,s20k,0)
        _ml.aes_ctr128_crypt(key,s20k,2000)
        _ml.aes_ctr128_crypt(key,"",2000,20000)
        _ml.aes_ctr128_crypt(key,"",0,20000)
        _ml.aes_ctr128_crypt(key,s20k,0,2000)
        try:
            _ml.aes_ctr128_crypt("abc",s20k,0,2000)
        except:
            pass
        _ml.strxor(s20k,s20k)
        try:
            _ml.strxor(s20k,keytxt)
        except:
            pass
        _ml.openssl_seed(s20k)
        r = _ml.add_oaep_padding("Hello",OAEP_PARAMETER,128)
        _ml.check_oaep_padding(r,OAEP_PARAMETER,128)
        try:
            _ml.check_oaep_padding("hello",OAEP_PARAMETER,128)
        except:
            pass
        try:
            _ml.add_oaep_padding(s20k,OAEP_PARAMETER,128)
        except:
            pass
        try:
            _ml.add_oaep_padding("a"*127,OAEP_PARAMETER,128)
        except:
            pass

def testLeaks2():
    print "Trying to leak (rsa)"

    s20 = "a"*20
    p = pk_generate(512)
    n,e = p.get_public_key()

    f = open("/dev/null", 'w')
    while 1:
        if 0:
            p = pk_generate(512)
        if 1:
            pk_decrypt(pk_encrypt(s20,p),p)
            for public in (0,1):
                x = p.encode_key(public)
                _ml.rsa_decode_key(x,public)
            p.get_public_key()
            _ml.rsa_make_public_key(n,e)
            p.get_modulus_bytes()
            p.get_exponent()
        if 1:
            p.PEM_write_key(f, 1)
            p.PEM_write_key(f, 0)
            p.PEM_write_key(f, 0, "Z")
        if 1:
            x = p.crypt("A"*64, 1, 1)
            p.crypt(x, 0, 0)

def testLeaks3():
    print "Trying to leak (certgen)"
    p = pk_generate(512)
    p2 = pk_generate(512)
    fn = mix_mktemp()
    while 1:
        _ml.generate_cert(fn, p, p2, "A", "B", 100, 10000)

def testLeaks4():
    print "Trying to leak (SSL)"

    p = pk_generate(512)
    p2 = pk_generate(512)
    fn = mix_mktemp()
    dh = mix_mktemp()
    _ml.generate_cert(fn, p, p2, "A", "B", 100, 10000)
    dh_fname = os.environ.get("MM_TEST_DHPARAMS")
    if dh_fname and os.path.exists(dh_fname):
        dh = dh_fname
    elif dh_fname:
        _ml.generate_dh_parameters(dh_fname, 1, 512)
        dh = dh_fname
    else:
        _ml.generate_dh_parameters(dh, 1, 512)
    print "OK"
    context = _ml.TLSContext_new(fn, p, dh)
    while 1:
        if 1:
            context = _ml.TLSContext_new(fn, p, dh)
            _ = context.sock(0, 0)
            _ = context.sock(0, 1)

def testLeaks5():
    from mixminion.test import _getMMTPServer
    server, listener, messagesIn, keyid = _getMMTPServer(1)
    #t = threading.Thread(None, testLeaks5_send,
    #                     args=(keyid,))
    #t.start()

    while 1:
        server.process(0.5)
        #if messagesIn:
        #    print "Connections"
        del messagesIn[:]
    #t.join()

def testLeaks5_send():
    from mixminion.test import TEST_PORT
    import mixminion.MMTPClient
    routing = IPV4Info("127.0.0.1", TEST_PORT, None)

    #msg = "X" * 32 * 1024
    n = 0
    while 1:
        mixminion.MMTPClient.sendMessages(routing, ["Z"*(32*1024)])
        n += 1
        print n, "sent"



def testLeaks5_send2():
    from mixminion.test import _getMMTPServer
    from mixminion.test import TEST_PORT, _getTLSContext
    import mixminion.MMTPClient

    #msg = "X" * 32 * 1024
    n = 0
    server, listener, messagesIn, keyid = _getMMTPServer(1,port=(TEST_PORT+1))
    #t = threading.Thread(None, testLeaks5_send,
    #                     args=(keyid,))
    #t.start()

    sending = [0]
    def sentHook(sending=sending):
        sending[0]=0

    certcache = mixminion.MMTPClient.PeerCertificateCache()

    print len(gc.get_objects())

    import socket

    context = _getTLSContext(0)

    i = 0
    while 0:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(1)
        sock.connect(("127.0.0.1", TEST_PORT))
        tls = _getTLSContext(0).sock(sock)
        tls.connect()
        #tls.check_cert_alive()
        #tls.verify_cert_and_get_identity_pk()
        #tls.get_peer_cert_pk()
        certcache.check(tls, keyid, ("127.0.0.1", TEST_PORT))
        #print certcache.cache
        
        tls.shutdown()
        sock.close()
            


    while 1:
        clientcon = mixminion.server.MMTPServer.MMTPClientConnection(
            _getTLSContext(0), "127.0.0.1", TEST_PORT, keyid,
            ["X"*(32*1024), "JUNK"], ["z", None],
            finishedCallback=sentHook, certCache=certcache)
        clientcon.register(server)
        i += 1
        sending[0] = 1
        print "Sending",i
        while sending[0]:
            server.process(0.5)

        #pprint.pprint( clientcon.__dict__ )
        old = clientcon
        clientcon = None
        gc.collect()
        #print len(certcache.cache)
        print len(gc.get_objects())
        print len(server.readers), len(server.writers)
        print gc.get_referrers(old)


def testLeaks6():
    import socket
    p = pk_generate(512)
    p2 = pk_generate(512)
    fn = mix_mktemp()
    dh = mix_mktemp()
    _ml.generate_cert(fn, p, p2, "A", "B", 100, 10000)
    dh_fname = os.environ.get("MM_TEST_DHPARAMS", None)
    if dh_fname and os.path.exists(dh_fname):
        dh = dh_fname
    elif dh_fname:
        _ml.generate_dh_parameters(dh_fname, 1, 512)
        dh = dh_fname
    else:
        _ml.generate_dh_parameters(dh, 1, 512)
    print "OK"
    context = _ml.TLSContext_new(fn, p)#XXXX, dh)

    listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listenSock.bind(("127.0.0.1", 48999))
    listenSock.listen(5)
    while 1:
        con, address = listenSock.accept()
        tls = context.sock(con, serverMode=1)
        tls.accept()
        while 1:
            r = tls.read(50)
            if r == 0:
                break
        while 1:
            r = tls.shutdown()
            if r == 1:
                break
        con.close()

def testLeaks6_2():
    import socket
    context = _ml.TLSContext_new()
    m = "X"*99*1024
    while 1:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 48999))
        tls = context.sock(sock)
        tls.connect()
        tls.write(m)
        while 1:
            r = tls.shutdown()
            if r: break
        tls.shutdown()
        sock.close()

def testLeaks_FEC():
    inp = [ "aaaaa"*1024, "bbbbb"*1024, "ccccc"*1024 ]
    while 1:
        fec = _ml.FEC_generate(3,5)
        chunks = [ fec.encode(i, inp) for i in xrange(5) ]
        dec = fec.decode([(i, chunks[i]) for i in xrange(2,5) ])

#----------------------------------------------------------------------
def timeAll(name, args):
    if 0:
        testLeaks_FEC()
        return

    fecTiming()    
    cryptoTiming()
    rsaTiming()
    buildMessageTiming()
    directoryTiming()
    fileOpsTiming()
    encodingTiming()
    serverQueueTiming()
    serverProcessTiming()
    hashlogTiming()
    timeEfficiency()
    #import profile
    #profile.run("import mixminion.benchmark; mixminion.benchmark.directoryTiming()")
