# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: benchmark.py,v 1.4 2002/05/31 12:47:58 nickm Exp $
from time import time

__all__ = [ 'timeAll', 'testLeaks1', 'testLeaks2' ]

PRECISION_FACTOR = 1

primitives = {}#XXXXDOC
loop_overhead = {}
def timeit_(fn, iters, ov=1, p=None):
    """XXXX"""
    iters *= PRECISION_FACTOR
    nones = [None]*iters
    overhead = [0, loop_overhead.get(iters, 0)][ov]
    t = time()
    for n in nones: fn()
    t2 = time()-t
    t_each = (t2-overhead) / float(iters)
    if p: primitives[p]=t_each
    return t_each

min_o = 1.0
max_o = 0.0
for iters in [10**n for n in range(2,7)]:
    overhead = timeit_((lambda:(lambda:None)()), iters)
    loop_overhead[iters] = overhead
    min_o = min(min_o, overhead/float(iters))
    max_o = max(max_o, overhead/float(iters))

def timestr(t):
    """XXXX"""
    if abs(t) >= 1.0:
        return "%.3f sec" % t
    elif abs(t) >= .001:
        return "%.3f msec" % (t*1000)
    elif abs(t) >= (.000001):
        return "%.3f usec" % (t*1000000)
    else:
        return "%f psec" % (t*1000000000L)

def timeit(fn,times, p=None):
    """XXXX"""
    return timestr(timeit_(fn,times,p=p))

def spacestr(n):
    if abs(n) < 1e4:
        return "%d bytes" %n
    elif abs(n) < 1e7:
        return "%d KB" % (n//1024)
    elif abs(n) < 1e10:
        return "%d MB" % (n//(1024*1024))
    else:
        return "%d GB" % (n//(1024*1024*1024))

#----------------------------------------------------------------------
import mixminion._minionlib as _ml
from Crypto import *
from Crypto import OAEP_PARAMETER

def cryptoTiming():
    short = "Hello, Dali!"
    s1K = "8charstr"*128
    s2K = s1K*2
    s4K = s2K*2
    s8K = s4K*2
    s28K = s1K*28
    s32K = s8K*4

    print "#==================== CRYPTO ======================="
    print "Timing overhead: %s...%s" % (timestr(min_o),timestr(max_o))

    print "SHA1 (short)", timeit((lambda : sha1(short)), 100000)
    print "SHA1 (2K)", timeit((lambda : sha1(s8K)), 10000, p="SHA2")
    print "SHA1 (8K)", timeit((lambda : sha1(s8K)), 10000)
    print "SHA1 (28K)", timeit((lambda : sha1(s28K)), 1000, p="SHA28")
    print "SHA1 (32K)", timeit((lambda : sha1(s32K)), 1000)

    shakey = "8charstr"*2
    #print "Keyed SHA1 (short)",
    #print timeit((lambda : _ml.sha1(short,shakey)), 100000)
    #print "Keyed SHA1 (8K)", timeit((lambda : _ml.sha1(s8K, shakey)), 10000)
    #print "Keyed SHA1 (32K)", timeit((lambda : _ml.sha1(s32K, shakey)), 1000)
    print "Keyed SHA1 for lioness (28K, unoptimized)", timeit(
        (lambda : _ml.sha1("".join([shakey,s28K,shakey]))), 1000)

    print "TRNG (20 byte)", timeit((lambda: trng(20)), 100)
    print "TRNG (128 byte)", timeit((lambda: trng(128)), 100)
    print "TRNG (1K)", timeit((lambda: trng(1024)), 100)

    print "xor (1K)", timeit((lambda: _ml.strxor(s1K,s1K)), 100000)
    print "xor (32K)", timeit((lambda: _ml.strxor(s32K,s32K)), 1000)

    key = "8charstr"*2
    print "aes (short)", timeit((lambda: ctr_crypt(short,key)), 100000)
    print "aes (1K)", timeit((lambda: ctr_crypt(s1K,key)), 10000)
    print "aes (2K)", timeit((lambda: ctr_crypt(s1K,key)), 10000, p="AES2")
    print "aes (28K)", timeit((lambda: ctr_crypt(s28K,key)), 100, p="AES28")
    print "aes (32K)", timeit((lambda: ctr_crypt(s32K,key)), 100)

    key = _ml.aes_key(key)
    print "aes (short,pre-key)", timeit((lambda: ctr_crypt(short,key)), 100000)
    print "aes (1K,pre-key)", timeit((lambda: ctr_crypt(s1K,key)), 10000)
    print "aes (28K,pre-key)", timeit((lambda: ctr_crypt(s28K,key)), 100)
    print "aes (32K,pre-key)", timeit((lambda: ctr_crypt(s32K,key)), 100)

    print "aes (32K,pre-key,unoptimized)", timeit(
        (lambda: _ml.strxor(prng(key,32768),s32K)), 100)

    print "prng (short)", timeit((lambda: prng(key,8)), 100000)
    print "prng (128b)", timeit((lambda: prng(key,18)), 10000, p="PRNG128b")
    print "prng (1K)", timeit((lambda: prng(key,1024)), 10000)
    print "prng (2K)", timeit((lambda: prng(key,1024)), 10000, p="PRNG2")
    print "prng (28K)", timeit((lambda: prng(key,28678)), 100, p="PRNG28")
    print "prng (32K)", timeit((lambda: prng(key,32768)), 100)
    print "prng (32K, unoptimized)", timeit(
        (lambda: ctr_crypt('\x00'*32768, key)), 100)

    lkey = Keyset("keymaterial foo bar baz").getLionessKeys("T")
    print "lioness E (1K)", timeit((lambda: lioness_encrypt(s1K, lkey)), 1000)
    print "lioness E (2K)", timeit((lambda: lioness_encrypt(s1K, lkey)), 1000,
                                   p="LIONESS2")
    print "lioness E (4K)", timeit((lambda: lioness_encrypt(s4K, lkey)), 1000)
    print "lioness E (28K)", timeit((lambda: lioness_encrypt(s28K, lkey)), 100,
                                    p="LIONESS28")
    print "lioness E (32K)", timeit((lambda: lioness_encrypt(s32K, lkey)), 100)
    print "lioness D (1K)", timeit((lambda: lioness_decrypt(s1K, lkey)), 1000)
    print "lioness D (2K)", timeit((lambda: lioness_decrypt(s1K, lkey)), 1000)
    print "lioness D (4K)", timeit((lambda: lioness_decrypt(s4K, lkey)), 1000)
    print "lioness D (28K)", timeit((lambda: lioness_decrypt(s28K, lkey)), 100)
    print "lioness D (32K)", timeit((lambda: lioness_decrypt(s32K, lkey)), 100)

    s70b = "10character"*7
    print "OAEP_add (70->128B)",
    print timeit((lambda: _ml.add_oaep_padding(s70b,OAEP_PARAMETER,128)),10000)
    r = _ml.add_oaep_padding(s70b, OAEP_PARAMETER,128)
    print "OAEP_check (128B->70B)",
    print timeit((lambda: _ml.check_oaep_padding(r,OAEP_PARAMETER,128)),10000)

    print "RSA generate (1024 bit)", timeit((lambda: pk_generate()),10)
    rsa = pk_generate()
    print "Pad+RSA public encrypt",
    print timeit((lambda: pk_encrypt(s70b, rsa)),1000,p="RSAENC")
    
    enc = pk_encrypt(s70b, rsa)
    print "Pad+RSA private decrypt", timeit((lambda: pk_decrypt(enc, rsa)),100)

    for (bits,it) in ((2048,10),(4096,10)):
        t = time()
        rsa2 = pk_generate(bits)
        t = time()-t
        print "RSA genrate (%d bit)"%bits, timestr(t)
        enc = pk_encrypt(s70b, rsa2)
        print "Pad+RSA private decrypt (%d bit)"%bits,
        print timeit((lambda: pk_decrypt(enc, rsa2)),it)

#----------------------------------------------------------------------
def hashlogTiming():
    import tempfile, os
    print "#==================== HASH LOGS ======================="
    for load in (100, 1000, 10000, 100000):
        fname = tempfile.mktemp(".db")
        try:
            _hashlogTiming(fname,load)
        finally:
            try:
                os.unlink(fname)
            except:
                pass

def _hashlogTiming(fname, load):
    import os
    from mixminion.Crypto import AESCounterPRNG
    from mixminion.HashLog import HashLog
    prng = AESCounterPRNG("a"*16)
        
    h = HashLog(fname, "A")
    hashes = [ prng.getBytes(20) for i in xrange(load) ]

    t = time()
    for hash in hashes:
        h.logHash(hash)
    t = time()-t
    print "Add entry (up to %s entries)" %load, timestr( t/float(load) )

    t = time()
    for hash in hashes[0:1000]:
        h.seenHash(hash)
    t = time()-t    
    print "Check entry [hit] (%s entries)" %load, timestr( t/1000.0 )

    hashes =[ prng.getBytes(20) for i in xrange(1000) ]
    t = time()
    for hash in hashes:
        h.seenHash(hash)
    t = time()-t   
    print "Check entry [miss] (%s entries)" %load, timestr( t/1000.0 )

    h.close()
    print "File size (%s entries)"%load, spacestr(os.stat(fname).st_size)

#----------------------------------------------------------------------

def buildMessageTiming():
    import mixminion.BuildMessage as BMsg
    from mixminion.ServerInfo import ServerInfo
    print "#================= BUILD MESSAGE ====================="
    pk = pk_generate()
    payload = ("Junky qoph flags vext crwd zimb."*1024)[:22*1024]
    serverinfo = [ ServerInfo("127.0.0.1", 48099, pk_get_modulus(pk),
                              "x"*20) ] * 16
    def bh(np,it):
        ctr = AESCounterPRNG()
        
        tm = timeit_( \
              lambda: BMsg._buildHeader(serverinfo[:np], ["Z"*16]*np,
                                        99, "Hello", ctr), it )
        
        print "Build header (%s)" %(np), timestr(tm)

    bh(1,100)
    bh(4,40)
    bh(8,20)
    bh(16,10)
    
    def bm(np1,np2,it):
        tm = timeit_( \
              lambda: BMsg.buildForwardMessage(payload,
                                               1,
                                               "Hello",
                                               serverinfo[:np1],
                                               serverinfo[:np2]), it)
        print "Build forward message (%sx%s)" %(np1,np2), timestr(tm)


    bm(1,1,100)
    bm(8,1,40)
    bm(8,8,20)
    bm(16,16,10)
#----------------------------------------------------------------------

def serverProcessTiming():
    print "#================= SERVER PROCESS ====================="
    from mixminion.ServerProcess import ServerProcess
    from mixminion.ServerInfo import ServerInfo
    from mixminion.BuildMessage import buildForwardMessage
    from mixminion.Modules import SMTP_TYPE
    class DummyLog:
        def seenHash(self,h): return 0
        def logHash(self,h): pass

    pk = pk_generate()
    n = pk_get_modulus(pk)
    server = ServerInfo("127.0.0.1", 1, n, "X"*20)
    sp = ServerProcess(pk, DummyLog(), None, None)

    m_noswap = buildForwardMessage("Hello world", SMTP_TYPE, "f@invalid",
                                   [server, server], [server, server])

    print "Server process (no swap, no log)", timeit(
        lambda : sp._processMessage(m_noswap), 100)

    m_swap = buildForwardMessage("Hello world", SMTP_TYPE, "f@invalid",
                                 [server], [server, server])

    print "Server process (swap, no log)", timeit(
        lambda : sp._processMessage(m_swap), 100)
    
#----------------------------------------------------------------------
def testLeaks1():
    print "Trying to leak (sha1,aes,xor,seed,oaep)"
    s20k="a"*20*1024
    keytxt="a"*16
    key = _ml.aes_key(keytxt)
    while 1:
        if 1:
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
    n,e = _ml.rsa_get_public_key(p)

    while 1:
        if 1:
            p = pk_generate(512)
            pk_decrypt(pk_encrypt(s20,p),p)
            for public in (0,1):
                x = _ml.rsa_encode_key(p,public)
                _ml.rsa_decode_key(x,public)
            _ml.rsa_get_public_key(p)
            _ml.rsa_make_public_key(n,e)

#----------------------------------------------------------------------

def timeAll():
    cryptoTiming()
    buildMessageTiming()
    hashlogTiming()
    serverProcessTiming()

if __name__ == '__main__':
    timeAll()
    #testLeaks1()
    #testLeaks2()
