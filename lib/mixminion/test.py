# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: test.py,v 1.5 2002/05/31 12:47:58 nickm Exp $

import unittest

def hexread(s):
    r = []
    hexvals = "0123456789ABCDEF"
    for i in range(len(s) // 2):
        v1 = hexvals.index(s[i*2])
        v2 = hexvals.index(s[i*2+1])
        c = (v1 << 4) + v2
        assert 0 <= c < 256
        r.append(chr(c))
    return "".join(r)

#----------------------------------------------------------------------
import mixminion._minionlib as _ml

class MinionlibCryptoTests(unittest.TestCase):
    """Tests for cryptographic C extensions."""
    def test_sha1(self):
        s1 = _ml.sha1

        # A test vector from the SHA1 spec
        self.assertEquals(s1("abc"),
              hexread("A9993E364706816ABA3E25717850C26C9CD0D89D"))

        # Another test vector from the SHA1 spec
        s = s1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        self.assertEquals(s,
               hexread("84983E441C3BD26EBAAE4AA1F95129E5E54670F1"))

        # Make sure that we fail gracefully on non-string input.
        self.failUnlessRaises(TypeError, s1, 1)

    def test_xor(self):
        xor = _ml.strxor

        # Try a few known-value XORs.
        self.assertEquals(xor("abc", "\000\000\000"), "abc")
        self.assertEquals(xor("abc", "abc"), "\000\000\000")
        self.assertEquals(xor("\xEF\xF0\x12", "\x11\x22\x35"), '\xFE\xD2\x27')

        # Make sure that the C doesn't (cringe) modify the strings out from
        # under us.
        a = "aaaa"
        self.assertEquals(xor(a,"\000\000\000a"), "aaa\000")
        self.assertEquals(a, "aaaa")
        self.assertEquals(xor("\000\000\000a",a), "aaa\000")
        self.assertEquals(a, "aaaa")

        # Check for error msg on XORing strings of unequal length.    
        self.failUnlessRaises(TypeError, xor, "a", "bb")
        
    def test_aes(self):
        crypt = _ml.aes_ctr128_crypt

        # First, try one of the test vectors from the AES spec.
        key = txt = "\x80" + "\x00" * 15
        key = _ml.aes_key(key)
        expected = hexread("8EDD33D3C621E546455BD8BA1418BEC8")
        self.failUnless(crypt(key, txt, 0) == expected)
        self.failUnless(crypt(key, txt) == expected)
        
        # Now, make sure that the counter implementation is sane.
        self.failUnless(crypt(key, " "*100, 0)[1:] == crypt(key, " "*99, 1))
        self.failUnless(crypt(key, " "*100, 0)[30:] == crypt(key, " "*70, 30))

        # Counter mode is its own inverse
        self.failUnless(crypt(key,crypt(key, " "*100, 0),0) == " "*100)

        # Try a different key to be sure.
        teststr = """I have seen the best ciphers of my generation
                     Destroyed by cryptanalysis, broken, insecure,
                     Implemented still in cryptographic libraries"""
        key2 = _ml.aes_key("xyzz"*4)
        self.assertEquals(teststr,crypt(key2,crypt(key2,teststr)))

        # Try generating the same test vector again, but this time in PRNG
        # mode
        expected2 = hexread("0EDD33D3C621E546455BD8BA1418BEC8")
        self.assertEquals(expected2, crypt(key, "", 0, len(expected2)))
        # PRNG mode ignores input.
        self.assertEquals(expected2, crypt(key, "Z", 0, len(expected2)))
        # Try an offset with prng mode.
        self.assertEquals(expected2[5:], crypt(key, "", 5, len(expected2)-5))
        # Make sure that PRNG mode with negative count yields ""
        self.assertEquals("", crypt(key,"",0,-1))

        # Can't use a non-key object.
        self.failUnlessRaises(TypeError, crypt, "a", teststr)
        # Can't make a key from a short string...
        self.failUnlessRaises(TypeError, _ml.aes_key, "a")
        # ...or a long string.
        self.failUnlessRaises(TypeError, _ml.aes_key, "a"*17)

    def test_openssl_seed(self):
        # Just try seeding openssl a couple of times, and make sure it
        # doesn't crash.
        _ml.openssl_seed("Hello")
        _ml.openssl_seed("")

    def test_oaep(self):
        strxor = _ml.strxor
        # Check_oaep inverts add_oaep successfully.
        x = _ml.add_oaep_padding("A", "B", 128)

        self.assertEquals("A",_ml.check_oaep_padding(x, "B", 128))

        # 86 bytes can be used with size=128
        _ml.add_oaep_padding("A"*86, "B",128)
        # But 300 is too much,
        self.failUnlessRaises(TypeError,
                              _ml.add_oaep_padding,"A"*300, "B", 128)
        # And so is even 87.
        self.failUnlessRaises(_ml.SSLError,
                              _ml.add_oaep_padding,"A"*87, "B", 128)
        # Changing a character at the beginning keeps it from checking.
        ch = strxor(x[0], '\x01')
        self.failUnlessRaises(_ml.SSLError,
                              _ml.check_oaep_padding,ch+x[1:],"B",128)
        # Changing a character at the end keeps it from checking.
        ch = strxor(x[-1], '\x01')
        self.failUnlessRaises(_ml.SSLError,
                              _ml.check_oaep_padding,x[:-1]+ch,"B",128)

    def test_rsa(self):
        p = _ml.rsa_generate(1024, 65535)
        def sslerr(*args): self.failUnlessRaises(_ml.SSLError, *args)

        #For all of SIGN, CHECK_SIG, ENCRYPT, DECRYPT...
        for pub1 in (0,1):
            for enc1 in (0,1):
                msg = "Now is the time for all anonymous parties"
                x = _ml.add_oaep_padding(msg, "B", 128)
                x2 = _ml.rsa_crypt(p, x, pub1, enc1);
                # ...Encryption inverts decryption...
                x3 = _ml.rsa_crypt(p, x2, [1,0][pub1], [1,0][enc1]);
                self.failUnless(x3 == x)
                # ...And oaep is preserved.
                x4 = _ml.check_oaep_padding(x3, "B", 128)
                self.failUnless(x4 == msg)

        # Fail if there is not enough padding
        self.failUnlessRaises(_ml.SSLError,_ml.rsa_crypt,p,"X",1,1)
        # Fail if there is too much padding
        self.failUnlessRaises(_ml.SSLError,_ml.rsa_crypt,p,x+"ZZZ",1,1)

        ####
        # Test key encoding
        padhello = _ml.add_oaep_padding("Hello", "B", 128)
        for public in (0,1):
            #encode(decode(encode(x))) == x.
            x = _ml.rsa_encode_key(p,public)
            p2 = _ml.rsa_decode_key(x,public)
            x3 = _ml.rsa_encode_key(p2,public)
            self.assertEquals(x,x3)
            # decode(encode(x)) encrypts the same as x.
            self.assertEquals(_ml.rsa_crypt(p,padhello,public,1),
                              _ml.rsa_crypt(p2,padhello,public,1))

        # encoding public keys to/from their moduli.
        self.assertEquals(_ml.rsa_get_modulus_bytes(p),1024/8)
        n,e = _ml.rsa_get_public_key(p)
        p2 = _ml.rsa_make_public_key(n,e)
        self.assertEquals((n,e), _ml.rsa_get_public_key(p2))
        self.assertEquals(65535,e)
        self.assertEquals(_ml.rsa_encode_key(p,1), _ml.rsa_encode_key(p,1))
        
        # Try private-key ops with public key p3.
        p3 = _ml.rsa_decode_key(_ml.rsa_encode_key(p,1),1)
        msg1 = _ml.rsa_crypt(p, padhello, 1,1)
        msg2 = _ml.rsa_crypt(p, padhello, 1,1)
        msg3 = _ml.rsa_crypt(p, padhello, 1,1)
        self.assertEquals(padhello, _ml.rsa_crypt(p,msg1,0,0))
        self.assertEquals(padhello, _ml.rsa_crypt(p,msg2,0,0))
        self.assertEquals(padhello, _ml.rsa_crypt(p,msg3,0,0))
        self.failUnlessRaises(TypeError, _ml.rsa_crypt, p2, msg1, 0, 0)
        self.failUnlessRaises(TypeError, _ml.rsa_crypt, p3, msg1, 0, 0)
        self.failUnlessRaises(TypeError, _ml.rsa_encode_key, p2, 0)
        self.failUnlessRaises(TypeError, _ml.rsa_encode_key, p3, 0)
#----------------------------------------------------------------------
import mixminion.Crypto
from mixminion.Crypto import *

class CryptoTests(unittest.TestCase):
    """Tests for Python cryptographic library"""
    def test_initcrypto(self):
        init_crypto()

    def test_wrappers(self):
        # Test simple wrappers over _minionlib functionality.  Mainly, just
        # test that _ml.foo and foo do the same thing.
        self.assertEquals(_ml.sha1("xyzzy"), sha1("xyzzy"))
        k = _ml.aes_key("xyzy"*4)
        self.assertEquals(_ml.aes_ctr128_crypt(k,"hello",0),
                          ctr_crypt("hello",k))
        self.assertEquals(_ml.aes_ctr128_crypt(k,"hello",99),
                          ctr_crypt("hello",k,99))
        self.assertEquals(_ml.aes_ctr128_crypt(k,"",0,99), prng(k,99))
        self.assertEquals(_ml.aes_ctr128_crypt(k,"",3,99), prng(k,99,3))
        self.assertEquals(prng(k,100,0),prng(k,50,0)+prng(k,50,50))

    def test_rsa(self):

        eq = self.assertEquals
        k512 = pk_generate(512)
        k1024 = pk_generate()

        eq(512/8, _ml.rsa_get_modulus_bytes(k512))
        eq(1024/8, _ml.rsa_get_modulus_bytes(k1024))

        # Check pk_get_modulus sanity
        self.failUnless((1L<<511) < pk_get_modulus(k512) < (1L<<513))
        self.failUnless((1L<<1023) < pk_get_modulus(k1024) < (1L<<1024))

        # Make sure that public keys can be made from moduli, and used to
        # encrypt and decrypt.
        msg="Good hello"
        pub512 = pk_from_modulus(pk_get_modulus(k512))
        pub1024 = pk_from_modulus(pk_get_modulus(k1024))

        eq(msg, pk_decrypt(pk_encrypt(msg, k512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, k1024),k1024))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub1024),k1024))

        # Make sure that CH_OAEP(RSA( )) inverts pk_encrypt.
        eq(msg, _ml.check_oaep_padding(
                    _ml.rsa_crypt(k512, pk_encrypt(msg,k512), 0, 0),
                    mixminion.Crypto.OAEP_PARAMETER, 64))

        # Make sure we can still encrypt after we've encoded/decoded a
        # key.
        encoded = pk_encode_private_key(k512)
        decoded = pk_decode_private_key(encoded)
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),decoded))
        
    def test_trng(self):
        # Make sure that the true rng is at least superficially ok.
        self.assertNotEquals(trng(40), trng(40))

    def test_lioness(self):
        enc = lioness_encrypt
        dec = lioness_decrypt

        # Check basic cipher properties.
        key = ("ABCDE"*4,) *4
        plain = "The more it snows the more it goes on snowing"*10
        self.assertNotEquals(plain, enc(plain,key))
        self.assertNotEquals(plain, dec(plain,key))
        self.assertEquals(len(plain), len(enc(plain,key)))
        self.assertEquals(len(plain), len(dec(plain,key)))
        self.assertEquals(plain, dec(enc(plain,key),key))
        self.assertEquals(plain, enc(dec(plain,key),key))

        # Walk through a LIONESS encryption to check for correct values.
        # Check getLionessKeys too.
        s = "ABCDE"*4
        key1 = sha1(s+"foo")
        key2 = key1[:-1]+strxor(key1[-1], chr(1))
        key3 = key1[:-1]+strxor(key1[-1], chr(2))
        key4 = key1[:-1]+strxor(key1[-1], chr(3))
        
        left = plain[:20]
        right = plain[20:]
        right = ctr_crypt( right, sha1(key1+left+key1)[:16] )
        left  = strxor(left, sha1(key2+right+key2)) 
        right = ctr_crypt( right, sha1(key3+left+key3)[:16] )
        left  = strxor(left, sha1(key4+right+key4)) 

        key = (key1,key2,key3,key4)
        self.assertEquals(left+right, lioness_encrypt(plain,key))
        self.assertEquals(key, Keyset("ABCDE"*4).getLionessKeys("foo"))

    def test_keyset(self):
        s = sha1
        x = _ml.strxor
        k = Keyset("a")
        eq = self.assertEquals
        eq(s("aFoo")[:10], k.get("Foo",10))
        eq(s("aBar")[:16], k.get("Bar"))

        z19 = "\x00"*19
        eq( (s("aBaz"),               x(s("aBaz"), z19+"\x01"),
             x(s("aBaz"),z19+"\x02"), x(s("aBaz"), z19+"\x03") ),
            k.getLionessKeys("Baz"))

    def test_aesprng(self):
        # Make sure that AESCounterPRNG is really repeatable.
        key ="aaaa"*4
        PRNG = AESCounterPRNG(key)
        self.assert_(prng(key,100000) == (
                          PRNG.getBytes(5)+PRNG.getBytes(16*1024-5)+
                          PRNG.getBytes(50)+PRNG.getBytes(32*1024)+
                          PRNG.getBytes(9)+PRNG.getBytes(10)+
                          PRNG.getBytes(15)+PRNG.getBytes(16000)+
                          PRNG.getBytes(34764)))

#----------------------------------------------------------------------
import mixminion.Formats
from mixminion.Formats import *

class FormatTests(unittest.TestCase):
    def test_subheader(self):
        s = Subheader(3,0,"abcdeabcdeabcdef",
                      "ABCDEFGHIJABCDEFGHIJ",
                      1, "Hello")
        
        expected = "\003\000abcdeabcdeabcdef"+\
                   "ABCDEFGHIJABCDEFGHIJ\000\005\000\001Hello"
        self.assertEquals(s.pack(), expected)
        self.failUnless(not s.isExtended())
        self.assertEquals(s.getNExtraBlocks(), 0)
        self.assertEquals(s.getExtraBlocks(), [])

        s = parseSubheader(s.pack())
        self.assertEquals(s.major, 3)
        self.assertEquals(s.minor, 0)
        self.assertEquals(s.secret, "abcde"*3+"f")
        self.assertEquals(s.digest, "ABCDEFGHIJ"*2)
        self.assertEquals(s.routingtype, 1)
        self.assertEquals(s.routinglen, 5)
        self.assertEquals(s.routinginfo, "Hello")
        self.failUnless(not s.isExtended())
        self.assertEquals(s.pack(), expected)

        ts_eliot = "Who is the third who walks always beside you? / "+\
                   "When I count, there are only you and I together / "+\
                   "But when I look ahead up the white road / "+\
                   "There is always another one walking beside you"

        s = Subheader(3,9,"abcdeabcdeabcdef",
                      "ABCDEFGHIJABCDEFGHIJ",
                      62, ts_eliot, len(ts_eliot))

        self.assertEquals(len(ts_eliot), 186)

        expected = "\003\011abcdeabcdeabcdefABCDEFGHIJABCDEFGHIJ\000\272\000\076Who is the third who walks always beside you"
        self.assertEquals(len(expected), mixminion.Formats.MAX_SUBHEADER_LEN)
        self.assertEquals(s.pack(), expected)

        extra = s.getExtraBlocks()
        self.assertEquals(len(extra), 2)
        self.assertEquals(extra[0], "? / When I count, there are only you "+\
                          "and I together / But when I look ahead up the white "+\
                          "road / There is always another one walk")
        self.assertEquals(extra[1], "ing beside you"+(114*'\000'))

        s = parseSubheader(expected)
        self.assertEquals(s.major, 3)
        self.assertEquals(s.minor, 9)
        self.assertEquals(s.secret, "abcde"*3+"f")
        self.assertEquals(s.digest, "ABCDEFGHIJ"*2)
        self.assertEquals(s.routingtype, 62)
        self.assertEquals(s.routinglen, 186)
        self.failUnless(s.isExtended())
        self.assertEquals(s.getNExtraBlocks(), 2)

        s.appendExtraBlocks("".join(extra))
        self.assertEquals(s.routinginfo, ts_eliot)
        self.assertEquals(s.pack(), expected)
        self.assertEquals(s.getExtraBlocks(), extra)

        self.failUnlessRaises(ParseError,
                              parseSubheader, "a"*(41))

    def test_headers(self):
        header = ("abcdefghi"*(256))[:2048]
        h = parseHeader(header)
        self.failUnless(h[0] == header[:128])
        self.failUnless(h[4] == header[128*4:128*5])
        self.failUnless(h[:1] == h[0])
        self.failUnless(h[1:] == header[128:])
        self.failUnless(h[1:4] == header[128:128*4])
        self.failUnless(h[15] == header[-128:])

    def test_message(self):
        # 9 is relatively prime to all pwrs of 2.
        m = ("abcdefghi"*(10000))[:32768]
        msg = parseMessage(m)
        self.assert_(msg.pack() == m)
        self.assert_(msg.header1 == m[:2048])
        self.assert_(msg.header2 == m[2048:4096])
        self.assert_(msg.payload == m[4096:])
        self.failUnlessRaises(ParseError, parseMessage, m[:-1])
        self.failUnlessRaises(ParseError, parseMessage, m+"x")
            
    def test_ipv4info(self):
        ri = hexread("12F400BCBBE30011223344556677889900112233445566778899")
        inf = parseIPV4Info(ri)
        self.assertEquals(inf.ip, "18.244.0.188")
        self.assertEquals(inf.port, 48099)
        self.assertEquals(inf.keyinfo, ri[-20:])
        self.assertEquals(len(inf.pack()), 26)
        self.assertEquals(inf.pack(), ri)
        self.assertEquals(IPV4Info("18.244.0.188", 48099, ri[-20:]).pack(),
                          ri)

        self.failUnlessRaises(ParseError, parseIPV4Info, ri[:-1])
        self.failUnlessRaises(ParseError, parseIPV4Info, ri+"x")

    def test_smtpinfolocalinfo(self):
        for _class, _parse, _key in ((SMTPInfo, parseSMTPInfo, 'email'),
                                     (LocalInfo, parseLocalInfo, 'user')):
            ri = "no-such-user@wangafu.net\x00xyzzy"
            inf = _parse(ri)
            self.assertEquals(getattr(inf,_key), "no-such-user@wangafu.net")
            self.assertEquals(inf.tag, "xyzzy")
            self.assertEquals(inf.pack(), ri)
            inf = _class("no-such-user@wangafu.net","xyzzy")
            self.assertEquals(inf.pack(), ri)
            # No tag
            ri = "no-such-user@wangafu.net"
            inf = _parse(ri)
            self.assertEquals(inf.tag, None)
            self.assertEquals(getattr(inf,_key), 'no-such-user@wangafu.net')
            self.assertEquals(inf.pack(), ri)
            # NUL in tag
            ri = "no-such-user@wangafu.net\x00xyzzy\x00plover"
            inf = _parse(ri)
            self.assertEquals(getattr(inf,_key), "no-such-user@wangafu.net")
            self.assertEquals(inf.tag, "xyzzy\x00plover")
            self.assertEquals(inf.pack(), ri)
        
        
#----------------------------------------------------------------------
from mixminion.HashLog import HashLog

class HashLogTests(unittest.TestCase):
    def test_hashlog(self):
        import tempfile, os
        fname = tempfile.mktemp(".db")
        try:
            self.hashlogTestImpl(fname)
        finally:
            try:
                os.unlink(fname)
            except:
                pass
        
    def hashlogTestImpl(self,fname):
        h = HashLog(fname, "Xyzzy")
        
        notseen = lambda hash: self.assert_(not h.seenHash(hash))
        seen = lambda hash: self.assert_(h.seenHash(hash))
        log = lambda hash: h.logHash(hash)
        
        notseen("a")
        notseen("a*20")
        notseen("\000"*10)
        notseen("\000")
        notseen("\277"*10)
        log("a")
        notseen("a*10")
        notseen("\000"*10)
        notseen("b")
        seen("a")

        log("b")
        seen("b")
        seen("a")
        
        log("\000")
        seen("\000")
        notseen("\000"*10)

        log("\000"*10)
        seen("\000"*10)

        log("\277"*20)
        seen("\277"*20)
        
        log("abcdef"*4)
        seen("abcdef"*4)
        
        h.close()
        h = HashLog(fname, "Xyzzy")
        seen("a")
        seen("b")
        seen("\277"*20)
        seen("abcdef"*4)
        seen("\000")
        seen("\000"*10)
        notseen(" ")
        notseen("\000"*5)

        notseen("ddddd")
        log("ddddd")
        seen("ddddd")
        
        h.close()
        h = HashLog(fname, "Xyzzy")
        seen("ddddd")

        h.close()


#----------------------------------------------------------------------
import mixminion.BuildMessage
from mixminion.Modules import *

class FakePRNG:
    def getBytes(self,n):
        return "\x00"*n

class _BMTSupport:
    def __init__(self):
        # We do this trick to keep from re-generating the keypairs
        # for every message test.
        self.pk1 = pk_generate()
        self.pk2 = pk_generate()
        self.pk3 = pk_generate()

BMTSupport = _BMTSupport()

class BuildMessageTests(unittest.TestCase):
    def setUp(self):
        from mixminion.ServerInfo import ServerInfo
        self.pk1 = BMTSupport.pk1
        self.pk2 = BMTSupport.pk2
        self.pk3 = BMTSupport.pk3
        n_1 = pk_get_modulus(self.pk1)
        n_2 = pk_get_modulus(self.pk2)
        n_3 = pk_get_modulus(self.pk3)
        self.server1 = ServerInfo("127.0.0.1", 1, n_1, "X"*20)
        self.server2 = ServerInfo("127.0.0.2", 3, n_2, "Z"*20)
        self.server3 = ServerInfo("127.0.0.3", 5, n_3, "Q"*20)        

    def test_buildheader_1hop(self):
        bhead = mixminion.BuildMessage._buildHeader

        head = bhead([self.server1], ["9"*16], 99, "Hi mom", AESCounterPRNG())
        self.do_header_test(head,
                            (self.pk1,),
                            ["9"*16,],
                            (99,),
                            ("Hi mom",))

    def test_buildheader_2hops(self):
        bhead = mixminion.BuildMessage._buildHeader
        # 2 hops
        head = bhead([self.server1, self.server2],
                     ["9"*16, "1"*16], 99, "Hi mom", AESCounterPRNG()) 

        ipv4 = mixminion.Formats.IPV4Info
        self.do_header_test(head,
                            (self.pk1, self.pk2),
                            ["9"*16, "1"*16],
                            (FWD_TYPE, 99),
                            (ipv4("127.0.0.2",3,"Z"*20).pack(),
                             "Hi mom"))
                            
    def test_buildheader_3hops(self):
        bhead = mixminion.BuildMessage._buildHeader
        # 3 hops
        secrets = ["9"*16, "1"*16, "z"*16]
        head = bhead([self.server1, self.server2, self.server3], secrets,
                      99, "Hi mom", AESCounterPRNG())
        pks = (self.pk1,self.pk2,self.pk3)
        rtypes = (FWD_TYPE, FWD_TYPE, 99)
        rinfo = (mixminion.Formats.IPV4Info("127.0.0.2", 3, "Z"*20).pack(),
                 mixminion.Formats.IPV4Info("127.0.0.3", 5, "Q"*20).pack(),
                 "Hi mom")
        self.do_header_test(head, pks, secrets, rtypes, rinfo)

    def do_header_test(self, head, pks, secrets, rtypes, rinfo):
        retsecrets = []
        retinfo = []
        if secrets == None:
            secrets = [ None ] * len(pks)
        self.assertEquals(len(head), mixminion.Formats.HEADER_LEN)
        for pk, secret, rt, ri in zip(pks, secrets,rtypes,rinfo):
            subh = mixminion.Formats.parseSubheader(pk_decrypt(head[:128], pk))
            if secret:
                self.assertEquals(subh.secret, secret)
            else:
                secret = subh.secret
                retsecrets.append(secret)
            self.assertEquals(subh.major, mixminion.Formats.MAJOR_NO)
            self.assertEquals(subh.minor, mixminion.Formats.MINOR_NO)
            
            self.assertEquals(subh.digest, sha1(head[128:]))
            self.assertEquals(subh.routingtype, rt)
            ks = Keyset(secret)
            key = ks.get(HEADER_SECRET_MODE)
            prngkey = ks.get(RANDOM_JUNK_MODE)
            if not subh.isExtended():
                if ri:
                    self.assertEquals(subh.routinginfo, ri)
                    self.assertEquals(subh.routinglen, len(ri))
                else:
                    retinfo.append(subh.routinginfo)
                size = 128
                n = 0
            else:
                self.assert_(len(ri) > mixminion.Formats.MAX_ROUTING_INFO_LEN)
                n = subh.getNExtraBlocks()
                size = (1+n)*128
                more = ctr_crypt(head[128:128+128*n], key)
                subh.appendExtraBlocks(more)
                if ri:
                    self.assertEquals(subh.routinginfo, ri)
                    self.assertEquals(subh.routinglen, len(ri))
                else:
                    retinfo.append(subh.routinginfo)

            head = ctr_crypt(head[size:]+prng(prngkey,size), key, 128*n)

        if retinfo:
            return retsecrets, retinfo
        else:
            return retsecrets

    def test_extended_routinginfo(self):
        bhead = mixminion.BuildMessage._buildHeader
        bhead_impl = mixminion.BuildMessage._buildHeader_impl
        secrets = ["9"*16 ]
        longStr = "Foo"*50
        head = bhead([self.server1 ], secrets, 99, longStr, AESCounterPRNG())
        pks = (self.pk1,)
        rtypes = (99,)
        rinfo = (longStr,)

        self.do_header_test(head, pks, secrets, rtypes, rinfo)

        secrets.append("1"*16)
        longStr2 = longStr*2

        head = bhead_impl([self.server1,self.server2], secrets,
                          [ (99,longStr2) , (99,longStr) ], AESCounterPRNG())

        pks = (self.pk1,self.pk2)
        rtypes = (99,99)
        rinfo = (longStr2,longStr)
        self.do_header_test(head, pks, secrets, rtypes, rinfo)

    def test_constructmessage(self):
        consMsg = mixminion.BuildMessage._constructMessage
        
        h1 = "abcdefgh"*(2048//8)
        h2 = "aBcDeFgH"*(2048//8)

        ######
        ### non-reply case
        secrets1 = [ x * 16 for x in "sqmsh"]
        secrets2 = [ x * 16 for x in "osfrg"]
        pld = """
           Everyone has the right to freedom of opinion and expression; this
           right includes freedom to hold opinions without interference and
           to seek, receive and impart information and ideas through any
           media and regardless of frontiers. 
           """
        pld += "\000"*(28*1024-len(pld))
        
        message = consMsg(secrets1, secrets2, h1, h2, pld)

        self.assertEquals(len(message), mixminion.Formats.MESSAGE_LEN)
        msg = mixminion.Formats.parseMessage(message)
        head1, head2, payload = msg.header1, msg.header2, msg.payload
        self.assert_(h1 == head1)

        for path in secrets1, secrets2:
            for s in path:
                ks = Keyset(s)
                hkey = ks.getLionessKeys(HEADER_ENCRYPT_MODE)
                pkey = ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE)
                if path is secrets1:
                    head2 = lioness_decrypt(head2, hkey)
                payload = lioness_decrypt(payload, pkey)

            if path is secrets1:
                swapkey = mixminion.Crypto.lioness_keys_from_payload(payload)
                head2 = lioness_decrypt(head2, swapkey)

        self.assert_(head2 == h2)
        self.assert_(payload == pld)

        ######
        ### Reply case
        message = consMsg(secrets1, None, h1, h2, pld)
        self.assertEquals(len(message), mixminion.Formats.MESSAGE_LEN)
        msg = mixminion.Formats.parseMessage(message)
        head1, head2, payload = msg.header1, msg.header2, msg.payload
        self.assert_(h1 == head1)

        for s in secrets1:
            ks = Keyset(s)
            hkey = ks.getLionessKeys(HEADER_ENCRYPT_MODE)
            pkey = ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE)
            head2 = lioness_decrypt(head2, hkey)
            payload = lioness_decrypt(payload, pkey)
        swapkey = mixminion.Crypto.lioness_keys_from_payload(payload)
        head2 = lioness_decrypt(head2, swapkey)

        self.assert_(head2 == h2)
        self.assert_(payload == pld)

    def do_message_test(self, msg,
                        header_info_1, #XXXX doc
                        header_info_2,
                        payload):
        # Check header 1, and get secrets
        sec = self.do_header_test(msg[:2048], *header_info_1)
        h2 = msg[2048:4096]
        p = msg[4096:]
        # Do decryption steps for header 1.
        for s in sec:
            ks = Keyset(s)
            p = lioness_decrypt(p,ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))
            h2 = lioness_decrypt(h2,ks.getLionessKeys(HEADER_ENCRYPT_MODE))
        h2 = lioness_decrypt(h2,mixminion.Crypto.lioness_keys_from_payload(p))

        sec = self.do_header_test(h2, *header_info_2)
        for s in sec:
            ks = Keyset(s)
            p = lioness_decrypt(p,ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))

        # XXXX Need to do something about size encoding.
        self.assertEquals(payload, p[:len(payload)])

        
    def test_build_fwd_message(self):
        bfm = mixminion.BuildMessage.buildForwardMessage
        payload = "Hello"
        
        m = bfm(payload, 99, "Goodbye",
                [self.server1, self.server2],
                [self.server3, self.server2])

        self.do_message_test(m,
                             ( (self.pk1, self.pk2), None,
                               (FWD_TYPE, SWAP_FWD_TYPE),
                               (self.server2.getRoutingInfo().pack(),
                                self.server3.getRoutingInfo().pack()) ),
                             ( (self.pk3, self.pk2), None,
                               (FWD_TYPE, 99),
                               (self.server2.getRoutingInfo().pack(),
                                "Goodbye") ),
                             "Hello" )

        m = bfm(payload, 99, "Goodbye",
                [self.server1, ],
                [self.server3, ])

        self.do_message_test(m,
                             ( (self.pk1,), None,
                               (SWAP_FWD_TYPE, ),
                               ( self.server3.getRoutingInfo().pack(), ) ),
                             ( (self.pk3, ), None,
                               (99,),
                               ("Goodbye",) ),
                             "Hello" )

    def test_buildreply(self):
        brb = mixminion.BuildMessage.buildReplyBlock
        bsrb = mixminion.BuildMessage.buildStatelessReplyBlock
        brm = mixminion.BuildMessage.buildReplyMessage

        ## Stateful reply blocks.
        (rb, node1), secrets = \
             brb([ self.server3, self.server1, self.server2,
                   self.server1, self.server3 ],
                 SMTP_TYPE,
                 SMTPInfo("no-such-user@invalid", None).pack())
        pks_1 = (self.pk3, self.pk1, self.pk2, self.pk1, self.pk3)
        infos = (self.server1.getRoutingInfo().pack(),
                 self.server2.getRoutingInfo().pack(),
                 self.server1.getRoutingInfo().pack(),
                 self.server3.getRoutingInfo().pack())

        self.assert_(node1 is self.server3)
                
        m = brm("Information?",
                [self.server3, self.server1],
                (rb,node1))

        self.do_message_test(m,
                             ((self.pk3, self.pk1), None,
                              (FWD_TYPE,SWAP_FWD_TYPE),
                              (self.server1.getRoutingInfo().pack(),
                               self.server3.getRoutingInfo().pack())),
                             (pks_1, secrets,
                              (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,SMTP_TYPE),
                              infos+(
                               SMTPInfo("no-such-user@invalid",None).pack(),
                               )),
                             "Information?")
                                   
        ## Stateless replies
        rb,node1 = bsrb([ self.server3, self.server1, self.server2,
                          self.server1, self.server3 ],
                        "fred", "Galaxy Far Away.", 1)

        sec,(loc,) = self.do_header_test(rb, pks_1, None,
                            (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,SMTP_TYPE),
                            infos+(None,))
        s = "fred\x00RTRN"
        self.assert_(loc.startswith(s))
        seed = ctr_crypt(loc[len(s):], "Galaxy Far Away.")
        prng = AESCounterPRNG(seed)
        self.assert_(sec == [ prng.getBytes(16) for i in range(5)])

        ## Stateless reply, no user key (trusted server)
        rb,node1 = bsrb([ self.server3, self.server1, self.server2,
                          self.server1, self.server3 ],
                        "fred" )
        sec,(loc,) = self.do_header_test(rb, pks_1, None,
                            (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,LOCAL_TYPE),
                                         infos+(None,))
        self.assert_(loc.startswith(s))
        seed = loc[len(s):]
        prng = AESCounterPRNG(seed)
        self.assert_(sec == [ prng.getBytes(16) for i in range(5)])
            
#----------------------------------------------------------------------
# Having tested BuildMessage without using ServerProcess, we can now use
# BuildMessage to see whether ServerProcess is doing the right thing.
#
# (of course, we still need to build failing messages by hand)

class ServerProcessTests(unittest.TestCase):
    def setUp(self):
        from mixminion.ServerProcess import ServerProcess
        from mixminion.ServerInfo import ServerInfo
        from tempfile import mktemp
        self.pk1 = BMTSupport.pk1
        self.pk2 = BMTSupport.pk2
        self.pk3 = BMTSupport.pk3
        self.tmpfile = mktemp(".db")
        h = self.hlog = HashLog(self.tmpfile, "Z"*20)
        n_1 = pk_get_modulus(self.pk1)
        n_2 = pk_get_modulus(self.pk2)
        n_3 = pk_get_modulus(self.pk3)
        self.server1 = ServerInfo("127.0.0.1", 1, n_1, "X"*20)
        self.server2 = ServerInfo("127.0.0.2", 3, n_2, "Z"*20)
        self.server3 = ServerInfo("127.0.0.3", 5, n_3, "Q"*20)
        self.sp1 = ServerProcess(self.pk1, h, None, None)
        self.sp2 = ServerProcess(self.pk2, h, None, None)
        self.sp3 = ServerProcess(self.pk3, h, None, None)

    def tearDown(self):
        import os
        try:
            os.unlink(self.tmpfile)
        except:
            pass

    def do_test_chain(self, m, sps, routingtypes, routinginfo, payload):
        for sp, rt, ri in zip(sps,routingtypes,routinginfo):
            res = sp._processMessage(m)
            self.assertEquals(len(res), 2)
            if rt in (FWD_TYPE, SWAP_FWD_TYPE):
                self.assertEquals(res[0], "QUEUE")
                self.assertEquals(res[1][0].pack(), ri)
                self.assertEquals(FWD_TYPE, rt)
                m = res[1][1]
            else:
                self.assertEquals(res[0], "EXIT")
                self.assertEquals(res[1][0], rt)
                self.assertEquals(res[1][1], ri)
                # XXXX TEST application key
                self.assert_(res[1][3].startswith(payload))
                break

    def test_successful(self):
        bfm = mixminion.BuildMessage.buildForwardMessage
        # A two-hop/one-hop message.
        p = "Now is the time for all good men to come to the aid"
        m = bfm(p, SMTP_TYPE, "nobody@invalid",
                [self.server1, self.server2], [self.server3])

        self.do_test_chain(m,
                           [self.sp1,self.sp2,self.sp3],
                           [FWD_TYPE, FWD_TYPE, SMTP_TYPE],
                           [self.server2.getRoutingInfo().pack(),
                            self.server3.getRoutingInfo().pack(),
                            "nobody@invalid"],
                           p)

        # A one-hop/one-hop message.
        m = bfm(p, SMTP_TYPE, "nobody@invalid",
                [self.server1], [self.server3])

        self.do_test_chain(m,
                           [self.sp1,self.sp3],
                           [FWD_TYPE, SMTP_TYPE],
                           [self.server3.getRoutingInfo().pack(),
                            "nobody@invalid"],
                           p)

        # A 3/3 message with a long exit header.
        for i in (100,300):
            longemail = "f"*i+"@invalid"
            m = bfm(p, SMTP_TYPE, longemail,
                    [self.server1, self.server2, self.server1],
                    [self.server3, self.server1, self.server2])
            
            self.do_test_chain(m,
                               [self.sp1,self.sp2,self.sp1,
                                self.sp3,self.sp1,self.sp2],
                               [FWD_TYPE,FWD_TYPE,FWD_TYPE,
                                FWD_TYPE,FWD_TYPE,SMTP_TYPE],
                               [self.server2.getRoutingInfo().pack(),
                                self.server1.getRoutingInfo().pack(),
                                self.server3.getRoutingInfo().pack(),
                                self.server1.getRoutingInfo().pack(),
                                self.server2.getRoutingInfo().pack(),
                                longemail],
                               p)


    def test_rejected(self):
        bfm = mixminion.BuildMessage.buildForwardMessage
        brm = mixminion.BuildMessage.buildReplyMessage
        brb = mixminion.BuildMessage.buildReplyBlock
        from mixminion.ServerProcess import ContentError

        # A long intermediate header needs to fail.
        from mixminion.ServerInfo import ServerInfo
        server1X = ServerInfo("127.0.0.1", 1, pk_get_modulus(self.pk1), "X"*20)
        class _packable:
            def pack(self): return "x"*200
        server1X.getRoutingInfo = lambda : _packable()
        
        m = bfm("Z", LOCAL_TYPE, "hello\000bye",
                [self.server2, server1X, self.server3],
                [server1X, self.server2, self.server3])
        self.failUnlessRaises(ContentError, self.sp2._processMessage, m)
        
        # Duplicate messages need to fail.
        m = bfm("Z", SMTP_TYPE, "nobody@invalid",
                [self.server1, self.server2], [self.server3])
        self.sp1._processMessage(m)
        self.failUnlessRaises(ContentError, self.sp1._processMessage, m)

        # Duplicate reply blocks need to fail
        (r,n),s = brb([self.server3], SMTP_TYPE, "fred@invalid")
        m = brm("Y", [self.server2], (r,n))
        m2 = brm("Y", [self.server1], (r,n))
        q, (a,m) = self.sp2._processMessage(m)
        self.sp3._processMessage(m)
        q, (a,m2) = self.sp1._processMessage(m2)
        self.failUnlessRaises(ContentError, self.sp3._processMessage, m2)

        # Even duplicate secrets need to go.
        prng = AESCounterPRNG(" "*16)
        (r1,n),s = brb([self.server1], SMTP_TYPE, "fred@invalid",prng)
        prng = AESCounterPRNG(" "*16)
        (r2,n),s = brb([self.server2], LOCAL_TYPE, "foo",prng)
        m = brm("Y", [self.server3], (r1,n))
        m2 = brm("Y", [self.server3], (r2,n))
        q, (a,m) = self.sp3._processMessage(m)
        self.sp1._processMessage(m)
        q, (a,m2) = self.sp3._processMessage(m2)
        self.failUnlessRaises(ContentError, self.sp2._processMessage, m2)

        # Drop gets dropped.
        m = bfm("Z", DROP_TYPE, "", [self.server2], [self.server2])
        q, (a,m) = self.sp2._processMessage(m)
        res = self.sp2._processMessage(m)
        self.assertEquals(res,None)

        # XXXX Bogus types
        # XXXX Non-parsing information
        # XXXX Bad Major or Minor
        # XXXX Bad digest
        # XXXX Bad payload

#----------------------------------------------------------------------

def testSuite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    tc = loader.loadTestsFromTestCase
    suite.addTest(tc(MinionlibCryptoTests))
    suite.addTest(tc(CryptoTests))
    suite.addTest(tc(FormatTests))
    suite.addTest(tc(HashLogTests))
    suite.addTest(tc(BuildMessageTests))
    suite.addTest(tc(ServerProcessTests))
    return suite

def testAll():
    unittest.TextTestRunner().run(testSuite())

if __name__ == '__main__':
    testAll()
