# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: test.py,v 1.1 2002/05/29 03:52:13 nickm Exp $

import unittest

#----------------------------------------------------------------------
import mixminion._minionlib as _ml

class MinionlibCryptoTests(unittest.TestCase):
    def hexread(self,s):
        r = []
        hexvals = "0123456789ABCDEF"
        for i in range(len(s) // 2):
            v1 = hexvals.index(s[i*2])
            v2 = hexvals.index(s[i*2+1])
            c = (v1 << 4) + v2
            assert 0 <= c < 256
            r.append(chr(c))
        return "".join(r)

    def test_sha1(self):
        s1 = _ml.sha1

        self.assertEquals(s1("abc"),
               self.hexread("A9993E364706816ABA3E25717850C26C9CD0D89D"))

        s = s1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        self.assertEquals(s,
               self.hexread("84983E441C3BD26EBAAE4AA1F95129E5E54670F1"))

        self.assertEquals(s1("abc", "def"),
                          s1("defabcdef"))
        self.failUnlessRaises(TypeError, s1, 1)

    def test_xor(self):
        xor = _ml.strxor
        self.assertEquals(xor("abc", "\000\000\000"), "abc")
        self.assertEquals(xor("abc", "abc"), "\000\000\000")
        self.assertEquals(xor("\xEF\xF0\x12", "\x11\x22\x35"), '\xFE\xD2\x27')

        self.failUnlessRaises(TypeError, xor, "a", "bb")
        
    def test_aes(self):
        crypt = _ml.aes_ctr128_crypt

        # One of the test vectors from AES.
        key = "\x80" + "\x00" * 15
        expected = self.hexread("8EDD33D3C621E546455BD8BA1418BEC8")
        self.failUnless(crypt(key, key, 0) == expected)
        self.failUnless(crypt(key, key) == expected)
        self.failUnless(crypt(key, " "*100, 0)[1:] == crypt(key, " "*99, 1))
        self.failUnless(crypt(key,crypt(key, " "*100, 0),0) == " "*100)

        teststr = """I have seen the best ciphers of my generation
                     Destroyed by cryptanalysis, broken, insecure,
                     Implemented still in cryptographic libraries"""
        
        self.assertEquals(teststr,crypt("xyzz"*4,crypt("xyzz"*4,teststr)))

        # PRNG mode
        expected2 = self.hexread("0EDD33D3C621E546455BD8BA1418BEC8")
        self.assertEquals(expected2, crypt(key, "", 0, len(expected2)))
        self.assertEquals(expected2, crypt(key, "Z", 0, len(expected2)))
        self.assertEquals(expected2[5:], crypt(key, "", 5, len(expected2)-5))

        # Failing cases
        self.failUnlessRaises(TypeError, crypt, "a", teststr)
        self.failUnlessRaises(TypeError, crypt, "a"*17, teststr)

        self.assertEquals("", crypt(key,"",0,-1))

    def test_openssl_seed(self):
        _ml.openssl_seed("Hello")
        _ml.openssl_seed("")

    def test_oaep(self):
        x = _ml.add_oaep_padding("A", "B", 128)
        self.assertEquals("A",_ml.check_oaep_padding(x, "B", 128))
        
        _ml.add_oaep_padding("A"*86, "B",128)
        self.failUnlessRaises(TypeError,
                              _ml.add_oaep_padding,"A"*300, "B", 128)
        self.failUnlessRaises(_ml.SSLError,
                              _ml.add_oaep_padding,"A"*87, "B", 128)
        self.failUnlessRaises(_ml.SSLError,
                              _ml.check_oaep_padding,x[1:]+"Y","B",128)
        self.failUnlessRaises(_ml.SSLError,
                              _ml.check_oaep_padding,x[:-1]+"Y","B",128)

    def test_rsa(self):
        p = _ml.rsa_generate(1024, 65535)
        def sslerr(*args): self.failUnlessRaises(_ml.SSLError, *args)

        for pub1 in (0,1):
            for enc1 in (0,1):
                msg = "Now is the time for all anonymous parties"
                x = _ml.add_oaep_padding(msg, "B", 128)
                x2 = _ml.rsa_crypt(p, x, pub1, enc1);
                x3 = _ml.rsa_crypt(p, x2, [1,0][pub1], [1,0][enc1]);
                self.failUnless(x3 == x)
                x4 = _ml.check_oaep_padding(x3, "B", 128)
                self.failUnless(x4 == msg)

        # Too short
        self.failUnlessRaises(_ml.SSLError,_ml.rsa_crypt,p,"X",1,1)
        # Too long
        self.failUnlessRaises(_ml.SSLError,_ml.rsa_crypt,p,x+"XXX",1,1)

        padhello = _ml.add_oaep_padding("Hello", "B", 128)
        for public in (0,1):
            x = _ml.rsa_encode_key(p,public)
            p2 = _ml.rsa_decode_key(x,public)
            x3 = _ml.rsa_encode_key(p2,public)
            self.assertEquals(x,x3)
            self.assertEquals(_ml.rsa_crypt(p,padhello,public,1),
                              _ml.rsa_crypt(p2,padhello,public,1))

        n,e = _ml.rsa_get_public_key(p)
        p2 = _ml.rsa_make_public_key(n,e)
        self.assertEquals((n,e), _ml.rsa_get_public_key(p2))
        self.assertEquals(65535,e)
        self.assertEquals(_ml.rsa_encode_key(p,1), _ml.rsa_encode_key(p,1))
        
        # Try private-key ops with public key
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
    def test_initcrypto(self):
        init_crypto()

    def test_wrappers(self):
        self.assertEquals(_ml.sha1("xyzzy"), sha1("xyzzy"))
        k = "xyzy"*4
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

        self.failUnless((1L<<511) < pk_get_modulus(k512) < (1L<<513))
        self.failUnless((1L<<1023) < pk_get_modulus(k1024) < (1L<<1024))

        msg="Good hello"
        pub512 = pk_from_modulus(pk_get_modulus(k512))
        pub1024 = pk_from_modulus(pk_get_modulus(k1024))

        eq(msg, pk_decrypt(pk_encrypt(msg, k512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, k1024),k1024))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub1024),k1024))

        eq(msg, _ml.check_oaep_padding(
                    _ml.rsa_crypt(k512, pk_encrypt(msg,k512), 0, 0),
                    mixminion.Crypto.OAEP_PARAMETER, 64))

        encoded = pk_encode_private_key(k512)
        decoded = pk_decode_private_key(encoded)
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),decoded))
        
    def test_trng(self):
        self.assertNotEquals(trng(40), trng(40))

    def test_lioness(self):
        enc = lioness_encrypt
        dec = lioness_decrypt
        key = ("ABCDE"*4, "ABCD"*4, "VWXYZ"*4, "WXYZ"*4)
        plain = mixminion.Crypto.OAEP_PARAMETER*100
        self.assertNotEquals(plain, enc(plain,key))
        self.assertNotEquals(plain, dec(plain,key))
        self.assertEquals(len(plain), len(enc(plain,key)))
        self.assertEquals(len(plain), len(dec(plain,key)))
        self.assertEquals(plain, dec(enc(plain,key),key))
        self.assertEquals(plain, enc(dec(plain,key),key))
        #XXXX check for correct values

    def test_keyset(self):
        s = sha1
        k = Keyset("a")
        eq = self.assertEquals
        eq(s("aFoo")[:10], k.get("Foo",10))
        eq(s("aBar")[:16], k.get("Bar"))
        eq( (s("aBaz (FIRST SUBKEY)"), s("aBaz (SECOND SUBKEY)")[:16],
             s("aBaz (THIRD SUBKEY)"), s("aBaz (FOURTH SUBKEY)")[:16]),
            k.getLionessKeys("Baz"))

    def test_aesprng(self):
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

        #XXXX Need failing tests, routinginfo tests.
        
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

    def test_headers(self):
        pass #XXXX

    def test_message(self):
        pass #XXXX

    def test_ipv4info(self):
        pass #XXXX

    def test_smtpinfo(self):
        pass #XXXX

    def test_localinfo(self):
        pass #XXXX

#----------------------------------------------------------------------
import mixminion.ServerProcess
#----------------------------------------------------------------------
import mixminion.BuildMessage
#----------------------------------------------------------------------

def testSuite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    tc = loader.loadTestsFromTestCase
    suite.addTest(tc(MinionlibCryptoTests))
    suite.addTest(tc(CryptoTests))
    suite.addTest(tc(FormatTests))
    suite.addTest(tc(HashLogTests))
    return suite

def testAll():
    unittest.TextTestRunner().run(testSuite())

if __name__ == '__main__':
    testAll()
