# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: test.py,v 1.4 2002/05/29 22:51:58 nickm Exp $

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

        self.failUnlessRaises(TypeError, s1, 1)

    def test_xor(self):
        xor = _ml.strxor
        
        self.assertEquals(xor("abc", "\000\000\000"), "abc")
        self.assertEquals(xor("abc", "abc"), "\000\000\000")
        self.assertEquals(xor("\xEF\xF0\x12", "\x11\x22\x35"), '\xFE\xD2\x27')

        # Make sure that the C doesn't (cringe) modify the strings.
        a = "aaaa"
        self.assertEquals(xor(a,"\000\000\000a"), "aaa\000")
        self.assertEquals(a, "aaaa")
        self.assertEquals(xor("\000\000\000a",a), "aaa\000")
        self.assertEquals(a, "aaaa")
        
        self.failUnlessRaises(TypeError, xor, "a", "bb")
        
    def test_aes(self):
        crypt = _ml.aes_ctr128_crypt

        # One of the test vectors from AES.
        key = txt = "\x80" + "\x00" * 15
        key = _ml.aes_key(key)

        expected = self.hexread("8EDD33D3C621E546455BD8BA1418BEC8")
        self.failUnless(crypt(key, txt, 0) == expected)
        self.failUnless(crypt(key, txt) == expected)
        self.failUnless(crypt(key, " "*100, 0)[1:] == crypt(key, " "*99, 1))
        self.failUnless(crypt(key,crypt(key, " "*100, 0),0) == " "*100)

        teststr = """I have seen the best ciphers of my generation
                     Destroyed by cryptanalysis, broken, insecure,
                     Implemented still in cryptographic libraries"""

        key2 = _ml.aes_key("xyzz"*4)
        self.assertEquals(teststr,crypt(key2,crypt(key2,teststr)))

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
        self.failUnlessRaises(_ml.SSLError,_ml.rsa_crypt,p,x+"ZZZ",1,1)

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
        key = ("ABCDE"*4,) *4
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

    def test_headers(self):
        pass #XXXX

    def test_message(self):
        # 9 is relatively prime to all pwrs of 2.
        m = ("abcdefghi"*(10000))[:32768]
        msg = parseMessage(m)
        self.assert_(msg.pack() == m)
        self.assert_(msg.header1 == m[:2048])
        self.assert_(msg.header2 == m[2048:4096])
        self.assert_(msg.payload == m[4096:])
        # FAILING CASES XXXX
            
    def test_ipv4info(self):
        pass #XXXX

    def test_smtpinfo(self):
        pass #XXXX

    def test_localinfo(self):
        pass #XXXX
        
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

class FakePRNG:
    def getBytes(self,n):
        return "\x00"*n

class BuildMessageTests(unittest.TestCase):
    def setUp(self):
        from ServerInfo import ServerInfo
        self.pk1 = pk_generate()
        self.pk2 = pk_generate()
        self.pk3 = pk_generate()
        self.n_1 = pk_get_modulus(self.pk1)
        self.n_2 = pk_get_modulus(self.pk2)
        self.n_3 = pk_get_modulus(self.pk3)
        self.server1 = ServerInfo("127.0.0.1", 1, self.n_1, "X"*20)
        self.server2 = ServerInfo("127.0.0.2", 3, self.n_2, "Z"*20)
        self.server3 = ServerInfo("127.0.0.3", 5, self.n_3, "Q"*20)

    def test_buildheader_1hop(self):
        bhead = mixminion.BuildMessage._buildHeaders

        head = bhead([self.server1], ["9"*16], 99, "Hi mom", AESCounterPRNG())
        self.do_header_test(head,
                            (self.pk1,),
                            ["9"*16,],
                            (99,),
                            ("Hi mom",))

    def test_buildheader_2hops(self):
        bhead = mixminion.BuildMessage._buildHeaders
        # 2 hops
        head = bhead([self.server1, self.server2],
                     ["9"*16, "1"*16], 99, "Hi mom", AESCounterPRNG()) 

        ipv4 = mixminion.Formats.IPV4Info
        self.do_header_test(head,
                            (self.pk1, self.pk2),
                            ["9"*16, "1"*16],
                            (mixminion.Modules.FWD_TYPE, 99),
                            (ipv4("127.0.0.2",3,"Z"*20).pack(),
                             "Hi mom"))
                            
    def test_buildheader_3hops(self):
        bhead = mixminion.BuildMessage._buildHeaders
        # 3 hops
        secrets = ["9"*16, "1"*16, "z"*16]
        head = bhead([self.server1, self.server2, self.server3], secrets,
                      99, "Hi mom", AESCounterPRNG())
        pks = (self.pk1,self.pk2,self.pk3)
        rtypes = (mixminion.Modules.FWD_TYPE,
                  mixminion.Modules.FWD_TYPE,
                  99)
        rinfo = (mixminion.Formats.IPV4Info("127.0.0.2", 3, "Z"*20).pack(),
                 mixminion.Formats.IPV4Info("127.0.0.3", 5, "Q"*20).pack(),
                 "Hi mom")
        self.do_header_test(head, pks, secrets, rtypes, rinfo)

    def do_header_test(self, head, pks, secrets, rtypes, rinfo):
        self.assertEquals(len(head), mixminion.Formats.HEADER_LEN)
        for pk, secret, rt, ri in zip(pks, secrets,rtypes,rinfo):
            subh = mixminion.Formats.parseSubheader(pk_decrypt(head[:128], pk))
            self.assertEquals(subh.secret, secret)
            self.assertEquals(subh.major, mixminion.Formats.MAJOR_NO)
            self.assertEquals(subh.minor, mixminion.Formats.MINOR_NO)
            self.assertEquals(subh.routingtype, rt)
            self.assertEquals(subh.routinginfo, ri)
            self.assertEquals(subh.digest, sha1(head[128:]))
            ks = Keyset(secret)
            key = ks.get(HEADER_SECRET_MODE)
            prngkey = ks.get(RANDOM_JUNK_MODE)
            head = ctr_crypt(head[128:]+prng(prngkey,128), key)

    def test_extended_routinginfo(self):
        #XXXX!!!! Code doesn't work 
        pass

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

        #### Reply case
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
        
    def test_buildmessage(self):
        #XXXX
        pass

    def test_buildreply(self):
        #XXXX
        pass

    def test_buildstatelessreply(self):
        #XXXX
        pass
            
#----------------------------------------------------------------------
import mixminion.ServerProcess
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
    return suite

def testAll():
    unittest.TextTestRunner().run(testSuite())

if __name__ == '__main__':
    testAll()
