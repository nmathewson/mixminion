# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: test.py,v 1.48 2002/12/15 04:35:54 nickm Exp $

"""mixminion.tests

   Unit tests for all Mixminion functionality.

   Usage:
   >>> import mixminion.tests
   >>> mixminion.tests.testAll()

   """

__pychecker__ = 'no-funcdoc maxlocals=100'

import base64
import cPickle
import cStringIO
import os
import re
import stat
import sys
import threading
import time
import types
from string import atoi

# Not every post-2.0 version of Python has a working 'unittest' module, so
# we include a copy with mixminion, as 'mixminion._unittest'.
try:
    import unittest
except ImportError:
    import mixminion._unittest as unittest

import mixminion.testSupport
from mixminion.testSupport import mix_mktemp, suspendLog, resumeLog, \
     replaceAttribute, undoReplacedAttributes, replaceFunction, \
     getReplacedFunctionCallLog, clearReplacedFunctionCallLog


import mixminion.BuildMessage as BuildMessage
import mixminion.ClientMain
import mixminion.Config
import mixminion.Crypto as Crypto
import mixminion.MMTPClient
import mixminion.Packet
import mixminion.ServerInfo
import mixminion._minionlib as _ml
import mixminion.server.MMTPServer
import mixminion.server.Modules
import mixminion.server.ServerConfig
import mixminion.server.ServerKeys
import mixminion.server.ServerMain
from mixminion.Common import *
from mixminion.Common import Log, _FileLogHandler, _ConsoleLogHandler
from mixminion.Config import _ConfigFile, ConfigError, _parseInt
from mixminion.Crypto import *
from mixminion.Packet import *
from mixminion.server.HashLog import HashLog
from mixminion.server.Modules import *
from mixminion.server.PacketHandler import *
from mixminion.server.Queue import *
from mixminion.server.ServerKeys import generateServerDescriptorAndKeys

# Set this flag to 1 in order to have all RSA keys and diffie-hellman params
# generated independently.  Otherwise, we cache diffie-hellman parameters
# on disk, and only generate a small number of RSA keys.
USE_SLOW_MODE = 0

#----------------------------------------------------------------------
# Misc helper functions
def hexread(s):
    """Helper function.  Converts a hexidecimal string into a binary string.
       For example, hexread('0A0B') == '\x0A\x0B'."""
    assert (len(s) % 2) == 0
    s = s.upper()
    r = []
    hexvals = "0123456789ABCDEF"
    for i in range(len(s) / 2):
        v1 = hexvals.index(s[i*2])
        v2 = hexvals.index(s[i*2+1])
        c = (v1 << 4) + v2
        assert 0 <= c < 256
        r.append(chr(c))
    return "".join(r)

def findFirstDiff(s1, s2):
    """Helper function.  Returns the first index i for which s1[i] != s2[i],
       or -1 s1 == s2."""
    if s1 == s2:
	return -1
    last = min(len(s1), len(s2))
    for i in xrange(last):
	if s1[i] != s2[i]:
	    return i
    return last

def floatEq(f1,f2):
    """Return true iff f1 is very close to f2."""
    return abs(f1-f2)/min(f1,f2) < .00001

def readFile(fname):
    """Return the contents of the file named 'fname'.  We could just say
       'open(fname).read()' instead, but that isn't as clean."""
    f = open(fname, 'r')
    try:
	return f.read()
    finally:
	f.close()

def writeFile(fname, contents):
    """Create a new file named fname, replacing any such file that exists,
       with the contents 'contents'."""
    f = open(fname, 'w')
    try:
	f.write(contents)
    finally:
	f.close()

#----------------------------------------------------------------------
# RSA key caching functionality

# Map from (n, bits) to a RSA key with bits bits.  Used to cache RSA keys
# for different purposes.
_generated_rsa_keys = {}
_generated_rsa_keys[(0,2048)] = mixminion.testSupport.TEST_KEYS_2048[0]
_generated_rsa_keys[(1,2048)] = mixminion.testSupport.TEST_KEYS_2048[1]
_generated_rsa_keys[(2,2048)] = mixminion.testSupport.TEST_KEYS_2048[2]
def getRSAKey(n,bits):
    """Return the n'th of an arbitrary number of cached 'bits'-bit RSA keys,
       generating them as necessary."""
    try:
	return _generated_rsa_keys[(n,bits)]
    except KeyError:
	if bits > 1024:
	    print "[generating %d-bit key #%d..."%(bits,n),
	    sys.stdout.flush()
	k = _pk_generate_orig(bits)
	if bits > 1024:
	    print "done]",
	    sys.stdout.flush()
	_generated_rsa_keys[(n,bits)] = k
	return k

# Functions to override Crypto.pk_generate to avoid generating a zillion RSA
# keys.
_pk_generate_orig = Crypto.pk_generate
_pk_generate_idx = 0
def _pk_generate_replacement(bits=1024,e=65537):
    if bits == 1024:
	global _pk_generate_idx
	_pk_generate_idx = (_pk_generate_idx + 1) % 4
	return getRSAKey(_pk_generate_idx, bits)
    else:
	return getRSAKey(0, bits)

if not USE_SLOW_MODE:
    Crypto.pk_generate = _pk_generate_replacement

#----------------------------------------------------------------------
# Tests for common functionality

class MiscTests(unittest.TestCase):
    def testDiv(self):
	self.assertEquals(floorDiv(10,1), 10)
	self.assertEquals(floorDiv(10,2), 5)
	self.assertEquals(floorDiv(10,3), 3)
	self.assertEquals(floorDiv(10,11), 0)
	self.assertEquals(floorDiv(0,11), 0)
	self.assertEquals(floorDiv(-1,1), -1)
	self.assertEquals(floorDiv(-1,2), -1)
	self.assertEquals(floorDiv(-10,3), -4)
	self.assertEquals(floorDiv(-10,-3), 3)

	self.assertEquals(ceilDiv(10,1), 10)
	self.assertEquals(ceilDiv(10,2), 5)
	self.assertEquals(ceilDiv(10,3), 4)
	self.assertEquals(ceilDiv(10,11), 1)
	self.assertEquals(ceilDiv(0,11), 0)
	self.assertEquals(ceilDiv(-1,1), -1)
	self.assertEquals(ceilDiv(-1,2), 0)
	self.assertEquals(ceilDiv(-10,3), -3)
	self.assertEquals(ceilDiv(-10,-3), 4)

    def testTimeFns(self):
	# This isn't a very good test.
	now = int(time.time())
	max_sec_per_day = 24*60*60+ 1
	# Sample 1000 evenly spaced points, making sure...
	for t in xrange(10, now, floorDiv(now, 1000)):
	    yyyy,MM,dd,hh,mm,ss = time.gmtime(t)[:6]
	    # 1. That mkgmtime inverts time.gmtime.
	    self.assertEquals(t, mkgmtime(yyyy,MM,dd,hh,mm,ss))
	    # 2. That previousMidnight returns the same day, at midnight.
	    pm = previousMidnight(t)
	    yyyy2,MM2,dd2,hh2,mm2,ss2 = time.gmtime(pm)[:6]
	    self.assertEquals((yyyy2,MM2,dd2), (yyyy,MM,dd))
	    self.assertEquals((0,0,0), (hh2,mm2,ss2))
	    self.failUnless(pm <= t and 0 <= (t-pm) <= max_sec_per_day)
	    # 3. That previousMidnight is repeatable
	    self.assertEquals(previousMidnight(t), pm)
	    # 4. That previousMidnight is idempotent
	    self.assertEquals(previousMidnight(pm), pm)

    def test_isSMTPMailbox(self):
	# Do we accept good addresses?
	for addr in "Foo@bar.com", "a@b", "a@b.c.d.e", "a!b.c@d", "z@z":
	    self.assert_(isSMTPMailbox(addr))

	# Do we reject bad addresses?
	for addr in ("(foo)@bar.com", "z.d" "z@", "@z", "@foo.com", "aaa",
		     "foo.bar@", "foo\177@bar.com", "foo@bar\177.com",
		     "foo@bar;cat /etc/shadow;echo ","foo bar@baz.com",
		     "a@b@c"):
	    self.assert_(not isSMTPMailbox(addr))

#----------------------------------------------------------------------

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
        _add = Crypto._add_oaep_padding
        _check = Crypto._check_oaep_padding
	# Perform OAEP tests with C implementation of OAEP and Python
	# implementation too.
        for add,check in ((_ml.add_oaep_padding, _ml.check_oaep_padding),
                          (_add, _check)):
            self.do_test_oaep(add, check)

	# Make sure they can invert one another.
        self.assertEquals("a",_check(_ml.add_oaep_padding("a", "b", 128),
                                         "b",128))
        self.assertEquals("a",_ml.check_oaep_padding(_add("a","b",128),
                                                         "b",128))

    def do_test_oaep(self, add, check):
        strxor = _ml.strxor
        # Check_oaep inverts add_oaep successfully.
        x = add("A", "B", 128)

        self.assertEquals("A",check(x, "B", 128))

        # 86 bytes can be used with size=128
        add("A"*86, "B",128)
        # But 300 is too much,
        self.failUnlessRaises(_ml.CryptoError,
                              add,"A"*300, "B", 128)
        # And so is even 87.
        self.failUnlessRaises(_ml.CryptoError,
                              add,"A"*87, "B", 128)
        # Changing a character at the beginning keeps it from checking.
        ch = strxor(x[0], '\x01')
        self.failUnlessRaises(_ml.CryptoError,
                              check,ch+x[1:],"B",128)
        # Changing a character at the end keeps it from checking.
        ch = strxor(x[-1], '\x01')
        self.failUnlessRaises(_ml.CryptoError,
                              check,x[:-1]+ch,"B",128)

    def test_rsa(self):
        p = getRSAKey(1,1024)

        #for all of SIGN, CHECK_SIG, ENCRYPT, DECRYPT...
        for pub1 in (0,1):
            for enc1 in (0,1):
                msg = "Now is the time for all anonymous parties"
                x = _ml.add_oaep_padding(msg, "B", 128)
                x2 = p.crypt(x, pub1, enc1);
                # ...Encryption inverts decryption...
                x3 = p.crypt(x2, [1,0][pub1], [1,0][enc1]);
                self.failUnless(x3 == x)
                # ...And oaep is preserved.
                x4 = _ml.check_oaep_padding(x3, "B", 128)
                self.failUnless(x4 == msg)

        # Fail if there is not enough padding
        self.failUnlessRaises(_ml.CryptoError,p.crypt,"X",1,1)
        # Fail if there is too much padding
        self.failUnlessRaises(_ml.CryptoError,p.crypt,x+"ZZZ",1,1)

        ####
        # Test key encoding
        padhello = _ml.add_oaep_padding("Hello", "B", 128)
        for public in (0,1):
            #encode(decode(encode(x))) == x.
            x = p.encode_key(public)
            p2 = _ml.rsa_decode_key(x,public)
            x3 = p2.encode_key(public)
            self.assertEquals(x,x3)
            # decode(encode(x)) encrypts the same as x.
            self.assertEquals(p.crypt(padhello,public,1),
                              p2.crypt(padhello,public,1))

        # encoding public keys to/from their moduli.
        self.assertEquals(p.get_modulus_bytes(),1024 >> 3)
        n,e = p.get_public_key()
	# Let p2 be the public portion of p.
        p2 = _ml.rsa_make_public_key(n,e)
        self.assertEquals((n,e), p2.get_public_key())
        self.assertEquals(65537,e)
        self.assertEquals(p.encode_key(1), p.encode_key(1))

        # Let P3 be the public key component of p.  Encrypt some messages
	# using p...
        p3 = _ml.rsa_decode_key(p.encode_key(1),1)
        msg1 = p.crypt(padhello, 1,1)
        msg2 = p.crypt(padhello, 1,1)
        msg3 = p.crypt(padhello, 1,1)
        self.assertEquals(padhello, p.crypt(msg1,0,0))
        self.assertEquals(padhello, p.crypt(msg2,0,0))
        self.assertEquals(padhello, p.crypt(msg3,0,0))
	# And make sure that neihter p2 nor p3 can decode them.
        self.failUnlessRaises(TypeError, p2.crypt, msg1, 0, 0)
        self.failUnlessRaises(TypeError, p3.crypt, msg1, 0, 0)
	# And make sure that we can't encode either as a private key
        self.failUnlessRaises(TypeError, p2.encode_key, 0)
        self.failUnlessRaises(TypeError, p3.encode_key, 0)

	# Test PEM encoding (we need this encoding because it's the
	# most widely used way to store encrypted private keys.(
        tf = mix_mktemp()
        tf_pub = tf + "1"
        tf_prv = tf + "2"
        tf_enc = tf + "3"

        p.PEM_write_key(open(tf_pub,'w'), 1)
        p.PEM_write_key(open(tf_prv,'w'), 0)
        p.PEM_write_key(open(tf_enc,'w'), 0, "top sekrit")
        p2 = _ml.rsa_PEM_read_key(open(tf_pub, 'r'), 1)
        self.assertEquals(p.get_public_key(), p2.get_public_key())

        p2 = _ml.rsa_PEM_read_key(open(tf_prv, 'r'), 0)
        self.assertEquals(p.encode_key(0), p2.encode_key(0))

        self.failUnlessRaises(_ml.CryptoError,
                              _ml.rsa_PEM_read_key,
                              open(tf_enc, 'r'), 0)

        p2 = _ml.rsa_PEM_read_key(open(tf_prv, 'r'), 0, "top sekrit")
        self.assertEquals(p.encode_key(0), p2.encode_key(0))

#----------------------------------------------------------------------

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
        k512 = getRSAKey(0,512)
        k1024 = getRSAKey(0,1024)

        eq(512>>3, k512.get_modulus_bytes())
        eq(1024>>3, k1024.get_modulus_bytes())

        # Check pk_get_modulus sanity
        self.failUnless((1L<<511) < pk_get_modulus(k512) < (1L<<513))
        self.failUnless((1L<<1023) < pk_get_modulus(k1024) < (1L<<1024))
        self.assertEquals(pk_get_modulus(k512),
                        pk_get_modulus(pk_from_modulus(pk_get_modulus(k512))))

        # Make sure that public keys can be made from moduli, and used to
        # encrypt and decrypt.
        msg="Good hello"
        pub512 = pk_from_modulus(pk_get_modulus(k512))
        pub1024 = pk_from_modulus(pk_get_modulus(k1024))

        eq(msg, pk_decrypt(pk_encrypt(msg, k512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, k1024),k1024))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub1024),k1024))

        # Make sure that CH_OAEP(RSA()) inverts pk_encrypt.
        eq(msg, _ml.check_oaep_padding(
                    k512.crypt(pk_encrypt(msg,k512), 0, 0),
                    Crypto.OAEP_PARAMETER, 64))

	# test signing
	eq(pk_check_signature(pk_sign(msg, k1024),pub1024), msg)
	eq(pk_check_signature(pk_sign(msg, k1024),k1024), msg)
	self.failUnlessRaises(TypeError,
			      pk_sign, msg, pub1024)
	self.failUnlessRaises(CryptoError,
			      pk_check_signature,
			      pk_sign(msg, k1024)+"X",
			      pub1024)

        # Make sure we can still encrypt after we've encoded/decoded a
        # key.
        encoded = pk_encode_private_key(k512)
        decoded = pk_decode_private_key(encoded)
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),decoded))

	# Test pickling
	init_crypto()
	s = cPickle.dumps(k512)
	self.assertEquals(cPickle.loads(s).get_public_key(),
			  k512.get_public_key())

    def test_trng(self):
        # Make sure that the true rng is at least superficially ok.
        self.assertNotEquals(trng(40), trng(40))

    def test_lioness(self):
        enc = lioness_encrypt
        dec = lioness_decrypt

        # Check basic cipher properties.
        key = ("ABCDE"*4, "ABCDF"*4, "DECBA"*4, "VWXYZ"*4)
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
        right = ctr_crypt(right, sha1(key1+left+key1)[:16])
        left  = strxor(left, sha1(key2+right+key2))
        right = ctr_crypt(right, sha1(key3+left+key3)[:16])
        left  = strxor(left, sha1(key4+right+key4))

        key = (key1,key2,key3,key4)
        self.assertEquals(left+right, lioness_encrypt(plain,key))
        self.assertEquals(key, Keyset("ABCDE"*4).getLionessKeys("foo"))

    def test_bear(self):
        enc = bear_encrypt
        dec = bear_decrypt

        # Check basic cipher properties.
        key = ("ABCDE"*4, "QRSTU"*4)
        plain = "The more it snows the more it goes on snowing"*10
        self.assertNotEquals(plain, enc(plain,key))
        self.assertNotEquals(plain, dec(plain,key))
        self.assertEquals(len(plain), len(enc(plain,key)))
        self.assertEquals(len(plain), len(dec(plain,key)))
        self.assertEquals(plain, dec(enc(plain,key),key))
        self.assertEquals(plain, enc(dec(plain,key),key))

        # Walk through a BEAR encryption to check for correct values.
        # Check getLionessKeys too.
        s = "ABCDE"*4
        key1 = sha1(s+"foo")
        key2 = key1[:-1]+strxor(key1[-1], chr(1))

        left = plain[:20]
        right = plain[20:]
        left = strxor(left, sha1(key1+right+key1))
        right = ctr_crypt(right, sha1(left)[:16])
        left = strxor(left, sha1(key2+right+key2))

        key = (key1,key2)
        self.assertEquals(left+right, bear_encrypt(plain,key))
        self.assertEquals(key, Keyset("ABCDE"*4).getBearKeys("foo"))

    def test_keyset(self):
        s = sha1
        x = _ml.strxor
	# Make sure that keyset.get expected
        k = Keyset("a")
        eq = self.assertEquals
        eq(s("aFoo")[:10], k.get("Foo",10))
        eq(s("aBar")[:16], k.get("Bar"))

	# Make sure that keyset.getLionessKeys works as expected.
        z19 = "\x00"*19
        eq((s("aBaz"),               x(s("aBaz"), z19+"\x01"),
            x(s("aBaz"),z19+"\x02"), x(s("aBaz"), z19+"\x03")),
           k.getLionessKeys("Baz"))

    def test_aesprng(self):
        # Make sure that AESCounterPRNG is really repeatable.
        key ="aaab"*4
        PRNG = AESCounterPRNG(key)
        self.assert_(prng(key,100000) == (
                          PRNG.getBytes(5)+PRNG.getBytes(16*1024-5)+
                          PRNG.getBytes(50)+PRNG.getBytes(32*1024)+
                          PRNG.getBytes(9)+PRNG.getBytes(10)+
                          PRNG.getBytes(15)+PRNG.getBytes(16000)+
                          PRNG.getBytes(34764)))

	# Check getInt, getFloat.
        for i in xrange(1,10000,17):
            self.failUnless(0 <= PRNG.getInt(10) < 10)
            self.failUnless(0 <= PRNG.getInt(i) < i)

##  	itot=ftot=0
##  	for i in xrange(1000000):
##  	    itot += PRNG.getInt(10)
##  	    ftot += PRNG.getFloat()

##  	print "AVG INT", itot/1000000.0
##  	print "AVG FLT", ftot/1000000.0

	for i in xrange(100):
	    self.failUnless(0 <= PRNG.getFloat() < 1)

	lst = range(100)
	# Test shuffle(0)
	self.assertEquals(PRNG.shuffle(lst,0), [])
	self.assertEquals(lst, range(100))
	# Make sure shuffle only shuffles the last n.
	PRNG.shuffle(lst,10)
	later = [ item for item in lst[10:] if item >= 10 ]
	s = later[:]
	s.sort()
	self.failUnless(later == s)

	# Make sure shuffle actually shuffles all positions.
	lists = [  ]
	for i in xrange(6):
	    lists.append(PRNG.shuffle(lst)[:])
	# This will fail accidentally once in 10,000,000,000 attempts.
	for crossSection in zip(*lists):
	    allEq = 1
	    for z in crossSection:
		if z != crossSection[0]: allEq = 0
	    self.failIf(allEq)
	foundUnmoved = 0
	for lst in lists:
	    for inorder, shuffled in zip(lst, range(100)):
		if inorder == shuffled:
		    foundUnmoved = 1
		    break
	    if foundUnmoved: break
	self.failUnless(foundUnmoved)
	for lst in lists:
	    s = lst[:]
	    s.sort()
	    self.assertEquals(s, range(100))

#----------------------------------------------------------------------

class PacketTests(unittest.TestCase):
    def test_subheader(self):
        s = Subheader(3,0,"abcdeabcdeabcdef",
                      "ABCDEFGHIJABCDEFGHIJ",
                      1, "Hello")

        expected = "\003\000abcdeabcdeabcdef"+\
                   "ABCDEFGHIJABCDEFGHIJ\000\005\000\001Hello"
        # test packing
        self.assertEquals(s.pack(), expected)
        self.failUnless(not s.isExtended())
        self.assertEquals(s.getNExtraBlocks(), 0)
        self.assertEquals(s.getExtraBlocks(), [])

        # test unpacking,
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

        ts_eliot = ("Who is the third who walks always beside you? / "+
		    "When I count, there are only you and I together / "+
		    "But when I look ahead up the white road / "+
		    "There is always another one walking beside you")

        s = Subheader(3,9,"abcdeabcdeabcdef",
                      "ABCDEFGHIJABCDEFGHIJ",
                      300, ts_eliot, len(ts_eliot))

        self.assertEquals(len(ts_eliot), 186)

        # test extended subeaders
        expected = ("\003\011abcdeabcdeabcdefABCDEFGHIJABCDEFGHIJ"+
		    "\000\272\001\054Who is the third who walks always"+
		    " beside you")
        self.assertEquals(len(expected), mixminion.Packet.MAX_SUBHEADER_LEN)
        self.assertEquals(s.pack(), expected)

        extra = s.getExtraBlocks()
        self.assertEquals(len(extra), 2)
        self.assertEquals(extra[0],
		 ("? / When I count, there are only you "+
		  "and I together / But when I look ahead up the white "+
		  "road / There is always another one walk"))
        self.assertEquals(extra[1], "ing beside you"+(114*'\000'))

        # test parsing extended subheaders
        s = parseSubheader(expected)
        self.assertEquals(s.major, 3)
        self.assertEquals(s.minor, 9)
        self.assertEquals(s.secret, "abcde"*3+"f")
        self.assertEquals(s.digest, "ABCDEFGHIJ"*2)
        self.assertEquals(s.routingtype, 300)
        self.assertEquals(s.routinglen, 186)
        self.failUnless(s.isExtended())
        self.assertEquals(s.getNExtraBlocks(), 2)

        s.appendExtraBlocks("".join(extra))
        self.assertEquals(s.routinginfo, ts_eliot)
	self.assertEquals(s.getExitAddress(), ts_eliot[20:])
	self.assertEquals(s.getTag(), ts_eliot[:20])
        self.assertEquals(s.pack(), expected)
        self.assertEquals(s.getExtraBlocks(), extra)

        # Underlong subheaders must fail
        self.failUnlessRaises(ParseError,
                              parseSubheader, "a"*(41))
        # overlong subheaders must fail
        self.failUnlessRaises(ParseError,
                              parseSubheader, "a"*(99))

    def test_headers(self):
	# Make sure we extract the subheaders from a header correctly.
	# (Generate a nice random string to make sure we're slicing right.)
        header = Crypto.prng("onefish, twofish", 2048)
        h = parseHeader(header)
        self.failUnless(h[0] == header[:128])
        self.failUnless(h[4] == header[128*4:128*5])
        self.failUnless(h[:1] == h[0])
        self.failUnless(h[1:] == header[128:])
        self.failUnless(h[1:4] == header[128:128*4])
        self.failUnless(h[15] == header[-128:])
        self.failUnless(h[15] == h[-1])
        self.failUnless(h[14:] == h[-2:])

    def test_message(self):
	# Make sure we can pull the headers and payload of a message apart
	# correctly.
	# (Generate a nice random string to make sure we're slicing right.)
        m = Crypto.prng("HappyFunAESKey!!", 32768)
        msg = parseMessage(m)
        self.assert_(msg.pack() == m)
        self.assert_(msg.header1 == m[:2048])
        self.assert_(msg.header2 == m[2048:4096])
        self.assert_(msg.payload == m[4096:])
        self.failUnlessRaises(ParseError, parseMessage, m[:-1])
        self.failUnlessRaises(ParseError, parseMessage, m+"x")

    def test_ipv4info(self):
	# Check the IPV4Info structure used to hold the addresses for the
	# FWD and SWAP_FWD routing types.
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

    def test_replyblock(self):
	# Try parsing an example 'reply block' object
	key = "\x99"*16
        r = ("SURB\x00\x01"+"\x00\x00\x00\x00"+("Z"*2048)+"\x00\x0A"+"\x00\x01"
	     +key+("F"*10))
        rb = parseReplyBlock(r)
        self.assertEquals(rb.timestamp, 0)
        self.assertEquals(rb.header, "Z"*2048)
        self.assertEquals(rb.routingType, 1)
        self.assertEquals(rb.routingInfo, "F"*10)
        self.assertEquals(rb.encryptionKey, key)
        self.assertEquals(r, rb.pack())
	# Now try regenerating it.
	rb = ReplyBlock(header="Z"*2048,useBy=0,rt=1,ri="F"*10,key=key)
	self.assertEquals(r, rb.pack())

    def test_payloads(self):
	# Checks for payload structure functions.

	# First, generate some plausible singleton payloads.
	contents = ("payload"*(4*1024))[:28*1024 - 22]
	hash = "HASH"*5
	singleton_payload_1 = "\x00\xff"+hash+contents
	singleton_payload_2 = singleton_payload_1[:-38] #efwd overhead
	# Make sure that parsePayload works as expected.
	p1 = parsePayload(singleton_payload_1)
	p2 = parsePayload(singleton_payload_2)
	self.failUnless(p1.isSingleton() and p2.isSingleton())
 	self.assertEquals(p1.size,255)
	self.assertEquals(p2.size,255)
	self.assertEquals(p1.hash,hash)
	self.assertEquals(p2.hash,hash)
	self.assertEquals(p1.data,contents)
	self.assertEquals(p2.data,contents[:-38])
	self.assertEquals(p1.getContents(), contents[:255])
	self.assertEquals(p2.getContents(), contents[:255])
	self.assertEquals(p1.pack(),singleton_payload_1)
	self.assertEquals(p2.pack(),singleton_payload_2)

	# Try SingletonPayload constructor and pack functions
	self.assertEquals(singleton_payload_1,
			  SingletonPayload(255, hash, contents).pack())
	self.assertEquals(singleton_payload_2,
			  SingletonPayload(255, hash, contents[:-38]).pack())

	# Impossible payload lengths
	self.failUnlessRaises(ParseError,parsePayload,singleton_payload_1+"a")
	self.failUnlessRaises(ParseError,parsePayload,singleton_payload_2+"a")
	self.failUnlessRaises(ParseError,parsePayload,singleton_payload_2[:-1])
	# Impossible value for size field
	bad = "\x7fff" + singleton_payload_1[2:]
	self.failUnlessRaises(ParseError,parsePayload,bad)

	## Now, for the fragment payloads.
	msgID = "This is a message123"
	assert len(msgID) == 20
	contents = contents[:28*1024 - 46]
	frag_payload_1 = "\x80\x02"+hash+msgID+"\x00\x01\x00\x00"+contents
	frag_payload_2 = frag_payload_1[:-38] # efwd overhead
	p1 = parsePayload(frag_payload_1)
	p2 = parsePayload(frag_payload_2)
	self.failUnless(not p1.isSingleton() and not p2.isSingleton())
 	self.assertEquals(p1.index,2)
	self.assertEquals(p2.index,2)
	self.assertEquals(p1.hash,hash)
	self.assertEquals(p2.hash,hash)
	self.assertEquals(p1.msgID,msgID)
	self.assertEquals(p2.msgID,msgID)
	self.assertEquals(p1.msgLen,64*1024)
	self.assertEquals(p2.msgLen,64*1024)
	self.assertEquals(p1.data,contents)
	self.assertEquals(p2.data,contents[:-38])
	self.assertEquals(p1.pack(),frag_payload_1)
	self.assertEquals(p2.pack(),frag_payload_2)

	self.assertEquals(frag_payload_1,
		  FragmentPayload(2,hash,msgID,64*1024,contents).pack())
	self.assertEquals(frag_payload_2,
		  FragmentPayload(2,hash,msgID,64*1024,contents[:-38]).pack())

	# Impossible payload lengths
	self.failUnlessRaises(ParseError,parsePayload,frag_payload_1+"a")
	self.failUnlessRaises(ParseError,parsePayload,frag_payload_2+"a")
	self.failUnlessRaises(ParseError,parsePayload,frag_payload_2[:-1])

	# Impossible message sizes
	min_payload_1 = "\x80\x02"+hash+msgID+"\x00\x00\x6F\xD3"+contents
	bad_payload_1 = "\x80\x02"+hash+msgID+"\x00\x00\x6F\xD2"+contents
	min_payload_2 = "\x80\x02"+hash+msgID+"\x00\x00\x6F\xAD"+contents[:-38]
	bad_payload_2 = "\x80\x02"+hash+msgID+"\x00\x00\x6F\xAC"+contents[:-38]
	min_payload_3 = "\x80\x02"+hash+msgID+"\x00\x00\x6F\xD2"+contents[:-38]
	parsePayload(min_payload_1)
	parsePayload(min_payload_2)
	parsePayload(min_payload_3)
	self.failUnlessRaises(ParseError,parsePayload,bad_payload_1)
	self.failUnlessRaises(ParseError,parsePayload,bad_payload_2)


#----------------------------------------------------------------------
class HashLogTests(unittest.TestCase):
    def test_hashlog(self):
	# Create a new,empty hashlog.
        fname = mix_mktemp(".db")

	# (We put the hashlog in a list so that we can pass the list to our
	#  internal helper functions, and change its contents later on.  If
	#  only we could rely on nested scopes (added to Python 2.1), this
	#  would be easier.)
        h = [HashLog(fname, "Xyzzy")]

        notseen=lambda hash,self=self,h=h:self.assert_(not h[0].seenHash(hash))
        seen = lambda hash,self=self,h=h: self.assert_(h[0].seenHash(hash))
        log = lambda hash,h=h: h[0].logHash(hash)

	# Make sure that an empty hash contains nothing, including NUL strings
	# and high-ascii strings.
        notseen("a")
        notseen("a*20")
        notseen("\000"*10)
        notseen("\000")
        notseen("\277"*10)
	# Log a value, and make sure that only that value is now in the log
        log("a"*20)
        notseen("a*10")
        notseen("\000"*10)
        notseen("b")
        seen("a"*20)

	# Try a second value; make sure both values are now there.
        log("b"*20)
        seen("b"*20)
        seen("a"*20)

	# Try logging a string of NULs
        log("\000"*20)
        seen("\000"*20)
        notseen("\000"*10)

	# Try double-logging.
        log("\000"*20)
        seen("\000"*20)

	# Try logging a string of ESCs
        log("\277"*20)
        seen("\277"*20)

	# And a nice plain ascii string
        log("abcde"*4)
        seen("abcde"*4)

	# Now reopen the log, and make sure it has all its original contents.
        h[0].close()
        h[0] = HashLog(fname, "Xyzzy")
        seen("a"*20)
        seen("b"*20)
        seen("\277"*20)
        seen("abcde"*4)
        seen("\000"*20)
	# (and no other contents)
        notseen(" ")
        notseen("\000"*5)
        notseen("\001"*20)

	# Now add more, close again, and see if our latest adddition went in.
        notseen("ddddd"*4)
        log("ddddd"*4)
        seen("ddddd"*4)

	h[0].sync()
        h[0].close()
        h[0] = HashLog(fname, "Xyzzy")
        seen("ddddd"*4)

	# Make sure that hashlog still works when we sync.
	log("Abcd"*5)
	log("Defg"*5)
	seen("Abcd"*5)
	seen("Defg"*5)
	h[0].sync()
	#   (This violates HashLog's encapsulation, but let's make double-sure
	#    that we've really flushed the journal to disk.)
	self.assertEquals(0, len(h[0].journal))
	seen("Abcd"*5)
	seen("Defg"*5)
	log("Ghij"*5)
	seen("Ghij"*5)

        h[0].close()

#----------------------------------------------------------------------

# Dummy PRNG class that just returns 0-valued bytes.  We use this to make
# generated padding predictable in our BuildMessage tests below.
class FakePRNG:
    def getBytes(self,n):
        return "\x00"*n

class FakeServerInfo:
    """Represents a Mixminion server, and the information needed to send
       messages to it."""
    def __init__(self, addr, port, key, keyid):
        self.addr = addr
        self.port = port
        self.key = key
        self.keyid = keyid

    def getNickname(self): return "N(%s:%s)"%(self.addr,self.port)
    def getAddr(self): return self.addr
    def getPort(self): return self.port
    def getPacketKey(self): return self.key
    def getKeyID(self): return self.keyid

    def getRoutingInfo(self):
        """Returns a mixminion.Packet.IPV4Info object for routing messages
           to this server."""
        return IPV4Info(self.addr, self.port, self.keyid)

class BuildMessageTests(unittest.TestCase):
    def setUp(self):
        self.pk1 = getRSAKey(0,1024)
        self.pk2 = getRSAKey(1,1024)
        self.pk3 = getRSAKey(2,1024)
	self.pk512 = getRSAKey(0,512)
        self.server1 = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        self.server2 = FakeServerInfo("127.0.0.2", 3, self.pk2, "Z"*20)
        self.server3 = FakeServerInfo("127.0.0.3", 5, self.pk3, "Q"*20)

    def test_compression(self):
	# Make sure that our compression helper functions work properly.

	p = AESCounterPRNG()
	longMsg = p.getBytes(100)*2 + str(dir(Crypto))

	# Make sure compression is reversible.
	for m in ("", "a", "\000", "xyzzy"*10, ("glossy glossolalia.."*2)[32],
		  longMsg):
	    c = BuildMessage.compressData(m)
	    self.assertEquals(m, BuildMessage.uncompressData(c))

	self.failUnlessRaises(ParseError, BuildMessage.uncompressData, "3")

	for _ in xrange(20):
	    for _ in xrange(20):
		m = p.getBytes(p.getInt(1000))
		try:
		    BuildMessage.uncompressData(m)
		except ParseError:
		    pass
	#FFFF Find a decent test vector.

    def test_payload_helpers(self):
	"test helpers for payload encoding"
	p = AESCounterPRNG()
	for _ in xrange(10):
	    t = BuildMessage._getRandomTag(p)
	    self.assertEquals(20, len(t))
	    self.assertEquals(0, ord(t[0])&0x80)

	b = p.getBytes(28*1024)
	self.assert_(not BuildMessage._checkPayload(b))

	for m in (p.getBytes(3000), p.getBytes(10000), "", "q", "blznerty"):
	    for ov in 0, 42-20+16: # encrypted forward overhead
		pld = BuildMessage._encodePayload(m,ov,p)
		self.assertEquals(28*1024, len(pld)+ov)
		comp = BuildMessage.compressData(m)
		self.assert_(pld[22:].startswith(comp))
		self.assertEquals(sha1(pld[22:]),pld[2:22])
		self.assert_(BuildMessage._checkPayload(pld))
		self.assertEquals(len(comp), ord(pld[0])*256+ord(pld[1]))
		self.assertEquals(0, ord(pld[0])&0x80)
		self.assertEquals(m, BuildMessage._decodePayloadImpl(pld))

	self.failUnlessRaises(MixError, BuildMessage._decodePayloadImpl, b)

	# Check fragments (not yet supported)
	pldFrag = chr(ord(pld[0])|0x80)+pld[1:]
	self.failUnlessRaises(MixError,BuildMessage._decodePayloadImpl,pldFrag)

	# Check impossibly long messages
	pldSize = "\x7f\xff"+pld[2:] #sha1(pld[22:])+pld[22:]
	self.failUnlessRaises(ParseError,
			      BuildMessage._decodePayloadImpl,pldSize)

    def test_buildheader_1hop(self):
        bhead = BuildMessage._buildHeader

        head = bhead([self.server1], ["9"*16], 99, "Hi mom", AESCounterPRNG())
        self.do_header_test(head,
                            (self.pk1,),
                            ["9"*16,],
                            (99,),
                            ("Hi mom",))

    def test_buildheader_2hops(self):
        bhead = BuildMessage._buildHeader
        # 2 hops
        head = bhead([self.server1, self.server2],
                     ["9"*16, "1"*16], 99, "Hi mom", AESCounterPRNG())

        ipv4 = mixminion.Packet.IPV4Info
        self.do_header_test(head,
                            (self.pk1, self.pk2),
                            ["9"*16, "1"*16],
                            (FWD_TYPE, 99),
                            (ipv4("127.0.0.2",3,"Z"*20).pack(),
                             "Hi mom"))

    def test_buildheader_3hops(self):
        bhead = BuildMessage._buildHeader
        # 3 hops
        secrets = ["9"*16, "1"*16, "z"*16]
        head = bhead([self.server1, self.server2, self.server3], secrets,
                      99, "Hi mom", AESCounterPRNG())
        pks = (self.pk1,self.pk2,self.pk3)
        rtypes = (FWD_TYPE, FWD_TYPE, 99)
        rinfo = (mixminion.Packet.IPV4Info("127.0.0.2", 3, "Z"*20).pack(),
                 mixminion.Packet.IPV4Info("127.0.0.3", 5, "Q"*20).pack(),
                 "Hi mom")
        self.do_header_test(head, pks, secrets, rtypes, rinfo)

    def do_header_test(self, head, pks, secrets, rtypes, rinfo):
        """Unwraps and checks the layers of a single header.
                    head: the header to check
                    pks: sequence of public keys for hops in the path
                    secrets: sequence of master secrets for the subheaders
                    rtypes: sequenece of expected routing types
                    rinfo: sequenece of expected routing info's.

           If secrets is None, takes secrets from the headers without
             checking.

           Returns a tuple of (a list of the secrets encountered,
                               a list of routinginfo strings,
			       the tag from the last routinginfo)
        """
        tag = None
        retsecrets = []
        retinfo = []
        if secrets is None:
            secrets = [None] * len(pks)
	# Is the header the right length?
        self.assertEquals(len(head), mixminion.Packet.HEADER_LEN)
	# Go through the hops one by one, simulating the decoding process.
        for pk, secret, rt, ri in zip(pks, secrets,rtypes,rinfo):
	    # Decrypt the first subheader.
            subh = mixminion.Packet.parseSubheader(pk_decrypt(head[:128], pk))
	    # If we're expecting a given secret in this subheader, check it.
            if secret:
                self.assertEquals(subh.secret, secret)
            else:
                secret = subh.secret
	    retsecrets.append(secret)
	    # Check the version, the digest, and the routing type.
            self.assertEquals(subh.major, mixminion.Packet.MAJOR_NO)
            self.assertEquals(subh.minor, mixminion.Packet.MINOR_NO)
            self.assertEquals(subh.digest, sha1(head[128:]))
            self.assertEquals(subh.routingtype, rt)

	    # Key to decrypt the rest of the header
            ks = Keyset(secret)
            key = ks.get(HEADER_SECRET_MODE)

	    # If we have an exit type, the first 20 bytes of the routinginfo
	    # are a decoding tag; extract it.
	    if rt < 0x100: # extra bytes for tag
		ext = 0
	    else:
		ext = 20
		if ri:
		    tag = subh.routinginfo[:20]

	    # Check the routinginfo.  This is a little different for regular
	    # and extended subheaders...
            if not subh.isExtended():
                if ri:
		    self.assertEquals(subh.routinginfo[ext:], ri)
                    self.assertEquals(subh.routinglen, len(ri)+ext)
                else:
                    retinfo.append(subh.routinginfo)
                size = 128
                n = 0
            else:
                self.assert_(len(ri)+ext>mixminion.Packet.MAX_ROUTING_INFO_LEN)
                n = subh.getNExtraBlocks()
                size = (1+n)*128
                more = ctr_crypt(head[128:128+128*n], key)
                subh.appendExtraBlocks(more)
                if ri:
		    self.assertEquals(subh.routinginfo[ext:], ri)
                    self.assertEquals(subh.routinglen, len(ri)+ext)
                else:
                    retinfo.append(subh.routinginfo)

	    # Decrypt and pad the rest of the header.
            prngkey = ks.get(RANDOM_JUNK_MODE)
            head = ctr_crypt(head[size:]+prng(prngkey,size), key, 128*n)

	return retsecrets, retinfo, tag

    def test_extended_routinginfo(self):
        bhead = BuildMessage._buildHeader

        secrets = ["9"*16]
        longStr = "Foo"*50
        head = bhead([self.server1], secrets, 99, longStr, AESCounterPRNG())
        pks = (self.pk1,)
        rtypes = (99,)
        rinfo = (longStr,)

        self.do_header_test(head, pks, secrets, rtypes, rinfo)

        # Now try a header with extended **intermediate** routing info.
        # Since this never happens in the wild, we fake it.
	tag = "dref"*5
        longStr2 = longStr * 2

        def getLongRoutingInfo(longStr2=longStr2,tag=tag):
            return MBOXInfo(tag+longStr2)

        server4 = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        server4.getRoutingInfo = getLongRoutingInfo

        secrets.append("1"*16)
        head = bhead([self.server2, server4], secrets, 99,
		     longStr,
                     AESCounterPRNG())
        pks = (self.pk2,self.pk1)
        rtypes = (FWD_TYPE,99)
        rinfo = (tag+longStr2,longStr)
        self.do_header_test(head, pks, secrets, rtypes, rinfo)

        # Now we make sure that overlong routing info fails.
        self.failUnlessRaises(MixError, bhead,
                              [self.server2, server4], secrets, 99, "Z"*2048,
                              AESCounterPRNG())

    def test_constructmessage(self):
        consMsg = BuildMessage._constructMessage

        h1 = "abcdefgh"*(2048 >> 3)
        h2 = "aBcDeFgH"*(2048 >> 3)

        ######
        ### non-reply case
        secrets1 = [ x * 16 for x in ("s","q","m","s","h")]
        secrets2 = [ x * 16 for x in ("o","s","f","r","g")]
        pld = """
           Everyone has the right to freedom of opinion and expression; this
           right includes freedom to hold opinions without interference and
           to seek, receive and impart information and ideas through any
           media and regardless of frontiers.
           """
        pld += "\000"*(28*1024-len(pld))

        message = consMsg(secrets1, secrets2, h1, h2, pld)

        self.assertEquals(len(message), mixminion.Packet.MESSAGE_LEN)
        msg = mixminion.Packet.parseMessage(message)
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
		swapkey = Crypto.lioness_keys_from_header(head2)
		payload = lioness_decrypt(payload, swapkey)

                swapkey = Crypto.lioness_keys_from_payload(payload)
                head2 = lioness_decrypt(head2, swapkey)

        self.assert_(head2 == h2)
        self.assert_(payload == pld)

        ######
        ### Reply case
        message = consMsg(secrets1, None, h1, h2, pld)
        self.assertEquals(len(message), mixminion.Packet.MESSAGE_LEN)
        msg = mixminion.Packet.parseMessage(message)
        head1, head2, payload = msg.header1, msg.header2, msg.payload
        self.assert_(h1 == head1)

        for s in secrets1:
            ks = Keyset(s)
            hkey = ks.getLionessKeys(HEADER_ENCRYPT_MODE)
            pkey = ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE)
            head2 = lioness_decrypt(head2, hkey)
            payload = lioness_decrypt(payload, pkey)

        swapkey = Crypto.lioness_keys_from_header(head2)
        payload = lioness_decrypt(payload, swapkey)

        swapkey = Crypto.lioness_keys_from_payload(payload)
        head2 = lioness_decrypt(head2, swapkey)

        self.assert_(head2 == h2)
        self.assert_(payload == pld)

    def do_message_test(self, msg,
                        header_info_1,
                        header_info_2,
                        payload, decoder=None):
        """Decrypts the layers of a message one by one, checking them for
           correctness.
                      msg: the message to examine
                      header_info_1: a tuple of (pks,secrets,rtypes,rinfo)
                            as used by do_header_test for the first header.
                      header_info_2: a tuple of (pks,secrets,rtypes,rinfo)
                            as used by do_header_test for the second header.
                      payload: The beginning of the expected decrypted payload.
		      decoder: A function to call on the exit payload before
		            comparing it to 'payload'.  Takes payload,tag;
			    returns string.
           """
        # Check header 1, and get secrets
        sec, _, _ = self.do_header_test(msg[:2048], *header_info_1)
        h2 = msg[2048:4096]
        p = msg[4096:]
        # Do decryption steps for header 1.
        for s in sec:
            ks = Keyset(s)
            p = lioness_decrypt(p,ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))
            h2 = lioness_decrypt(h2,ks.getLionessKeys(HEADER_ENCRYPT_MODE))
	p = lioness_decrypt(p,Crypto.lioness_keys_from_header(h2))
        h2 = lioness_decrypt(h2,Crypto.lioness_keys_from_payload(p))

        sec, _, tag = self.do_header_test(h2, *header_info_2)
        for s in sec:
            ks = Keyset(s)
            p = lioness_decrypt(p,ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))

	if decoder is None:
	    p = BuildMessage._decodeForwardPayload(p)
	else:
	    p = decoder(p, tag)

        self.assertEquals(payload, p[:len(payload)])

    def test_build_fwd_message(self):
        bfm = BuildMessage.buildForwardMessage
        befm = BuildMessage.buildEncryptedForwardMessage
        payload = "Hello!!!!"

        m = bfm(payload, 500, "Goodbye",
                [self.server1, self.server2],
                [self.server3, self.server2])

        self.do_message_test(m,
                             ( (self.pk1, self.pk2), None,
                               (FWD_TYPE, SWAP_FWD_TYPE),
                               (self.server2.getRoutingInfo().pack(),
                                self.server3.getRoutingInfo().pack()) ),
                             ( (self.pk3, self.pk2), None,
                               (FWD_TYPE, 500),
                               (self.server2.getRoutingInfo().pack(),
                                "Goodbye") ),
                             "Hello!!!!")

        m = bfm(payload, 500, "Goodbye",
                [self.server1,],
                [self.server3,])

	messages = {}

	def decoder0(p,t,messages=messages):
	    messages['fwd'] = (p,t)
	    return BuildMessage._decodeForwardPayload(p)

        self.do_message_test(m,
                             ( (self.pk1,), None,
                               (SWAP_FWD_TYPE,),
                               (self.server3.getRoutingInfo().pack(),) ),
                             ( (self.pk3,), None,
                               (500,),
                               ("Goodbye",) ),
                             "Hello!!!!",
			     decoder=decoder0)

	# Encrypted forward message
	rsa1, rsa2 = self.pk1, self.pk512
	payload = "<<<<Hello>>>>" * 100
	for rsakey in rsa1,rsa2:
	    m = befm(payload, 500, "Phello",
		     [self.server1, self.server2],
		     [self.server3, self.server2],
		     rsakey)
	    def decoder(p,t,key=rsakey,messages=messages):
		messages['efwd'+str(key.get_modulus_bytes())] = (p,t)
		return BuildMessage._decodeEncryptedForwardPayload(p,t,key)

	    self.do_message_test(m,
				 ( (self.pk1, self.pk2), None,
				   (FWD_TYPE, SWAP_FWD_TYPE),
				   (self.server2.getRoutingInfo().pack(),
				    self.server3.getRoutingInfo().pack()) ),
				 ( (self.pk3, self.pk2), None,
				   (FWD_TYPE, 500),
				   (self.server2.getRoutingInfo().pack(),
				    "Phello") ),
				 payload,
				 decoder=decoder)

	# Now do more tests on final messages: is the format as expected?
	p,t = messages['fwd']
	self.assertEquals(20, len(t))
	self.assertEquals(28*1024,len(p))
	self.assertEquals(0, ord(t[0]) & 0x80)
	comp = BuildMessage.compressData("Hello!!!!")
	self.assertEquals(len(comp), ord(p[0])*256 +ord(p[1]))
	self.assert_(p[22:].startswith(comp))
	self.assertEquals(sha1(p[22:]), p[2:22])

	for rsakey in (rsa1, rsa2):
	    n = rsakey.get_modulus_bytes()
	    p,t = messages['efwd'+str(n)]
	    mrsa, mrest = t+p[:n-20], p[n-20:]
	    mrsa = pk_decrypt(mrsa, rsakey)
	    sessionkey, rsa_rest = mrsa[:16], mrsa[16:]
	    ks = Keyset(sessionkey)
	    msg = rsa_rest + lioness_decrypt(mrest,
			      ks.getLionessKeys("END-TO-END ENCRYPT"))
	    comp = BuildMessage.compressData(payload)
	    self.assert_(len(comp), ord(msg[0])*256 + ord(msg[1]))
	    self.assertEquals(sha1(msg[22:]), msg[2:22])
	    self.assert_(msg[22:].startswith(comp))

    def test_buildreply(self):
        brbi = BuildMessage._buildReplyBlockImpl
        brb = BuildMessage.buildReplyBlock
        brm = BuildMessage.buildReplyMessage

        ## Stateful reply blocks.
        reply, secrets_1, tag_1 = \
             brbi([self.server3, self.server1, self.server2,
                  self.server1, self.server3],
                 SMTP_TYPE,
		 "no-such-user@invalid", tag=("+"*20))
	hsecrets = secrets_1[:-1]
	hsecrets.reverse()

        pks_1 = (self.pk3, self.pk1, self.pk2, self.pk1, self.pk3)
        infos = (self.server1.getRoutingInfo().pack(),
                 self.server2.getRoutingInfo().pack(),
                 self.server1.getRoutingInfo().pack(),
                 self.server3.getRoutingInfo().pack())

        self.assert_(reply.routingInfo == self.server3.getRoutingInfo().pack())

        m = brm("Information???",
                [self.server3, self.server1],
                reply)

	messages = {}
	def decoder(p,t,secrets=secrets_1,messages=messages):
	    messages['repl'] = p,t
	    return BuildMessage._decodeReplyPayload(p,secrets)

        self.do_message_test(m,
                             ((self.pk3, self.pk1), None,
                              (FWD_TYPE,SWAP_FWD_TYPE),
                              (self.server1.getRoutingInfo().pack(),
                               self.server3.getRoutingInfo().pack())),
                             (pks_1, hsecrets,
                              (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,SMTP_TYPE),
                              infos+("no-such-user@invalid",)),
                             "Information???",
			     decoder=decoder)
        ## Stateless replies
        reply = brb([self.server3, self.server1, self.server2,
                      self.server1, self.server3], MBOX_TYPE,
                     "fred", "Tyrone Slothrop", 0)

        sec,(loc,), _ = self.do_header_test(reply.header, pks_1, None,
                            (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,MBOX_TYPE),
                            infos+(None,))

	self.assertEquals(loc[20:], "fred")

	seed = loc[:20]
	prng = AESCounterPRNG(sha1(seed+"Tyrone SlothropGenerate")[:16])
	sec.reverse()
	self.assertEquals(sec, [ prng.getBytes(16) for _ in range(len(sec)) ])

	# _Gravity's Rainbow_, page 258.
	payload = '''
              "...Is it any wonder the world's gone insane, with information
	    come to the be the only medium of exchange?"
	      "I thought it was cigarettes."
	      "You dream."
	          -- Gravity's Rainbow, p.258 ''' # " <- for emacs python-mode
        m = brm(payload,
                [self.server3, self.server1],
                reply)

	def decoder2(p,t,messages=messages):
	    messages['srepl'] = p,t
	    return BuildMessage._decodeStatelessReplyPayload(p,t,
							 "Tyrone Slothrop")
        self.do_message_test(m,
                             ((self.pk3, self.pk1), None,
                              (FWD_TYPE,SWAP_FWD_TYPE),
                              (self.server1.getRoutingInfo().pack(),
                               self.server3.getRoutingInfo().pack())),
                             (pks_1, None,
                              (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,MBOX_TYPE),
                              infos+("fred",)),
			     payload,
			     decoder=decoder2)

	# Now test format of generated messages.
	p,t = messages['repl']
	self.assertEquals(t, tag_1)
	for s in secrets_1:
	    ks = Keyset(s)
	    p = lioness_encrypt(p, ks.getLionessKeys(
 	 	               Crypto.PAYLOAD_ENCRYPT_MODE))
	comp = BuildMessage.compressData('Information???')
	self.assertEquals(len(comp), ord(p[0])*256 +ord(p[1]))
	self.assert_(p[22:].startswith(comp))
	self.assertEquals(sha1(p[22:]), p[2:22])

	p,t = messages['srepl']
	self.assertEquals('\000', sha1(t+"Tyrone SlothropValidate")[-1])
	prng = AESCounterPRNG(sha1(t+"Tyrone SlothropGenerate")[:16])
	for _ in xrange(6): # 5 hops plus end-to-end
	    s = prng.getBytes(16)
	    ks = Keyset(s)
	    p = lioness_encrypt(p, ks.getLionessKeys(
		                      Crypto.PAYLOAD_ENCRYPT_MODE))
	comp = BuildMessage.compressData(payload)
	self.assertEquals(len(comp), ord(p[0])*256 +ord(p[1]))
	self.assert_(p[22:].startswith(comp))
	self.assertEquals(sha1(p[22:]), p[2:22])

    def test_decoding(self):
	# Now we create a bunch of fake payloads and try to decode them.

	# Successful messages:
	payload = "All dreamers and sleepwalkers must pay the price, and "+\
	  "even the invisible victim is responsible for the fate of all.\n"+\
	  "   -- _Invisible Man_"

	comp = BuildMessage.compressData(payload)
	self.assertEquals(len(comp), 109)
	encoded1 = (comp+ "RWE/HGW"*4096)[:28*1024-22]
	encoded1 = '\x00\x6D'+sha1(encoded1)+encoded1
	# Forward message.
	self.assertEquals(payload, BuildMessage._decodeForwardPayload(encoded1))

	# Encoded forward message
	efwd = (comp+"RWE/HGW"*4096)[:28*1024-22-38]
	efwd = '\x00\x6D'+sha1(efwd)+efwd
	rsa1 = self.pk1
	key1 = Keyset("RWE "*4).getLionessKeys("END-TO-END ENCRYPT")
	efwd_rsa = pk_encrypt(("RWE "*4)+efwd[:70], rsa1)
	efwd_lioness = lioness_encrypt(efwd[70:], key1)
	efwd_t = efwd_rsa[:20]
	efwd_p = efwd_rsa[20:]+efwd_lioness
	self.assertEquals(payload,
	     BuildMessage._decodeEncryptedForwardPayload(efwd_p,efwd_t,rsa1))

## 	# Stateful reply
## 	secrets = [ "Is that you, Des","troyer?Rinehart?" ]
## 	sdict = { 'tag1'*5 : secrets }
## 	ks = Keyset(secrets[1])
## 	m = lioness_decrypt(encoded1, ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))
## 	ks = Keyset(secrets[0])
## 	m = lioness_decrypt(m, ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))
## 	self.assertEquals(payload, BuildMessage._decodeReplyPayload(m,secrets))
## 	repl1 = m

	# Stateless reply
	tag = "To light my way out\xBE"
	passwd = "out I would have to burn every paper in the briefcase"
	self.assertEquals('\000', sha1(tag+passwd+"Validate")[-1])
	prng = AESCounterPRNG(sha1(tag+passwd+"Generate")[:16])
	secrets2 = [ prng.getBytes(16) for _ in xrange(5) ]
	m = encoded1
	s = secrets2[:]
	s.reverse()
	for k in s:
	    key = Keyset(k).getLionessKeys(PAYLOAD_ENCRYPT_MODE)
	    m = lioness_decrypt(m,key)
	self.assertEquals(payload,
		     BuildMessage._decodeStatelessReplyPayload(m,tag,passwd))
	repl2, repl2tag = m, tag

	#
	# Okay, now let's try out 'decodePayload' (and thereby test its
	# children).  First, we test all the cases that succeed; or that
	# fail and return None to indicate that another key might decrypt
	# the message.
	decodePayload = BuildMessage.decodePayload
	# fwd
	for pk in (self.pk1, None):
	    ##for d in (sdict, None): # stateful replies disabled.
		for p in (passwd, None):
		    for tag in ("zzzz"*5, "pzzz"*5):
			self.assertEquals(payload,
					  decodePayload(encoded1, tag, pk, p))

	# efwd
	##for d in (sdict, None): # stateful replies disabled
	if 1:
	    for p in (passwd, None):
		self.assertEquals(payload,
		        decodePayload(efwd_p, efwd_t, self.pk1, p))
		self.assertEquals(None,
		        decodePayload(efwd_p, efwd_t, None, p))
		self.assertEquals(None,
		        decodePayload(efwd_p, efwd_t, self.pk2, p))

	# Stateful replies are disabled.

## 	# repl (stateful)
## 	sdict2 = { 'tag2'*5 : [secrets] + [ '\x00\xFF'*8] }
## 	for pk in (self.pk1, None):
## 	    for p in (passwd, None):
## 		sd = sdict.copy()
## 		self.assertEquals(payload,
## 		       decodePayload(repl1, "tag1"*5, pk, sd, p))
## 		self.assert_(not sd)
## 		self.assertEquals(None,
## 		       decodePayload(repl1, "tag1"*5, pk, None, p))
## 		self.assertEquals(None,
## 		       decodePayload(repl1, "tag1"*5, pk, sdict2, p))

	# repl (stateless)
	for pk in (self.pk1, None):
	    #for sd in (sdict, None): #Stateful replies are disabled
		self.assertEquals(payload,
			    decodePayload(repl2, repl2tag, pk, passwd))
		self.assertEquals(None,
			    decodePayload(repl2, repl2tag, pk, "Bliznerty"))
		self.assertEquals(None,
			    decodePayload(repl2, repl2tag, pk, None))

	# And now the cases that fail hard.  This can only happen on:
	#   1) *: Hash checks out, but zlib or size is wrong.  Already tested.
	#   2) EFWD: OAEP checks out, but hash is wrong.
	#   3) REPLY: Tag matches; hash doesn't.
	#   4) SREPLY: ---.

	# Bad efwd
	efwd_pbad = efwd_p[:-1] + chr(ord(efwd_p[-1])^0xaa)
	self.failUnlessRaises(MixError,
			      BuildMessage._decodeEncryptedForwardPayload,
			      efwd_pbad, efwd_t, self.pk1)
	#for d in (sdict, None):
	if 1:
	    for p in (passwd, None):
		self.failUnlessRaises(MixError, decodePayload,
				      efwd_pbad, efwd_t, self.pk1, p)
		self.assertEquals(None,
			  decodePayload(efwd_pbad, efwd_t, self.pk2, p))

## 	# Bad repl
## 	repl2_bad = repl2[:-1] + chr(ord(repl1[-1])^0xaa)
## 	for pk in (self.pk1, None):
## 	    for p in (passwd, None):
## 		#sd = sdict.copy()
## 		self.failUnlessRaises(MixError,
## 			 decodePayload, repl1_bad, "tag1"*5, pk, p)
## 		#sd = sdict.copy()
## 		self.failUnlessRaises(MixError,
## 			 BuildMessage._decodeReplyPayload, repl1_bad,
## 				      sd["tag1"*5])
	# Bad srepl
	repl2_bad = repl2[:-1] + chr(ord(repl2[-1])^0xaa)
	self.assertEquals(None,
		  decodePayload(repl2_bad, repl2tag, None, passwd))

#----------------------------------------------------------------------
# Having tested BuildMessage without using PacketHandler, we can now use
# BuildMessage to see whether PacketHandler is doing the right thing.
#
# (of course, we still need to build failing messages by hand)

class PacketHandlerTests(unittest.TestCase):
    def setUp(self):
        self.pk1 = getRSAKey(0,1024)
        self.pk2 = getRSAKey(1,1024)
        self.pk3 = getRSAKey(2,1024)
        self.tmpfile = mix_mktemp(".db")
        h = self.hlog = HashLog(self.tmpfile, "Z"*20)

        self.server1 = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        self.server2 = FakeServerInfo("127.0.0.2", 3, self.pk2, "Z"*20)
        self.server3 = FakeServerInfo("127.0.0.3", 5, self.pk3, "Q"*20)
        self.sp1 = PacketHandler(self.pk1, h)
        self.sp2 = PacketHandler(self.pk2, h)
        self.sp3 = PacketHandler(self.pk3, h)
        self.sp2_3 = PacketHandler((self.pk2,self.pk3), (h,h))

    def tearDown(self):
        self.hlog.close()

    def do_test_chain(self, m, sps, routingtypes, routinginfo, payload,
		      appkey=None):
        """Routes a message through a series of servers, making sure that
           each one decrypts it properly and routes it correctly to the
           next.
                    m: the message to test
                    sps: sequence of PacketHandler objects for m's path
                    routingtypes: sequence of expected routingtype
                    routinginfo: sequence of expected routinginfo, excl tags
                    payload: beginning of expected final payload."""
        for sp, rt, ri in zip(sps,routingtypes,routinginfo):
            res = sp.processMessage(m)
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
                if appkey:
                    self.assertEquals(appkey, res[1][2])

		#tag = res[1][3]
		p = res[1][4]
		p = BuildMessage._decodeForwardPayload(p)
                self.assert_(p.startswith(payload))
                break

    def test_successful(self):
        bfm = BuildMessage.buildForwardMessage
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
        m = bfm(p, SMTP_TYPE, "nobody@invalid", [self.server1], [self.server3])

        self.do_test_chain(m,
                           [self.sp1,self.sp3],
                           [FWD_TYPE, SMTP_TYPE],
                           [self.server3.getRoutingInfo().pack(),
                            "nobody@invalid"],
                           p)

        # Try servers with multiple keys
        m = bfm(p, SMTP_TYPE, "nobody@invalid", [self.server2], [self.server3])
        self.do_test_chain(m, [self.sp2_3, self.sp2_3], [FWD_TYPE, SMTP_TYPE],
                           [self.server3.getRoutingInfo().pack(),
                            "nobody@invalid"], p)

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
        bfm = BuildMessage.buildForwardMessage
        brm = BuildMessage.buildReplyMessage
        brbi = BuildMessage._buildReplyBlockImpl

        # A long intermediate header needs to fail.
        server1X = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        class _packable:
            def pack(self): return "x"*200
        server1X.getRoutingInfo = lambda _packable=_packable: _packable()

        m = bfm("Z", MBOX_TYPE, "hello\000bye",
                [self.server2, server1X, self.server3],
                [server1X, self.server2, self.server3])
        self.failUnlessRaises(ContentError, self.sp2.processMessage, m)

        # Duplicate messages need to fail.
        m = bfm("Z", SMTP_TYPE, "nobody@invalid",
                [self.server1, self.server2], [self.server3])
        self.sp1.processMessage(m)
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m)

        # Duplicate reply blocks need to fail
        reply,s,tag = brbi([self.server3], SMTP_TYPE, "fred@invalid")
        m = brm("Y", [self.server2], reply)
        m2 = brm("Y", [self.server1], reply)
        q, (a,m) = self.sp2.processMessage(m)
        self.sp3.processMessage(m)
        q, (a,m2) = self.sp1.processMessage(m2)
        self.failUnlessRaises(ContentError, self.sp3.processMessage, m2)

        # Even duplicate secrets need to go.
        prng = AESCounterPRNG(" "*16)
        reply1,s,t = brbi([self.server1], SMTP_TYPE, "fred@invalid",0,prng)
        prng = AESCounterPRNG(" "*16)
        reply2,s,t = brbi([self.server2], MBOX_TYPE, "foo",0,prng)
        m = brm("Y", [self.server3], reply1)
        m2 = brm("Y", [self.server3], reply2)
        q, (a,m) = self.sp3.processMessage(m)
        self.sp1.processMessage(m)
        q, (a,m2) = self.sp3.processMessage(m2)
        self.failUnlessRaises(ContentError, self.sp2.processMessage, m2)

        # Drop gets dropped.
        m = bfm("Z", DROP_TYPE, "", [self.server2], [self.server2])
        q, (a,m) = self.sp2.processMessage(m)
        res = self.sp2.processMessage(m)
        self.assertEquals(res,None)

        # Wrong server.
        m = bfm("Z", DROP_TYPE, "", [self.server1], [self.server2])
        self.failUnlessRaises(CryptoError, self.sp2.processMessage, m)
        self.failUnlessRaises(CryptoError, self.sp2_3.processMessage, m)

        # Plain junk in header
        m_x = ("XY"*64)+m[128:]
        self.failUnlessRaises(CryptoError, self.sp1.processMessage, m_x)

        # Bad message length
        m_x = m+"Z"
        self.failUnlessRaises(ParseError, self.sp1.processMessage, m_x)

        # Bad internal type
	try:
	    # (We temporarily override the setting from 'BuildMessage',
	    #  not Packet; BuildMessage has already imported a copy of this
	    #  constant.)
	    save = mixminion.BuildMessage.SWAP_FWD_TYPE
	    mixminion.BuildMessage.SWAP_FWD_TYPE = 50
	    m_x = bfm("Z", 500, "", [self.server1], [self.server2])
	finally:
	    mixminion.BuildMessage.SWAP_FWD_TYPE = save
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Subhead we can't parse
        m_x = pk_encrypt("foo", self.pk1)+m[128:]
        self.failUnlessRaises(ParseError, self.sp1.processMessage, m_x)

        # Bad IPV4 info
        subh_real = pk_decrypt(m[:128], self.pk1)
        subh = parseSubheader(subh_real)
        subh.setRoutingInfo(subh.routinginfo + "X")
        m_x = pk_encrypt(subh.pack(), self.pk1)+m[128:]
        self.failUnlessRaises(ParseError, self.sp1.processMessage, m_x)

        # Subhead that claims to be impossibly long: FWD case
        subh = parseSubheader(subh_real)
        subh.setRoutingInfo("X"*100)
        m_x = pk_encrypt(subh.pack(), self.pk1)+m[128:]
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Subhead that claims to be impossibly long: exit case
        subh = parseSubheader(subh_real)
        subh.routingtype = MBOX_TYPE
        subh.setRoutingInfo("X"*10000)
        m_x = pk_encrypt(subh.pack(), self.pk1)+m[128:]
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Bad Major or Minor
        subh = parseSubheader(subh_real)
        subh.major = 255
        m_x = pk_encrypt(subh.pack(), self.pk1)+m[128:]
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Bad digest
        subh = parseSubheader(subh_real)
        subh.digest = " "*20
        m_x = pk_encrypt(subh.pack(), self.pk1)+m[128:]
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Corrupt payload
        m = bfm("Z", MBOX_TYPE, "Z", [self.server1, self.server2],
                [self.server3])
        m_x = m[:-30] + " "*30
        assert len(m_x) == len(m)
        q, (a, m_x) = self.sp1.processMessage(m_x)
        q, (a, m_x) = self.sp2.processMessage(m_x)
        self.failUnlessRaises(CryptoError, self.sp3.processMessage, m_x)


#----------------------------------------------------------------------
# QUEUE


class TestDeliveryQueue(DeliveryQueue):
    def __init__(self,d):
	DeliveryQueue.__init__(self,d)
	self._msgs = None
    def _deliverMessages(self, msgList):
	self._msgs = msgList

class QueueTests(unittest.TestCase):
    def setUp(self):
        mixminion.Common.installSignalHandlers(child=1,hup=0,term=0)
        self.d1 = mix_mktemp("q1")
        self.d2 = mix_mktemp("q2")
        self.d3 = mix_mktemp("q3")

    def testCreateQueue(self):
        # Nonexistent dir.
        self.failUnlessRaises(MixFatalError, Queue, self.d1)
        # File in place of dir
        writeFile(self.d1, "   ")
        self.failUnlessRaises(MixFatalError, Queue, self.d1)
        self.failUnlessRaises(MixFatalError, Queue, self.d1, create=1)
        os.unlink(self.d1)

        # Try to create
        queue = Queue(self.d1, create=1)
        self.failUnless(os.path.isdir(self.d1))
        self.assertEquals(0700, os.stat(self.d1)[stat.ST_MODE] & 0777)
        self.assertEquals(0, len(os.listdir(self.d1)))
        queue.queueMessage("Hello world 1")
        h2 = queue.queueMessage("Hello world 2")
        self.assertEquals(2, len(os.listdir(self.d1)))
        self.assertEquals(2, queue.count())

        # Make sure recreate doesn't bonk
        queue = Queue(self.d1, create=1)

        # Use a queue we haven't just made.
        queue = Queue(self.d1)
        self.assertEquals(2, queue.count())
        self.assertEquals(queue.messageContents(h2), "Hello world 2")
        queue.removeMessage(h2)
        self.assertEquals(1, queue.count())

        queue.removeAll()

    def testQueueOps(self):
        queue1 = Queue(self.d2, create=1)
        queue2 = Queue(self.d3, create=1)

        # Put 100 messages in queue1
        handles = [queue1.queueMessage("Sample message %s" % i)
                   for i in range(100)]
        hdict = {}
        for i in range(100): hdict[handles[i]] = i
        # Make sure that queue1 has all 100 elements
        self.assertEquals(queue1.count(), 100)
        self.assertEquals(len(handles), 100)

        # Get the messages in random order, and make sure the contents
        # of each one are correct
        foundHandles = queue1.pickRandom(100)
        self.assertEquals(len(foundHandles), 100)
        for h in foundHandles:
            self.failUnless(hdict.has_key(h))
            i = hdict[h]
            self.assertEquals("Sample message %s" %i,
                              queue1.messageContents(h))

        assert len(hdict) == len(handles) == 100

        # Move the first 30 messages to queue2
        q2h = []
        for h in handles[:30]:
            nh = queue1.moveMessage(h, queue2)
            q2h.append(nh)

        # Look at the messages in queue2, 15 then 30 at a time.
        for group in queue2.pickRandom(15), queue2.pickRandom(30):
            seen = {}
            for h in group:
                c = queue2.messageContents(h)
                self.failUnless(c.startswith("Sample message "))
                i = atoi(c[15:])
                self.failIf(seen.has_key(i))
                seen[i]=1

        # Make sure that we got all 30 messages
        for i in range(30):
            self.failUnless(seen.has_key(i))

        # Remove messages 30..59 from queue1.
        for h in handles[30:60]:
            queue1.removeMessage(h)
        self.assertEquals(40, queue1.count())

        # Make sure that smaller pickRandoms work.
        L1 = queue1.pickRandom(10)
        L2 = queue1.pickRandom(10)
        self.failUnless(len(L1) == 10)
        self.failUnless(len(L2) == 10)
        self.failUnless(L1 != L2)

        # Test 'openMessage'
        f = queue1.openMessage(handles[60])
        s = f.read()
        f.close()
        self.assertEquals(s, "Sample message 60")

        # test successful 'openNewMessage'
        f, h = queue1.openNewMessage()
        f.write("z"*100)
        self.failUnlessRaises(IOError, queue1.messageContents, h)
        self.assertEquals(queue1.count(), 40)
        queue1.finishMessage(f,h)
        self.assertEquals(queue1.messageContents(h), "z"*100)
        self.assertEquals(queue1.count(), 41)

        # test aborted 'openNewMessage'
        f, h = queue1.openNewMessage()
        f.write("z"*100)
        queue1.abortMessage(f,h)
        self.failUnlessRaises(IOError, queue1.messageContents, h)
        self.assertEquals(queue1.count(), 41)
        self.assert_(not os.path.exists(os.path.join(self.d2, "msg_"+h)))

	# Test object functionality
	obj = [ ("A pair of strings", "in a tuple in a list") ]
	h1 = queue1.queueObject(obj)
	h2 = queue1.queueObject(6060842)
	self.assertEquals(obj, queue1.getObject(h1))
	self.assertEquals(6060842, queue1.getObject(h2))
	self.assertEquals(obj, cPickle.loads(queue1.messageContents(h1)))

        # Scrub both queues.
        queue1.removeAll()
        queue2.removeAll()
        queue1.cleanQueue()
        queue2.cleanQueue()

    def testDeliveryQueues(self):
	d_d = mix_mktemp("qd")

	queue = TestDeliveryQueue(d_d)

	# First, make sure the queue stores messages correctly.
	h1 = queue.queueDeliveryMessage("Address 1", "Message 1")
	h2 = queue.queueDeliveryMessage("Address 2", "Message 2")
	self.assertEquals((0, "Address 1", "Message 1"), queue.get(h1))

	# Call sendReadyMessages to begin 'sending' msg1 and msg2.
	queue.sendReadyMessages()
	msgs = queue._msgs
	self.assertEquals(2, len(msgs))
	# _deliverMessages should have gotten them both.
	self.failUnless((h1, "Address 1", "Message 1", 0) in msgs)
	self.failUnless((h2, "Address 2", "Message 2", 0) in msgs)
	# Add msg3, and acknowledge that msg1 succeeded.  msg2 is now in limbo
	h3 = queue.queueDeliveryMessage("Address 3", "Message 3")
	queue.deliverySucceeded(h1)
	# Only msg3 should get sent out, since msg2 is still in progress.
	queue.sendReadyMessages()
	msgs = queue._msgs
	self.assertEquals([(h3, "Address 3", "Message 3", 0)], msgs)

	# Now, make sure that msg1 is gone from the pool.
	allHandles = queue.getAllMessages()
	allHandles.sort()
	exHandles = [h2,h3]
	exHandles.sort()
	self.assertEquals(exHandles, allHandles)

	# Now, fail msg2 retriably, and fail msg3 hard.  Only one message
	# should be left.  (It will have a different handle from the old
	# msg2.)
	queue.deliveryFailed(h2, retriable=1)
	queue.deliveryFailed(h3, retriable=0)
	allHandles = queue.getAllMessages()
	h4 = allHandles[0]
	self.assertEquals([h4], queue.getAllMessages())
	# When we try to send messages again, msg2 should be atttempted.
	queue.sendReadyMessages()
	msgs = queue._msgs
	self.assertEquals([(h4, "Address 2", "Message 2", 1)], msgs)
	self.assertNotEquals(h2, h4)

	queue.removeAll()
	queue.cleanQueue()

    def testMixQueues(self):
	d_m = mix_mktemp("qm")

	# Trivial 'TimedMixQueue'
	queue = TimedMixQueue(d_m)
	h1 = queue.queueMessage("Hello1")
	h2 = queue.queueMessage("Hello2")
	h3 = queue.queueMessage("Hello3")
	b = queue.getBatch()
	msgs = [h1,h2,h3]
	msgs.sort()
	b.sort()
	self.assertEquals(msgs,b)

	# Now, test the CottrellMixQueue.
	cmq = CottrellMixQueue(d_m, 600, 6, sendRate=.3)
	# Not enough messages (<= 6) -- none will be sent.
	self.assertEquals([], cmq.getBatch())
	self.assertEquals([], cmq.getBatch())
	# 8 messages: 2 get sent
	for i in range(5):
	    cmq.queueMessage("Message %s"%i)
	self.assertEquals(8, cmq.count())
	b1, b2, b3 = cmq.getBatch(), cmq.getBatch(), cmq.getBatch()
	self.assertEquals(2, len(b1))
	self.assertEquals(2, len(b2))
	self.assertEquals(2, len(b3))

	# Make sure that all message batches are different.
	allEq = 1
	for x in xrange(13): #fails <one in a trillion
	    b = cmq.getBatch()
	    if b != b1:
		allEq = 0; break
	self.failIf(allEq)

	# Send 30 when there are 100 messages.
	for x in xrange(92):
	    cmq.queueMessage("Hello2 %s"%x)
	for x in xrange(10):
	    self.assertEquals(30, len(cmq.getBatch()))

	# Binomial Cottrell pool
	bcmq = BinomialCottrellMixQueue(d_m, 600, 6, sendRate=.3)
	# (Just make sure that we don't always return the same number of
	#  messages each time.)
	messageLens = []
	for i in range(31):
	    b = bcmq.getBatch()
	    messageLens.append(len(b))
	messageLens.sort()
	self.failIf(messageLens[0] == messageLens[-1])
	# (Fails less than once in 2 **30 tests.)
	self.assert_(messageLens[0] <= 30)
	self.assert_(messageLens[-1] >= 30)
	#print messageLens

	bcmq.removeAll()
	bcmq.cleanQueue()

#---------------------------------------------------------------------
# LOGGING
class LogTests(unittest.TestCase):
    def testLogging(self):

	# Create a new loghandler, and try sending a few messages to it.
        log = Log("INFO")
        self.assertEquals(log.getMinSeverity(), "INFO")
	log.handlers = []
        log.log("WARN", "This message should not appear")
        buf = cStringIO.StringIO()
        log.addHandler(_ConsoleLogHandler(buf))
        log.trace("Foo")
        self.assertEquals(buf.getvalue(), "")
        log.log("WARN", "Hello%sworld", ", ")
        self.failUnless(buf.getvalue().endswith(
            "[WARN] Hello, world\n"))
        self.failUnless(buf.getvalue().index('\n') == len(buf.getvalue())-1)
        log.error("All your anonymity are belong to us")
        self.failUnless(buf.getvalue().endswith(
            "[ERROR] All your anonymity are belong to us\n"))

	buf.truncate(0)

	# Try out error_exc.
	try:
	    raise MixError()
	except:
	    inf = sys.exc_info()
	log.error_exc(inf)
	log.error_exc(inf, "And so on")
	log.error_exc(inf, "And so %s", "on")

	# print buf.getvalue()
	# FFFF We should examine the value of the above, but inspection
	# FFFF show that we're fine.

	# Try out file logging
        t = mix_mktemp("log")
        t1 = t+"1"

        log.addHandler(_FileLogHandler(t))
        log.info("Abc")
        log.info("Def")
        os.rename(t,t1)
        log.info("Ghi")
        log.reset()
        log.info("Klm")
        log.close()
        self.assertEquals(readFile(t).count("\n") , 1)
        self.assertEquals(readFile(t1).count("\n"), 3)

#----------------------------------------------------------------------
# File paranoia


class FileParanoiaTests(unittest.TestCase):
    def testPrivateDirs(self):
	# Pick a private directory under tempdir, but don't create it.
	noia = mix_mktemp("noia")
	tempdir = mixminion.testSupport._MM_TESTING_TEMPDIR

	# If our tempdir doesn't exist and isn't private, we can't go on.
	try:
	    checkPrivateDir(tempdir)
	except MixFatalError, e:
	    self.fail("Can't test directory paranoia, because something's\n"
		      +" wrong with %s: %s"%(tempdir, str(e)))

	# Nonexistant directory.
	self.failUnlessRaises(MixFatalError, checkPrivateDir, noia)
	# Bad permissions.
	os.mkdir(noia)
	os.chmod(noia, 0777)
	self.failUnlessRaises(MixFatalError, checkPrivateDir, noia)
	# Bad permissions on parent
	subdir = os.path.join(noia, "subdir")
	os.mkdir(subdir, 0700)
	self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
	os.chmod(noia, 0755)
	checkPrivateDir(subdir)
	os.chmod(noia, 0700)
	checkPrivateDir(subdir)
	# Not writable by self
	os.chmod(subdir, 0600)
	self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
	# Not a directory
	os.rmdir(subdir)
	writeFile(subdir, "x")
	os.chmod(subdir, 0700)
	self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
	os.unlink(subdir)
	os.mkdir(subdir, 0700)

	# Now we test a directory we don't own...
	if os.getuid() == 0: # If we're root, we can play with chown!
	    # We don't own the directory
	    os.chown(subdir, 1, 1)
	    self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
	    os.chown(subdir, 0, os.getgid())
	    # We don't own the parent
	    os.chown(noia, 1, 1)
	    self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
	    os.chown(noia, 0, os.getgid())
	else:
	    # We're not root.  We can't reliably find or make a directory
	    # that's non-root and non-us.  Let's just make sure we don't
	    # own temp.
	    if os.path.exists("/tmp"):
		self.failUnlessRaises(MixFatalError, checkPrivateDir, "/tmp")

	# Helper fn: return mode,uid,isdir
	def mud(f):
	    st = os.stat(f)
	    return st[stat.ST_MODE]&0777, st[stat.ST_UID], os.path.isdir(f)

	# Okay.  Now we try createPrivateDir a couple of times...
	old_mask = None
	try:
	    # Make sure umask is lenient, so we can tell whether c-p-d is
	    # strict.
	    old_mask = os.umask(022)
	    # 1. Create the world.
	    os.rmdir(subdir)
	    os.rmdir(noia)
	    createPrivateDir(subdir)
	    self.assertEquals((0700,os.getuid(),1), mud(subdir))
	    self.assertEquals((0700,os.getuid(),1), mud(noia))
	    # 2. Just create one dir.
	    os.rmdir(subdir)
	    os.chmod(noia, 0755)
	    createPrivateDir(subdir)
	    self.assertEquals((0700,os.getuid(),1), mud(subdir))
	    self.assertEquals((0755,os.getuid(),1), mud(noia))
	    # 3. Fail to create because of bad permissions
	    os.rmdir(subdir)
	    os.chmod(noia, 0777)
	    self.failUnlessRaises(MixFatalError, createPrivateDir, subdir)
	    # 4. Fail to create because of OSError
	    os.rmdir(subdir)
	    writeFile(subdir, 'W')
	    self.failUnlessRaises(MixFatalError, createPrivateDir, subdir)
	    os.unlink(subdir)
	    # 5. Succeed: it's already there.
	    os.chmod(noia, 0700)
	    os.mkdir(subdir, 0700)
	    createPrivateDir(subdir)
	    # 6. Fail: it's already there, but has bad permissions
	    os.chmod(subdir, 0777)
	    self.failUnlessRaises(MixFatalError, createPrivateDir, subdir)
	    os.chmod(subdir, 0700)
	finally:
	    if old_mask is not None:
		os.umask(old_mask)

#----------------------------------------------------------------------
# SIGHANDLERS
# FFFF Write tests here


#----------------------------------------------------------------------
# MMTP
# FFFF Write more tests

# Run on a different port so we don't conflict with any actual servers
# running on this machine.
TEST_PORT = 40199

dhfile = pkfile = certfile = None

def _getTLSContext(isServer):
    "Helper function: create a new TLSContext object."
    global dhfile
    global pkfile
    global certfile
    if isServer:
        if dhfile is None:
            f = mix_mktemp()
            dhfile = f+"_dh"
            pkfile = f+"_pk"
            certfile = f+"_cert"
            dh_fname = os.environ.get("MM_TEST_DHPARAMS", None)
            if dh_fname and not USE_SLOW_MODE:
                dhfile = dh_fname
                if not os.path.exists(dh_fname):
		    print "[Generating DH parameters...",
		    sys.stdout.flush()
		    _ml.generate_dh_parameters(dhfile, 0)
		    print "done.]",
		    sys.stdout.flush()
            else:
		print "[Generating DH parameters (not caching)...",
		sys.stdout.flush()
                _ml.generate_dh_parameters(dhfile, 0)
		print "done.]",
		sys.stdout.flush()
            pk = getRSAKey(3,1024)
            pk.PEM_write_key(open(pkfile, 'w'), 0)
            _ml.generate_cert(certfile, pk, "Testing certificate",
                              time.time(), time.time()+365*24*60*60)

	pk = _ml.rsa_PEM_read_key(open(pkfile, 'r'), 0)
        return _ml.TLSContext_new(certfile, pk, dhfile)
    else:
        return _ml.TLSContext_new()

def _getMMTPServer():
    """Helper function: create a new MMTP server with a listener connection
       Return a tuple of AsyncServer, ListenerConnection, list of received
       messages, and keyid."""
    server = mixminion.server.MMTPServer.AsyncServer()
    messagesIn = []
    def receivedHook(pkt,m=messagesIn):
	m.append(pkt)
    def conFactory(sock, context=_getTLSContext(1),
		   receiveMessage=receivedHook):
	tls = context.sock(sock, serverMode=1)
	sock.setblocking(0)
	return mixminion.server.MMTPServer.MMTPServerConnection(sock,tls,
							 receiveMessage)
    listener = mixminion.server.MMTPServer.ListenConnection("127.0.0.1",
						 TEST_PORT, 5, conFactory)
    listener.register(server)
    pk = _ml.rsa_PEM_read_key(open(pkfile, 'r'), public=0)
    keyid = sha1(pk.encode_key(1))

    return server, listener, messagesIn, keyid

class MMTPTests(unittest.TestCase):

    def doTest(self, fn):
	"""Wraps an underlying test function 'fn' to make sure we kill the
	   MMTPServer, but don't block."""
        self.listener = self.server = None
        try:
            fn()
        finally:
            if self.listener is not None:
                self.listener.shutdown()
            if self.server is not None:
                count = 0
                while count < 100 and (self.server.readers or
                                       self.server.writers):
                    self.server.process(0.1)
                    count = count + 1

    def testBlockingTransmission(self):
        self.doTest(self._testBlockingTransmission)

    def testNonblockingTransmission(self):
        self.doTest(self._testNonblockingTransmission)

    def _testBlockingTransmission(self):
        server, listener, messagesIn, keyid = _getMMTPServer()
        self.listener = listener
        self.server = server

        messages = ["helloxxx"*4096, "helloyyy"*4096]

        server.process(0.1)
        t = threading.Thread(None,
                             mixminion.MMTPClient.sendMessages,
                             args=("127.0.0.1", TEST_PORT, keyid, messages))
        t.start()
        while len(messagesIn) < 2:
            server.process(0.1)
        t.join()

        for _ in xrange(10):
            server.process(0.1)

        self.failUnless(messagesIn == messages)

        # Now, with bad keyid.
        t = threading.Thread(None,
                             self.failUnlessRaises,
                             args=(MixProtocolError,
                                   mixminion.MMTPClient.sendMessages,
                                   "127.0.0.1", TEST_PORT, "Z"*20, messages))
        t.start()
        while t.isAlive():
            server.process(0.1)
        t.join()


    def _testNonblockingTransmission(self):
        server, listener, messagesIn, keyid = _getMMTPServer()
        self.listener = listener
        self.server = server

        messages = ["helloxxx"*4096, "helloyyy"*4096]
        async = mixminion.server.MMTPServer.AsyncServer()
        clientcon = mixminion.server.MMTPServer.MMTPClientConnection(
           _getTLSContext(0), "127.0.0.1", TEST_PORT, keyid, messages[:],
	   [None, None], None)
        clientcon.register(async)
        def clientThread(clientcon=clientcon, async=async):
            while not clientcon.isShutdown():
                async.process(2)

        server.process(0.1)
        t = threading.Thread(None, clientThread)

        t.start()
        while len(messagesIn) < 2:
            server.process(0.1)
        while t.isAlive():
            server.process(0.1)
        t.join()

        self.assertEquals(len(messagesIn), len(messages))
        self.failUnless(messagesIn == messages)

        # Again, with bad keyid.
        clientcon = mixminion.server.MMTPServer.MMTPClientConnection(
           _getTLSContext(0), "127.0.0.1", TEST_PORT, "Z"*20,
           messages[:], [None, None], None)
        clientcon.register(async)
        def clientThread2(clientcon=clientcon, async=async):
            while not clientcon.isShutdown():
                async.process(2)

        try:
	    suspendLog() # suppress warning
            server.process(0.1)
            t = threading.Thread(None, clientThread2)

            t.start()
            while t.isAlive():
                server.process(0.1)
            t.join()
        finally:
            resumeLog()  #unsuppress warning


#----------------------------------------------------------------------
# Config files


class TestConfigFile(_ConfigFile):
    _syntax = { 'Sec1' : {'__SECTION__': ('REQUIRE', None, None),
                          'Foo': ('REQUIRE', None, None),
                          'Bar': ('ALLOW', None, "default"),
                          'Baz': ('ALLOW', None, None),},
                'Sec2' : {'Fob': ('ALLOW*', None, None),
                          'Bap': ('REQUIRE', None, None),
                          'Quz': ('REQUIRE*', None, None), },
                'Sec3' : {'IntAS': ('ALLOW', _parseInt, None),
                          'IntAS2': ('ALLOW', _parseInt, None),
                          'IntASD': ('ALLOW', _parseInt, "5"),
                          'IntASD2': ('ALLOW', _parseInt, "5"),
                          'IntAM': ('ALLOW*', _parseInt, None),
                          'IntAMD': ('ALLOW*', _parseInt, ["5", "2"]),
                          'IntAMD2': ('ALLOW*', _parseInt, ["5", "2"]),
                          'IntRS': ('REQUIRE', _parseInt, None) }
                }
    def __init__(self, fname=None, string=None, restrict=0):
        self._restrictFormat = restrict
        _ConfigFile.__init__(self,fname,string)

class ConfigFileTests(unittest.TestCase):
    def testValidFiles(self):
        TCF = TestConfigFile
	# Try a minimal file.
        shorterString = """[Sec1]\nFoo a\n"""
        f = TCF(string=shorterString)
        self.assertEquals(f['Sec1']['Foo'], 'a')
	# Try a slightly more spaceful version of the above.
        f = TCF(string="""\n\n[ Sec1 ]  \n  \n\nFoo a  \n""")
        self.assertEquals(f['Sec1']['Foo'], 'a')
        self.assertEquals(f['Sec2'], {})

	# Now, try all the syntaxtical possibilities, and all the fields
        longerString = """[Sec1]

Foo=  abcde f

Bar bar
Baz:
  baz
  and more baz
  and more baz
[Sec2]

# Comment
Bap +
Quz 99 99


Fob=1
Quz : 88
     88

[Sec3]
IntAS=9
IntASD=10
IntAMD=8
IntAMD=10
IntRS=5

  """

        f = TCF(string=longerString)
        self.assertEquals(f['Sec1']['Foo'], 'abcde f')
        self.assertEquals(f['Sec1']['Bar'], 'bar')
        self.assertEquals(f['Sec1']['Baz'], ' baz and more baz and more baz')
        self.assertEquals(f['Sec2']['Bap'], '+')
        self.assertEquals(f['Sec2']['Fob'], ['1'])
        self.assertEquals(f['Sec2']['Quz'], ['99 99', '88 88'])
        self.assertEquals(f.getSectionItems('Sec2'),
                          [ ('Bap', '+'),
                            ('Quz', '99 99'),
                            ('Fob', '1'),
                            ('Quz', '88 88') ])

        # Make sure that str(f) works.
        self.assertEquals(str(f),
           ("[Sec1]\nFoo: abcde f\nBar: bar\nBaz:  baz and more baz"+
            " and more baz\n\n[Sec2]\nBap: +\nQuz: 99 99\nFob: 1\n"+
            "Quz: 88 88\n\n[Sec3]\nIntAS: 9\nIntASD: 10\nIntAMD: 8\n"+
            "IntAMD: 10\nIntRS: 5\n\n"))
        # Test file input
        fn = mix_mktemp()

        writeFile(fn, longerString)
        f = TCF(fname=fn)
        self.assertEquals(f['Sec1']['Bar'], 'bar')
        self.assertEquals(f['Sec2']['Quz'], ['99 99', '88 88'])

        self.assertEquals(f['Sec3']['IntAS'], 9)
        self.assertEquals(f['Sec3']['IntAS2'], None)
        self.assertEquals(f['Sec3']['IntASD'], 10)
        self.assertEquals(f['Sec3']['IntASD2'], 5)
        self.assertEquals(f['Sec3']['IntAM'], [])
        self.assertEquals(f['Sec3']['IntAMD'], [8,10])
        self.assertEquals(f['Sec3']['IntAMD2'], [5,2])
        self.assertEquals(f['Sec3']['IntRS'], 5)

        # Test failing reload
        writeFile(fn, "[Sec1]\nFoo=99\nBadEntry 3\n\n")
        self.failUnlessRaises(ConfigError, f.reload)
        self.assertEquals(f['Sec1']['Foo'], 'abcde f')
        self.assertEquals(f['Sec1']['Bar'], 'bar')
        self.assertEquals(f['Sec2']['Quz'], ['99 99', '88 88'])

        # Test 'reload' operation
        writeFile(fn, shorterString)
        f.reload()
        self.assertEquals(f['Sec1']['Foo'], 'a')
        self.assertEquals(f['Sec1']['Bar'], "default")
        self.assertEquals(f['Sec2'], {})

        # Test restricted mode
        s = "[Sec1]\nFoo: Bar\nBaz: Quux\n[Sec3]\nIntRS: 9\n"
        f = TCF(string=s, restrict=1)
        self.assertEquals(f['Sec1']['Foo'], "Bar")
        self.assertEquals(f['Sec3']['IntRS'], 9)

    def testBadFiles(self):
        def fails(string, self=self):
            self.failUnlessRaises(ConfigError, TestConfigFile, None, string)


	# Missing section header
        fails("Foo = Bar\n")
	# Invalid indentation on key
        fails("[Sec1]\n  Foo = Bar\n")
	# Invalid indentation on header
	fails("  [Sec1]\n  Foo = Bar\n")
	# Unrecognized key
        fails("[Sec1]\nFoo! Bar\n")

        fails("[Sec1]\nFoob: Bar\n") # No such key
        fails("[Sec1]\nFoo: Bar\nFoo: Bar\n") #  Duplicate key
        fails("[Sec1]\nBaz: 3\n") # Missing key
        fails("[Sec2]\nBap = 9\nQuz=6\n") # Missing section
        fails("[Sec1]\nFoo 1\n[Sec2]\nBap = 9\n") # Missing require*
        fails("[Sec1]\nFoo: Bar\n[Sec3]\nIntRS=Z\n") # Failed validation

        # now test the restricted format
        def failsR(string, self=self):
            self.failUnlessRaises(ConfigError, TestConfigFile, None, string, 1)
        failsR("[Sec1]\nFoo=Bar\n")
        failsR("[Sec1]\nFoo Bar\n")
        failsR("[Sec1]\n\nFoo: Bar\n")
        failsR("\n[Sec1]\nFoo: Bar\n")
        failsR("\n[Sec1]\nFoo: Bar\n\n")

    def testValidationFns(self):
        import mixminion.Config as C

	## First, check valid cases.
	# boolean
        self.assertEquals(C._parseBoolean("yes"), 1)
        self.assertEquals(C._parseBoolean(" NO"), 0)
	# severity
        self.assertEquals(C._parseSeverity("error"), "ERROR")
	# serverMode
        self.assertEquals(C._parseServerMode(" relay "), "relay")
        self.assertEquals(C._parseServerMode("Local"), "local")
	# interval
        self.assertEquals(C._parseInterval(" 1 sec "), (1,"second", 1))
        self.assertEquals(C._parseInterval(" 99 sec "), (99,"second", 99))
        self.failUnless(floatEq(C._parseInterval("1.5 minutes")[2],
                                90))
        self.assertEquals(C._parseInterval("2 houRS"), (2,"hour",7200))
	# int
        self.assertEquals(C._parseInt("99"), 99)
	# IP
        self.assertEquals(C._parseIP("192.168.0.1"), "192.168.0.1")
	# AddressSet
        pa = C._parseAddressSet_allow
        self.assertEquals(pa("*"), ("0.0.0.0", "0.0.0.0", 48099, 48099))
        self.assertEquals(pa("192.168.0.1/255.255.0.0"),
                          ("192.168.0.1", "255.255.0.0", 48099, 48099))
        self.assertEquals(pa("192.168.0.1 /  255.255.0.0  23-99"),
                          ("192.168.0.1", "255.255.0.0", 23, 99))
        self.assertEquals(pa("192.168.0.1 /  255.255.0.0  23"),
                          ("192.168.0.1", "255.255.0.0", 23, 23))
        self.assertEquals(pa("192.168.0.1"),
                          ("192.168.0.1", "255.255.255.255", 48099, 48099))
        self.assertEquals(pa("192.168.0.1",0),
                          ("192.168.0.1", "255.255.255.255", 0, 65535))

	# Command
	if not sys.platform == 'win32':
	    # FFFF This should get implemented for Windows.
	    self.assertEquals(C._parseCommand("ls -l"), ("/bin/ls", ['-l']))
	    self.assertEquals(C._parseCommand("rm"), ("/bin/rm", []))
	    self.assertEquals(C._parseCommand("/bin/ls"), ("/bin/ls", []))
	    self.failUnless(C._parseCommand("python")[0] is not None)

	# Base64
	self.assertEquals(C._parseBase64(" YW\nJj"), "abc")
	# Hex
	self.assertEquals(C._parseHex(" C0D0"), "\xC0\xD0")
	# Date
	tm = C._parseDate("2002/05/30")
	self.assertEquals(time.gmtime(tm)[:6], (2002,5,30,0,0,0))
	tm = C._parseDate("2000/01/01")
	self.assertEquals(time.gmtime(tm)[:6], (2000,1,1,0,0,0))
	# Time
	tm = C._parseTime("2001/12/25 06:15:10")
	self.assertEquals(time.gmtime(tm)[:6], (2001,12,25,6,15,10))

	##
	# Now, try the failing cases.
        def fails(fn, val, self=self):
            self.failUnlessRaises(ConfigError, fn, val)

        fails(C._parseBoolean, "yo")
        fails(C._parseBoolean, "'yo'")
        fails(C._parseBoolean, "")
        fails(C._parseSeverity, "really bad")
        fails(C._parseServerMode, "whatever")
        fails(C._parseInterval, "seconds")
        fails(C._parseInterval, "15")
        fails(C._parseInterval, " 10 intervals")
        fails(C._parseInt, "9.9")
        fails(C._parseInt, "9abc")
        fails(C._parseIP, "256.0.0.1")
        fails(C._parseIP, "192.0.0")
        fails(C._parseIP, "192.0.0.0.0")
        fails(C._parseIP, "A.0.0.0")
        fails(pa, "1/1")
        fails(pa, "192.168.0.1 50-40")
        fails(pa, "192.168.0.1 50-9999999")
	fails(C._parseBase64, "Y")
	fails(C._parseHex, "Z")
	fails(C._parseHex, "A")
	fails(C._parseDate, "2000/1/1")
	fails(C._parseDate, "2000/50/01")
	fails(C._parseDate, "2000/50/01 12:12:12")
	fails(C._parseTime, "2000/50/01 12:12:12")
	fails(C._parseTime, "2000/50/01 12:12:99")

        nonexistcmd = '/file/that/does/not/exist'
        if not os.path.exists(nonexistcmd):
            fails(C._parseCommand, nonexistcmd)
        else:
            print 'Whoa. Kurt Go"del would be proud of you.'

        # Nobody would ever have an executable named after my sister's
        # cats, would they?
        nonexistcmd = 'LindenAndPierre -meow'
        try:
            cmd, opts = C._parseCommand(nonexistcmd)
            if os.path.exists(cmd):
                # Ok, I guess they would.
                self.assertEquals(opts, ["-meow"])
            else:
                self.fail("_parseCommand is not working as expected")
        except ConfigError:
            # This is what we expect
            pass


#----------------------------------------------------------------------
# Server descriptors
SERVER_CONFIG = """
[Server]
EncryptIdentityKey: no
PublicKeyLifetime: 10 days
EncryptPrivateKey: no
Homedir: %s
Mode: relay
Nickname: The Server
Contact-Email: a@b.c
Comments: This is a test of the emergency
   broadcast system

[Incoming/MMTP]
Enabled = yes
IP: 192.168.0.1
Allow: 192.168.0.16 1-1024
Deny: 192.168.0.16
Allow: *

[Outgoing/MMTP]
Enabled = yes
Allow: *

[Delivery/MBOX]
Enabled: no

"""

SERVER_CONFIG_SHORT = """
[Server]
EncryptIdentityKey: no
PublicKeyLifetime: 10 days
EncryptPrivateKey: no
Homedir: %s
Mode: relay
Nickname: fred-the-bunny
"""


class ServerInfoTests(unittest.TestCase):
    def testServerInfoGen(self):
	# Try generating a serverinfo and see if its values are as expected.
	identity = getRSAKey(1, 2048)
        d = mix_mktemp()
	try:
	    suspendLog()
	    conf = mixminion.server.ServerConfig.ServerConfig(string=(SERVER_CONFIG % mix_mktemp()))
	finally:
	    resumeLog()
        if not os.path.exists(d):
            os.mkdir(d, 0700)

        inf = generateServerDescriptorAndKeys(conf,
					      identity,
					      d,
					      "key1",
					      d)
        info = mixminion.ServerInfo.ServerInfo(string=inf)
        eq = self.assertEquals
        eq(info['Server']['Descriptor-Version'], "0.1")
        eq(info['Server']['IP'], "192.168.0.1")
        eq(info['Server']['Nickname'], "The Server")
        self.failUnless(0 <= time.time()-info['Server']['Published'] <= 120)
        self.failUnless(0 <= time.time()-info['Server']['Valid-After']
                          <= 24*60*60)
        eq(info['Server']['Valid-Until']-info['Server']['Valid-After'],
           10*24*60*60)
        eq(info['Server']['Contact'], "a@b.c")
        eq(info['Server']['Comments'],
           "This is a test of the emergency broadcast system")

        eq(info['Incoming/MMTP']['Version'], "0.1")
        eq(info['Incoming/MMTP']['Port'], 48099)
        eq(info['Incoming/MMTP']['Protocols'], "0.1")
        eq(info['Outgoing/MMTP']['Version'], "0.1")
        eq(info['Outgoing/MMTP']['Protocols'], "0.1")
        eq(info['Incoming/MMTP']['Allow'], [("192.168.0.16", "255.255.255.255",
                                            1,1024),
                                           ("0.0.0.0", "0.0.0.0",
                                            48099, 48099)] )
        eq(info['Incoming/MMTP']['Deny'], [("192.168.0.16", "255.255.255.255",
                                            0,65535),
                                           ])
        eq(info['Delivery/MBOX'].get('Version'), None)

        # Now make sure everything was saved properly
        keydir = os.path.join(d, "key_key1")
        eq(inf, readFile(os.path.join(keydir, "ServerDesc")))
	mixminion.server.ServerKeys.ServerKeyset(d, "key1", d) # Can we load?
        packetKey = Crypto.pk_PEM_load(
            os.path.join(keydir, "mix.key"))
        eq(packetKey.get_public_key(),
           info['Server']['Packet-Key'].get_public_key())
        mmtpKey = Crypto.pk_PEM_load(
            os.path.join(keydir, "mmtp.key"))
        eq(Crypto.sha1(mmtpKey.encode_key(1)),
           info['Incoming/MMTP']['Key-Digest'])

        # Now check the digest and signature
        identityPK = info['Server']['Identity']
        pat = re.compile(r'^(Digest:|Signature:).*$', re.M)
        x = sha1(pat.sub(r'\1', inf))

        eq(info['Server']['Digest'], x)
        eq(x, Crypto.pk_check_signature(info['Server']['Signature'],
                                                  identityPK))

        # Now with a shorter configuration
	try:
	    suspendLog()
	    conf = mixminion.server.ServerConfig.ServerConfig(string=(SERVER_CONFIG_SHORT%mix_mktemp())+
					   """[Incoming/MMTP]
Enabled: yes
IP: 192.168.0.99
""")
	finally:
	    resumeLog()
	generateServerDescriptorAndKeys(conf,
	                                identity,
					d,
					"key2",
					d)
        # Now with a bad signature
        sig2 = Crypto.pk_sign(sha1("Hello"), identity)
        sig2 = base64.encodestring(sig2).replace("\n", "")
        sigpat = re.compile('^Signature:.*$', re.M)
        badSig = sigpat.sub("Signature: %s" % sig2, inf)
        self.failUnlessRaises(ConfigError,
                              mixminion.ServerInfo.ServerInfo,
                              None, badSig)

        # But make sure we don't check the sig on assumeValid
        mixminion.ServerInfo.ServerInfo(None, badSig, assumeValid=1)

        # Now with a bad digest
        badSig = inf.replace("a@b.c", "---")
        self.failUnlessRaises(ConfigError,
                              mixminion.ServerInfo.ServerInfo,
                              None, badSig)

# FFFF We *must* have tests for invalid server descriptors

#----------------------------------------------------------------------
# Modules annd ModuleManager

# Text of an example module that we load dynamically.
EXAMPLE_MODULE_TEXT = \
"""
import mixminion.server.Modules
from mixminion.Config import ConfigError

class TestModule(mixminion.server.Modules.DeliveryModule):
    def __init__(self):
	self.processedMessages = []
	self.processedAll = []
    def getName(self):
	return "TestModule"
    def getConfigSyntax(self):
	return { "Example" : { "Foo" : ("REQUIRE",
					mixminion.Config._parseInt, None) } }
    def validateConfig(self, cfg, entries, lines, contents):
	if cfg['Example'] is not None:
	    if cfg['Example'].get('Foo',1) % 2 == 0:
		raise ConfigError("Foo was even")
    def configure(self,cfg, manager):
	if cfg['Example']:
	    self.enabled = 1
	    self.foo = cfg['Example'].get('Foo',1)
	    manager.enableModule(self)
	else:
	    self.foo = None
	    self.enabled = 0
    def getServerInfoBlock(self):
	if self.enabled:
	    return "[Example]\\nFoo: %s\\n" % self.foo
	else:
	    return None
    def getExitTypes(self):
	return (1234,)
    def processMessage(self, message, tag, exitType, exitInfo):
	self.processedMessages.append(message)
	self.processedAll.append( (message, tag, exitType, exitInfo) )
	if exitInfo == 'fail?':
	    return mixminion.server.Modules.DELIVER_FAIL_RETRY
	elif exitInfo == 'fail!':
	    return mixminion.server.Modules.DELIVER_FAIL_NORETRY
	else:
	    return mixminion.server.Modules.DELIVER_OK
"""

class ModuleManagerTests(unittest.TestCase):
    def testModuleManager(self):
	mod_dir = mix_mktemp()
	home_dir = mix_mktemp()

	# Create an example module, and try to load iit.
	os.mkdir(mod_dir, 0700)
	writeFile(os.path.join(mod_dir, "ExampleMod.py"),
		  EXAMPLE_MODULE_TEXT)

	cfg_test = (SERVER_CONFIG_SHORT%home_dir) + """
ModulePath = %s
Module ExampleMod.TestModule
[Example]
Foo: 99
[Incoming/MMTP]
Enabled: yes
IP: 1.0.0.1
""" % (mod_dir)

        try:
	    suspendLog()
	    conf = mixminion.server.ServerConfig.ServerConfig(string=cfg_test)
	finally:
	    resumeLog()
	manager = conf.getModuleManager()
	exampleMod = None
	for m in manager.modules:
	    if m.getName() == "TestModule":
		exampleMod = m
	self.failUnless(exampleMod is not None)
	# Configure the new module, and make sure it recognizes its own config.
	manager.configure(conf)

	# Make sure the module enables itself.
	self.failUnless(exampleMod is manager.typeToModule[1234])

	# Try sending a few messages to the module.
	t = "ZZZZ"*5
	manager.queueMessage("Hello 1", t, 1234, "fail!")
	manager.queueMessage("Hello 2", t, 1234, "fail?")
	manager.queueMessage("Hello 3", t, 1234, "good")
	manager.queueMessage("Drop very much", None,
			     mixminion.Packet.DROP_TYPE, t)
	queue = manager.queues['TestModule']
	# Did the test module's delivery queue get the messages?
	self.failUnless(isinstance(queue,
			   mixminion.server.Modules.SimpleModuleDeliveryQueue))
	self.assertEquals(3, queue.count())
	# Has it processed any yet? (No.)
	self.assertEquals(exampleMod.processedMessages, [])
	# Now, tell the module to deliver the messages.
	try:
	    suspendLog()
	    manager.sendReadyMessages()
	finally:
            resumeLog()
	# There should be one message (the retriable one) left in the queue.
	self.assertEquals(1, queue.count())
	# It should have processed all three.
	self.assertEquals(3, len(exampleMod.processedMessages))
	# If we try to send agin, the second message should get re-sent.
	manager.sendReadyMessages()
	self.assertEquals(1, queue.count())
	self.assertEquals(4, len(exampleMod.processedMessages))
	self.assertEquals("Hello 2", exampleMod.processedMessages[-1])

	# But, none of them was decodeable: all of them should have been
	# tagged as 'err'
	self.assertEquals('err', exampleMod.processedAll[0][1])

	# Try a real message, to make sure that we really decode stuff properly
	msg = mixminion.BuildMessage._encodePayload(
	    "A man disguised as an ostrich, actually.",
	    0, Crypto.getCommonPRNG())
	manager.queueMessage(msg, "A"*20, 1234, "Hello")
	exampleMod.processedAll = []
	manager.sendReadyMessages()
	# The retriable message got sent again; the other one, we care about.
	pos = None
	for i in xrange(len(exampleMod.processedAll)):
	    if not exampleMod.processedAll[i][0].startswith('Hello'):
		pos = i
	self.assert_(pos is not None)
	self.assertEquals(exampleMod.processedAll[i],
			  ("A man disguised as an ostrich, actually.",
			   None, 1234, "Hello" ))

	# Now a non-decodeable message
	manager.queueMessage("XYZZYZZY"*3584, "Z"*20, 1234, "Buenas noches")
	exampleMod.processedAll = []
	manager.sendReadyMessages()
	pos = None
	for i in xrange(len(exampleMod.processedAll)):
	    if not exampleMod.processedAll[i][0].startswith('Hello'):
		pos = i
	self.assert_(pos is not None)
	self.assertEquals(exampleMod.processedAll[i],
			  ("XYZZYZZY"*3584, "Z"*20, 1234, "Buenas noches"))

	# Check serverinfo generation.
	try:
	    suspendLog()
	    info = generateServerDescriptorAndKeys(
		conf, getRSAKey(0,2048), home_dir, "key11", home_dir)
	    self.failUnless(stringContains(info,"\n[Example]\nFoo: 99\n"))
	finally:
	    resumeLog()

	# Try again, this time with the test module disabled.
	#
	cfg_test = (SERVER_CONFIG_SHORT%home_dir) + """
ModulePath = %s
Module ExampleMod.TestModule
""" % (mod_dir)

        try:
	    suspendLog()
	    conf = mixminion.server.ServerConfig.ServerConfig(string=cfg_test)
	finally:
	    resumeLog()
	manager = conf.getModuleManager()
	exampleMod = None
	for m in manager.modules:
	    if m.getName() == "TestModule":
		exampleMod = m
	self.failUnless(exampleMod is not None)
	manager.configure(conf)

	self.failIf(exampleMod is manager.typeToModule.get(1234))

	# Failing validation
	cfg_test = SERVER_CONFIG_SHORT%home_dir + """
ModulePath = %s
Module ExampleMod.TestModule
[Example]
Foo: 100
""" % (mod_dir)

	# FFFF Add tests for catching exceptions from buggy modules

    def testDecoding(self):
	'test decoding and test encapsulation.'
	em = mixminion.server.Modules._escapeMessage
	eme = mixminion.server.Modules._escapeMessageForEmail

	message = "Somebody set up us the module!\n\n(What you say?)\n"
	binmessage = hexread("00ADD1EDC0FFEED00DAD")*40
	tag = ".!..!....!........!."

	#####
	# Test escapeMessage

	# plaintext text message, text mode.
	self.assertEquals(em(message, None, 1), ("TXT", message, None))
	# plaintext text message, bin mode.
	self.assertEquals(em(message, None, 0), ("TXT", message, None))
	# plaintext bin message, text mode.
	self.assertEquals(em(binmessage, None, 1),
			  ("BIN", base64.encodestring(binmessage), None))
	# plaintext bin message, bin mode.
	self.assertEquals(em(binmessage, None, 0), ("BIN", binmessage, None))

	encoded = "baobob "*1024*4
	# "Encoded" message, text mode
	self.assertEquals(em(encoded, tag, 1),
			  ("ENC", base64.encodestring(encoded),
			   base64.encodestring(tag)[:-1]))
	# "Encoded" message, binary mode
	self.assertEquals(em(encoded, tag, 0),
			  ("ENC", encoded, tag))

	####
	# Tests escapeMessageForEmail
	self.assert_(stringContains(eme(message, None), message))
	expect = "BEGINS\n"+base64.encodestring(binmessage)+"====="
	self.assert_(stringContains(eme(binmessage, None), expect))
	expect = "BEGINS\nDecoding handle: "+base64.encodestring(tag)+\
		 base64.encodestring(encoded)+"====="
	self.assert_(stringContains(eme(encoded, tag), expect))

# Sample address file for testing MBOX
MBOX_ADDRESS_SAMPLE = """\
# This is a sample address file
mix-minion: mixminion@thishost

mixdaddy: mixminion@thathost
mixdiddy=mixminion@theotherhost
"""

# The message we expect MBOX to deliver.
MBOX_EXPECTED_MESSAGE = """\
To: mixminion@theotherhost
From: returnaddress@x
Subject: Anonymous Mixminion message

THIS IS AN ANONYMOUS MESSAGE.  The mixminion server 'nickname' at
<Unknown IP> has been configured to deliver messages to your address.
If you do not want to receive messages in the future, contact removeaddress@x
and you will be removed.

This message is not in plaintext.  It's either 1) a reply; 2) a forward
message encrypted to you; or 3) junk.

============ ANONYMOUS MESSAGE BEGINS
Decoding handle: eHh4eHh4eHh4eHh4eHh4eHh4eHg=
7/rOqx76yt7v+s6rHvrK3u/6zqse+sre7/rOqx76yt7v+s6rHvrK3u/6zqse+sre7/rOqx76yt7v
+s6rHvrK3u/6zqse+sre7/rOqx76yt7v+s6rHvrK3u/6zqse+sre7/rOqx76yt7v+s6rHvrK3u/6
zqse+sre7/rOqx76yt7v+s6rHvrK3u/6zqse+sre7/rOqx76yt7v+s6rHvrK3g==
============ ANONYMOUS MESSAGE ENDS
"""

class ModuleTests(unittest.TestCase):
    def testMixmasterSMTP(self):
	"""Check out the SMTP-Via-Mixmaster module.  (We temporarily relace
	   os.spawnl with a stub function so that we don't actually send
	   anything."""
	manager = self.getManager()

	# Configure the module.
	module = mixminion.server.Modules.MixmasterSMTPModule()
	module.configure({"Delivery/SMTP-Via-Mixmaster" :
			  {"Enabled":1, "Server": "nonesuch",
			   "SubjectLine":'foobar',
			   'MixCommand' : ('ls', ['-z'])}},
			 manager)
	queue = manager.queues['SMTP_MIX2']
	replaceFunction(os, "spawnl")
	try:
	    # Send a message...
	    queue.queueDeliveryMessage((SMTP_TYPE, "foo@bar", None),
				       "This is the message")
	    queue.sendReadyMessages()
	    # And make sure that Mixmaster was invoked correctly.
	    calls = getReplacedFunctionCallLog()
	    self.assertEquals('spawnl', calls[0][0])
	    mixfn, mixargs = calls[0][1][2], calls[0][1][3:]
	    self.assertEquals("ls", mixfn)
	    self.assertEquals(mixargs[:-1],
			      ('-z', '-l', 'nonesuch', '-s', 'foobar',
			       '-t', 'foo@bar'))
	    # ...and, if the temporary file it used hasn't been removed yet,
	    # that it contains the correct data.
	    fn = mixargs[-1]
	    fn = os.path.join(os.path.split(fn)[0],
			      "rmv_"+os.path.split(fn)[1][4:])
	    if os.path.exists(fn):
		self.assert_(stringContains(readFile(fn),
					    "This is the message"))

	    ## What about the flush command?
	    self.assertEquals("spawnl", calls[-1][0])
	    sendfn, sendargs = calls[-1][1][2], calls[-1][1][3:]
	    self.assertEquals("ls", sendfn)
	    self.assertEquals(sendargs, ('-S',))
	finally:
	    undoReplacedAttributes()
	    clearReplacedFunctionCallLog()

    def testMBOX(self):
	"""Check out the MBOX module.  (We temporarily relace sendSMTPMessage
	   with a stub function so that we don't actually send anything."""
        # Configure the module
	manager = self.getManager()
	module = mixminion.server.Modules.MBoxModule()
	addrfile = mix_mktemp()
	writeFile(addrfile, MBOX_ADDRESS_SAMPLE)
	module.configure({'Server':{'Nickname': "nickname"},
                          'Incoming/MMTP':{},
			  "Delivery/MBOX" :
			  {"Enabled": 1,
			   "AddressFile": addrfile,
			   "ReturnAddress": "returnaddress@x",
			   "RemoveContact": "removeaddress@x",
			   "SMTPServer" : "foo.bar.baz"}}, manager)
	# Check that the address file was read correctly.
        self.assertEquals({'mix-minion': 'mixminion@thishost',
	                   'mixdaddy':   'mixminion@thathost',
 	                   'mixdiddy':   'mixminion@theotherhost'},
			   module.addresses)
	queue = manager.queues['MBOX']
	# Stub out sendSMTPMessage.
	replaceFunction(mixminion.server.Modules, 'sendSMTPMessage',
 	         lambda *args: mixminion.server.Modules.DELIVER_OK)
	try:
	    # Try queueing a message...
	    queue.queueDeliveryMessage((MBOX_TYPE, 'mixdiddy', "x"*20),
				       hexread("EFFACEAB1EFACADE")*20)
	    self.assertEquals(getReplacedFunctionCallLog(), [])
	    # ...and sending it.
	    queue.sendReadyMessages()
	    try:
		# Also, try sending a message to an unknown address
		suspendLog()
		queue.queueDeliveryMessage((MBOX_TYPE, 'mixmuffin', "x"*20),
					   hexread("EFFACEAB1EFACADE")*20)
		queue.sendReadyMessages()
	    finally:
		m = resumeLog()
		self.assert_(stringContains(m,"Unknown MBOX user 'mixmuffin'"))
		self.assert_(stringContains(m,"Unable to deliver message"))

	    # Check that sendSMTPMessage was called correctly.
	    self.assertEquals(1, len(getReplacedFunctionCallLog()))
	    fn, args, _ = getReplacedFunctionCallLog()[0]
	    self.assertEquals('sendSMTPMessage', fn)
	    self.assertEquals(('foo.bar.baz',
			       ['mixminion@theotherhost'],
			       'returnaddress@x'),
			      args[:3])
	    d = findFirstDiff(MBOX_EXPECTED_MESSAGE, args[3])
	    if d != -1:
		print d, "near", repr(args[3][d:d+10])
	    self.assertEquals(MBOX_EXPECTED_MESSAGE, args[3])
	finally:
	    undoReplacedAttributes()
	    clearReplacedFunctionCallLog()

    def testDirectoryDump(self):
	"""Check out the DirectoryStoreModule that we use for testing on
	   machines with unreliable/nonexistant SMTP."""
	eme = mixminion.server.Modules._escapeMessageForEmail
	dir = mix_mktemp()
	manager = self.getManager()
	# Configure the module: disabled and enabled (queueless mode)
	module = mixminion.testSupport.DirectoryStoreModule()
	module.configure({'Testing/DirectoryDump' : {}}, manager)
	self.assert_(not manager.queues.has_key('Testing_DirectoryDump'))
	module.configure({'Testing/DirectoryDump' :
			  {'Location': dir, 'UseQueue' : 0}}, manager)
	# Try sending a couple of messages.
	queue = manager.queues['Testing_DirectoryDump']
	queue.queueDeliveryMessage((0xFFFE, "addr1", "t"*20),
				   "This is the message")
	self.assert_(os.path.exists(os.path.join(dir, "0")))
	queue.queueDeliveryMessage((0xFFFE, "addr2", "x"*20),
				   "This is message 2")
	self.assert_(os.path.exists(os.path.join(dir, "1")))
	self.assertEquals(eme("This is message 2", "x"*20),
			  readFile(os.path.join(dir, "1")))
	# test failure.
	try:
	    suspendLog()
	    queue.queueDeliveryMessage((0xFFFE, "FAIL!", "y"*20),
			       "This is message X which won't be delivered")
	    self.assert_(not os.path.exists(os.path.join(dir, "2")))
	finally:
	    m = resumeLog()
	    self.assert_(m.endswith("Unable to deliver message\n"))

	try:
	    suspendLog()
	    queue.queueDeliveryMessage((0xFFFE, "fail", "z"*20),
			       "This is message X which won't be delivered")
	    self.assert_(not os.path.exists(os.path.join(dir, "2")))
	finally:
	    m = resumeLog()
	    self.assert_(m.endswith("Unable to retry delivery for message\n"))

	queue.sendReadyMessages()

	# Check sane behavior on missing files, and on restart.
	writeFile(os.path.join(dir, "90"), 'zed')
	module = mixminion.testSupport.DirectoryStoreModule()
	# This time, use a queue.
	module.configure({'Testing/DirectoryDump' :
			  {'Location': dir, 'UseQueue' : 1}}, manager)
	# Do we skip over the missing messages?
	self.assertEquals(module.next, 91)
	self.assertEquals(len(os.listdir(dir)), 3)
	queue = manager.queues['Testing_DirectoryDump']
	queue.queueDeliveryMessage((0xFFFE, "addr91", None),
				   "This is message 91")
	queue.queueDeliveryMessage((0xFFFE, "addr92", None),
				   "This is message 92")
	queue.queueDeliveryMessage((0xFFFE, "fail", None),
				   "This is message 93")
	queue.queueDeliveryMessage((0xFFFE, "FAIL!", None),
				   "This is message 94")
	# All 4 messages go into the queue...
	self.assertEquals(4, queue.count())
	self.assertEquals(3, len(os.listdir(dir)))
	try:
	    suspendLog()
	    queue.sendReadyMessages()
	finally:
	    m = resumeLog()
	    self.assert_(m.endswith("[ERROR] Unable to deliver message\n"))
	# After delivery: 91 and 92 go through, 93 stays, and 94 gets dropped.
	self.assertEquals(1, queue.count())
	self.assertEquals(5, len(os.listdir(dir)))

    def getManager(self):
	d = mix_mktemp()
	c = SERVER_CONFIG_SHORT % d
	try:
	    suspendLog()
	    conf = mixminion.server.ServerConfig.ServerConfig(string=c)
	    m = conf.getModuleManager()
	    m.configure(conf)
	    return m
	finally:
	    resumeLog()

#----------------------------------------------------------------------

# Sample server configuration to test ServerKeys
SERVERCFG = """
[Server]
Homedir: %(home)s
Mode: local
EncryptIdentityKey: No
PublicKeyLifetime: 10 days
IdentityKeyBits: 2048
EncryptPrivateKey: no
Nickname: mac-the-knife
[Incoming/MMTP]
Enabled: yes
IP: 10.0.0.1
"""

_FAKE_HOME = None
def _getServerKeyring():
    global _FAKE_HOME
    _FAKE_HOME = mix_mktemp()
    cfg = SERVERCFG % { 'home' : _FAKE_HOME }
    try:
	suspendLog()
	conf = mixminion.server.ServerConfig.ServerConfig(string=cfg)
    finally:
	resumeLog()
    return mixminion.server.ServerKeys.ServerKeyring(conf)

class ServerKeysTests(unittest.TestCase):
    def testServerKeyring(self):
	keyring = _getServerKeyring()
	home = _FAKE_HOME

	# Test creating identity key
	#identity = getRSAKey(0,2048)
	identity = keyring.getIdentityKey()
	fn = os.path.join(home, "keys", "identity.key")
	identity2 = Crypto.pk_PEM_load(fn)
	self.assertEquals(Crypto.pk_get_modulus(identity),
			  Crypto.pk_get_modulus(identity2))
	# (Make sure warning case can occur.)
	pk = getRSAKey(0,128)
	Crypto.pk_PEM_save(pk, fn)
	suspendLog()
	keyring.getIdentityKey()
	msg = resumeLog()
	self.failUnless(len(msg))
	Crypto.pk_PEM_save(identity, fn)

	# Now create a keyset
	now = time.time()
	keyring.createKeys(1, now)
	# check internal state
	ivals = keyring.keyIntervals
	start = mixminion.Common.previousMidnight(now)
	finish = mixminion.Common.previousMidnight(start+(10*24*60*60)+30)
	self.assertEquals(1, len(ivals))
	self.assertEquals((start,finish,"0001"), ivals[0])

	keyring.createKeys(2)

	# Check the first key we created
	va, vu, curKey = keyring._getLiveKey()
	self.assertEquals(va, start)
	self.assertEquals(vu, finish)
	self.assertEquals(vu, keyring.getNextKeyRotation())
	self.assertEquals(curKey, "0001")
	keyset = keyring.getServerKeyset()
	self.assertEquals(keyset.getHashLogFileName(),
			  os.path.join(home, "work", "hashlogs", "hash_0001"))

	# Check the second key we created.
	va, vu, curKey = keyring._getLiveKey(vu + 3600)
	self.assertEquals(va, finish)
	self.assertEquals(vu, mixminion.Common.previousMidnight(
	    finish+10*24*60*60+60))

	# Make a key in the past, to see if it gets scrubbed.
	keyring.createKeys(1, mixminion.Common.previousMidnight(
	    start - 10*24*60*60 + 1))
	self.assertEquals(4, len(keyring.keyIntervals))
        waitForChildren() # make sure keys are really gone before we remove

        # In case we started very close to midnight, remove keys as if it
	# were a little in the future; otherwise, we won't remove the
	# just-expired keys.
	keyring.removeDeadKeys(now+360)
	self.assertEquals(3, len(keyring.keyIntervals))

	if USE_SLOW_MODE:
	    # These are slow, since they regenerate the DH params.
	    # Test getDHFile
	    f = keyring.getDHFile()
	    f2 = keyring.getDHFile()
	    self.assertEquals(f, f2)

	    # Test getTLSContext
	    keyring.getTLSContext()

	# Test getPacketHandler
	_ = keyring.getPacketHandler()

#----------------------------------------------------------------------

_EXAMPLE_DESCRIPTORS = {} # name->list of str
EX_SERVER_CONF_TEMPLATE = """
[Server]
Mode: relay
Homedir: %(homedir)s
EncryptIdentityKey: No
PublicKeyLifetime: %(lifetime)s days
IdentityKeyBits: 2048
EncryptPrivateKey: no
Nickname: %(nickname)s
[Incoming/MMTP]
Enabled: yes
IP: %(ip)s
[Outgoing/MMTP]
Enabled: yes
"""

_EXAMPLE_DESCRIPTORS_INP = [
    # name        days         ip?        validAt
    [ "Fred",	  "10 days", "10.0.0.6", (-19,-9,1,11), () ],
    [ "Lola",	  "5 days",  "10.0.0.7", (-2,0,5),      (MBOX_TYPE,) ],
    [ "Joe",	  "20 days", "10.0.0.8", (-15,5,25),    (SMTP_TYPE,) ],
    [ "Alice",	  "8 days",  "10.0.0.9", (-3,5,13),     () ],
    [ "Bob",	  "11 days", "10.0.0.10", (-10,-1,6),   () ],
    [ "Lisa",	  "3 days",  "10.0.0.11", (-10,-1,5),   () ],
]

def getExampleServerDescriptors():
    """Helper function: generate a list of list of ServerInfo objects based
       on the values of _EXAMPLE_DESCRIPTORS_INP"""
    if _EXAMPLE_DESCRIPTORS:
 	return _EXAMPLE_DESCRIPTORS

    gen = generateServerDescriptorAndKeys
    tmpkeydir = mix_mktemp()
    now = time.time()

    sys.stdout.flush()

    # For each server...
    for (nickname, lifetime, ip, starting, types) in _EXAMPLE_DESCRIPTORS_INP:
	# Generate a config file
	homedir = mix_mktemp()
	conf = EX_SERVER_CONF_TEMPLATE % locals()
	for t in types:
	    if t == MBOX_TYPE:
		addrf = mix_mktemp()
		writeFile(addrf,"")
		conf += ("[Delivery/MBOX]\nEnabled: yes\nAddressFile: %s\n"+
			 "ReturnAddress: a@b.c\nRemoveContact: b@c.d\n") %(
		    addrf)
	    elif t == SMTP_TYPE:
		conf += ("[Delivery/SMTP-Via-Mixmaster]\nEnabled: yes\n"+
			 "MixCommand: /bin/ls\nServer: foobar\n")
	    else:
		raise MixFatalError("Unrecognized type: %04x"%t)
	try:
	    suspendLog()
	    conf = mixminion.server.ServerConfig.ServerConfig(string=conf)
	    conf.getModuleManager().configure(conf)
	finally:
	    resumeLog()
	    pass

	# Now, for each starting time, generate a server desciprtor.x
	_EXAMPLE_DESCRIPTORS[nickname] = []
	for n in xrange(len(starting)):
	    k = "tst%d"%n
	    validAt = previousMidnight(now + 24*60*60*starting[n])
	    gen(config=conf, identityKey=getRSAKey(n%3,2048), keyname=k,
		keydir=tmpkeydir, hashdir=tmpkeydir, validAt=validAt)

	    sd = os.path.join(tmpkeydir,"key_"+k,"ServerDesc")
	    _EXAMPLE_DESCRIPTORS[nickname].append(readFile(sd))

	    # (print some dots here; this step can take a while)
	    sys.stdout.write('.')
	    sys.stdout.flush()
    sys.stdout.flush()
    return _EXAMPLE_DESCRIPTORS

# variable to hold the latest instance of FakeBCC.
BCC_INSTANCE = None


class ClientMainTests(unittest.TestCase):
    def testTrivialKeystore(self):
	"""Check out ClientMain's keystore implementation"""
	eq = self.assertEquals
	raises = self.failUnlessRaises

	ServerInfo = mixminion.ServerInfo.ServerInfo

	dirname = mix_mktemp()
	ks = mixminion.ClientMain.TrivialKeystore(dirname)

	edesc = getExampleServerDescriptors()

	# Test empty keystore
	eq(None, ks.getServerInfo("Fred"))
	try:
	    suspendLog()
	    raises(MixError, ks.getPath, ["Fred"])
	finally:
	    resumeLog()
	fred = ServerInfo(string=edesc["Fred"][0])
	eq(1, len(ks.getPath([fred])))
	self.failUnless(ks.getPath([fred])[0] is fred)

	## Test importing.
	for sname, servers in edesc.items():
	    for idx, sdesc in zip(range(len(servers)), servers):
		writeFile(os.path.join(dirname, "%s%02d"%(sname,idx)), sdesc)

	suspendLog()
	try:
	    ks = mixminion.ClientMain.TrivialKeystore(dirname)
	finally:
	    resumeLog()

	# Try getServerInfo(ServerInfo)
	si = ServerInfo(string=edesc['Lisa'][0])
	self.assert_(si is ks.getServerInfo(si))

	# 'Bob' and 'Fred' are dangerous with regspect to the 'almost-expired'
	# check; don't use them here
	for (s,i) in [("Lola",0), ("Joe",0),("Alice",0),("Lisa",1)]:
	    self.assert_(self.isSameServerDesc(edesc[s][i],
				      ks.getServerInfo(s)))
	    self.assert_(self.isSameServerDesc(edesc[s][i],
				      ks.getServerInfo("%s%02d"%(s,i))))

	# Check a nonexistant server.
	self.assertEquals(None, ks.getServerInfo("Foob"))

	# Try getPath()
	x = mix_mktemp()
	writeFile(x, edesc["Fred"][1])
	p = ks.getPath(("Lola", "Joe", "Lola00", ks.getServerInfo("Lisa"), x))
	self.assert_(self.isSameServerDesc(ks.getServerInfo("Lola"), p[0]))
	self.assert_(self.isSameServerDesc(ks.getServerInfo("Joe"), p[1]))
	self.assert_(self.isSameServerDesc(ks.getServerInfo("Lola"), p[2]))
	self.assert_(self.isSameServerDesc(ks.getServerInfo("Lisa"), p[3]))
	self.assert_(self.isSameServerDesc(edesc["Fred"][1], p[4]))

	# We fail on nonexistant files.
	self.failUnlessRaises(MixError, ks.getPath, ["Lola", mix_mktemp()])

	# We warn on unparseable files.
	fn = os.path.join(dirname, "xyzzy")
	writeFile(fn, "this file is not a server descriptor\n")
	try:
	    suspendLog()
	    _ = mixminion.ClientMain.TrivialKeystore(dirname)
	finally:
	    msg = resumeLog()
	    self.assert_(stringContains(msg,"Invalid server descriptor %s"%fn))

    def testAddress(self):
	def parseEq(s, tp, addr, server, eq=self.assertEquals):
	    "Helper: return true iff parseAddress(s).getRouting() == t,s,a."
	    t, a, s = mixminion.ClientMain.parseAddress(s).getRouting()
	    eq(t, tp)
	    eq(s, server)
	    eq(a, addr)

	##
	# Check valid mbox and smtp addresses
        parseEq("mbox:foo", MBOX_TYPE, "foo", None)
	parseEq("mbox:foo@bar", MBOX_TYPE, "foo", "bar")
	parseEq("mbox:foo@bar@baz", MBOX_TYPE, "foo", "bar@baz")
	parseEq("smtp:foo@bar", SMTP_TYPE, "foo@bar", None)
	parseEq("smtp:foo@bar.com", SMTP_TYPE, "foo@bar.com", None)
	parseEq("foo@bar.com", SMTP_TYPE, "foo@bar.com", None)
	##
	# Check other address formats.
	parseEq("drop", DROP_TYPE, None, None)
	parseEq("test:foobar", 0xFFFE, "foobar", None)
	parseEq("test", 0xFFFE, "", None)
	parseEq("0x999:zymurgy", 0x999, "zymurgy", None)
	parseEq("0x999:", 0x999, "", None)

	def parseFails(s, f=self.failUnlessRaises):
	    f(ParseError, mixminion.ClientMain.parseAddress, s)

	# Check failing cases
	parseFails("sxtp:foo@bar.com") # unknown module
	parseFails("mbox") # missing mbox address
	parseFails("mbox:") # missing mbox address
	parseFails("smtp:Foo") # Invalid mailbox
	parseFails("smtp:foo@bar@baz") # Invalid mailbox
	parseFails("hello-friends") # Invalid mailbox
	parseFails("@bar.baz") # Invalid mailbox
	parseFails("moo:") # Unknown module; no text
	parseFails("moo") # Unknown module; no text
	parseFails(":oom") # Missing module
	parseFails("0xZZ:zymurgy") # Bad hex literal
	parseFails("0xZZ") # Bad hex literal, no data.
	parseFails("0x9999") # No data
	parseFails("0xFFFFF:zymurgy") # Hex literal out of range

    def testMixminionClient(self):
	# Create and configure a MixminionClient object...
	parseAddress = mixminion.ClientMain.parseAddress
	userdir = mix_mktemp()
	usercfgstr = "[User]\nUserDir: %s\n[DirectoryServers]\n"%userdir
	usercfg = mixminion.Config.ClientConfig(string=usercfgstr)
	client = mixminion.ClientMain.MixminionClient(usercfg)

	# Make sure client sets its directories up correctly.
	serverdir = os.path.join(userdir, 'servers')
	self.assert_(os.path.exists(serverdir))
	self.assertEquals([], os.listdir(serverdir))

	# Now try with some servers...
	edesc = getExampleServerDescriptors()
	writeFile(os.path.join(serverdir,"lola1"), edesc["Lola"][1])
	writeFile(os.path.join(serverdir,"joe1"), edesc["Joe"][0])
	writeFile(os.path.join(serverdir,"alice1"), edesc["Alice"][0])

	# ... and for now, we need to restart the client.
	client = mixminion.ClientMain.MixminionClient(usercfg)

	##  Test generateForwardMessage.
	# We replace 'buildForwardMessage' to make this easier to test.
	replaceFunction(mixminion.BuildMessage, "buildForwardMessage",
			lambda *a:"X")
	try:
	    getCalls = getReplacedFunctionCallLog
	    clearCalls = clearReplacedFunctionCallLog
	    # First, two forward messages that end with 'joe' and go via
	    # SMTP
	    payload = "Hey Joe, where you goin' with that gun in your hand?"
	    client.generateForwardMessage(
		parseAddress("joe@cledonism.net"),
		payload,
		path1=["Lola", "Joe"], path2=["Alice", "Joe"])
            client.generateForwardMessage(
		parseAddress("smtp:joe@cledonism.net"),
		"Hey Joe, where you goin' with that gun in your hand?",
		path1=["Lola", "Joe"], path2=["Alice", "Joe"])

	    for fn, args, kwargs in getCalls():
		self.assertEquals(fn, "buildForwardMessage")
		self.assertEquals(args[0:3],
				  (payload, SMTP_TYPE, "joe@cledonism.net"))
		self.assert_(len(args[3]) == len(args[4]) == 2)
		self.assertEquals(["Lola", "Joe", "Alice", "Joe"],
		     [x['Server']['Nickname'] for x in args[3]+args[4]])
	    clearCalls()

	    # Now try an mbox message, with an explicit last hop.
	    payload = "Hey, Lo', where you goin' with that pun in your hand?"
	    client.generateForwardMessage(
		parseAddress("mbox:granola"),
		payload,
		path1=["Lola", "Joe"], path2=["Alice", "Lola"])
	    # And an mbox message with a last hop implicit in the address
	    client.generateForwardMessage(
		parseAddress("mbox:granola@Lola"),
		payload,
		path1=["Lola", "Joe"], path2=["Alice"])

	    for fn, args, kwargs in getCalls():
		self.assertEquals(fn, "buildForwardMessage")
		self.assertEquals(args[0:3],
				  (payload, MBOX_TYPE, "granola"))
		self.assert_(len(args[3]) == len(args[4]) == 2)
		self.assertEquals(["Lola", "Joe", "Alice", "Lola"],
		     [x['Server']['Nickname'] for x in args[3]+args[4]])
	    clearCalls()
	finally:
	    undoReplacedAttributes()
	    clearCalls()

	### Now try some failing cases for generateForwardMessage:
	# Empty path...
	self.assertRaises(MixError,
			  client.generateForwardMessage,
			  parseAddress("0xFFFF:zed"),
			  "Z", [], ["Alice"])
	# Nonexistant servers...
	self.assertRaises(MixError,
			  client.generateForwardMessage,
			  parseAddress("0xFFFF:zed"),
			  "Z", ["Marvin"], ["Fred"])
	# Lola doesn't support SMTP...
	self.assertRaises(MixError,
			  client.generateForwardMessage,
			  parseAddress("smtp:joe@cledonism.net"),
			  "Z", ["Joe"], ["Lola"])
	# Joe doesn't support MBOX...
	self.assertRaises(MixError,
			  client.generateForwardMessage,
			  parseAddress("mbox:wahoo"),
			  "Z", ["Lola"], ["Joe"])


	# Temporarily replace BlockingClientConnection so we can try the client
	# without hitting the network.
	class FakeBCC:
	    def __init__(self, addr, port, keyid):
		global BCC_INSTANCE
		BCC_INSTANCE = self
		self.addr = addr
		self.port = port
		self.keyid = keyid
		self.packets = []
		self.connected = 0
	    def connect(self):
		self.connected = 1
	    def sendPacket(self, msg):
		assert self.connected
		self.packets.append(msg)
	    def shutdown(self):
		self.connected = 0

	replaceAttribute(mixminion.MMTPClient, "BlockingClientConnection",
			 FakeBCC)
	try:
	    client.sendForwardMessage(
		parseAddress("mbox:granola@Lola"),
		"You only give me your information.",
		["Alice", "Lola", "Joe", "Alice"], ["Joe", "Alice"])
	    bcc = BCC_INSTANCE
	    # first hop is alice
	    self.assertEquals(bcc.addr, "10.0.0.9")
	    self.assertEquals(bcc.port, 48099)
	    self.assertEquals(0, bcc.connected)
	    self.assertEquals(1, len(bcc.packets))
	    self.assertEquals(32*1024, len(bcc.packets[0]))

	finally:
	    undoReplacedAttributes()
	    clearCalls()

    def isSameServerDesc(self, s1, s2):
	"""s1 and s2 are either ServerInfo objects or strings containing server
	   descriptors. Returns 1 iff their digest fields match"""
	ds = []
	for s in s1, s2:
	    if type(s) == types.StringType:
		m = re.search(r"^Digest: (\S+)\n", s, re.M)
		assert m
		ds.append(base64.decodestring(m.group(1)))
	    else:
		ds.append(s['Server']['Digest'])
	return ds[0] == ds[1]

#----------------------------------------------------------------------
def testSuite():
    """Return a PyUnit test suite containing all the unit test cases."""
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    tc = loader.loadTestsFromTestCase

    suite.addTest(tc(MiscTests))
    suite.addTest(tc(MinionlibCryptoTests))
    suite.addTest(tc(CryptoTests))
    suite.addTest(tc(PacketTests))
    suite.addTest(tc(LogTests))
    suite.addTest(tc(FileParanoiaTests))
    suite.addTest(tc(ConfigFileTests))
    suite.addTest(tc(HashLogTests))
    suite.addTest(tc(BuildMessageTests))
    suite.addTest(tc(PacketHandlerTests))
    suite.addTest(tc(QueueTests))
    suite.addTest(tc(ModuleTests))

    suite.addTest(tc(ClientMainTests))
    suite.addTest(tc(ServerKeysTests))

    # These tests are slowest, so we do them last.
    suite.addTest(tc(ModuleManagerTests))
    suite.addTest(tc(ServerInfoTests))
    suite.addTest(tc(MMTPTests))

    return suite

def testAll(name, args):
    init_crypto()

    # Suppress 'files-can't-be-securely-deleted' message while testing
    LOG.setMinSeverity("FATAL")
    mixminion.Common.secureDelete([],1)

    # Disable TRACE and DEBUG log messages, unless somebody overrides from
    # the environment.
    LOG.setMinSeverity(os.environ.get('MM_TEST_LOGLEVEL', "WARN"))
    #LOG.setMinSeverity(os.environ.get('MM_TEST_LOGLEVEL', "TRACE"))

    unittest.TextTestRunner(verbosity=1).run(testSuite())
