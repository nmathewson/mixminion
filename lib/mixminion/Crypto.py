# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Crypto.py,v 1.23 2002/11/22 00:21:20 nickm Exp $
"""mixminion.Crypto

   This package contains all the cryptographic primitives required
   my the Mixminion spec.  Some of these are wrappers for functionality
   implemented in C by OpenSSL.  Nonetheless, other modules should call
   the functions in mixminion.Crypto, and not call _minionlib's crypto
   functionality themselves."""

import os
import sys
import stat
import copy_reg
from types import StringType

import mixminion._minionlib as _ml
from mixminion.Common import MixError, MixFatalError, floorDiv, ceilDiv, getLog

__all__ = [ 'CryptoError', 'init_crypto', 'sha1', 'ctr_crypt', 'prng',
            'strxor', 'lioness_encrypt', 'lioness_decrypt',
            'bear_encrypt', 'bear_decrypt', 'trng',
            'pk_encrypt', 'pk_decrypt', 'pk_sign', 'pk_check_signature',
	    'pk_generate', 'openssl_seed',
            'pk_get_modulus', 'pk_from_modulus',
            'pk_encode_private_key', 'pk_decode_private_key',
            'Keyset', 'AESCounterPRNG', 'HEADER_SECRET_MODE',
            'PRNG_MODE', 'RANDOM_JUNK_MODE', 'HEADER_ENCRYPT_MODE',
            'APPLICATION_KEY_MODE', 'PAYLOAD_ENCRYPT_MODE',
            'HIDE_HEADER_MODE' ]

CryptoError = _ml.CryptoError
generate_cert = _ml.generate_cert

# Number of bytes in an AES key.
AES_KEY_LEN = 128 >> 3
# Number of bytes in a SHA1 digest
DIGEST_LEN = 160 >> 3

def init_crypto(config=None):
    """Initialize the crypto subsystem."""
    configure_trng(config)
    trng(1)
    try:
        # Try to read /dev/urandom
        trng(1)
    except MixFatalError, _:
	raise
    except:
        raise MixFatalError("Error initializing entropy source")
    openssl_seed(40)
    
def sha1(s):
    """Return the SHA1 hash of its argument"""
    return _ml.sha1(s)

def strxor(s1, s2):
    """Computes the bitwise xor of two strings.  Raises an exception if the
       strings' lengths are unequal.
    """
    return _ml.strxor(s1, s2)

def aes_key(key):
    """Returns an opaque precomputation of the 16-byte AES key, key."""
    return _ml.aes_key(key)

def ctr_crypt(s, key, idx=0):
    """Given a string s and a 16-byte key key, computes the AES counter-mode
       encryption of s using k.  The counter begins at idx.
    """
    if isinstance(key, StringType):
        key = _ml.aes_key(key)
    return _ml.aes_ctr128_crypt(key,s,idx)

def prng(key,count,idx=0):
    """Returns the bytestream 0x00000000...., encrypted in counter mode."""
    if isinstance(key, StringType):
        key = _ml.aes_key(key)
    return _ml.aes_ctr128_crypt(key,"",idx,count)

def lioness_encrypt(s,(key1,key2,key3,key4)):
    """Given four 20-byte keys, encrypts s using the LIONESS
       super-pseudorandom permutation.
    """

    assert len(key1) == len(key3) == DIGEST_LEN
    assert len(key2) == len(key4) == DIGEST_LEN
    assert len(s) > DIGEST_LEN

    left = s[:DIGEST_LEN]
    right = s[DIGEST_LEN:]
    del s
    # Performance note: This business with sha1("".join((key,right,key)))
    # may look slow, but it contributes only a 6% to the hashing step,
    # which in turn contributes under 11% of the time for LIONESS.
    right = _ml.aes_ctr128_crypt(
	_ml.aes_key(_ml.sha1("".join((key1,left,key1)))[:AES_KEY_LEN]), 
	right, 0) 
    left = _ml.strxor(left,  _ml.sha1("".join((key2,right,key2))))
    right = _ml.aes_ctr128_crypt(
	_ml.aes_key(_ml.sha1("".join((key3,left,key3)))[:AES_KEY_LEN]), 
	right, 0)
    left = _ml.strxor(left,  _ml.sha1("".join((key4,right,key4))))

    return left + right

def lioness_decrypt(s,(key1,key2,key3,key4)):
    """Given a 16-byte key2 and key4, and a 20-byte key1 and key3, decrypts
       s using the LIONESS super-pseudorandom permutation.
    """

    assert len(key1)==len(key3)==DIGEST_LEN
    assert len(key2)==len(key4)==DIGEST_LEN
    assert len(s) > DIGEST_LEN

    left = s[:DIGEST_LEN]
    right = s[DIGEST_LEN:]
    del s
    left = _ml.strxor(left,  _ml.sha1("".join([key4,right,key4])))
    right = ctr_crypt(right, _ml.sha1("".join([key3,left,key3]))[:AES_KEY_LEN])
    left = _ml.strxor(left,  _ml.sha1("".join([key2,right,key2])))
    right = ctr_crypt(right, _ml.sha1("".join([key1,left,key1]))[:AES_KEY_LEN])
    return left + right

def bear_encrypt(s,(key1,key2)):
    """Given four 20-byte keys, encrypts s using the BEAR
       pseudorandom permutation.
    """

    assert len(key1) == len(key2) == DIGEST_LEN
    assert len(s) > DIGEST_LEN

    left = s[:DIGEST_LEN]
    right = s[DIGEST_LEN:]
    del s
    left = _ml.strxor(left, _ml.sha1("".join((key1,right,key1))))
    right = ctr_crypt(right, _ml.sha1(left)[:AES_KEY_LEN])
    left = _ml.strxor(left, _ml.sha1("".join((key2,right,key2))))
    return left + right

def bear_decrypt(s,(key1,key2)):
    """Given four 20-byte keys, decrypts s using the BEAR
       pseudorandom permutation.
    """

    assert len(key1) == len(key2) == DIGEST_LEN
    assert len(s) > DIGEST_LEN

    left = s[:DIGEST_LEN]
    right = s[DIGEST_LEN:]
    del s
    left = _ml.strxor(left, _ml.sha1("".join((key2,right,key2))))
    right = ctr_crypt(right, _ml.sha1(left)[:AES_KEY_LEN])
    left = _ml.strxor(left, _ml.sha1("".join((key1,right,key1))))
    return left + right

def openssl_seed(count):
    """Seeds the openssl rng with 'count' bytes of real entropy."""
    _ml.openssl_seed(trng(count))

def trng(count):
    """Returns (count) bytes of true random data from a true source of
       entropy (/dev/urandom).  May read ahead and cache values.
    """
    return _theTrueRNG.getBytes(count)

# Specified in the Mixminion spec.
OAEP_PARAMETER = "He who would make his own liberty secure, "+\
                 "must guard even his enemy from oppression."

def pk_encrypt(data,key):
    """Return the RSA encryption of OAEP-padded data, using the public key
       in key.
    """
    bytes = key.get_modulus_bytes()
    data = add_oaep(data,OAEP_PARAMETER,bytes)
    # public key encrypt
    return key.crypt(data, 1, 1)

def pk_sign(data, key):
    """Return the RSA signature of OAEP-padded data, using the public key
       in key."""
    bytes = key.get_modulus_bytes()
    data = add_oaep(data,OAEP_PARAMETER,bytes)
    return key.crypt(data, 0, 1)

def pk_decrypt(data,key):
    """Returns the unpadded RSA decryption of data, using the private key in
       key.
    """
    bytes = key.get_modulus_bytes()
    # private key decrypt
    data = key.crypt(data, 0, 0)
    return check_oaep(data,OAEP_PARAMETER,bytes)

def pk_check_signature(data, key):
    """If data holds the RSA signature of some OAEP-padded data, check the
       signature using public key 'key', and return the orignal data.  
       Throw CryptoError on failure. """
    bytes = key.get_modulus_bytes()
    # private key decrypt
    data = key.crypt(data, 1, 0)
    return check_oaep(data,OAEP_PARAMETER,bytes)

def pk_generate(bits=1024,e=65537):
    """Generate a new RSA keypair with 'bits' bits and exponent 'e'.  It is
       safe to use the default value of 'e'.
    """
    return _ml.rsa_generate(bits,e)

def pk_get_modulus(key):
    """Extracts the modulus of a public key."""
    return key.get_public_key()[0]

def pk_from_modulus(n, e=65537L):
    """Given a modulus and exponent, creates an RSA public key."""
    return _ml.rsa_make_public_key(long(n),long(e))

def pk_encode_private_key(key):
    """Creates an ASN1 representation of a keypair for external storage."""
    return key.encode_key(0)

def pk_decode_private_key(s):
    """Reads an ASN1 representation of a keypair from external storage."""
    return _ml.rsa_decode_key(s,0)

def pk_encode_public_key(key):
    """Creates an ASN1 representation of a public key for external storage."""
    return key.encode_key(1)

def pk_decode_public_key(s):
    """Reads an ASN1 representation of a public key from external storage."""
    return _ml.rsa_decode_key(s,1)

def pk_PEM_save(rsa, filename, password=None):
    """Save a PEM-encoded private key to a file.  If <password> is provided,
       encrypt the key using the password."""
    f = open(filename, 'w')
    if password:
        rsa.PEM_write_key(f, 0, password)
    else:
        rsa.PEM_write_key(f, 0)
    f.close()

def pk_PEM_load(filename, password=None):
    """Load a PEM-encoded private key from a file.  If <password> is provided,
       decrypt the key using the password."""
    f = open(filename, 'r')
    if password:
        rsa = _ml.rsa_PEM_read_key(f, 0, password)
    else:
        rsa = _ml.rsa_PEM_read_key(f, 0)
    f.close()
    return rsa
    
def _pickle_rsa(rsa):
    return _ml.rsa_make_public_key, rsa.get_public_key()

# Register this function to make RSA keys pickleable.  Note that we only
# pickle the public part of an RSA key; for long-term storage of private
# keys, you should use PEM so we can support encryption.
copy_reg.pickle(_ml.RSA, _pickle_rsa, _ml.rsa_make_public_key)

#----------------------------------------------------------------------
# OAEP Functionality
#
# OpenSSL already has OAEP builtin.  When/if we port to libgcrypt, however,
# we'll have to do OAEP ourselves.
#
# Note: OAEP is secure when used as in RSA-OAEP, but not in the general
# case.  See [1] for an overview on OAEP's security properties.  RSA-OAEP,
# as implemented here, is described in [2].
#
# [1] http://lists.w3.org/Archives/Public/xml-encryption/2001Jun/0072.html
# [2] RSAES-OAEP Encryption Scheme: Algorithm specification and supporting
#     documentation.  (Downloadable from
#       ftp://ftp.rsasecurity.com/pub/rsalabs/rsa_algorithm/rsa-oaep_spec.pdf)

def _oaep_mgf(seed, bytes):
    ''' Mask generation function specified for RAESA-OAEP.  Given a seed
        and a number of bytes, generates a mask for OAEP by computing
        sha1(seed + "\x00\x00\x00\x00")+sha1(seed+"\x00\x00\x00\x01)+...

        The mask is truncated to the specified length.

        LIMITATION: This implementation can only generate 5120 bytes of
        key material.'''

    assert bytes <= 5120
    padding = []
    nHashes = ceilDiv(bytes, DIGEST_LEN)
    #assert (nHashes-1)*DIGEST_LEN <= bytes <= nHashes*DIGEST_LEN
    padding = [ _ml.sha1("%s\x00\x00\x00%c"%(seed,i)) for i in range(nHashes) ]
    padding = "".join(padding)
    return padding[:bytes]

def _add_oaep_padding(data, p, bytes, rng=None):
    '''Add oaep padding suitable for a 'bytes'-byte key, using 'p' as a
       security parameter and 'rng' as a random number generator.

       If rng is None, uses the general purpose RNG.  The parameter may
       be any length.  len(data) must be <= bytes-42.  '''
    if rng is None:
        rng = getCommonPRNG()
    bytes = bytes-1
    mLen = len(data)
    paddingLen = bytes-mLen-2*DIGEST_LEN-1
    if paddingLen < 0:
        raise CryptoError("Message too long")
    db = "%s%s\x01%s" %(sha1(p),"\x00"*paddingLen,data)
    seed = rng.getBytes(DIGEST_LEN)
    maskedDB = _ml.strxor(db, _oaep_mgf(seed, bytes-DIGEST_LEN))
    maskedSeed = _ml.strxor(seed, _oaep_mgf(maskedDB, DIGEST_LEN))
    return '\x00%s%s'%(maskedSeed, maskedDB)

def _check_oaep_padding(data, p, bytes):
    '''Checks the OAEP padding on a 'bytes'-byte string.'''
    if len(data) != bytes:
        raise CryptoError("Decoding error")

    # This test (though required in the OAEP spec) is extraneous here.
    #if len(data) < 2*DIGEST_LEN+1:
    #    raise CryptoError("Decoding error")
    
    if data[0]!= '\x00':
        raise CryptoError("Decoding error")
    maskedSeed, maskedDB = data[1:DIGEST_LEN+1], data[DIGEST_LEN+1:]
    seed = _ml.strxor(maskedSeed, _oaep_mgf(maskedDB, DIGEST_LEN))
    db = _ml.strxor(maskedDB, _oaep_mgf(seed, len(maskedDB)))
    m = None

    if db[:DIGEST_LEN] != _ml.sha1(p):
        raise CryptoError("Decoding error")

    for i in xrange(DIGEST_LEN,len(db)):
        if db[i] == '\x01':
            m = db[i+1:]
            break
        elif db[i] == '\x00':
            pass
        else:
            raise CryptoError("Decoding error")
    if m is None:
        raise CryptoError("Decoding error")
    return m

# Use the fastest implementaiton of OAEP we have.
if hasattr(_ml, 'check_oaep_padding'):
    check_oaep = _ml.check_oaep_padding
    add_oaep = _ml.add_oaep_padding
else:
    check_oaep = _check_oaep_padding
    add_oaep = _add_oaep_padding

#----------------------------------------------------------------------
# Key generation mode strings, as given in the Mixminion spec.

# Used to AES-encrypt the current header
HEADER_SECRET_MODE = "HEADER SECRET KEY"

# Used to pad the header
PRNG_MODE = RANDOM_JUNK_MODE = "RANDOM JUNK"

# Used to LIONESS-encrypt the off header
HEADER_ENCRYPT_MODE = "HEADER ENCRYPT"

# Used to LIONESS-encrypt the payload
PAYLOAD_ENCRYPT_MODE = "PAYLOAD ENCRYPT"

# Used to LIONESS-encrypt the header at the swap point.
HIDE_HEADER_MODE = "HIDE HEADER"

# Used to LIONESS-encrypt the payload at the swap point.
HIDE_PAYLOAD_MODE = "HIDE PAYLOAD"

# Used to remember whether we've seen a secret before
REPLAY_PREVENTION_MODE = "REPLAY PREVENTION"

# Passed to the delivery module
APPLICATION_KEY_MODE = "APPLICATION KEY"

#----------------------------------------------------------------------
# Key generation

class Keyset:
    """A Keyset represents a set of keys generated from a single master
       secret."""
    # Fields:  master-- the master secret.
    def __init__(self, master):
        """Creates a new keyset from a given master secret."""
        self.master = master
    def get(self, mode, bytes=AES_KEY_LEN):
        """Creates a new key from the master secret, using the first <bytes>
           bytes of SHA1(master||mode)."""
        assert 0 < bytes <= DIGEST_LEN
        return sha1(self.master+mode)[:bytes]
    def getLionessKeys(self, mode):
        """Returns a set of 4 lioness keys, as described in the Mixminion
           specification."""
        z19 = "\x00"*19
        key1 = sha1(self.master+mode)
        key2 = _ml.strxor(key1, z19+"\x01")
        key3 = _ml.strxor(key1, z19+"\x02")
        key4 = _ml.strxor(key1, z19+"\x03")
        
        return (key1, key2, key3, key4)

    def getBearKeys(self,mode):
        z19 = "\x00"*19
        key1 = sha1(self.master+mode)
        key2 = _ml.strxor(key1, z19+"\x01")
        return (key1, key2)

def lioness_keys_from_payload(payload):
    '''Given a payload, returns the LIONESS keys to encrypt the off-header
       at the swap point.''' 
    digest = sha1(payload)
    return Keyset(digest).getLionessKeys(HIDE_HEADER_MODE)

def lioness_keys_from_header(header2):
    '''Given the off-header, returns the LIONESS keys to encrypt the payload
       at the swap point.''' 
    digest = sha1(header2)
    return Keyset(digest).getLionessKeys(HIDE_PAYLOAD_MODE)

#---------------------------------------------------------------------
# Random number generators

class RNG:
    '''Base implementation class for random number generators.  Works
       by requesting a bunch of bytes via self._prng, and doling them
       out piecemeal via self.getBytes.'''
    def __init__(self, chunksize):
        """Initializes a RNG.  Bytes will be fetched from _prng by 'chunkSize'
           bytes at a time."""
        self.bytes = ""
        self.chunksize = chunksize
    def getBytes(self, n):
        """Returns a string of 'n' random bytes."""

        if n > len(self.bytes):
            # If we don't have enough bytes, fetch enough so that we'll have
            # a full chunk left over.
            nMore = n+self.chunksize-len(self.bytes)
            morebytes = self._prng(nMore)
            res = self.bytes+morebytes[:n-len(self.bytes)]
            self.bytes = morebytes[n-len(self.bytes):]
            return res
        else:
            res = self.bytes[:n]
            self.bytes = self.bytes[n:]
            return res

    def shuffle(self, lst, n=None):
	"""Rearranges the elements of lst so that the first n elements
	   are randomly chosen from lst.  Returns the first n elements.
	   (Other elements are still in lst, but may be in a nonrandom
	   order.)  If n is None, shuffles and returns the entire list"""
        size = len(lst)
	if n is None:
	    n = size
	else:
	    n = min(n, size)

	if n == size:
	    series = xrange(n-1)
	else:
	    series = xrange(n)

        # This permutation algorithm yields all permutation with equal
        # probability (assuming a good rng); others do not.
	getInt = self.getInt
        for i in series:
            swap = i+getInt(size-i)
	    lst[swap],lst[i] = lst[i],lst[swap]

	return lst[:n]

    def getInt(self, max):
        """Returns a random integer i s.t. 0 <= i < max.

           The value of max must be less than 2**30."""

        # FFFF This implementation is about 2-4x as good as the last one, but
	# FFFF still could be better.  It's faster than getFloat()*max.

	# XXXX (This code assumes that integers are at least 32 bits.)

        assert 0 < max < 0x3fffffff
	_ord = ord
	while 1:
	    # Get a random positive int between 0 and 0x7fffffff.
	    b = self.getBytes(4)
	    o = ((((((_ord(b[0])&0x7f)<<8) + _ord(b[1]))<<8) + 
		  _ord(b[2]))<<8) + _ord(b[3])
	    # Retry if we got a value that would fall in an incomplete
	    # run of 'max' elements.
	    if 0x7fffffff - max >= o:
		return o % max

    def getFloat(self):
	"""Return a floating-point number between 0 and 1."""
	b = self.getBytes(4)
	_ord = ord
	o = ((((((_ord(b[0])&0x7f)<<8) + _ord(b[1]))<<8) + 
	      _ord(b[2]))<<8) + _ord(b[3])
	#return o / float(0x7fffffff)
	return o / 2147483647.0

    def _prng(self, n):
        """Abstract method: Must be overridden to return n bytes of fresh
           entropy."""
        raise NotImplementedError("_prng")

class AESCounterPRNG(RNG):
    '''Pseudorandom number generator that yields an AES counter-mode cipher'''
    def __init__(self, seed=None):
        """Creates a new AESCounterPRNG with a given seed.  If no seed
           is specified, gets one from the true random number generator."""
        RNG.__init__(self, 16*1024)
        self.counter = 0
        if seed is None:
            seed = trng(AES_KEY_LEN)
        self.key = aes_key(seed)
        
    def _prng(self, n):
        """Implementation: uses the AES counter stream to generate entropy."""
        c = self.counter
        self.counter += n
        # On python2.0, we overflow and wrap around.
        if (self.counter < c) or (self.counter >> 32):
            raise MixFatalError("Exhausted period of PRNG.")
        return prng(self.key,n,c)

_theSharedPRNG = None
def getCommonPRNG():
    '''Returns a general-use AESCounterPRNG, initializing it if necessary.'''
    global _theSharedPRNG
    if _theSharedPRNG is None:
        _theSharedPRNG = AESCounterPRNG()
    return _theSharedPRNG

#----------------------------------------------------------------------
# TRNG implementation

# Here, we pick default files.
#
# This is a tricky point.  We want a device that gives securely-seeded
# numbers from a really strong entropy source, but we don't need it to
# block.  On Linux, this is /dev/urandom.  On BSD-ish things, this
# MAY be /dev/srandom (the man page only says that urandom 'is not
# guaranteed to be secure).  On Darwin, neither one seems to block.
# On commercial Unices, your guess is as good as mine.
PLATFORM_TRNG_DEFAULTS = {
    'darwin' : [ "/dev/urandom", "/dev/random" ],
    'linux2' : [ "/dev/urandom" ],
    '***' : [ "/dev/urandom", "/dev/srandom", "/dev/random" ],
    }

_TRNG_FILENAME = None
def configure_trng(config):
    """Initialize the true entropy source from a given Config object.  If
       none is provided, tries some sane defaults.""" 
    global _TRNG_FILENAME
    if config is not None:
        requestedFile = config['Host'].get('EntropySource', None)
    else:
	requestedFile = None

    defaults = 	PLATFORM_TRNG_DEFAULTS.get(sys.platform,
				   PLATFORM_TRNG_DEFAULTS['***'])
    files = [ requestedFile ] + defaults

    randFile = None
    for file in files:
	if file is None: 
	    continue

	verbose = 1#(file == requestedFile)
	if not os.path.exists(file):
	    if verbose:
		getLog().error("No such file as %s", file)
	else:
	    st = os.stat(file)
	    if not (st[stat.ST_MODE] & stat.S_IFCHR):
		if verbose:
		    getLog().error("Entropy source %s isn't a character device",
				   file)
	    else:
		randFile = file
		break

    if randFile is None and _TRNG_FILENAME is None:
        getLog().fatal("No entropy source available")
        raise MixFatalError("No entropy source available")
    elif randFile is None:
        getLog().warn("Falling back to previous entropy source %s",
                      _TRNG_FILENAME)
    else:
	getLog().info("Setting entropy source to %r", randFile)
        _TRNG_FILENAME = randFile
    
def _trng_uncached(n):
    '''Underlying access to our true entropy source.'''
    if _TRNG_FILENAME is None:
        configure_trng(None)
        
    f = open(_TRNG_FILENAME, 'rb')
    d = f.read(n)
    f.close()
    return d

class _TrueRNG(RNG):
    '''Random number generator that yields pieces of entropy from
       our true rng.'''
    def __init__(self,n):
        """Creates a TrueRNG to retrieve data from our underlying RNG 'n'
           bytes at a time"""
        RNG.__init__(self,n)
    def _prng(self,n):
        "Returns n fresh bytes from our true RNG."
        return _trng_uncached(n)

_theTrueRNG = _TrueRNG(1024)

