# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Crypto.py,v 1.11 2002/07/28 22:42:33 nickm Exp $
"""mixminion.Crypto

   This package contains all the cryptographic primitives required
   my the Mixminion spec.  Some of these are wrappers for functionality
   implemented in C by OpenSSL.  Nonetheless, other modules should call
   the functions in mixminion.Crypto, and not call _minionlib's crypto
   functionality themselves."""

import os
import stat
from types import StringType

import mixminion.Config
import mixminion._minionlib as _ml
from mixminion.Common import MixError, MixFatalError, floorDiv, ceilDiv, getLog

__all__ = [ 'CryptoError', 'init_crypto', 'sha1', 'ctr_crypt', 'prng',
            'strxor', 'lioness_encrypt', 'lioness_decrypt', 'trng',
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

def init_crypto():
    """Initialize the crypto subsystem."""
    trng(1)
    try:
        # Try to read /dev/urandom
        trng(1)
    except:
        raise MixFatalError("Couldn't initialize entropy source")
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
    """Given a 16-byte key2 and key4, and a 20-byte key1 and key3, encrypts
       s using the LIONESS super-pseudorandom permutation.
    """

    assert len(key1) == len(key3) == DIGEST_LEN
    assert len(key2) == len(key4) == DIGEST_LEN
    assert len(s) > DIGEST_LEN

    left = s[:DIGEST_LEN]
    right = s[DIGEST_LEN:]
    del s
    # Performance note: This business with sha1("".join([key,right,key]))
    # may look slow, but it contributes only a 6% to the hashing step,
    # which in turn contributes under 11% of the time for LIONESS.
    right = ctr_crypt(right, _ml.sha1("".join([key1,left,key1]))[:AES_KEY_LEN])
    left = _ml.strxor(left,  _ml.sha1("".join([key2,right,key2])))
    right = ctr_crypt(right, _ml.sha1("".join([key3,left,key3]))[:AES_KEY_LEN])
    left = _ml.strxor(left,  _ml.sha1("".join([key4,right,key4])))
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
    """Returns the RSA encryption of OAEP-padded data, using the public key
       in key.
    """
    bytes = key.get_modulus_bytes()
    data = add_oaep(data,OAEP_PARAMETER,bytes)
    # public key encrypt
    return key.crypt(data, 1, 1)

def pk_sign(data, key):
    """XXXX"""
    bytes = key.get_modulus_bytes()
    data = add_oaep(data,OAEP_PARAMETER,bytes)
    return key.crypt(data, 0, 1)

def pk_decrypt(data,key):
    """Returns the unpadded RSA decryption of data, using the private key in\n
       key
    """
    bytes = key.get_modulus_bytes()
    # private key decrypt
    data = key.crypt(data, 0, 0)
    return check_oaep(data,OAEP_PARAMETER,bytes)

def pk_check_signature(data, key):
    """XXXX"""
    bytes = key.get_modulus_bytes()
    # private key decrypt
    data = key.crypt(data, 1, 0)
    return check_oaep(data,OAEP_PARAMETER,bytes)

def pk_generate(bits=1024,e=65535):
    """Generate a new RSA keypair with 'bits' bits and exponent 'e'.  It is
       safe to use the default value of 'e'.
    """
    return _ml.rsa_generate(bits,e)

def pk_get_modulus(key):
    """Extracts the modulus of a public key."""
    return key.get_public_key()[0]

def pk_from_modulus(n, e=65535L):
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
        key2 = _ml.strxor(sha1(self.master+mode), z19+"\x01")
        key3 = _ml.strxor(sha1(self.master+mode), z19+"\x02")
        key4 = _ml.strxor(sha1(self.master+mode), z19+"\x03")

        return (key1, key2, key3, key4)

def lioness_keys_from_payload(payload):
    '''Given a payload, returns the LIONESS keys to encrypt the off-header
       at the swap point.''' 
    
    # XXXX Temporary method till George and I agree on a key schedule.
    digest = sha1(payload)
    return Keyset(digest).getLionessKeys(HIDE_HEADER_MODE)

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

    def getInt(self, max):
        """Returns a random integer i s.t. 0 <= i < max.

           The value of max must be less than 2**32."""

        # FFFF This implementation isn't very good.  It determines the number
        # of bytes in max (nBytes), and a bitmask 1 less than the first power
        # of 2 less than max.
        #
        # Then, it gets nBytes random bytes, ANDs them with the bitmask, and
        # checks to see whether the result is < max.  If so, it returns.  Else,
        # it generates more random bytes and tries again.
        #
        # On the plus side, this algorithm will obviously give all values
        # 0 <= i < max with equal probability.  On the minus side, it
        # requires (on average) 2*nBytes entropy to do so.
        
        assert max > 0
        for bits in xrange(1,33):
            if max < 1<<bits:
                nBytes = ceilDiv(bits,8)
                mask = (1<<bits)-1
                break
        if bits == 33:
            raise "I didn't expect to have to generate a number over 2**32"

        while 1:
            bytes = self.getBytes(nBytes)
            r = 0
            for byte in bytes:
                r = (r << 8) + ord(byte)
            r = r & mask
            if r < max:
                return r

    def _prng(self, n):
        """Abstract method: Must be overridden to return n bytes of fresh
           entropy."""
        raise MixFatalError()

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

_TRNG_FILENAME = None
def _trng_set_filename():
    global _TRNG_FILENAME
    config = mixminion.Config.getConfig()
    if config is not None:
        file = config['Host'].get('EntropySource', "/dev/urandom")
    else:
        file = "/dev/urandom"

    if not os.path.exists(file):
        getLog().error("No such file as %s", file)
        file = None
    else:
        st = os.stat(file)
        if not (st[stat.ST_MODE] & stat.S_IFCHR):
            getLog().error("Entropy source %s isn't a character device", file)
            file = None

    if file is None and _TRNG_FILENAME is None:
        getLog().fatal("No entropy source available")
        raise MixFatalError("No entropy source available")
    elif file is None:
        getLog().warn("Falling back to previous entropy source %s",
                      _TRNG_FILENAME)
    else:
        _TRNG_FILENAME = file
    
def _trng_uncached(n):
    '''Underlying access to our true entropy source.'''
    if _TRNG_FILENAME is None:
        _trng_set_filename()
        mixminion.Config.addHook(_trng_set_filename)
        
    f = open(_TRNG_FILENAME)
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
