# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Crypto.py,v 1.48 2003/07/13 03:45:33 nickm Exp $
"""mixminion.Crypto

   This package contains all the cryptographic primitives required
   my the Mixminion spec.  Some of these are wrappers for functionality
   implemented in C by OpenSSL.  Nonetheless, other modules should call
   the functions in mixminion.Crypto, and not call _minionlib's crypto
   functionality themselves."""

import binascii
import copy_reg
import errno
import math
import os
import stat
import sys
import threading
from types import StringType

import mixminion._minionlib as _ml
from mixminion.Common import MixError, MixFatalError, floorDiv, ceilDiv, LOG

__all__ = [ 'AESCounterPRNG', 'CryptoError', 'Keyset', 'bear_decrypt',
            'bear_encrypt', 'ctr_crypt', 'getCommonPRNG', 'init_crypto',
            'lioness_decrypt', 'lioness_encrypt', 'openssl_seed',
            'pk_check_signature', 'pk_decode_private_key',
            'pk_decode_public_key', 'pk_decrypt', 'pk_encode_private_key',
            'pk_encode_public_key', 'pk_encrypt', 'pk_fingerprint',
            'pk_from_modulus', 'pk_generate', 'pk_get_modulus',
            'pk_same_public_key', 'pk_sign', 'prng', 'sha1', 'strxor', 'trng',
            'AES_KEY_LEN', 'DIGEST_LEN', 'HEADER_SECRET_MODE', 'PRNG_MODE',
            'RANDOM_JUNK_MODE', 'HEADER_ENCRYPT_MODE', 'APPLICATION_KEY_MODE',
            'PAYLOAD_ENCRYPT_MODE', 'HIDE_HEADER_MODE' ]

# Expose _minionlib.CryptoError as Crypto.CryptoError
CryptoError = _ml.CryptoError
# Expose _minionlib.generate_cert
generate_cert = _ml.generate_cert

# Number of bytes in an AES key.
AES_KEY_LEN = 128 >> 3
# Number of bytes in a SHA1 digest
DIGEST_LEN = 160 >> 3

def init_crypto(config=None):
    """Initialize the crypto subsystem."""
    configure_trng(config)
    try:
        # Try to read /dev/urandom
        trng(1)
    except MixFatalError:
        raise
    except:
        info = sys.exc_info()
        raise MixFatalError("Error initializing entropy source: %s", info[0])
    openssl_seed(40)

def sha1(s):
    """Return the SHA1 hash of a string"""
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

    # Split the message.
    left = s[:DIGEST_LEN]
    right = s[DIGEST_LEN:]
    del s
    # Performance note: This business with sha1("".join((key,right,key)))
    # may look slow, but it contributes only .7% to the total time for
    # LIONESS.
    right = _ml.aes_ctr128_crypt(
        _ml.aes_key(_ml.sha1("".join((key1,left,key1)))[:AES_KEY_LEN]),
        right, 0)
    left = _ml.strxor(left,  _ml.sha1("".join((key2,right,key2))))
    right = _ml.aes_ctr128_crypt(
        _ml.aes_key(_ml.sha1("".join((key3,left,key3)))[:AES_KEY_LEN]),
        right, 0)
    left = _ml.strxor(left,  _ml.sha1("".join((key4,right,key4))))

    # You could write the above as:
    #   right = ctr_crypt(right, "".join((key1,left,key1))[:AES_KEY_LEN])
    #   left = strxor(left, sha1("".join((key2,right,key2))))
    #   right = ctr_crypt(right, "".join((key3,left,key3))[:AES_KEY_LEN])
    #   left = strxor(left, sha1("".join((key4,right,key4))))
    # but that would be slower by about 10%.  (Since LIONESS is in the
    # critical path, we care.)

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

    # Slow, comprehensible version:
    #left = strxor(left,  sha1("".join([key4,right,key4])))
    #right = ctr_crypt(right, sha1("".join([key3,left,key3]))[:AES_KEY_LEN])
    #left = strxor(left,  sha1("".join([key2,right,key2])))
    #right = ctr_crypt(right, sha1("".join([key1,left,key1]))[:AES_KEY_LEN])

    # Equivalent-but-faster version:
    left = _ml.strxor(left, _ml.sha1("".join((key4,right,key4))))
    right = _ml.aes_ctr128_crypt(
        _ml.aes_key(_ml.sha1("".join((key3,left, key3)))[:AES_KEY_LEN]),
        right, 0)
    left = _ml.strxor(left, _ml.sha1("".join((key2,right,key2))))
    right = _ml.aes_ctr128_crypt(
        _ml.aes_key(_ml.sha1("".join((key1,left, key1)))[:AES_KEY_LEN]),
        right, 0)

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
    if _theTrueRNG is None:
        configure_trng(None)
    return _theTrueRNG.getBytes(count)

# Specified in the Mixminion spec.  It's a Thomas Paine quotation.
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
    # private key encrypt
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

def pk_same_public_key(key1, key2):
    """Return true iff key1 and key2 are the same key."""
    return key1.encode_key(1) == key2.encode_key(1)

def pk_fingerprint(key):
    """Return the 40-character fingerprint of public key 'key'.  This
       is computed as the hex encoding of the SHA-1 digest of the
       ASN.1 encoding of the public portion of key."""
    return binascii.b2a_hex(sha1(key.encode_key(1))).upper()

def pk_PEM_save(rsa, filename, password=None):
    """Save a PEM-encoded private key to a file.  If <password> is provided,
       encrypt the key using the password."""
    fd = os.open(filename, os.O_WRONLY|os.O_CREAT,0600)
    f = os.fdopen(fd, 'w')
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
    return _ml.rsa_decode_key, (rsa.encode_key(1),1)

# Register this function to make RSA keys pickleable.  Note that we only
# pickle the public part of an RSA key; for long-term storage of private
# keys, you should use PEM so we can support encryption.
copy_reg.pickle(_ml.RSA, _pickle_rsa, _ml.rsa_decode_key)

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
    ''' Mask generation function specified for RSA-OAEP.  Given a seed
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

# Use the fastest implementation of OAEP we have.
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

# Used by the sender to encrypt the payload when sending an encrypted forward
#  message
END_TO_END_ENCRYPT_MODE = "END-TO-END ENCRYPT"

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

# The getInt code below assumes that ints are at least 32 bits long. Here
# we assert it.
assert sys.maxint >= 0x7fffffff

# Magic number used for normal distribution
NV_MAGICCONST = 4 * math.exp(-0.5)/math.sqrt(2.0)

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

    def pick(self, lst):
        """Return a member of 'lst', chosen randomly according to a uniform
           distribution.  Raises IndexError if lst is empty."""
        if not lst:
            raise IndexError("rng.pick([])")
        return lst[self.getInt(len(lst))]

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

        # FFFF (This code assumes that integers are at least 32 bits. Maybe
        # FFFF  we could do better.)

        assert 0 < max < 0x3fffffff
        _ord = ord
        while 1:
            # Get a random positive int between 0 and 0x7fffffff.
            b = self.getBytes(4)
            o = (((((((_ord(b[0])&0x7f)<<8) +
                       _ord(b[1]))<<8) +
                       _ord(b[2]))<<8) +
                       _ord(b[3]))
            # Retry if we got a value that would fall in an incomplete
            # run of 'max' elements.
            if 0x7fffffff - max >= o:
                return o % max

    def getNormal(self, m, s):
        """Return a random value with mean m and standard deviation s.
        """
        # Lifted from random.py in standard python dist.
        while 1:
            u1 = self.getFloat()
            u2 = 1.0 - self.getFloat()
            z = NV_MAGICCONST*(u1-0.5)/u2
            zz = z*z/4.0
            if zz <= -math.log(u2):
                break
        return m + z*s

    def getFloat(self):
        """Return a floating-point number between 0 and 1."""
        b = self.getBytes(4)
        _ord = ord
        o = ((((((_ord(b[0])&0x7f)<<8) + _ord(b[1]))<<8) +
              _ord(b[2]))<<8) + _ord(b[3])
        #return o / float(0x7fffffff)
        return o / 2147483647.0

    def openNewFile(self, dir, prefix="", binary=1):
        """Generate a new random filename within a directory with a given
           prefix within a directory, and open a new file within the directory
           with that filename.  Return 2-tuple of a file object and the
           random portion of the filename.

           Random portions are generated by choosing 8 random characters
           from the set 'A-Za-z0-9+-'.
           """
        flags = os.O_WRONLY|os.O_CREAT|os.O_EXCL
        mode = "w"
        if binary:
            flags |= getattr(os, 'O_BINARY', 0)
            mode = "wb"
        while 1:
            bytes = self.getBytes(6)
            base = binascii.b2a_base64(bytes).strip().replace("/","-")
            fname = os.path.join(dir, "%s%s"%(prefix,base))
            try:
                fd = os.open(fname, flags, 0600)
                return os.fdopen(fd, mode), base
            except OSError, e:
                if e.errno != errno.EEXIST:
                    raise e
                # If the file exists (a rare event!) we pass through, and
                # try again.  This paranoia is brought to you by user
                # request. :)
        raise MixFatalError("Unreachable") # appease pychecker.

    def _prng(self, n):
        """Abstract method: Must be overridden to return n bytes of fresh
           entropy."""
        raise NotImplementedError("_prng")

class AESCounterPRNG(RNG):
    '''Pseudorandom number generator that yields an AES counter-mode cipher'''
    ## Fields:
    # counter: the current index into the AES counter-mode keystream
    # key: the current AES key.
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

def getCommonPRNG():
    '''Returns a general-use AESCounterPRNG, initializing it if necessary.'''
    # We create one PRNG per thread.
    thisThread = threading.currentThread()
    try:
        return thisThread.minion_shared_PRNG
    except AttributeError:
        thisThread.minion_shared_PRNG = AESCounterPRNG()
        return thisThread.minion_shared_PRNG

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
    global _theTrueRNG
    if config is not None:
        requestedFile = config['Host'].get('EntropySource')
    else:
        requestedFile = None

    # Build a list of candidates
    defaults =  PLATFORM_TRNG_DEFAULTS.get(sys.platform,
                           PLATFORM_TRNG_DEFAULTS['***'])
    files = [ requestedFile ] + defaults

    # Now find the first of our candidates that exists and is a character
    # device.
    randFile = None
    for file in files:
        if file is None:
            continue

        verbose = 1#(file == requestedFile)
        if not os.path.exists(file):
            if verbose:
                LOG.error("No such file as %s", file)
        else:
            st = os.stat(file)
            if not (st[stat.ST_MODE] & stat.S_IFCHR):
                if verbose:
                    LOG.error("Entropy source %s isn't a character device",
                                   file)
            else:
                randFile = file
                break

    if randFile is None and _TRNG_FILENAME is None:
        if sys.platform == 'win32':
            LOG.warn("Using bogus screen snapshot for entropy source: beware!") 
            _ml.openssl_seed_win32()
            _theTrueRNG = _OpensslRNG()
        else:
            LOG.fatal("No entropy source available")
            raise MixFatalError("No entropy source available")
    elif randFile is None:
        LOG.warn("Falling back to previous entropy source %s",
                 _TRNG_FILENAME)
    else:
        LOG.info("Setting entropy source to %r", randFile)
        _TRNG_FILENAME = randFile
        _theTrueRNG = _TrueRNG(1024)


# Global TRN instance, for use by trng().
_theTrueRNG = None 

class _TrueRNG(RNG):
    '''Random number generator that yields pieces of entropy from
       our true rng.'''
    def __init__(self,n):
        """Creates a TrueRNG to retrieve data from our underlying RNG 'n'
           bytes at a time"""
        RNG.__init__(self,n)
        self.__lock = threading.Lock()

    def _prng(self,n):
        "Returns n fresh bytes from our true RNG."
        if _TRNG_FILENAME is None:
            configure_trng(None)

        f = open(_TRNG_FILENAME, 'rb')
        d = f.read(n)
        f.close()
        return d

    def getBytes(self, n):
        # We need to synchronize this method, since a single TRNG instance
        # is shared by all threads.
        self.__lock.acquire()
        b = RNG.getBytes(self, n)
        self.__lock.release()
        return b

class _OpensslRNG(RNG):
    """DOCDOC"""
    def __init__(self):
        """DOCDOC"""
        RNG.__init__(self, 1024)
    def _prng(self,n):
        return _ml.openssl_rand(n)

# Return the shared instance of the true RNG.
def getTrueRNG():
    """Return the shared instance of the true RNG."""
    if _theTrueRNG is None:
        configure_trng(None)
    return _theTrueRNG
