# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Crypto.py,v 1.3 2002/05/29 18:54:43 nickm Exp $
"""mixminion.Crypto

   This package contains all the cryptographic primitives required
   my the Mixminion spec.  Some of these are wrappers for functionality
   implemented in C by OpenSSL.  Nonetheless, other modules should call
   the functions in mixminion.Crypto, and not call _minionlib's crypto
   functionality themselves."""

import sys
import mixminion._minionlib as _ml

__all__ = [ 'init_crypto', 'sha1',  'ctr_crypt', 'prng',
            'lioness_encrypt', 'lioness_decrypt', 'trng', 'pk_encrypt',
            'pk_decrypt', 'pk_generate', 'openssl_seed',
            'pk_get_modulus', 'pk_from_modulus',
            'pk_encode_private_key', 'pk_decode_private_key',
            'Keyset', 'AESCounterPRNG',
            'HEADER_SECRET_MODE', 'PRNG_MODE', 'HEADER_ENCRYPT_MODE',
            'PAYLOAD_ENCRYPT_MODE', 'HIDE_HEADER_MODE' ]

AES_KEY_LEN = 128/8
DIGEST_LEN = 160/8

def init_crypto():
    """init_crypto()

       Initialize the crypto subsystem."""
    try:
        # Try to read /dev/urandom.
        seed = trng(1)
    except:
        print "Couldn't initialize entropy source (/dev/urandom).  Bailing..."
        sys.exit(1)
    openssl_seed(40)

def sha1(s):
    """sha1(s) -> str

    Returns the SHA1 hash of its argument"""
    return _ml.sha1(s)

def strxor(s1, s2):
    """strxor(s1, s2) -> str

    Computes the bitwise xor of two strings.  Raises an exception if the
    strings' lengths are unequal."""
    return _ml.strxor(s1, s2)

def ctr_crypt(s, key, idx=0):
    """ctr_crypt(s, key, idx=0) -> str

       Given a string s and a 16-byte key key, computes the AES counter-mode
       encryption of s using k.  The counter begins at idx."""
    if type(key) == str:
        key = _ml.aes_key(key)
    return _ml.aes_ctr128_crypt(key,s,idx)

def prng(key,count,idx=0):
    """Returns the bytestream 0x00000000...., encrypted in counter mode."""
    if type(key) == str:
        key = _ml.aes_key(key)
    return _ml.aes_ctr128_crypt(key,"",idx,count)

def lioness_encrypt(s,key):
    """lioness_encrypt(s, (key1,key2,key3,key4)) -> str

    Given a 16-byte key2 and key4, and a 20-byte key1 and key3, encrypts
    s using the LIONESS super-pseudorandom permutation."""

    assert len(key) == 4
    key1,key2,key3,key4 = key
    assert len(key1)==len(key3)==20
    assert len(key2)==len(key4)==20
    assert len(s) > 20

    left = s[:20]
    right = s[20:]
    del s
    # Performance note: This business with sha1("".join([key,right,key]))
    # may look slow, but it contributes only a 6% to the hashing step,
    # which in turn contributes under 11% of the time for LIONESS.
    right = ctr_crypt(right, _ml.sha1("".join([key1,left,key1]))[:16])
    left = _ml.strxor(left,  _ml.sha1("".join([key2,right,key2])))
    right = ctr_crypt(right, _ml.sha1("".join([key3,left,key3]))[:16])
    left = _ml.strxor(left,  _ml.sha1("".join([key4,right,key4])))
    return left + right

def lioness_decrypt(s,key):
    """lioness_encrypt(s, (key1,key2,key3,key4)) -> str

    Given a 16-byte key2 and key4, and a 20-byte key1 and key3, decrypts
    s using the LIONESS super-pseudorandom permutation."""

    assert len(key) == 4
    key1,key2,key3,key4 = key
    assert len(key1)==len(key3)==20
    assert len(key2)==len(key4)==20
    assert len(s) > 20

    left = s[:20]
    right = s[20:]
    del s
    #XXXX This slice makes me nervous
    left = _ml.strxor(left,  _ml.sha1("".join([key4,right,key4])))
    right = ctr_crypt(right, _ml.sha1("".join([key3,left,key3]))[:16])
    left = _ml.strxor(left,  _ml.sha1("".join([key2,right,key2])))
    right = ctr_crypt(right, _ml.sha1("".join([key1,left,key1]))[:16])
    return left + right

def openssl_seed(count):
    """openssl_seed(count)

       Seeds the openssl rng with 'count' bytes of real entropy."""
    _ml.openssl_seed(trng(count))

def trng(count):
    """trng(count) -> str

    Returns (count) bytes of true random data from a true source of
    entropy (/dev/urandom)"""
    f = open('/dev/urandom')
    d = f.read(count)
    f.close()
    return d

OAEP_PARAMETER = "He who would make his own liberty secure, "+\
                 "must guard even his enemy from oppression."

def pk_encrypt(data,key):
    """pk_encrypt(data,key)->str

    Returns the RSA encryption of OAEP-padded data, using the public key in\n
    key"""
    bytes = _ml.rsa_get_modulus_bytes(key)
    data = _ml.add_oaep_padding(data,OAEP_PARAMETER,bytes)
    # public key encrypt
    return _ml.rsa_crypt(key, data, 1, 1)

def pk_decrypt(data,key):
    """pk_decrypt(data,key)->str

    Returns the unpadded RSA decryption of data, using the private key in\n
    key"""
    bytes = _ml.rsa_get_modulus_bytes(key)
    # private key decrypt
    data = _ml.rsa_crypt(key, data, 0, 0)
    return  _ml.check_oaep_padding(data,OAEP_PARAMETER,bytes)

def pk_generate(bits=1024,e=65535):
    """pk_generate(bits=1024, e=65535) -> rsa

       Generate a new RSA keypair with 'bits' bits and exponent 'e'.  It is
       safe to use the default value of 'e'."""
    return _ml.rsa_generate(bits,e)

def pk_get_modulus(key):
    """pk_get_modulus(rsa)->long

       Extracts the modulus of a public key."""
    return _ml.rsa_get_public_key(key)[0]

def pk_from_modulus(n, e=65535L):
    """pk_from_modulus(rsa,e=65535L)->rsa

       Given a modulus and exponent, creates an RSA public key."""
    return _ml.rsa_make_public_key(long(n),long(e))

def pk_encode_private_key(key):
    """pk_encode_private_key(rsa)->str

       Creates an ASN1 representation of a keypair for external storage."""
    return _ml.rsa_encode_key(key,0)

def pk_decode_private_key(s):
    """pk_encode_private_key(str)->rsa

       Reads an ASN1 representation of a keypair from external storage."""
    return _ml.rsa_decode_key(s,0)

#----------------------------------------------------------------------

HEADER_SECRET_MODE = "HEADER SECRET KEY"
PRNG_MODE = "RANDOM JUNK"
HEADER_ENCRYPT_MODE = "HEADER ENCRYPT"
PAYLOAD_ENCRYPT_MODE = "PAYLOAD ENCRYPT"
HIDE_HEADER_MODE = "HIDE HEADER"
REPLAY_PREVENTION_MODE = "REPLAY PREVENTION"

class Keyset:
    """A Keyset represents a set of keys generated from a single master
       secret."""
    def __init__(self, master):
        """Keyset(master)

           Creates a new keyset from a given master secret."""
        self.master = master
    def get(self, mode, bytes=AES_KEY_LEN):
        """ks.get(mode, bytes=AES_KEY_LEN)

           Creates a new key from the master secret, using the first <bytes>
           bytes of SHA1(master||mode)."""
        assert 0<bytes<=DIGEST_LEN
        return sha1(self.master+mode)[:bytes]
    def getLionessKeys(self, mode):
        """ks.getLionessKeys(mode)

           Returns a set of 4 lioness keys, as described in the Mixminion
           specification."""
        z19="\x00"*19
        key1 = sha1(self.master+mode)
        key2 = _ml.strxor(sha1(self.master+mode), z19+"\x01")
        key3 = _ml.strxor(sha1(self.master+mode), z19+"\x02")
        key4 = _ml.strxor(sha1(self.master+mode), z19+"\x03")
        
        return (key1, key2, key3, key4)

def lioness_keys_from_payload(payload):
    # XXXX Temporary method till George and I agree on a key schedule.
    digest = sha1(payload)
    return Keyset(digest).getLionessKeys(HIDE_HEADER_MODE)

#---------------------------------------------------------------------

class AESCounterPRNG:
    _CHUNKSIZE = 16*1024
    _KEYSIZE = 16
    def __init__(self, seed=None):
        self.counter = 0
        self.bytes = ""
        if seed==None: seed=trng(AESCounterPRNG._KEYSIZE)
        self.key = _ml.aes_key(seed)

    def getBytes(self, n):
        if n > len(self.bytes):
            nMore = n+AESCounterPRNG._CHUNKSIZE-len(self.bytes)
            morebytes = prng(self.key,nMore,self.counter)
            self.counter+=nMore
            res = self.bytes+morebytes[:n-len(self.bytes)]
            self.bytes=morebytes[n-len(self.bytes):]
            return res
        else:
            res = self.bytes[:n]
            self.bytes=self.bytes[n:]
            return res
