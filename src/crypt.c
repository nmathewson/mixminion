/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: crypt.c,v 1.4 2002/06/02 06:11:16 nickm Exp $ */
#include <Python.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <_minionlib.h>
#include <assert.h>

#define TYPE_ERR(s) PyErr_SetString(PyExc_TypeError, s)
#define KEY_IS_PRIVATE(rsa) ((rsa)->p)

PyObject *mm_SSLError = NULL;

/* Helper function: raise an SSLError with appropriate text from the
 * underlying SSL exception.  
 *
 * Requires that mm_SSLError is initialized and ERR_load_*_strings
 * have been called.
 */
static void 
SSL_ERR() 
{
	int err = ERR_get_error();
	const char *str = ERR_reason_error_string(err);
	assert(mm_SSLError);
	if (str)
		PyErr_SetString(mm_SSLError, str);
	else
		PyErr_SetString(mm_SSLError, "SSL error");
}

const char mm_sha1__doc__[] = 
  "sha1(s) -> str\n\n"
  "Computes the SHA-1 hash of a string.\n";

PyObject*
mm_sha1(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "string", NULL};
	unsigned char *cp = NULL;
	int len;
	SHA_CTX ctx;
	PyObject *output;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#:sha1", kwlist,
					 &cp, &len))
		return NULL;	
	if (!(output = PyString_FromStringAndSize(NULL, SHA_DIGEST_LENGTH))) {
		PyErr_NoMemory();
		return NULL;
	}
	
	SHA1_Init(&ctx);
	SHA1_Update(&ctx,cp,len); 
	SHA1_Final(PyString_AS_STRING(output),&ctx);
	memset(&ctx,0,sizeof(ctx));
	
	return output;
}

static char aes_descriptor[] = "AES key objects descriptor";

/* Destructor of PyCObject
 */
static void
aes_destruct(void *obj, void *desc)
{
	assert(desc==aes_descriptor);
	memset(obj, 0, sizeof(AES_KEY));
	free(obj);
}

/* Converter fn for "O&" argument conversion with AES keys. */
static int
aes_arg_convert(PyObject *obj, void *adr)
{
	if (PyCObject_Check(obj) && PyCObject_GetDesc(obj) == aes_descriptor) {
		*((AES_KEY**) adr) = (AES_KEY*) PyCObject_AsVoidPtr(obj);
		return 1;
	} else {
		TYPE_ERR("Expected an AES key as an argument.");
		return 0;
	}
}

#define WRAP_AES(aes) (PyCObject_FromVoidPtrAndDesc( (void*) (aes),\
		       (void*) aes_descriptor, aes_destruct))

const char mm_aes_key__doc__[] = 
    "aes_key(str) -> key\n\n"
    "Converts a 16-byte string to an AES key for use with aes_ctr128_crypt.\n"
    "\n(The performance advantage to doing so is only significant for small\n"
    "(<1K) blocks.)\n";  

PyObject*
mm_aes_key(PyObject *self, PyObject *args, PyObject *kwdict)
{
	static char *kwlist[] = { "key", NULL }; 
	char *key;
	int keylen;
	AES_KEY *aes_key = NULL;
	PyObject *result;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#:aes_key", kwlist,
					 &key, &keylen))
		return NULL;
	if (keylen != 16) {
		TYPE_ERR("aes_key() requires a 128-bit (16 byte) string");
		return NULL;
	}
	
	if (!(aes_key = malloc(sizeof(AES_KEY)))) {
		PyErr_NoMemory(); goto err; 
	}
	if (AES_set_encrypt_key(key, keylen*8, aes_key)) {
		SSL_ERR();
		goto err;
	}
	if (!(result = WRAP_AES(aes_key))) { 
		PyErr_NoMemory(); goto err; 
	}
	return result;

 err:
	if (aes_key) {
		memset(aes_key, 0, sizeof(AES_KEY));
		free(aes_key);
	}
	return NULL;
}


const char mm_aes_ctr128_crypt__doc__[] = 
  "aes_ctr128_crypt(key, string, idx=0, prng=0) -> str\n\n"
  "Encrypts a string in counter mode.  If idx is nonzero, the counter begins\n"
  "at idx.  If prng is nonzero, ignores string and just produces a stream of\n"
  "length prng.\n\n"
  "WART: only the 32 least significant bits of idx are used.\n\n"
  "Performance notes:  PRNG mode is much faster (36% @ 32K) than generating\n"
  "a string of NULs in Python and encrypting it.  Encryption, on the other\n"
  "hand, is only slightly faster (15% @ 32K) than XORing the prng output\n"
  "with the plaintext.\n";

PyObject*
mm_aes_ctr128_crypt(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "key", "string", "idx", "prng", NULL };
	unsigned char *input;
        int inputlen, prng=0;
	long idx=0;
	AES_KEY *aes_key = NULL;

	PyObject *output;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "O&s#|li:aes_ctr128_crypt", kwlist,
					 aes_arg_convert, &aes_key, 
					 &input, &inputlen,
					 &idx, &prng))
		return NULL;
	
	if (idx < 0) idx = 0;
	if (prng < 0) prng = 0;

	if (prng) { 
		inputlen = prng;
		if (!(input = malloc(prng))) { PyErr_NoMemory(); return NULL; }
		memset(input, 0, inputlen);
	} 
	
	if (!(output = PyString_FromStringAndSize(NULL, inputlen))) {
		PyErr_NoMemory(); 
		if (prng) free(input);
		return NULL;
	}

	mm_aes_counter128(input, PyString_AS_STRING(output), inputlen,
			  aes_key, idx); 

	if (prng) free(input);
	return output;
}

const char mm_strxor__doc__[]=
  "strxor(str1, str2) -> str\n\n"
  "Computes the bitwise xor of two equally-long strings.  Throws TypeError\n"
  "if the strings\' lengths are not the same.";

PyObject*
mm_strxor(PyObject *self, PyObject *args, PyObject *kwdict)
{
	static char *kwlist[] = { "str1", "str2", NULL };
	unsigned char *s1, *s2;
	unsigned char *outp;
	int s1len, s2len;
	PyObject *output;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict,
					 "s#s#:strxor", kwlist,
					 &s1, &s1len, &s2, &s2len))
		return NULL;
	if (s1len != s2len) {
		TYPE_ERR("Mismatch between argument lengths");
		return NULL;
	}

	
	if (!(output = PyString_FromStringAndSize(NULL,s1len))) { 
		PyErr_NoMemory(); 
		return NULL; 
	}

	outp = PyString_AS_STRING(output);
	while (s1len--) {
		*(outp++) = *(s1++) ^ *(s2++);
	}

	return output;
}

const char mm_openssl_seed__doc__[]=
  "openssl_seed(str)\n\n"
  "Seeds OpenSSL\'s internal random number generator with a provided source\n"
  "of entropy.  This method must be called before generating RSA keys or\n"
  "OAEP padding.\n";

PyObject *
mm_openssl_seed(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "seed", NULL };
	unsigned char *seed;
	int seedlen;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#:openssl_seed", 
					 kwlist,
					 &seed, &seedlen))
		return NULL;

	
	RAND_seed(seed, seedlen);
	Py_INCREF(Py_None);
	return Py_None;
}

static char rsa_descriptor[] = "RSA objects descriptor";

/* Destructor for PyCObject
 */
static void
rsa_destruct(void *obj, void *desc) 
{
	assert(desc==rsa_descriptor);
	RSA_free( (RSA*) obj);
}

/* Converter fn for "O&" argument conversion with RSA keys. */
static int
rsa_arg_convert(PyObject *obj, void *adr) 
{
	if (PyCObject_Check(obj) && PyCObject_GetDesc(obj) == rsa_descriptor) {
		*((RSA**) adr) = (RSA*) PyCObject_AsVoidPtr(obj);
		return 1;
	} else {
		TYPE_ERR("Expected an RSA key as an argument.");
		return 0;
	}
}

#define WRAP_RSA(rsa) (PyCObject_FromVoidPtrAndDesc( (void*) (rsa),\
		       (void*) rsa_descriptor, rsa_destruct))
					     
const char mm_rsa_crypt__doc__[]=
  "rsa_crypt(key, string, public, encrypt) -> str\n\n"
  "Uses RSA to encrypt or decrypt a provided string.  If encrypt is true,\n"
  "encrypts; else, decrypts.  If public is true, performs a public-key\n"
  "operation; else, performs a private-key operation.";

PyObject *
mm_rsa_crypt(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "key", "string", "public", "encrypt", NULL };

	RSA *rsa;
	unsigned char *string;
	int stringlen, pub, encrypt;

	int keylen, i;
	char *out;
	PyObject *output;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "O&s#ii:rsa_crypt", kwlist,
					 rsa_arg_convert, &rsa, 
					 &string, &stringlen, &pub, &encrypt))
		return NULL;
	if (!pub && !KEY_IS_PRIVATE(rsa)) {
		TYPE_ERR("Can\'t use public key for private-key operation");
		return NULL;
	}

	keylen = BN_num_bytes(rsa->n);

	output = PyString_FromStringAndSize(NULL, keylen);
	out = PyString_AS_STRING(output);
	if (encrypt) {
		if (pub)
			i = RSA_public_encrypt(stringlen, string, out, rsa, 
					       RSA_NO_PADDING);
		else 
			i = RSA_private_encrypt(stringlen, string, out, rsa, 
						RSA_NO_PADDING);
	} else {
		if (pub)
			i = RSA_public_decrypt(stringlen, string, out, rsa,
					       RSA_NO_PADDING);
		else
			i = RSA_private_decrypt(stringlen, string, out, rsa,
						RSA_NO_PADDING);
	}

	if (i <= 0) {
		Py_DECREF(output);
		SSL_ERR();
		return NULL;
	}
	if(_PyString_Resize(&output, i)) return NULL; 

	return output;
}

const char mm_rsa_generate__doc__[]=
  "rsa_generate(bits,e) -> rsa\n\n"
  "Generates a new RSA key with a requested number of bits and e parameter.\n"
  "Remember to seed the OpenSSL rng before calling this method.\n";

PyObject *
mm_rsa_generate(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = {"bits", "e", NULL};
	int bits, e;
	RSA *rsa;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "ii:rsa_generate", 
					 kwlist,
					 &bits, &e))
		return NULL;

	rsa = RSA_generate_key(bits, e, NULL, NULL);
	if (rsa == NULL) {
		SSL_ERR();
		return NULL;
	}
	
	return WRAP_RSA(rsa);
}

const char mm_rsa_encode_key__doc__[]=
  "rsa_encode_key(rsa,public) -> str\n\n"
  "Computes the DER encoding of a given key.  If 'public' is true, encodes\n"
  "only the public-key portions of rsa.\n";
 
PyObject *
mm_rsa_encode_key(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "key", "public", NULL };
	
	RSA *rsa;
	int public;

	int len;
	PyObject *output;
	unsigned char *out, *outp;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "O&i:rsa_encode_key", kwlist,
					 rsa_arg_convert, &rsa, &public))
		return NULL;

	if (!public && !KEY_IS_PRIVATE(rsa)) {
		TYPE_ERR("Can\'t use public key for private-key operation");
		return NULL;
	}

	len = public ? i2d_RSAPublicKey(rsa,NULL) : 
		i2d_RSAPrivateKey(rsa,NULL);
	if (len < 0) {
		SSL_ERR();
		return NULL;
	}
	out = outp = malloc(len+1);
	if (public) 
		len = i2d_RSAPublicKey(rsa, &outp);
	else 
		len = i2d_RSAPrivateKey(rsa, &outp);
	if (len < 0) {
		free(out);
		SSL_ERR();
		return NULL;
	}

	output = PyString_FromStringAndSize(out, len);
	free(out);
	if (!output) {
		PyErr_NoMemory();
		return NULL;
	}
	return output;
}

const char mm_rsa_decode_key__doc__[]=
  "rsa_decode_key(key, public) -> rsa\n\n"
  "Extracts an RSA key from its DER encoding.  If public is true, expects a\n"
  "public key only.  Otherwise, expects a private key.\n";

PyObject *
mm_rsa_decode_key(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "key", "public", NULL };
	
	const unsigned char *string;
	int stringlen, public;

	RSA *rsa;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "s#i:rsa_decode_key", kwlist,
					 &string, &stringlen, &public))
		return NULL;

	rsa = public ? d2i_RSAPublicKey(NULL, &string, stringlen) : 
		d2i_RSAPrivateKey(NULL, &string, stringlen);
	if (!rsa) {
		SSL_ERR();
		return NULL;
	}
	return WRAP_RSA(rsa);
}

/**
 * Converts a BIGNUM into a newly allocated PyLongObject.  
 **/
static PyObject*
bn2pylong(const BIGNUM *bn) 
{
	PyObject *output;

	/**
	 * We could get better performance with _PyLong_FromByteArray,
	 * but that wasn't introduced until Python 2.2.  We go with
	 * only a single implementation here, since this isn't in the
	 * critical path.  See CVS version 1.3 of this file for such
	 * an implementation.
	 **/
	char *hex = BN_bn2hex(bn);
	output = PyLong_FromString(hex, NULL, 16); 
	OPENSSL_free(hex);
	return output; /* pass along errors */
}

/**
 * Converts a PyLongObject into a freshly allocated BIGNUM.
 **/
static BIGNUM*
pylong2bn(PyObject *pylong)
{
	PyObject *str;
	char *buf;
	BIGNUM *result = NULL;
	int r;
	assert(PyLong_Check(pylong));
	assert(pylong && pylong->ob_type 
	       && pylong->ob_type->tp_as_number
	       && pylong->ob_type->tp_as_number->nb_hex);
	
	if (!(str = pylong->ob_type->tp_as_number->nb_hex(pylong)))
		return NULL;
	
	buf = PyString_AsString(str);
	if (!buf || buf[0]!='0' || buf[1]!='x') {
		Py_DECREF(str); return NULL;
	}
	r = BN_hex2bn(&result, &buf[2]);
	if (r<0 || result == NULL) {
		Py_DECREF(str); return NULL;
	}
	Py_DECREF(str);
	return result;
}

const char mm_rsa_get_public_key__doc__[]=
   "rsa_get_public_key(rsa) -> (n,e)\n";

PyObject *
mm_rsa_get_public_key(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "key", NULL };
	
	RSA *rsa;
	PyObject *n, *e;
	PyObject *output;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "O&:rsa_get_public_key", kwlist,
					 rsa_arg_convert, &rsa))
		return NULL;
	
	if (!rsa->n) { TYPE_ERR("Key has no modulus"); return NULL;}
	if (!rsa->e) { TYPE_ERR("Key has no e"); return NULL; }
	if (!(n = bn2pylong(rsa->n))) { 
		PyErr_NoMemory(); return NULL; 
	}
	if (!(e = bn2pylong(rsa->e))) { 
		PyErr_NoMemory(); Py_DECREF(n); return NULL; 
	}
	output = Py_BuildValue("OO", n, e);
	Py_DECREF(n);
	Py_DECREF(e);
	return output;
}

const char mm_rsa_make_public_key__doc__[]=
   "rsa_make_public_key(n,e) -> rsa\n\n"
   "n and e must both be long integers.  Ints won't work.\n";

PyObject *
mm_rsa_make_public_key(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "n","e", NULL };
	
	RSA *rsa;
	PyObject *n, *e;
	PyObject *output;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "O!O!:rsa_make_public_key", kwlist,
					 &PyLong_Type, &n, &PyLong_Type, &e))
		return NULL;
	
	rsa = RSA_new();
	if (!(rsa = RSA_new())) { PyErr_NoMemory(); return NULL; }
	if (!(rsa->n = pylong2bn(n))) { RSA_free(rsa); return NULL; }
	if (!(rsa->e = pylong2bn(e))) { 
		RSA_free(rsa); BN_free(rsa->n); return NULL; 
	}

	output = WRAP_RSA(rsa);
	
	return output;
}

const char mm_rsa_get_modulus_bytes__doc__[]=
   "rsa_get_modulus_bytes(rsa) -> int\n\n"
   "Returns the number of *bytes* (not bits) in an RSA modulus.\n";

PyObject *
mm_rsa_get_modulus_bytes(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "key", NULL };
	
	RSA *rsa;

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "O&:rsa_get_modulus_bytes", kwlist,
					 rsa_arg_convert, &rsa))
		return NULL;
	
	return PyInt_FromLong(BN_num_bytes(rsa->n));
}

const char mm_add_oaep_padding__doc__[]=
   "add_oaep_padding(s, param, keylen) -> str\n\n"
   "Adds OAEP padding to a string.  Keylen is the length of the RSA key to\n"
   "be used, in bytes;  Param is the security parameter string.\n";

PyObject *
mm_add_oaep_padding(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "s", "param", "keylen", NULL };

	const unsigned char *param, *input;
	int paramlen, inputlen;
	int keylen, r;

	PyObject *output;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "s#s#i:add_oaep_padding", kwlist,
			      &input,&inputlen,&param,&paramlen,&keylen))
		return NULL;
	
	if (inputlen >= keylen) {
		TYPE_ERR("String too long to pad.");
		return NULL;
	}
	
	if (!(output = PyString_FromStringAndSize(NULL,keylen))) { 
		PyErr_NoMemory(); return NULL; 
	}
	
	r = RSA_padding_add_PKCS1_OAEP(PyString_AS_STRING(output), keylen,
				       input, inputlen,
				       param, paramlen);
	if (r <= 0) {
		SSL_ERR(); 
		Py_DECREF(output);
		return NULL;
	}
	
	return output;
}

const char mm_check_oaep_padding__doc__[]=
   "check_oaep_padding(s, param, keylen) -> str\n\n"
   "Checks OAEP padding on a string.  Keylen is the length of the RSA key to\n"
   "be used, in bytes;  Param is the security parameter string.\n"
   "If the padding is in tact, the original string is returned.\n";

PyObject *
mm_check_oaep_padding(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "s", "param", "keylen", NULL };

	const unsigned char *param, *input;
	int paramlen, inputlen;
	int keylen, r;

	PyObject *output;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "s#s#i:check_oaep_padding", kwlist,
				  &input,&inputlen,&param,&paramlen,&keylen))
		return NULL;

	/**
	 * XXXX Why is this test (along with the input+1 below) necessary?
	 * XXXX I'd be happier if I knew, and I'd take out the bit about
	 * XXXX our assumptions being gravely mistaken. :)
	 **/
	if (inputlen == 0 || *input != '\000') {
		PyErr_SetString(mm_SSLError,
				"Bad padding, or our assumptions about "
				"OAEP padding are gravely mistaken");
		return NULL;
	}
	
	
	if (!(output = PyString_FromStringAndSize(NULL,keylen))) { 
		PyErr_NoMemory(); return NULL; 
	}
	
	r = RSA_padding_check_PKCS1_OAEP(PyString_AS_STRING(output), keylen,
					 input+1, inputlen-1, keylen,
					 param, paramlen);
	if (r <= 0) {
		SSL_ERR();
		Py_DECREF(output);
		return NULL;
	}
	if(_PyString_Resize(&output, r)) return NULL;

	return output;
}

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
