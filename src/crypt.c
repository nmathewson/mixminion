/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: crypt.c,v 1.13 2002/10/16 23:12:13 nickm Exp $ */
#include <Python.h>

#include <time.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <_minionlib.h>
#include <assert.h>

#define TYPE_ERR(s) PyErr_SetString(PyExc_TypeError, s)
#define KEY_IS_PRIVATE(rsa) ((rsa)->p)

char mm_CryptoError__doc__[] = 
  "mixminion._minionlib.SSLError\n\n"
  "Exception raised for error in crypto library.\n";

PyObject *mm_CryptoError = NULL;

/* Helper function: raise an error with appropriate text from the
 * underlying OpenSSL exception.  
 *
 * Requires that mm_*Error are initialized and ERR_load_*_strings
 * have been called.
 */
void 
mm_SSL_ERR(int crypto)
{
	int err = ERR_get_error();
	const char *str = ERR_reason_error_string(err);
	PyObject *exception = crypto ? mm_CryptoError : mm_TLSError;
	assert(exception);
	if (str)
		PyErr_SetString(exception, str);
	else
		PyErr_SetString(exception, "Internal error");
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
		mm_SSL_ERR(1);
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


static void
mm_RSA_dealloc(mm_RSA *self)
{
	RSA_free(self->rsa);
	PyObject_DEL(self);
}

static PyObject *
mm_RSA_new(RSA *rsa) {
	mm_RSA *self;
	
	assert(rsa);
	if (!(self=PyObject_NEW(mm_RSA, &mm_RSA_Type)))
		return NULL;
	self->rsa = rsa;
	return (PyObject*)self;
}

const char mm_RSA_crypt__doc__[]=
  "rsa.crypt(string, public, encrypt) -> str\n\n"
  "Uses RSA to encrypt or decrypt a provided string.  If encrypt is true,\n"
  "encrypts; else, decrypts.  If public is true, performs a public-key\n"
  "operation; else, performs a private-key operation.";

PyObject *
mm_RSA_crypt(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "string", "public", "encrypt", NULL };

	RSA *rsa;
	unsigned char *string;
	int stringlen, pub, encrypt;

	int keylen, i;
	char *out;
	PyObject *output;
	assert(mm_RSA_Check(self));

	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "s#ii:crypt", kwlist,
					 &string, &stringlen, &pub, &encrypt))
		return NULL;
	rsa = ((mm_RSA*)self)->rsa;
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
		mm_SSL_ERR(1);
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

	if ((bits < 64) || (bits > 16384)) {
		PyErr_SetString(mm_CryptoError, "Invalid length for RSA key");
		return NULL;
	} 
	if (e < 2) {
		PyErr_SetString(mm_CryptoError, "Invalid RSA exponent");
		return NULL;
	}

	rsa = RSA_generate_key(bits, e, NULL, NULL);
	if (rsa == NULL) {
		mm_SSL_ERR(1);
		return NULL;
	}
	
	return mm_RSA_new(rsa);
}

const char mm_RSA_encode_key__doc__[]=
  "rsa.encode_key(public) -> str\n\n"
  "Computes the DER encoding of a given key.  If 'public' is true, encodes\n"
  "only the public-key portions of rsa.\n";
 
PyObject *
mm_RSA_encode_key(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = { "public", NULL };
	
	RSA *rsa;
	int public;

	int len;
	PyObject *output;
	unsigned char *out, *outp;

	assert(mm_RSA_Check(self));
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 "i:rsa_encode_key", kwlist, &public))
		return NULL;
	rsa = ((mm_RSA*)self)->rsa;
	
	if (!public && !KEY_IS_PRIVATE(rsa)) {
		TYPE_ERR("Can\'t use public key for private-key operation");
		return NULL;
	}

	len = public ? i2d_RSAPublicKey(rsa,NULL) : 
		i2d_RSAPrivateKey(rsa,NULL);
	if (len < 0) {
		mm_SSL_ERR(1);
		return NULL;
	}
	out = outp = malloc(len+1);
	if (public) 
		len = i2d_RSAPublicKey(rsa, &outp);
	else 
		len = i2d_RSAPrivateKey(rsa, &outp);
	if (len < 0) {
		free(out);
		mm_SSL_ERR(1);
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
		mm_SSL_ERR(1);
		return NULL;
	}
	return mm_RSA_new(rsa);
}

const char mm_RSA_PEM_write_key__doc__[]=
  "rsa.PEM_write_key(file, public, [password])\n\n"
  "Writes an RSA key to a file in PEM format with PKCS#8 encryption.\n" 
  "If public is true, writes only the public key, and ignores the password.\n"
  "Otherwise, writes the full private key, optionally encrypted by a\n"
  "password.\n";

PyObject *
mm_RSA_PEM_write_key(PyObject *self, PyObject *args, PyObject *kwdict)
{
	static char* kwlist[] = { "file", "public", "password", NULL };
	PyObject *pyfile;
	int public, passwordlen=0;
	char *password=NULL;

	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	FILE *file;
	
	assert(mm_RSA_Check(self));
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "O!i|s#:PEM_write_key",
					 kwlist, &PyFile_Type, &pyfile,
					 &public,
					 &password, &passwordlen))
		return NULL;
	if (!(file = PyFile_AsFile(pyfile))) {
		TYPE_ERR("Invalid file object"); 
		return NULL;
	}

	if (public) {
		rsa = ((mm_RSA*)self)->rsa;
		if (!PEM_write_RSAPublicKey(file, rsa))
			goto error;
	} else {
		if (!(rsa = RSAPrivateKey_dup(((mm_RSA*)self)->rsa)))
			goto error;
		if (!(pkey = EVP_PKEY_new()))
			goto error;
		if (!EVP_PKEY_assign_RSA(pkey,rsa))
			goto error;
		rsa = NULL;

		if (password) {
			if (!PEM_write_PKCS8PrivateKey(file, pkey,
						       EVP_des_ede3_cbc(),
						       NULL, 0,
						       NULL, password))
				goto error;
		} else {
			if (!PEM_write_PKCS8PrivateKey(file, pkey,
						       NULL, 
						       NULL, 0,
						       NULL, NULL))
				goto error;
		}
	}
	Py_INCREF(Py_None);
	return Py_None;

 error:
	if (rsa && !public)
		RSA_free(rsa);
	if (pkey)
		EVP_PKEY_free(pkey);

	mm_SSL_ERR(1);
	return NULL;
}

const char mm_rsa_PEM_read_key__doc__[]=
  "rsa_PEM_read_key(file, public, [password]) -> rsa\n\n"
  "Writes an RSA key to a file in PEM format with PKCS#8 encryption.\n" 
  "If public is true, reads only the public key, and ignores the password.\n"
  "Otherwise, writes the full private key, optionally encrypted by a\n"
  "password.\n";

PyObject *
mm_rsa_PEM_read_key(PyObject *self, PyObject *args, PyObject *kwdict)
{
	static char *kwlist[] = { "file", "public", "password", NULL };
	PyObject *pyfile;
	int public, passwordlen=0;
	char *password=NULL;

	RSA *rsa;
	FILE *file;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwdict,
					 "O!i|s#:rsa_PEM_read_key",
					 kwlist, &PyFile_Type, &pyfile,
					 &public,
					 &password, &passwordlen))
		return NULL;
	if (!(file = PyFile_AsFile(pyfile))) {
		TYPE_ERR("Invalid file object"); 
		return NULL;
	}
	if (!passwordlen)
		password = "";

	if (public) {
		rsa = PEM_read_RSAPublicKey(file, NULL, NULL, NULL);
	} else {
		rsa = PEM_read_RSAPrivateKey(file, NULL,
					     NULL, password);
	}
	if (!rsa) {
		mm_SSL_ERR(1);
		return NULL;
	}

	return mm_RSA_new(rsa);
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

const char mm_RSA_get_public_key__doc__[]=
   "rsa.get_public_key() -> (n,e)\n";

PyObject *
mm_RSA_get_public_key(PyObject *self, PyObject *args, PyObject *kwdict) 
{
	static char *kwlist[] = {  NULL };
	
	RSA *rsa;
	PyObject *n, *e;
	PyObject *output;

	assert(mm_RSA_Check(self));
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, 
					 ":rsa_get_public_key", kwlist))
		return NULL;
	
	rsa = ((mm_RSA*)self)->rsa;
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

	output = mm_RSA_new(rsa);
	
	return output;
}

const char mm_RSA_get_modulus_bytes__doc__[]=
   "rsa.get_modulus_bytes() -> int\n\n"
   "Returns the number of *bytes* (not bits) in an RSA modulus.\n";

static PyObject *
mm_RSA_get_modulus_bytes(PyObject *self, PyObject *args, PyObject *kwargs) 
{
	static char *kwlist[] = { NULL };
	RSA *rsa;

	assert(mm_RSA_Check(self));
	rsa = ((mm_RSA*)self)->rsa;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs,
					 ":get_modulus_bytes", kwlist))
		return NULL;
	
	return PyInt_FromLong(BN_num_bytes(rsa->n));
}

static PyMethodDef mm_RSA_methods[] = {
	METHOD(mm_RSA, crypt),
	METHOD(mm_RSA, encode_key),
	METHOD(mm_RSA, get_modulus_bytes),
	METHOD(mm_RSA, get_public_key),
	METHOD(mm_RSA, PEM_write_key),
	{ NULL, NULL }
};
 
static PyObject*
mm_RSA_getattr(PyObject *self, char *name) 
{
	return Py_FindMethod(mm_RSA_methods, self, name);
}

static const char mm_RSA_Type__doc__[] = 
  "An RSA key.  May be public or private.";
 
PyTypeObject mm_RSA_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,                                  /*ob_size*/
	"mixminion._minionlib.RSA",         /*tp_name*/
	sizeof(mm_RSA),                     /*tp_basicsize*/
	0,                                  /*tp_itemsize*/
	/* methods */
	(destructor)mm_RSA_dealloc,         /*tp_dealloc*/
	(printfunc)0,                       /*tp_print*/
	(getattrfunc)mm_RSA_getattr,        /*tp_getattr*/
	(setattrfunc)0,                     /*tp_setattr*/
	0,0,
	0,0,0,
	0,0,0,0,0,
	0,0,
	(char*)mm_RSA_Type__doc__
};

const char mm_add_oaep_padding__doc__[]=
   "add_oaep_padding(s, param, keylen) -> str\n\n"
   "Adds OAEP padding to a string.  Keylen is the length of the RSA key to\n"
   "be used, in bytes;  Param is the security parameter string.\n";

PyObject *
mm_add_oaep_padding(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "s", "param", "keylen", NULL };

	const unsigned char *param, *input;
	int paramlen, inputlen;
	int keylen, r;

	PyObject *output;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, 
					 "s#s#i:add_oaep_padding", kwlist,
			      &input,&inputlen,&param,&paramlen,&keylen))
		return NULL;
	
	/* Strictly speaking, this is redundant.  Nevertheless, I suspect
	   the openssl implementation of fragility, so better safe than sorry.
	  */
	if (inputlen >= keylen) {
		PyErr_SetString(mm_CryptoError, "String too long to pad.");
		return NULL;
	}
	
	if (!(output = PyString_FromStringAndSize(NULL,keylen))) { 
		PyErr_NoMemory(); return NULL; 
	}
	
	r = RSA_padding_add_PKCS1_OAEP(PyString_AS_STRING(output), keylen,
				       input, inputlen,
				       param, paramlen);
	if (r <= 0) {
		mm_SSL_ERR(1); 
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
mm_check_oaep_padding(PyObject *self, PyObject *args, PyObject *kwargs) 
{
	static char *kwlist[] = { "s", "param", "keylen", NULL };

	const unsigned char *param, *input;
	int paramlen, inputlen;
	int keylen, r;

	PyObject *output;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, 
					 "s#s#i:check_oaep_padding", kwlist,
				  &input,&inputlen,&param,&paramlen,&keylen))
		return NULL;


	if (inputlen == 0 || *input != '\000') {
		PyErr_SetString(mm_CryptoError, "Bad padding");
		return NULL;
	}
	
	if (!(output = PyString_FromStringAndSize(NULL,keylen))) { 
		PyErr_NoMemory(); return NULL; 
	}
	
	r = RSA_padding_check_PKCS1_OAEP(PyString_AS_STRING(output), keylen,
					 input+1, inputlen-1, keylen,
					 param, paramlen);
	if (r <= 0) {
		mm_SSL_ERR(1);
		Py_DECREF(output);
		return NULL;
	}
	if(_PyString_Resize(&output, r)) return NULL;

	return output;
}

static void
gen_dh_callback(int p, int n, void *arg) 
{
	if (p == 0) fputs(".", stderr);
	if (p == 1) fputs("+", stderr);
	if (p == 2) fputs("*", stderr);
	if (p == 3) fputs("\n", stderr);
}

const char mm_generate_dh_parameters__doc__[] = 
   "generate_dh_parameters(filename, [verbose, [bits]])\n\n"
   "Generate a DH parameter file named <filename>. The parameters will be of\n"
   "size <bits>, which defaults to 512.  If <verbose>, a pattern of dots\n"
   "will appear on the screen to let you know that the program is still\n"
   "thinking.";

PyObject *
mm_generate_dh_parameters(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "filename", "verbose", "bits", NULL };
	char *filename;
	int bits=512, verbose=0;
	
	BIO *out = NULL;
	DH *dh = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, 
					 "s|ii:generate_dh_parameters", 
					 kwlist,
					 &filename, &verbose, &bits))
		return NULL;
	
	if (!(out = BIO_new_file(filename, "w")))
		goto error;
	if (!(dh = DH_generate_parameters(bits, 2, 
					  verbose?gen_dh_callback:NULL, 
					  NULL)))
		goto error;
	if (!PEM_write_bio_DHparams(out, dh))
		goto error;
	BIO_free(out);
	DH_free(dh);
	Py_INCREF(Py_None);
	return Py_None;

 error:
	if (out)
		BIO_free(out);
	if (dh)
		DH_free(dh);
	mm_SSL_ERR(0);
	return NULL;
}

const char mm_generate_cert__doc__[] = 
  "generate_cert(filename, rsa, cn, start_time, end_time)\n\n"
  "Generate a self-signed X509 certificate suitable for use by a Mixminion\n"
  "server.  The certificate will be stored to <filename>, and use the\n"
  "=private= key <rsa>.  The certificate\'s commonName field will be set to\n"
  "<cn>.  The key will be valid from <start_time> until <end_time>.\n"
  "All other fields will be given reasonable defaults.\n";

PyObject *
mm_generate_cert(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "filename", "rsa", "cn", 
				  "start_time", "end_time", NULL };
	char *filename, *cn;
	PyObject *_rsa;

	/*
	 * Python wants time to be a double. OpenSSL wants time_t.
	 * Ordinarily, I'd worry about resolution and bounds, but if time_t
	 * doesn't fit in a double, Python's time.time() function is already
	 * doomed.  
	 */
	double start_time, end_time;
	
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *out = NULL;
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	int nid;
	PyObject *retval;
	time_t time;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sO!sdd:generate_cert",
					 kwlist, &filename,
					 &mm_RSA_Type, &_rsa, &cn, 
					 &start_time, &end_time))
		return NULL;

	if (!(rsa = RSAPrivateKey_dup(((mm_RSA*)_rsa)->rsa)))
		goto error;
	if (!(pkey = EVP_PKEY_new()))
		goto error;
	if (!(EVP_PKEY_assign_RSA(pkey, rsa)))
		goto error;
	rsa = NULL;

	if (!(x509 = X509_new()))
		goto error;
	if (!(X509_set_version(x509, 2)))
		goto error;
	if (!(ASN1_INTEGER_set(X509_get_serialNumber(x509),0L)))
		goto error;
	if (!(name = X509_NAME_new()))
		goto error;
	
#define SET_PART(part, val)                                     \
	if ((nid = OBJ_txt2nid(part)) == NID_undef) goto error; \
        if (!X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,\
                                        val, -1, -1, 0)) goto error;
       
	SET_PART("countryName", "US");
	SET_PART("organizationName", "Mixminion network");
	SET_PART("commonName", cn);

	if (!(X509_set_issuer_name(x509, name)))
		goto error;

	time = (time_t) start_time;
	if (!X509_time_adj(X509_get_notBefore(x509),0,&time)) 
		goto error;
	time = (time_t) end_time;
	if (!X509_time_adj(X509_get_notAfter(x509),0,&time))
		goto error;
	if (!(X509_set_pubkey(x509, pkey)))
		goto error;
	if (!(X509_sign(x509, pkey, EVP_md5())))
		goto error;

	if (!(out = BIO_new_file(filename, "w")))
		goto error;
	if (!(PEM_write_bio_X509(out, x509)))
		goto error;

	retval = Py_None;
	Py_INCREF(Py_None);
	goto done;

error:
	retval = NULL;
	mm_SSL_ERR(1);
 done:
	if (out)
		BIO_free(out);
	if (name)
		X509_NAME_free(name);
	if (x509)
		X509_free(x509);
	if (rsa)
		RSA_free(rsa);
	if (pkey)
		EVP_PKEY_free(pkey);

	return retval;
}

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
