/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: _minionlib.h,v 1.4 2002/06/24 20:28:19 nickm Exp $ */
#ifndef _MINIONLIB_H
#define _MINIONLIB_H

#include <Python.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x00907000L)
#error "Mixminion requires OpenSSL 0.9.7 (which might not have been released yet, but you can get snapshots from openssl.org)."
#endif

void mm_aes_counter128(const char *in, char *out, unsigned int len, 
		       AES_KEY *key, unsigned long count);

void mm_SSL_ERR(int crypto);

extern PyTypeObject mm_RSA_Type;
typedef struct mm_RSA {
	PyObject_HEAD
	RSA* rsa;
} mm_RSA;
#define mm_RSA_Check(v) ((v)->ob_type == &mm_RSA_Type)

extern PyTypeObject mm_TLSContext_Type;
extern PyTypeObject mm_TLSSock_Type;

#define FUNC(fn) PyObject* fn(PyObject *self, PyObject *args, PyObject *kwdict)
#define DOC(fn) extern const char fn##__doc__[]
#define FUNC_DOC(fn) FUNC(fn); DOC(fn)

/* Functions from crypt.c */
FUNC_DOC(mm_sha1);
FUNC_DOC(mm_sha1);
FUNC_DOC(mm_aes_key);
FUNC_DOC(mm_aes_ctr128_crypt);
FUNC_DOC(mm_strxor);
FUNC_DOC(mm_openssl_seed);
FUNC_DOC(mm_add_oaep_padding);
FUNC_DOC(mm_check_oaep_padding);
FUNC_DOC(mm_rsa_generate);
FUNC_DOC(mm_rsa_crypt);
FUNC_DOC(mm_rsa_encode_key);
FUNC_DOC(mm_rsa_decode_key);
FUNC_DOC(mm_rsa_get_modulus_bytes);
FUNC_DOC(mm_rsa_get_public_key);
FUNC_DOC(mm_rsa_make_public_key);
extern PyObject *mm_CryptoError;
extern char mm_CryptoError__doc__[];


/* From tls.c */
extern PyTypeObject mm_TLSSock_Type;
FUNC_DOC(mm_TLSContext_new);
extern PyObject *mm_TLSError;
extern char mm_TLSError__doc__[];
extern PyObject *mm_TLSWantRead;
extern char mm_TLSWantRead__doc__[];
extern PyObject *mm_TLSWantWrite;
extern char mm_TLSWantWrite__doc__[];

#endif

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
