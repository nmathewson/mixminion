/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: _minionlib.h,v 1.7 2002/07/25 15:52:57 nickm Exp $ */
#ifndef _MINIONLIB_H
#define _MINIONLIB_H

#include <Python.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x00907000L)
#error "Mixminion requires OpenSSL 0.9.7 (which might not have been released yet, but you can get snapshots from openssl.org)."
#endif

/* We provide our own implementation of counter mode; see aes_ctr.c
 */
void mm_aes_counter128(const char *in, char *out, unsigned int len, 
		       AES_KEY *key, unsigned long count);

/* Propagate an error from OpenSSL.  If 'crypto', it's a cryptography
 * error.  Else, it's a TLS error.
 */
void mm_SSL_ERR(int crypto);

extern PyTypeObject mm_RSA_Type;
typedef struct mm_RSA {
	PyObject_HEAD
	RSA* rsa;
} mm_RSA;
#define mm_RSA_Check(v) ((v)->ob_type == &mm_RSA_Type)

extern PyTypeObject mm_TLSContext_Type;
extern PyTypeObject mm_TLSSock_Type;

/**
 * Macros to declare function prototypes with the proper signatures for Python.
 **/
#define FUNC(fn) PyObject* fn(PyObject *self, PyObject *args, PyObject *kwdict)
#define DOC(fn) extern const char fn##__doc__[]
#define FUNC_DOC(fn) FUNC(fn); DOC(fn)


/* Macro to declare entries for a method table.
 */
#define METHOD(obj, name) { #name, (PyCFunction)obj##_##name, \
                        METH_VARARGS|METH_KEYWORDS,       \
                        (char*)obj##_##name##__doc__ }


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
FUNC_DOC(mm_rsa_decode_key);
FUNC_DOC(mm_rsa_PEM_read_key);
FUNC_DOC(mm_rsa_get_public_key);
FUNC_DOC(mm_rsa_make_public_key);
FUNC_DOC(mm_generate_dh_parameters);
FUNC_DOC(mm_generate_cert);
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
extern PyObject *mm_TLSClosed;
extern char mm_TLSClosed__doc__[];

#endif

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
