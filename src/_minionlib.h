/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: _minionlib.h,v 1.3 2002/05/31 12:39:18 nickm Exp $ */
#ifndef _MINIONLIB_H
#define _MINIONLIB_H

#include <Python.h>
#include <openssl/aes.h>
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x00907000L)
#error "Mixminion requires OpenSSL 0.9.7 (which might not have been released yet, but you can get snapshots from openssl.org)."
#endif

void mm_aes_counter128(const char *in, char *out, unsigned int len, 
		       AES_KEY *key, unsigned long count);

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
extern PyObject *mm_SSLError;

#endif
