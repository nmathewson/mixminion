/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: _minionlib.h,v 1.1 2002/05/29 03:52:13 nickm Exp $ */
#ifndef _MINIONLIB_H
#define _MINIONLIB_H

#include <Python.h>
#include <openssl/aes.h>

#define AESCRYPT mix_AES_ctr128_encrypt
void mix_AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			    const unsigned long length, const AES_KEY *key,
			    unsigned char *counter, unsigned int *num);

#define FUNC(fn) PyObject* fn(PyObject *self, PyObject *args, PyObject *kwdict)
#define DOC(fn) extern const char fn##__doc__[]
#define FUNC_DOC(fn) FUNC(fn); DOC(fn)

/* Functions from crypt.c */
FUNC_DOC(mm_sha1);
FUNC_DOC(mm_sha1);
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
