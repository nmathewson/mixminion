/* Copyright 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: main.c,v 1.2 2002/05/29 17:46:24 nickm Exp $ */
#include <_minionlib.h>

#include <openssl/err.h>
#include <openssl/rsa.h>

#define ENTRY_ND(fn) { #fn, (PyCFunction)mm_##fn, METH_VARARGS|METH_KEYWORDS,\
                       0}
#define ENTRY(fn) { #fn, (PyCFunction)mm_##fn, METH_VARARGS|METH_KEYWORDS, \
             (char*)mm_##fn##__doc__}

static struct PyMethodDef _mixcryptlib_functions[] = {
	ENTRY(sha1),
	ENTRY(aes_key),
	ENTRY(aes_ctr128_crypt),
	ENTRY(strxor),
	ENTRY(openssl_seed),
	ENTRY(add_oaep_padding),
	ENTRY(check_oaep_padding),
	ENTRY(rsa_generate),
	ENTRY(rsa_crypt),
	ENTRY(rsa_encode_key),
	ENTRY(rsa_decode_key),
	ENTRY(rsa_get_modulus_bytes),
	ENTRY(rsa_get_public_key),
	ENTRY(rsa_make_public_key),
	
	{ NULL, NULL }
};

DL_EXPORT(void)
init_minionlib(void)
{
	PyObject *m, *d;
	m = Py_InitModule("_minionlib", _mixcryptlib_functions);
	d = PyModule_GetDict(m);

	/* crypt */
	ERR_load_ERR_strings();
 	ERR_load_RSA_strings();
	mm_SSLError = PyErr_NewException("mixminion.SSLError", PyExc_Exception, NULL);

	if (PyDict_SetItemString(d, "SSLError", mm_SSLError) < 0)
		return;
}

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
