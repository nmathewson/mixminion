/* Copyright 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: main.c,v 1.3 2002/06/24 20:28:19 nickm Exp $ */
#include <_minionlib.h>

#include <openssl/ssl.h>
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
	ENTRY(rsa_decode_key),
	ENTRY(rsa_make_public_key),
	
	ENTRY(TLSContext_new),
	{ NULL, NULL }
};

/* return 1 on failure. */
static int
exc(PyObject *module_dict, PyObject **exception, char *longName, 
    char *itemString, char *doc)
{
	PyObject *s, *exc_d;
	if (!(s = PyString_FromString(doc)))
		return 1;
	if (!(exc_d = PyDict_New()))
		return 1; /* XXXX FREE */
	if (PyDict_SetItemString(exc_d, "__doc__", s)<0) {
		/* XXXX FREE */ 
		return 1;
	}
	*exception = PyErr_NewException(longName, PyExc_Exception, exc_d);
	if (! *exception) {
		/* XXXX FREE */
		return 1;
	}
	if (PyDict_SetItemString(module_dict,itemString,*exception) < 0)
		return 1;

	return 0;
}

DL_EXPORT(void)
init_minionlib(void)
{
	PyObject *m, *d;
	m = Py_InitModule("_minionlib", _mixcryptlib_functions);
	d = PyModule_GetDict(m);


	SSL_library_init();
	SSL_load_error_strings();

	/* crypt */
	ERR_load_ERR_strings();
 	ERR_load_RSA_strings();

	if (exc(d, &mm_CryptoError, "mixminion._minionlib.CryptoError", 
		"CryptoError", mm_CryptoError__doc__))
		return;
	if (exc(d, &mm_TLSError, "mixminion._minionlib.TLSError", 
		"TLSError", mm_TLSError__doc__))
		return;
	if (exc(d, &mm_TLSWantRead, "mixminion._minionlib.TLSWantRead", 
		"TLSWantRead", mm_TLSWantRead__doc__))
		return;
	if (exc(d, &mm_TLSWantWrite, "mixminion._minionlib.TLSWantWrite", 
		"TLSWantWrite", mm_TLSWantWrite__doc__))
		return;

	Py_INCREF(&mm_RSA_Type);
	if (PyDict_SetItemString(d, "RSA", (PyObject*)&mm_RSA_Type) < 0)
		return;

	Py_INCREF(&mm_TLSContext_Type);
	if (PyDict_SetItemString(d, "TLSContext", (PyObject*)&mm_TLSContext_Type) < 0)
		return;

	Py_INCREF(&mm_TLSSock_Type);
	if (PyDict_SetItemString(d, "TLSSock", (PyObject*)&mm_TLSSock_Type) < 0)
		return;


}

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
