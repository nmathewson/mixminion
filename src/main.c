/* Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: main.c,v 1.20 2003/10/02 21:46:23 nickm Exp $ */

/*
  If you're not familiar with writing Python extensions, you should
  read "Extending and Embedding the Python Interpreter" at
  "http://www.python.org/doc/current/ext/ext.html".
*/

#include "_minionlib.h"

#ifndef TRUNCATED_OPENSSL_INCLUDES
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#else
#include <ssl.h>
#include <err.h>
#include <rsa.h>
#endif

/* Macros to declare function tables for Python. */
#define ENTRY_ND(fn) { #fn, (PyCFunction)mm_##fn, METH_VARARGS|METH_KEYWORDS,\
                       0}
#define ENTRY(fn) { #fn, (PyCFunction)mm_##fn, METH_VARARGS|METH_KEYWORDS, \
             (char*)mm_##fn##__doc__}

static struct PyMethodDef _mixcryptlib_functions[] = {
        ENTRY(sha1),
        ENTRY(aes_key),
        ENTRY(aes_ctr128_crypt),
        ENTRY(aes128_block_crypt),
        ENTRY(strxor),
        ENTRY(openssl_seed),
        ENTRY(openssl_rand),
#ifdef MS_WINDOWS
        ENTRY(win32_openssl_seed),
        ENTRY(win32_get_random_bytes),
#endif
        ENTRY(add_oaep_padding),
        ENTRY(check_oaep_padding),
        ENTRY(rsa_generate),
        ENTRY(rsa_decode_key),
        ENTRY(rsa_PEM_read_key),
        ENTRY(rsa_make_public_key),
        ENTRY(generate_dh_parameters),
        ENTRY(generate_cert),

        ENTRY(TLSContext_new),

        ENTRY(FEC_generate),
        { NULL, NULL }
};

/* Helper method to create an exception object and register it in a
   module's dictionary.

   module_dict: A PyDictObject* for the module's namespace.
   exception: Set to point to a pointer to the newly allocated exception.
   longName: The fully qualified name of this exception.
   itemString: The name of this exception within the module.
   doc: The docstring for this exception.

   returns 1 on failure; 0 on success */
static int
exc(PyObject *module_dict, PyObject **exception, char *longName,
    char *itemString, char *doc)
{
        PyObject *s, *exc_d;
        if (!(s = PyString_FromString(doc)))
                return 1;
        if (!(exc_d = PyDict_New())) {
                Py_DECREF(s);
                return 1;
        }
        if (PyDict_SetItemString(exc_d, "__doc__", s)<0) {
                Py_DECREF(s); Py_DECREF(exc_d);
                return 1;
        }
        *exception = PyErr_NewException(longName, PyExc_Exception, exc_d);
        if (! *exception) {
                Py_DECREF(s); Py_DECREF(exc_d);
                return 1;
        }
        if (PyDict_SetItemString(module_dict,itemString,*exception) < 0) {
                Py_DECREF(s); Py_DECREF(exc_d); Py_DECREF(*exception);
                return 1;
        }

        return 0;
}

/* Required by Python: magic method to tell the Python runtime about our
 * new module and its contents.  Also initializes OpenSSL as needed.
 */
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

        OpenSSL_add_all_algorithms();

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
        if (exc(d, &mm_TLSClosed, "mixminion._minionlib.TLSClosed",
                "TLSClosed", mm_TLSClosed__doc__))
                return;
        if (exc(d, &mm_FECError, "mixminion._minionlib.FECError",
                "FECError", mm_FECError__doc__))
                return;

        /* We set ob_type here so that Cygwin and Win32 are happy. */
        mm_RSA_Type.ob_type = mm_TLSContext_Type.ob_type =
                mm_TLSSock_Type.ob_type = mm_FEC_Type.ob_type = &PyType_Type;

        Py_INCREF(&mm_RSA_Type);
        if (PyDict_SetItemString(d, "RSA", (PyObject*)&mm_RSA_Type) < 0)
                return;

        Py_INCREF(&mm_TLSContext_Type);
        if (PyDict_SetItemString(d, "TLSContext",
                                 (PyObject*)&mm_TLSContext_Type) < 0)
                return;

        Py_INCREF(&mm_TLSSock_Type);
        if (PyDict_SetItemString(d, "TLSSock",
                                 (PyObject*)&mm_TLSSock_Type) < 0)
                return;

        Py_INCREF(&mm_FEC_Type);
        if (PyDict_SetItemString(d, "FEC",
                                 (PyObject*)&mm_FEC_Type) < 0)
                return;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:8
  End:
*/
