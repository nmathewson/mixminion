/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: tls.c,v 1.7 2002/08/06 16:09:21 nickm Exp $ */
#include "_minionlib.h"

#include <openssl/ssl.h>
#include <openssl/tls1.h>

char mm_TLSError__doc__[] = 
  "mixminion._minionlib.TLSError\n\n"
  "Exception raised for error in underlying TLS/SSL library.\n";
PyObject *mm_TLSError = NULL;

char mm_TLSWantRead__doc__[] = 
  "mixminion._minionlib.TLSWantRead\n\n"
"Exception raised when a non-blocking TLS operation would block on reading.\n";
PyObject *mm_TLSWantRead = NULL;

char mm_TLSWantWrite__doc__[] = 
  "mixminion._minionlib.TLSWantWrite\n\n"
"Exception raised when a non-blocking TLS operation would block on writing.\n";
PyObject *mm_TLSWantWrite = NULL;

char mm_TLSClosed__doc__[] = 
  "mixminion._minionlib.TLSClosed\n\n"
"Exception raised when a connection is unexpectedly closed.\n";
PyObject *mm_TLSClosed = NULL;

/* Convenience macro to set a type error with a given string. */
#define TYPE_ERR(s) PyErr_SetString(PyExc_TypeError, s)

/* Convenience macro to set an error and quit if a 0-argument function
   was called with arguments.  (We can't just use 'METH_NOARGS', since
   that wasn't available in Python 2.0.) */
#define FAIL_IF_ARGS() if (PyTuple_Size(args)) { \
                           TYPE_ERR("No arguments expected"); \
                           return NULL; \
                       }
 
/* Return values for tls_error */
#define NO_ERROR 0
#define ERROR 1
#define ZERO_RETURN -1
/* 
 * Checks for an outstanding error on a given SSL object that has just
 * returned the value 'r'.  Returns NO_ERROR, ERROR, or ZERO_RETURN.
 * On ERROR, a Python error is set.  On ZERO_RETURN, a Python error is
 * set if 'zeroReturnIsError'.
 */
static int 
tls_error(SSL *ssl, int r, int zeroReturnIsError) 
{
	int err = SSL_get_error(ssl,r);
	switch (err) {
 	  case SSL_ERROR_NONE:
		  return NO_ERROR;
	  case SSL_ERROR_ZERO_RETURN:
		  if (zeroReturnIsError)
			  mm_SSL_ERR(0);
		  return ZERO_RETURN;
 	  case SSL_ERROR_WANT_READ:
		  PyErr_SetNone(mm_TLSWantRead);
		  return ERROR;
 	  case SSL_ERROR_WANT_WRITE:
		  PyErr_SetNone(mm_TLSWantWrite);
		  return ERROR;
 	  case SSL_ERROR_SYSCALL:
		  PyErr_SetNone(mm_TLSClosed);
		  return ERROR;
 	  default:
		  mm_SSL_ERR(0);
		  return ERROR;
	}
}

typedef struct mm_TLSContext {
	PyObject_HEAD
	SSL_CTX *ctx;
} mm_TLSContext;
#define mm_TLSContext_Check(v) ((v)->ob_type == &mm_TLSContext_Type)

typedef struct mm_TLSSock {
	PyObject_HEAD
	PyObject *context;
	SSL *ssl;
	int sock;
	PyObject *sockObj;
} mm_TLSSock;

#define mm_TLSSock_Check(v) ((v)->ob_type == &mm_TLSSock_Type)

const char mm_TLSContext_new__doc__[] = 
   "TLSContext([certfile, [rsa, [dhfile] ] ] )\n\n"
   "Allocates a new TLSContext object.  The files, if provided, are used\n"
   "contain the PEM-encoded X509 public keys, private key, and DH\n"
   "parameters for this context.\n\n"
   "If a cert is provided, assume we're working in server mode, and allow\n"
   "BUG:In the future, certs, pks, and dh parameters will be first-class.\n\n"
   "LIMITATION: We don\'t expose any more features than Mixminion needs.\n";

PyObject*
mm_TLSContext_new(PyObject *self, PyObject *args, PyObject *kwargs) 
{
	static char *kwlist[] = { "certfile", "pkfile", "dhfile", NULL };
	char *certfile = NULL, *dhfile=NULL;
	mm_RSA *rsa = NULL;

	SSL_METHOD *method;
	SSL_CTX *ctx;
	DH *dh;
	mm_TLSContext *result;
	BIO *bio;
	RSA *_rsa = NULL;
	EVP_PKEY *pkey = NULL; /* Leaked? ???? */
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|sO!s:TLSContext_new", 
					 kwlist,
					 &certfile, 
					 &mm_RSA_Type, &rsa,
					 &dhfile))
		return NULL;

	method = TLSv1_method();
	
	if (!(ctx = SSL_CTX_new(method))) {
		mm_SSL_ERR(0); return NULL;
	}
	if (!SSL_CTX_set_cipher_list(ctx, TLS1_TXT_DHE_RSA_WITH_AES_128_SHA)){
		SSL_CTX_free(ctx); mm_SSL_ERR(0); return NULL;
	}
	if (certfile && 
	    !SSL_CTX_use_certificate_file(ctx,certfile,SSL_FILETYPE_PEM)) {
		SSL_CTX_free(ctx); mm_SSL_ERR(0); return NULL;
	}
	if (rsa) {
		if (!(_rsa = RSAPrivateKey_dup(rsa->rsa)) || 
		    !(pkey = EVP_PKEY_new()) ||
		    !EVP_PKEY_assign_RSA(pkey, _rsa)) {
			if (!pkey && _rsa) RSA_free(_rsa);
			if (pkey) EVP_PKEY_free(pkey);
			SSL_CTX_free(ctx); mm_SSL_ERR(0); return NULL;
		}
		if (!(SSL_CTX_use_PrivateKey(ctx, pkey))) {
			EVP_PKEY_free(pkey);
			SSL_CTX_free(ctx); mm_SSL_ERR(0); return NULL;
		}
	} 

	if (dhfile) {
		if ( !(bio = BIO_new_file(dhfile, "r"))) {
			SSL_CTX_free(ctx); mm_SSL_ERR(0); return NULL;
		}
		dh=PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
		BIO_free(bio); 
		if (!dh) {
			SSL_CTX_free(ctx); mm_SSL_ERR(0); return NULL; 
		}
		SSL_CTX_set_tmp_dh(ctx,dh); 
		DH_free(dh);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	
	result = PyObject_New(mm_TLSContext, &mm_TLSContext_Type);
	if (!result) {
		SSL_CTX_free(ctx); return NULL; 
	}
	result->ctx = ctx;
	return (PyObject*)result;
}

static void 
mm_TLSContext_dealloc(mm_TLSContext *self)
{
	SSL_CTX_free(self->ctx);
	PyObject_DEL(self);
}

static char mm_TLSContext_sock__doc__[] = 
   "context.sock(socket, [serverMode])\n\n"
   "Creates a new TLS socket to send and receive from a given underlying\n"
   "socket.\n\n"
   "If serverMode is set, allow incoming non-DHE connections.\n";

static PyObject *
mm_TLSContext_sock(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "socket", "serverMode", NULL };
	PyObject *sockObj;
	int serverMode = 0;
	int sock;

	SSL_CTX *ctx;
	BIO *bio;
	SSL *ssl;
	mm_TLSSock *ret;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|i:sock", 
					 kwlist, &sockObj, &serverMode))
		return NULL;
	assert(mm_TLSContext_Check(self));

	if ((sock = PyObject_AsFileDescriptor(sockObj)) < 0) {
		TYPE_ERR("TLSContext.sock requires a socket");
		return NULL;
	}

	ctx = ((mm_TLSContext*)self)->ctx;

	if (!(ssl = SSL_new(ctx))) {
		mm_SSL_ERR(0); return NULL;
	}

	if (serverMode && !SSL_set_cipher_list(ssl, 
		    TLS1_TXT_DHE_RSA_WITH_AES_128_SHA ":"
		    SSL3_TXT_RSA_DES_192_CBC3_SHA)) {
		mm_SSL_ERR(0); SSL_free(ssl); return NULL;
	}

	if (!(bio = BIO_new_socket(sock, BIO_NOCLOSE))) {
		SSL_free(ssl); mm_SSL_ERR(0); return NULL;
	}
	SSL_set_bio(ssl,bio,bio);
	
	if (!(ret = PyObject_New(mm_TLSSock, &mm_TLSSock_Type))) {
		SSL_free(ssl); PyErr_NoMemory(); SSL_free(ssl); return NULL;
	}
	ret->ssl = ssl;
	ret->context = self;
	ret->sock = sock;
	ret->sockObj = sockObj;
	Py_INCREF(self);
	Py_INCREF(sockObj);
	return (PyObject*)ret;
}

static PyMethodDef mm_TLSContext_methods[] = {
	METHOD(mm_TLSContext, sock),
	{ NULL, NULL }
};
 
static PyObject*
mm_TLSContext_getattr(PyObject *self, char *name) 
{
	return Py_FindMethod(mm_TLSContext_methods, self, name);
}

static const char mm_TLSContext_Type__doc__[] =
   "mixminion._minionlib.TLSContext\n\n"
   "A TLSContext object represents the resources shared by a set of TLS\n"
   "sockets.  It has a single method, 'sock()', to create new sockets.\n";

PyTypeObject mm_TLSContext_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,                                  /*ob_size*/
	"mixminion._minionlib.TLSContext",  /*tp_name*/
	sizeof(mm_TLSContext),              /*tp_basicsize*/
	0,                                  /*tp_itemsize*/
	/* methods */
	(destructor)mm_TLSContext_dealloc,  /*tp_dealloc*/
	(printfunc)0,                       /*tp_print*/
	(getattrfunc)mm_TLSContext_getattr, /*tp_getattr*/
	(setattrfunc)0,                     /*tp_setattr*/
	0,0,
	0,0,0,
	0,0,0,0,0,
	0,0,
	(char*)mm_TLSContext_Type__doc__
};

static void 
mm_TLSSock_dealloc(mm_TLSSock *self)
{
	Py_DECREF(self->context);
	Py_DECREF(self->sockObj);
	SSL_free(self->ssl);
	PyObject_DEL(self);
}

static char mm_TLSSock_accept__doc__[] = 
  "tlssock.accept()\n\n"
  "Perform initial server-side TLS handshaking.\n"
  "Returns None if finished.  May raise TLSWantRead or TLSWantWrite.\n";

static PyObject*
mm_TLSSock_accept(PyObject *self, PyObject *args, PyObject *kwargs)
{
	SSL *ssl;
	int r;

	assert(mm_TLSSock_Check(self));
	FAIL_IF_ARGS();
	
	ssl = ((mm_TLSSock*)self)->ssl;
	Py_BEGIN_ALLOW_THREADS
	r = SSL_accept(ssl);
	Py_END_ALLOW_THREADS
	
	if (tls_error(ssl, r, 1))
		return NULL;
	
	Py_INCREF(Py_None);
	return Py_None;
} 

static char mm_TLSSock_connect__doc__[] =
  "tlssock.connect()\n\n"
  "Perform initial client-side TLS handshaking.\n"
  "returns: None for finished. May raise TLSWantRead, TLSWantWrite.\n";

static PyObject*
mm_TLSSock_connect(PyObject *self, PyObject *args, PyObject *kwargs)
{
	SSL *ssl;
	int r, err; 

	assert(mm_TLSSock_Check(self));
	FAIL_IF_ARGS();
	
	ssl = ((mm_TLSSock*)self)->ssl;

	Py_BEGIN_ALLOW_THREADS
	r = SSL_connect(ssl);
	Py_END_ALLOW_THREADS
	err = SSL_get_error(ssl,r);
	if (tls_error(ssl, r, 1))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
} 

static char mm_TLSSock_pending__doc__[] = 
   "tlssock.pending()\n\n"
   "Returns true iff there is data waiting to be read from this socket.";

static PyObject*
mm_TLSSock_pending(PyObject *self, PyObject *args, PyObject *kwargs)
{
	SSL *ssl;

	assert(mm_TLSSock_Check(self));
	FAIL_IF_ARGS();
	
	ssl = ((mm_TLSSock*)self)->ssl;
	
	return PyInt_FromLong(SSL_pending(ssl));
} 

static char mm_TLSSock_read__doc__[] = 
   "tlssock.read(size)\n\n"
   "Tries to read [up to] size bytes from this socket.\n"
  "Returns a string if the read was successful.  Returns 0 if the connection\n"
   "has been closed.  Raises TLSWantRead or TLSWantWrite if the underlying\n"
   "nonblocking socket would block on one of these operations.\n";

static PyObject*
mm_TLSSock_read(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "size", NULL };
	int n;
	SSL *ssl;
	int r;
	PyObject *res;

	assert(mm_TLSSock_Check(self));
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i:read", kwlist,
					 &n))
		return NULL;
	
	ssl = ((mm_TLSSock*)self)->ssl;
	
	if (!(res = PyString_FromStringAndSize(NULL, n))) {
		PyErr_NoMemory(); return NULL; 
	}
	
	Py_BEGIN_ALLOW_THREADS
	r = SSL_read(ssl, PyString_AS_STRING(res), n);
	Py_END_ALLOW_THREADS
	if (r > 0) {
		if (r != n && _PyString_Resize(&res,r) < 0) {
			return NULL;
		}
		return res;
	}
	Py_DECREF(res);
	switch (tls_error(ssl, r, 0)) {
	    case NO_ERROR:
		    Py_INCREF(Py_None);
		    return Py_None;
	    case ZERO_RETURN:	    
		    return PyInt_FromLong(0);
	    case ERROR:
	    default:
		    return NULL;
	}
} 

static char mm_TLSSock_write__doc__[] = 
   "tlssock.write(string)\n\n"
   "Try to write to a TLS socket.\n"
   "If the write was successful, returns the number of bytes written. If the\n"
   "connection is being shutdown, returns 0. Raises TLSWantRead or\n" 
   "TLSWantWrite if the underlying nonblocking socket would block on one of\n"
   "these operations.\n";

static PyObject*
mm_TLSSock_write(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "s", NULL };
	char *string;
	int stringlen;
	SSL *ssl;
	int r;

	assert(mm_TLSSock_Check(self));
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#:write", kwlist,
					  &string, &stringlen))
		return NULL;
	
	ssl = ((mm_TLSSock*)self)->ssl;
	
	Py_BEGIN_ALLOW_THREADS
	r = SSL_write(ssl, string, stringlen);
	Py_END_ALLOW_THREADS
	
	switch(tls_error(ssl, r, 0)) {
	    case NO_ERROR:	    
		    return PyInt_FromLong(r);
	    case ZERO_RETURN:
		    return PyInt_FromLong(0);
	    case ERROR:
	    default:
		    return NULL;

	}
}

static char mm_TLSSock_shutdown__doc__[] = 
  "tlssock.shutdown()\n\n"
  "Initiates a shutdown.\n"
  "If 0 is returned, the shutdown is not complete.  If 1 is returned, the\n"
  "shutdown is complete. May raise TLSWantRead, TLSWantWrite.\n";

static PyObject*
mm_TLSSock_shutdown(PyObject *self, PyObject *args, PyObject *kwargs)
{
	SSL *ssl;
	int r;

	assert(mm_TLSSock_Check(self));
	FAIL_IF_ARGS();
	
	ssl = ((mm_TLSSock*)self)->ssl;

	Py_BEGIN_ALLOW_THREADS
	r = SSL_shutdown(ssl);
	Py_END_ALLOW_THREADS
	if (r == 0) return PyInt_FromLong(0);
	if (r == 1) return PyInt_FromLong(1);
	if (tls_error(ssl,r,1))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
} 

#if 0
static char mm_TLSSock_renegotiate__doc__[] = "XXXX";

static PyObject*
mm_TLSSock_renegotiate(PyObject *self, PyObject *args, PyObject *kwargs)
{
	
	
} 
#endif

static char mm_TLSSock_fileno__doc__[] = 
    "tlssock.fileno()\n\n"
    "Returns the integer filehandle underlying this TLS socket.\n";

static PyObject*
mm_TLSSock_fileno(PyObject *self, PyObject *args, PyObject *kwargs)
{

	assert(mm_TLSSock_Check(self));
	FAIL_IF_ARGS();
	
	return PyInt_FromLong(((mm_TLSSock*)self)->sock);
}

static char mm_TLSSock_get_peer_cert_pk__doc__[] = 
    "tlssock.get_peer_cert_pk()\n\n"
    "Returns the public key of the certificate used by the server on the\n"
    "other side of this connection.  Returns None if no such cert exists\n";

static PyObject*
mm_TLSSock_get_peer_cert_pk(PyObject *self, PyObject *args, PyObject *kwargs)
{
	SSL *ssl;
	X509 *cert;
	EVP_PKEY *pkey;
	RSA *rsa;
	mm_RSA *result;

	assert(mm_TLSSock_Check(self));
	FAIL_IF_ARGS();
	
	ssl = ((mm_TLSSock*)self)->ssl;
	if (!(cert = SSL_get_peer_certificate(ssl))) {
		mm_SSL_ERR(0); return NULL; /* ???? */
	}
	pkey = X509_get_pubkey(cert);
	/* ???? free? leak? */
	if (!(rsa = EVP_PKEY_get1_RSA(pkey))) 
		return NULL; /* XXXX */
	
	if (!(result = PyObject_New(mm_RSA, &mm_RSA_Type))) {
		PyErr_NoMemory(); return NULL; 
	}
	result->rsa = rsa;

	return (PyObject*) result;
}

static PyMethodDef mm_TLSSock_methods[] = {
	METHOD(mm_TLSSock, accept),
	METHOD(mm_TLSSock, connect),
	METHOD(mm_TLSSock, pending),
	METHOD(mm_TLSSock, read),
	METHOD(mm_TLSSock, write),
	METHOD(mm_TLSSock, shutdown),
	METHOD(mm_TLSSock, get_peer_cert_pk),
	METHOD(mm_TLSSock, fileno),
	{ NULL, NULL }
};
 
static PyObject*
mm_TLSSock_getattr(PyObject *self, char *name) 
{
	return Py_FindMethod(mm_TLSSock_methods, self, name);
}

static const char mm_TLSSock_Type__doc__[] =
   "mixminion._minionlib.TLSSock\n\n"
   "A single TLS connection.";

PyTypeObject mm_TLSSock_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,                                  /*ob_size*/
	"mixminion._minionlib.TLSSock",     /*tp_name*/
	sizeof(mm_TLSSock),                 /*tp_basicsize*/
	0,                                  /*tp_itemsize*/
	/* methods */
	(destructor)mm_TLSSock_dealloc,     /*tp_dealloc*/
	(printfunc)0,                       /*tp_print*/
	(getattrfunc)mm_TLSSock_getattr,    /*tp_getattr*/
	(setattrfunc)0,                     /*tp_setattr*/
	0,0,
	0,0,0,
	0,0,0,0,0,
	0,0,
	(char*)mm_TLSSock_Type__doc__
};

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
