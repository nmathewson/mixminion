#!/usr/bin/python
# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: setup.py,v 1.10 2002/12/02 03:45:56 nickm Exp $
import sys

# Check the version.  We need to make sure version_info exists before we
# compare to it: it was only added as of Python version 1.6.
#
# (Because of syntax issues, this file won't even parse for any python older
#  than 1.3.  I'm okay with that.)
if not hasattr(sys, 'version_info') or sys.version_info < (2, 0, 0):
    print "Sorry, but I require Python 2.0 or higher."
    sys.exit(0)

try:
    import zlib
except ImportError, _:
    print "Zlib support seems to be missing; install python with zlib support."
    sys.exit(0)

import os, struct, shutil

VERSION= '0.1'

USE_OPENSSL=1

if USE_OPENSSL:
    # For now, we assume that openssl-0.9.7 hasn't been released.  When this
    # changes, we can fix this rigamarole.
    openssl_inc = os.environ.get("MM_OPENSSL_INCLUDE", 
 				 "./contrib/openssl/include")
    INCLUDE_DIRS=[openssl_inc]
    STATIC_LIBS=['./contrib/openssl/libssl.a', './contrib/openssl/libcrypto.a']
##      openssl_lib = os.environ.get("MM_OPENSSL_LIB", "./contrib/openssl")
##      LIB_DIRS=[openssl_lib]
##      LIBRARIES=['ssl','crypto']

MACROS=[]
MODULES=[]

#======================================================================
# Install unittest if python doesn't provide it. (This is a 2.0 issue)
try:
    import unittest
except:
    shutil.copy("contrib/unittest.py", "lib/mixminion/_unittest.py")

#======================================================================
# Detect endian-ness

#XXXX This breaks cross-compilation, but might be good enough for now.
num = struct.pack("@I", 0x01020304) 
big_endian = (num== "\x01\x02\x03\x04")
little_endian = (num=="\x04\x03\x02\x01")
other_endian = not (big_endian or little_endian)

if big_endian:
    print "Host is big-endian"
    MACROS.append( ("MM_B_ENDIAN", 1) )
elif little_endian:
    print "Host is little-endian"
    MACROS.append( ("MM_L_ENDIAN", 1) )
elif other_endian:
    print "Wild!  Your machine seems to be middle-endian, and yet you've"
    print "somehow made it run Python.  Despite your perversity, I admire"
    print "your nerve, and will try to soldier on."
    MACROS.append( ("MM_O_ENDIAN", 1)  )

#======================================================================
from distutils.core import setup, Extension

INCLUDE_DIRS.append("src")

extmodule = Extension("mixminion._minionlib",
                      ["src/crypt.c", "src/aes_ctr.c", "src/main.c",
                       "src/tls.c" ],
                      include_dirs=INCLUDE_DIRS,
                      extra_objects=STATIC_LIBS,
                      extra_compile_args=["-Wno-strict-prototypes" ],
                      define_macros=MACROS)

setup(name='Mixminion',
      version=VERSION,
      description="Mixminion: Python implementation of the Type III MIX protocol (ALPHA)",
      author="Nick Mathewson",
      package_dir={ '' : 'lib' },
      packages=['mixminion'],
      ext_modules=[extmodule])
