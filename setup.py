#!/usr/bin/python

# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: setup.py,v 1.2 2002/05/31 12:47:58 nickm Exp $

import os, struct
from distutils.core import setup, Extension

VERSION= '0.1'

# For now, we assume that openssl-0.9.7 hasn't been released.  When this
# changes, we can fix this rigamarole.
SSL_DIR="contrib/openssl"

MACROS=[]

#======================================================================
# Detect endian-ness

#XXXX this breaks cross-compilation
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
    if os.path.exists("/usr/include/byteswap.h"):
        MACROS.append( ("MM_HAVE_BYTESWAP_H", 1) )
elif other_endian:
    print "Feh! Host is neither little-endian or big-endian"

#======================================================================

extmodule = Extension("mixminion._minionlib",
                      ["src/crypt.c", "src/aes_ctr.c", "src/main.c" ],
                      library_dirs=[SSL_DIR],
                      include_dirs=[SSL_DIR+"/include", "src"],
                      libraries=["ssl", "crypto"],
                      extra_compile_args=["-Wno-strict-prototypes" ],
                      define_macros=MACROS)

setup(name='Mixminion',
      version=VERSION,
      description="Mixminion: Python implementation of the Type III MIX protocol (ALPHA)",
      author="Nick Mathewson",
      package_dir={ '' : 'lib' },
      packages=['mixminion'],
      ext_modules=[extmodule])
