#!/usr/bin/python

# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: setup.py,v 1.1 2002/05/29 03:52:13 nickm Exp $

import os
from distutils.core import setup, Extension

VERSION= '0.1'

# For now, we assume that openssl-0.9.7 hasn't been released.  When this
# changes, we can fix this rigamarole.
SSL_DIR="contrib/openssl"

#====================================================================

extmodule = Extension("mixminion._minionlib",
                      ["src/crypt.c", "src/aes_ctr.c", "src/main.c"],
                      library_dirs=[SSL_DIR],
                      include_dirs=[SSL_DIR+"/include", "src"],
                      libraries=["ssl", "crypto"],
                      extra_compile_args=["-Wno-strict-prototypes"])

setup(name='Mixminion',
      version=VERSION,
      description="Mixminion: Python implementation of the Type III MIX protocol (ALPHA)",
      author="Nick Mathewson",
      package_dir={ '' : 'lib' },
      packages=['mixminion'],
      ext_modules=[extmodule])
