#!/usr/bin/python
# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: setup.py,v 1.35 2003/01/08 03:58:31 nickm Exp $
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
except ImportError:
    print "Zlib support seems to be missing; install python with zlib support."
    sys.exit(0)

import os, re, struct, shutil

os.umask(022)

VERSION= '0.0.2.1'

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
# Check the version of Mixminion as it's set in the source, and update
# __init__.py as needed.

f = open("lib/mixminion/__init__.py", 'r')
initFile = f.read()
f.close()
initCorrected = re.compile(r'^__version__\s*=.*$', re.M).sub(
    '__version__ = \"%s\"'%VERSION, initFile)
if initCorrected != initFile:
    f = open("lib/mixminion/__init__.py", 'w')
    f.write(initCorrected)
    f.close()

#======================================================================
# Install unittest if python doesn't provide it. (This is a 2.0 issue)
try:
    import unittest
except:
    shutil.copy("contrib/unittest.py", "lib/mixminion/_unittest.py")

# Install textwrap if Python doesn't provide it. (This goes for all python<2.3)
try:
    import textwrap
except:
    shutil.copy("contrib/textwrap.py", "lib/mixminion/_textwrap.py")

# If we have a version of Python older than 2.2, we can't do bounded-space
# decompression without magic.  That magic is written by Zooko.
if sys.version_info[:3] < (2,2,0):
    shutil.copy("contrib/zlibutil.py", "lib/mixminion/_zlibutil.py")

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
# Create a startup script if we're installing.

# This isn't as fully general as distutils allows.  Unfortunately, distutils
# doesn't make it easy for us to create a script that knows where distutils
# has been told to install.

if os.environ.get('PREFIX'):
    prefix = os.path.expanduser(os.environ["PREFIX"])
    pathextra = os.path.join(prefix, "lib",
                             "python"+(sys.version)[:3],
                             "site-packages")
else:
    pathextra = ""

SCRIPT_PATH = os.path.join("build", "mixminion")
if not os.path.exists("build"):
    os.mkdir("build")
f = open(SCRIPT_PATH, 'wt')
# Distutils will take care of the executable path, and actually gets angry
# if we try to be smart on our own. *sigh*.
f.write("#!python -O\n")
f.write("import sys\n")
if pathextra:
    f.write("sys.path[0:0] = [%r]\n"%pathextra)
f.write("""\
try:
    import mixminion.Main
except:
    print 'ERROR importing mixminion package.'
    raise

mixminion.Main.main(sys.argv)
""")
f.close()

#======================================================================
# Define a helper to let us run commands from the compiled code.
def _haveCmd(cmdname):
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.exists(os.path.join(entry, cmdname)):
            return 1
    return 0

try:
    from distutils.core import Command
except ImportError:
    print "Uh oh.  You have Python installed, but I didn't find the distutils"
    print "module, which is supposed to come with the standard library."
    if os.path.exits("/etc/debian_version"):
        v = sys.version[:3]
        print "Debian may expect you to install python%s-dev"%v
    elif os.path.exists("/etc/redhat-release"):
        print "Redhat may need to install python2-devel"
    else:
        print "You may be missing some 'python development' package for your"
        print "distribution."
    sys.exit(0)
        

class runMMCommand(Command):
    # Based on setup.py from Zooko's pyutil package, which is in turn based on
    # http://mail.python.org/pipermail/distutils-sig/2002-January/002714.html
    description = "Run a subcommand from mixminion.Main"
    user_options = [
        ('subcommand=', None, 'Subcommand to run')]

    def initialize_options(self):
        self.subcommand = "unittests"

    def finalize_options(self):
        build = self.get_finalized_command('build')
        self.build_purelib = build.build_purelib
        self.build_platlib = build.build_platlib

    def run(self):
        self.run_command('build')
        old_path = sys.path
        sys.path[0:0] = [ self.build_purelib, self.build_platlib ]
        try:
            minion = __import__("mixminion.Main", globals(), "", [])
            minion.Main.main(["mixminion.Main", self.subcommand])
        finally:
            sys.path = old_path

#======================================================================
# Now, tell setup.py how to cope.
import distutils.core
from distutils.core import setup, Extension
from distutils import sysconfig

if os.environ.get("PREFIX") and 'install' in sys.argv:
    # Try to suppress the warning about sys.path by appending to the end of
    # the path temporarily.
    sys.path.append(os.path.join(os.environ.get("PREFIX"),
                                 "lib",
                                 "python%s"%sys.version[:3],
                                 "site-packages"))


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
      license="LGPL",
      description="Mixminion: Python implementation of the Type III Mix protocol (ALPHA)",
      author="Nick Mathewson",
      author_email="nickm@freehaven.net",
      url="http://www.mixminion.net/",
      package_dir={ '' : 'lib' },
      packages=['mixminion', 'mixminion.server', 'mixminion.directory'],
      scripts=[SCRIPT_PATH],
      ext_modules=[extmodule],
      cmdclass={'run': runMMCommand})

try:
    os.unlink(SCRIPT_PATH)
except:
    pass
