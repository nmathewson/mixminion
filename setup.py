#!/usr/bin/python
# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: setup.py,v 1.42 2003/02/11 23:34:08 nickm Exp $
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

import os, re, shutil, string, struct

os.umask(022)

VERSION = '0.0.3alpha'
# System: 0==alpha, 1==beta, 99==release candidate, 100==release
VERSION_INFO = (0,0,3,'a',0)

# Function to pull openssl version number out of opensslv.h
_define_version_line = re.compile(
    r'\s*#\s*define\s+OPENSSL_VERSION_NUMBER\s+(\S+)$')
def getOpenSSLVersion(filename):
    if not os.path.exists(filename):
        print "Uh oh; can't open %s"%filename
        return None
    f = open(filename, 'r')
    version = None
    for l in f.readlines():
        m = _define_version_line.match(l)
        if m:
            version = m.group(1)
            break
    f.close()
    if not version:
        print "Uh oh; can't find a version in %s"%filename
        return None
    version = version.lower()
    try:
        return string.atol(version, 0)
    except ValueError:
        print "Can't parse version from %s"%filename

USE_OPENSSL=1
MIN_OPENSSL_VERSION = 0x00907003L

OPENSSL_CFLAGS = []
OPENSSL_LDFLAGS = []

if USE_OPENSSL:
    # For now, we assume that openssl-0.9.7 isn't generally deployed.
    if os.environ.get("OPENSSL_CFLAGS") or os.environ.get("OPENSSL_LDFLAGS"):
        OPENSSL_CFLAGS = os.environ.get("OPENSSL_CFLAGS", "").split()
        OPENSSL_LDFLAGS = os.environ.get("OPENSSL_LDFLAGS", "").split()
        print "Using OpenSSL as specified in OPENSSL_CFLAGS/OPENSSL_LDFLAGS."
        INCLUDE_DIRS = []
        STATIC_LIBS = []
        LIBRARY_DIRS = []
        LIBRARIES = []
    elif os.path.exists("./contrib/openssl"):
        print "Using OpenSSL from ./contrib/openssl"
        openssl_inc = "./contrib/openssl/include"
        INCLUDE_DIRS = [openssl_inc]
        STATIC_LIBS=['./contrib/openssl/libssl.a',
                     './contrib/openssl/libcrypto.a']
        LIBRARY_DIRS=[]
        LIBRARIES=[]
        v = getOpenSSLVersion("./contrib/openssl/include/openssl/opensslv.h")
        if not v or v < MIN_OPENSSL_VERSION:
            print "\nBizarrely, ./contrib/openssl contains an obsolete version"
            print "of OpenSSL.  Try removing ./contrib/openssl, then running"
            print "make download-openssl; make build-openssl again.\n"
            sys.exit(0)
    else:
        print "Searching for platform OpenSSL."
        found = 0
        for prefix in ("/usr/local", "/usr", "/"):
            incdir = os.path.join(prefix, "include")
            opensslv_h = os.path.join(incdir, "openssl", "opensslv.h")
            if os.path.exists(opensslv_h):
                v = getOpenSSLVersion(opensslv_h)
                if v and v >= MIN_OPENSSL_VERSION:
                    INCLUDE_DIRS = [incdir]
                    LIBRARY_DIRS = [os.path.join(prefix,"lib")]
                    print "Using version of OpenSSL in %s"%prefix
                    break
                print "Skipping old version of OpenSSL in %s"%prefix
        if not found:
            print "\nI couldn't find any version of OpenSSL > 0.9.7.  I'm"
            print "going to hope that your default C compiler knows something"
            print "that I don't.\n"
            INCLUDE_DIRS=[]
            LIBRARY_DIRS=[]
        
        STATIC_LIBS=[]
        LIBRARIES=['ssl','crypto']

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
initCorrected = re.compile(r'^version_info\s*=.*$', re.M).sub(
    'version_info = %r'%(VERSION_INFO,), initCorrected)
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
    print "\nWild!  Your machine seems to be middle-endian, and yet you've"
    print "somehow made it run Python.  Despite your perversity, I admire"
    print "your nerve, and will try to soldier on.\n"
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
#f.write("#!python -O\n")  #disable -O for asserts.
f.write("#!python\n")
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
    print "\nUh oh. You have Python installed, but I didn't find the distutils"
    print "module, which is supposed to come with the standard library."
    if os.path.exists("/etc/debian_version"):
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

if 'install' in sys.argv:
    if os.environ.get("PREFIX"):
        sp = os.path.join(os.environ.get("PREFIX"),
                          "lib",
                          "python%s"%sys.version[:3],
                          "site-packages")
    else:
        sp = os.path.join(sys.prefix,
                          "lib",
                          "python%s"%sys.version[:3],
                          "site-packages")

    fn = os.path.join(sp, "mixminion", "server", "Queue.py")
    if os.path.exists(fn):
        print "Removing obsolete Queue.py"
        try:
            os.unlink(fn)
        except OSError, e:
            print "Couldn't unlink obsolete Queue.py: %s"%e

INCLUDE_DIRS.append("src")

extmodule = Extension(
    "mixminion._minionlib",
    ["src/crypt.c", "src/aes_ctr.c", "src/main.c","src/tls.c" ],
    include_dirs=INCLUDE_DIRS,
    extra_objects=STATIC_LIBS,
    extra_compile_args=["-Wno-strict-prototypes"]+OPENSSL_CFLAGS,
    extra_link_args=OPENSSL_LDFLAGS,
    library_dirs=LIBRARY_DIRS,
    libraries=LIBRARIES,
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
