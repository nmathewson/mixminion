#!/usr/bin/python
# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: setup.py,v 1.69 2003/07/10 23:12:02 nickm Exp $
import sys

#
#   Current Mixminion version
#
VERSION = '0.0.5alpha1'
# System: 0==alpha, 50==beta, 98=pre, 99==release candidate, 100==release
VERSION_INFO = (0,0,5,0,1)

# Check the version.  We need to make sure version_info exists before we
# compare to it: it was only added as of Python version 1.6.
#
# (Because of syntax issues, this file won't even parse for any python older
#  than 1.3.  I'm okay with that.)
if not hasattr(sys, 'version_info') or sys.version_info < (2, 0, 0):
    print "Sorry, but I require Python 2.0 or higher."
    sys.exit(1)
if sys.version_info[:3] == (2,1,0):
    print "Python 2.1.0 has known bugs that keep Mixminion from working."
    print "Maybe you should upgrade to 2.1.3 or some more recent version."
    sys.exit(1)
if sys.version_info[:3] == (2,1,1):
    print "Python 2.1.1 has known bugs that keep Mixminion from working."
    print "Maybe you should upgrade to 2.1.3 or some more recent version."
    sys.exit(1)
    
try:
    import zlib
except ImportError:
    print "Zlib support seems to be missing; install Python with zlib support."
    sys.exit(1)

try:
    import _socket
    del _socket
except ImportError:
    print "Your Python installation is somehow missing socket support."
    if sys.platform.startswith("sunos") or sys.platform.startswith("solaris"):
        print "This is a known issue when building some versions of Python"
        print "on Solaris."
    sys.exit(1)

import os, re, shutil, string, struct

os.umask(022)

# Function to pull openssl version number out of an opensslv.h file.  This
# isn't a real C preprocessor, but it seems to work well enough.
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
        return None

USE_OPENSSL = 1
# Lowest allowable OpenSSL version; this corresponds to OpenSSL 0.9.7b3
MIN_OPENSSL_VERSION = 0x00907003L

OPENSSL_CFLAGS = []
OPENSSL_LDFLAGS = []
MACROS=[]
MODULES=[]

BAD_OPENSSL_IN_CONTRIB = """
=========================================================
Bizarrely, ./contrib/openssl contains an obsolete version
of OpenSSL.  Try removing ./contrib/openssl, then running
make download-openssl; make build-openssl again.
========================================================="""

NO_OPENSSL_FOUND = """
======================================================================
I need OpenSSL 0.9.7 or greater, and I couldn't find it anywhere that
I looked.  If you installed it somewhere unusual, try setting the
variable OPENSSL_PREFIX as in:

      make OPENSSL_PREFIX=/opt/openssl-0.9.7

If you have a nonstandard OpenSSL 0.9.7 installation, you may need to
give compiler flags directly, as in:

      make OPENSSL_CFLAGS='-I ~/openssl-include' \\
           OPENSSL_LDFLAGS='-L ~/openssl-libs -lssl097 -lcrypto097'

If your C compiler knows where to find OpenSSL 0.9.7, and I should
just trust it, use the SKIP_OPENSSL_SEARCH option, as in:

      make SKIP_OPENSSL_SEARCH="y"

Finally, if you don't have OpenSSL 0.9.7 and you don't want to install
it, you can grab and build a local copy for Mixminion only by running:

      make download-openssl
      make build-openssl

      (then)
      make build

      (Or, if you have the OpenSSL source somewhere else, use OPENSSL_SRC
      as in:
               make build-openssl OPENSSL_SRC=~/src/openssl-0.9.7
               make build         OPENSSL_SRC=~/src/openssl-0.9.7
      )
======================================================================"""

#XXXX005 Use pkg-config when possible, if it exists.

if USE_OPENSSL and sys.platform == 'win32':
    INCLUDE_DIRS = []
    STATIC_LIBS = []
    LIBRARY_DIRS = []
    
    # WWWW Right now, this is hardwired to my openssl installation.
    INCLUDE_DIRS.append("d:\\openssl\\include")
    LIBRARY_DIRS.append("D:\\openssl\\lib\\vc")

    LIBRARIES = [ "ssleay32", "libeay32" ]

elif USE_OPENSSL:
    # For now, we assume that openssl-0.9.7 isn't generally deployed, so we
    # need to look carefully.

    # If the user has specified an OpenSSL installation, we trust the user.
    # Anything else is loopy.
    if os.environ.get("OPENSSL_CFLAGS") or os.environ.get("OPENSSL_LDFLAGS"):
        OPENSSL_CFLAGS = os.environ.get("OPENSSL_CFLAGS", "").split()
        OPENSSL_LDFLAGS = os.environ.get("OPENSSL_LDFLAGS", "").split()
        print "Using OpenSSL as specified in OPENSSL_CFLAGS/OPENSSL_LDFLAGS."
        INCLUDE_DIRS = []
        STATIC_LIBS = []
        LIBRARY_DIRS = []
        LIBRARIES = []
    # Otherwise, if the user has run 'make build-openssl', we have a good
    # copy of OpenSSL sitting in ./contrib/openssl that they want us to use.
    elif os.environ.get("SKIP_OPENSSL_SEARCH"):
        print "Assuming that the C compiler knows where to find OpenSSL."
        INCLUDE_DIRS = []
        STATIC_LIBS = []
        LIBRARY_DIRS = []
        LIBRARIES = [ 'ssl', 'crypto' ]
    elif (os.path.exists(os.environ.get("OPENSSL_SRC", "./contrib/openssl"))
          and not os.environ.get("OPENSSL_PREFIX")):
        openssl_src = os.environ.get("OPENSSL_SRC", "./contrib/openssl")
        print "Using OpenSSL from", openssl_src
        openssl_inc = os.path.join(openssl_src, "include")
        INCLUDE_DIRS = [openssl_inc]
        STATIC_LIBS=[ os.path.join(openssl_src, "libssl.a"),
                      os.path.join(openssl_src, "libcrypto.a") ]
        LIBRARY_DIRS=[]
        LIBRARIES=[]
        v = getOpenSSLVersion(os.path.join(openssl_src,
                                           "include", "openssl", "opensslv.h"))
        if not v or v < MIN_OPENSSL_VERSION:
            print BAD_OPENSSL_IN_CONTRIB
            sys.exit(1)
    # Otherwise, look in a bunch of standard places for a possible OpenSSL
    # installation.  This logic is adapted from check_ssl.m4 from ac-archive;
    # the list of locations is extended with locations from Python's setup.py.
    else:
        print "Searching for platform OpenSSL."
        found = 0
        PREFIXES = ("/usr/local/ssl", "/usr/contrib/ssl", "/usr/lib/ssl",
                    "/usr/ssl", "/usr/pkg", "/usr/local", "/usr", "/")
        if os.environ.get("OPENSSL_PREFIX"):
            PREFIXES = (os.environ["OPENSSL_PREFIX"],)
        for prefix in PREFIXES:
            if found:
                break
            print "Looking in %s ..."%prefix
            incdir = os.path.join(prefix, "include")
            for trunc in 0,1:
                if trunc:
                    opensslv_h = os.path.join(incdir, "opensslv.h")
                else:
                    opensslv_h = os.path.join(incdir, "openssl", "opensslv.h")
                if os.path.exists(opensslv_h):
                    v = getOpenSSLVersion(opensslv_h)
                    if v and v >= MIN_OPENSSL_VERSION:
                        INCLUDE_DIRS = [incdir]
                        LIBRARY_DIRS = [os.path.join(prefix,"lib")]
                        if trunc:
                            MACROS.append(('TRUNCATED_OPENSSL_INCLUDES', None))
                        print "Using version of OpenSSL in %s"%prefix
                        found = 1
                        break
                    print "Skipping old version of OpenSSL in %s"%prefix
        if not found:
            print NO_OPENSSL_FOUND
            sys.exit(1)
        
        STATIC_LIBS=[]
        LIBRARIES=['ssl','crypto']

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
    if not os.path.exists("lib/mixminion/_unittest.py"):
        shutil.copy("contrib/unittest.py", "lib/mixminion/_unittest.py")

# Install textwrap if Python doesn't provide it. (This goes for all python<2.3)
try:
    import textwrap
except:
    if not os.path.exists("lib/mixminion/_textwrap.py"):
        shutil.copy("contrib/textwrap.py", "lib/mixminion/_textwrap.py")

# If we have a version of Python older than 2.2, we can't do bounded-space
# decompression without magic.  That magic is written by Zooko.
if sys.version_info[:3] < (2,2,0):
    if not os.path.exists("lib/mixminion/_zlibutil.py"):
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

if sys.platform == 'win32':
    f = open(SCRIPT_PATH+"i.py", 'wt')
    f.write("import sys\n")
    if pathextra:
        f.write("sys.path[0:0] = [%r]\n"%pathextra)
    f.write("""\
    try:
        import mixminion.Main
    except:
        print 'ERROR importing mixminion package.'
        raise

    mixminion.Main.main(sys.argv+['shell'])
    """)
    f.close()

#======================================================================
# Define a helper to let us run commands from the compiled code.
def _haveCmd(cmdname):
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.exists(os.path.join(entry, cmdname)):
            return 1
    return 0

def requirePythonDev(e=None):
    if os.path.exists("/etc/debian_version"):
        v = sys.version[:3]
        print "Debian may expect you to install python%s-dev"%v
    elif os.path.exists("/etc/redhat-release"):
        print "Redhat may expect you to install python2-devel"
    else:
        print "You may be missing some 'python development' package for your"
        print "distribution."

    if e:
        print "(Error was: %s)"%e

    sys.exit(1)

try:
    from distutils.core import Command
    from distutils.errors import DistutilsPlatformError
    from distutils.sysconfig import get_makefile_filename
except ImportError, e:
    print "\nUh oh. You have Python installed, but I didn't find the distutils"
    print "module, which is supposed to come with the standard library.\n"

    requirePythonDev()

try:
    # This catches failures to install python2-dev on some Recent Redhats.
    mf = get_makefile_filename()
    print mf
except IOError:
    print "\nUh oh. You have Python installed, but distutils can't find the"
    print "Makefile it needs to build additional Python components.\n"

    requirePythonDev()
    

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

# This is needed for a clean build on redhat 9.
if os.path.exists("/usr/kerberos/include"):
    INCLUDE_DIRS.append("/usr/kerberos/include")

INCLUDE_DIRS.append("src")

EXTRA_CFLAGS = []
if sys.platform != 'win32':
    EXTRA_CFLAGS += [ '-Wno-strict-prototypes' ]

extmodule = Extension(
    "mixminion._minionlib",
    ["src/crypt.c", "src/aes_ctr.c", "src/main.c", "src/tls.c", "src/fec.c" ],
    include_dirs=INCLUDE_DIRS,
    extra_objects=STATIC_LIBS,
    extra_compile_args=EXTRA_CFLAGS + OPENSSL_CFLAGS,
    extra_link_args=OPENSSL_LDFLAGS,
    library_dirs=LIBRARY_DIRS,
    libraries=LIBRARIES,
    define_macros=MACROS)

setup(name='Mixminion',
      version=VERSION,
      license="LGPL",
      description=
      "Mixminion: Python implementation of the Type III Mix protocol (ALPHA)",
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
