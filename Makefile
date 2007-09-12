# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Makefile,v 1.72 2007/09/12 20:49:09 nickm Exp $

# Okay, we'll start with a little make magic.   The goal is to define the
# make variable '$(FINDPYTHON)' as a chunk of shell script that sets
# the shell variable '$PYTHON' to a working python2 interpreter.
#
# (This is nontrivial because not all python2 installers install a command
# called 'python2'.)
#
# (If anybody can think of a better way to do this, please let me know.)

# XXXX This fails when PYTHON is set to a version of Python earlier than 1.3

PYTHON_CANDIDATES = python \
        python3.0 python3 \
        python2p6 python2.6 python2.6x \
        python2p5 python2.5 python2.5x \
        python2p4 python2.4 python2.4x \
        python2p3 python2.3 python2.3x \
        python2p2 python2.2 python2.2x \
        python2p1 python2.1 python2.1x \
        python2.0 python2.0x \
        python2

FINDPYTHON = \
   if [ "x`which which`" = "x" ]; then                                       \
        echo "Ouch!  I couldn't run 'which' on your system.";                \
        echo "Please make sure it is there, and try again.";                 \
        exit;                                                                \
   fi;                                                                       \
   if [ 'x' = "x$$PYTHON" ]; then                                            \
	for n in $(PYTHON_CANDIDATES) ; do                                   \
	  if [ 'x' = "x$$PYTHON" ]; then                                     \
            if [ -x "`which $$n 2>&1`" ]; then                               \
	      if [ 'x' != "`$$n -V 2>&1 | grep 'Python [23456789]'`x" ]; then\
                if [ '1' != "`$$n -c 'import thread; print 1'`" ]; then      \
                  echo "Skipping $$n; no thread support.";                   \
                else                                                         \
	           PYTHON=$$n;                                               \
                fi                                                           \
              else                                                           \
	        echo "Skipping `which $$n`; Not recent enough.";             \
	      fi;                                                            \
            fi;                                                              \
          fi;	                                                             \
	done;                                                                \
	if [ 'x' = "x$$PYTHON" ]; then                                       \
	    echo "ERROR: couldn't find Python 2 or later (with threads) on PATH as any of ";\
	    echo "   $(PYTHON_CANDIDATES) in PATH";                          \
	    echo "   Please install python in your path, or set the PYTHON"; \
            echo '   environment variable';                                  \
	    exit;                                                            \
        fi;                                                                  \
	if [ 'x' = "`$$PYTHON -V 2>&1 | grep 'Python [23456789]'`x" ]; then  \
	   echo "WARNING: $$PYTHON doesn't seem to be version 2 or later.";  \
	   echo ' If this fails, please set the PYTHON environment variable.';\
	fi                                                                   \
   fi

#
# Here are the real make targets.
#
all: do_build

do_build:
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py build; \
	$$PYTHON -tt setup.py build

clean:
	@$(FINDPYTHON); \
	echo $$PYTHON -tt setup.py clean; \
	$$PYTHON -tt setup.py clean
	rm -rf build dist
	rm -f MANIFEST
	rm -f lib/mixminion/_unittest.py
	rm -f lib/mixminion/_textwrap.py
	rm -f lib/mixminion/_zlibutil.py
	rm -f lib/mixminion/*.pyc
	rm -f lib/mixminion/*.pyo
	rm -f lib/mixminion/*/*.pyc
	rm -f lib/mixminion/*/*.pyo
	find . -name '*~' -print0 |xargs -0 rm -f
	find . -name '.#*' -print0 |xargs -0 rm -f
	find . -name '*.bak' -print0 |xargs -0 rm -f

test:
	@$(FINDPYTHON); \
	echo $$PYTHON -tt setup.py run --subcommand=unittests; \
	$$PYTHON -tt setup.py run --subcommand=unittests

time:
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py run --subcommand=benchmarks; \
	$$PYTHON -tt setup.py run --subcommand=benchmarks

testvectors:
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py run --subcommand=testvectors; \
	$$PYTHON -tt setup.py run --subcommand=testvectors

#======================================================================
# Install target (minimal.)


install: do_build
	@$(FINDPYTHON);                                                      \
	ARGS="install --compile --optimize=1 --force";                       \
        PREFIXARG="";                                                        \
        ROOTARG="";                                                          \
	if [ 'x' != "x$(PREFIX)" ] ; then                                    \
	  PREFIX="$(PREFIX)"; export PREFIX;                                 \
	  PREFIXARG=--prefix="$(PREFIX)";                                    \
	fi;                                                                  \
	if [ 'x' != "x$(DESTDIR)" ] ; then                                   \
	  ROOTARG=--root="$(DESTDIR)";                                       \
        fi;                                                                  \
	echo $$PYTHON -tt setup.py $$ARGS $$PREFIXARG $$ROOTARG;             \
	$$PYTHON -tt setup.py $$ARGS $$PREFIXARG $$ROOTARG

update:
	@$(FINDPYTHON);                                                      \
	PYVER=`$$PYTHON -c 'import sys; print sys.version[:3]'`;             \
	if [ 'x' = "x$(PREFIX)" ] ; then                                     \
	  PFX=`$$PYTHON -c 'import sys; print sys.prefix'`;                  \
	  LIB=$$PFX/lib/python$$PYVER/site-packages/mixminion;               \
	else                                                                 \
	  LIB=$(PREFIX)/lib/python$$PYVER/site-packages/mixminion;           \
	fi;                                                                  \
	if [ ! -d $$LIB ] ; then                                             \
	  echo "Didn't find an existing installation in $$LIB; bailing.";    \
	elif [ ! -w $$LIB ] ; then                                           \
	  echo "You don't seem to have write access to $$LIB; bailing.";     \
	else                                                                 \
          rm -rf $$LIB;                                                      \
	  $(MAKE) install;                                                   \
	fi

upgrade: update

#======================================================================
#  Uninstall target (phony.)

uninstall:
	@echo "Sorry, I don't do that yet... but if you run";                \
	echo "'make uninstall-help', I might be able to offer some advice."

uninstall-help:
	@$(FINDPYTHON);                                                      \
	PYVER=`$$PYTHON -c 'import sys; print sys.version[:3]'`;             \
	if [ 'x' = "x$(PREFIX)" ] ; then                                     \
	  EPFX=`$$PYTHON -c 'import sys; print sys.exec_prefix'`;            \
	  PFX=`$$PYTHON -c 'import sys; print sys.prefix'`;                  \
	  BIN=$$EPFX/bin/mixminon;                                           \
	  LIB=$$PFX/lib/python$$PYVER/site-packages/mixminion;               \
	else                                                                 \
	  BIN=$(PREFIX)/bin/mixminion;                                       \
	  LIB=$(PREFIX)/lib/python$$PYVER/site-packages/mixminion;           \
	fi;                                                                  \
	echo "Sorry, but I'm too cowardly to remove files for you.";         \
	echo "To remove your installation of mixminion, I think you should"; \
	echo "delete:";                                                      \
	echo "    * The file $$BIN";                                         \
	echo "    * All the files under $$LIB";                              \
	echo;                                                                \
	if [ 'x' = "x$(PREFIX)" ] ; then                                     \
	  echo "(But if you installed with 'make install PREFIX=XX', you";   \
	  echo "should run 'make uninstall-help PREFIX=XX' to get the real"; \
	  echo "story.)";                                                    \
	else                                                                 \
	  echo "(But if you installed without PREFIX, you should run";       \
	  echo "'make uninstall-help' without PREFIX to get the real story)";\
	fi

#======================================================================
# Source dist target

sdist: clean
	@$(FINDPYTHON); \
	echo $$PYTHON -tt setup.py sdist; \
	$$PYTHON -tt setup.py sdist; \
	VERSION=`ls dist/*.tar.gz | sed -e s/.*-// | sed -e s/.tar.gz//`; \
	cp README dist/README-$$VERSION

signdist: sdist
	gpg -ba dist/Mixminion*.tar.gz


#======================================================================
# Packaging related targets

# create a Debian package
# requires you installed at least build-essential, devscripts,
# fakeroot, and whatever is listed as Build-Depends: in debian/control.
bdist_debian:
	if [ -e debian/changelog.shipped ]; then mv debian/changelog.shipped debian/changelog; fi
	cp debian/changelog debian/changelog.shipped
	VERSION=`grep '^VERSION = ' setup.py | sed -e "s/.*'\(.*\)'.*/\1/"`; \
	debchange \
		--newversion $$VERSION'-0.custom'\
		--distribution unofficial \
		--preserve \
		'Build unofficial debian package.'
	#dpkg-buildpackage -rfakeroot -uc -us

bdist_wininst:
	@$(FINDPYTHON); \
	echo $$PYTHON -tt setup.py bdist_wininst; \
	$$PYTHON -tt setup.py bdist_wininst

bdist_py2exe:
	@$(FINDPYTHON); \
	VERSION=`grep '^VERSION = ' setup.py | sed -e "s/.*'\(.*\)'.*/\1/"`; \
	rm -rf dist Mixminion-$$VERSION; \
	echo $$PYTHON -tt setup.py py2exe; \
	$$PYTHON -tt setup.py py2exe; \
	mv dist Mixminion-$$VERSION; \
	zip -9 Mixminion-$$VERSION.win32.zip Mixminion-$$VERSION/* \
           Mixminion-$$VERSION/lib/*

#======================================================================
# OpenSSL-related targets

OPENSSL_URL = http://www.openssl.org/source/openssl-0.9.8e.tar.gz
OPENSSL_FILE = openssl-0.9.8e.tar.gz
OPENSSL_SRC = ./contrib/openssl
OPENSSL_SHA = b429872d2a287714ab37e42296e6a5fbe23d32ff
# I have verified that the above digest matches the tarball signed by the
# openssl maintainer.  If you are paranoid, you should doublecheck. -Nick.

download-openssl:
	@if [ -x "`which wget 2>&1`" ] ; then                             \
	  cd contrib; wget $(OPENSSL_URL);                                \
        elif [ -x "`which curl 2>&1`" ] ; then                            \
	  cd contrib; curl -o $(OPENSSL_FILE) $(OPENSSL_URL);             \
	else                                                              \
          echo "I can't find wget or curl.  Please download $(OPENSSL_URL)";\
	  echo "and put the file in ./contrib";                           \
	fi

destroy-openssl:
	cd ./contrib; \
	rm -rf `ls -d openssl* | grep -v .tar.gz`

build-openssl: $(OPENSSL_SRC)/libcrypto.a

$(OPENSSL_SRC)/libcrypto.a: $(OPENSSL_SRC)/config
	cd $(OPENSSL_SRC); \
	./config; \
	make

./contrib/openssl/config:
	$(MAKE) unpack-openssl

# This target assumes you have openssl-foo.tar.gz in contrib, and you
# want to unpack it into ./contrib/openssl-foo, and symlink ./openssl to
# ./openssl-foo.
#
# It checks 1) whether there is a single, unique openssl-foo.tar.gz
#           2) whether contrib/openssl is a real file or directory
unpack-openssl:
	@$(FINDPYTHON);                                                     \
	cd ./contrib;                                                       \
	if [ -d ./openssl -a ! -h ./openssl ]; then                         \
	    echo "Ouch. contrib/openssl seems not to be a symlink: "        \
	         "I'm afraid to delete it." ;                               \
	    exit;                                                           \
	fi;                                                                 \
	if [ -f $(OPENSSL_FILE) ]; then                                     \
            SHA=`$$PYTHON -c "import sha;print sha.sha(open(\"$(OPENSSL_FILE)\").read()).hexdigest()"`; \
	    if [ "$$SHA" != "$(OPENSSL_SHA)" ]; then                        \
                echo "Unexpected digest on $(OPENSSL_FILE)!";               \
	        exit;                                                       \
            fi;                                                             \
	    echo "Digest on $(OPENSSL_FILE) is correct.";                   \
	else                                                                \
            echo "Found unexpected version of $(OPENSSL_FILE); not checking digest."; \
	fi;                                                                 \
	TGZ=`ls openssl-*.tar.gz` ;                                         \
	if [ "x$$TGZ" = "x" ]; then                                         \
	    echo "I didn't find any openssl-*.tar.gz in ./contrib/";        \
	    echo "Try 'make download-openssl'.";                            \
	    exit;                                                           \
	fi;                                                                 \
	for n in $$TGZ; do                                                  \
	    if [ $$n != "$$TGZ" ]; then                                     \
	        echo "Found more than one openssl-*.tar.gz in ./contrib/";  \
	        echo "(Remove all but the most recent.)";                   \
		exit;                                                       \
	    fi;                                                             \
	done;                                                               \
	UNPACKED=`echo $$TGZ | sed -e s/.tar.gz$$//`;                       \
	echo "Unpacking $$TGZ...";                                          \
	gunzip -c $$TGZ | tar xf -;                                         \
	if [ ! -d $$UNPACKED ]; then                                        \
	    echo "Oops.  I unpacked $$TGZ, but didn't find $$UNPACKED.";    \
	fi;                                                                 \
	rm -f ./openssl;                                                    \
	ln -sf $$UNPACKED openssl

#======================================================================
# Coding style targets

pychecker: do_build
	( export PYTHONPATH=.; cd build/lib*; pychecker -F ../../pycheckrc \
	  ./mixminion/*.py ./mixminion/*/*.py )

lines:
	@$(FINDPYTHON);                                                      \
	$$PYTHON -tt etc/countlines.py src/*.[ch] lib/mixminion/[A-Z_]*.py   \
	         lib/mixminion/*/*.py --noncode lib/mixminion/[a-z]*.py

xxxx:
	find lib src \( -name '*.py' -or -name '*.[ch]' \) -print0 \
	   | xargs -0 grep 'XXXX\|FFFF\|DOCDOC\|????'

xxxx007:
	find lib src \( -name '*.py' -or -name '*.[ch]' \) -print0 \
	   | xargs -0 grep 'XXXX00[1-7]\|FFFF00[1-7]\|DOCDOC\|????00[1-7]'

eolspace:
	perl -i.bak -pe 's/\s+\n$$/\1\n/;' ACKS HACKING LICENSE HISTORY \
		MANIFEST.in \
		Makefile README HISTORY TODO pycheckrc setup.py src/*.[ch] \
		lib/mixminion/*.py lib/mixminion/*/*.py

update-copyright:
	touch -t 200401010000 jan1
	find . -type f -newer jan1 | xargs perl -i.bak -pe \
          's/Copyrigh[t] 2002.* Nick Mathewson/Copyright 2002-2007 Nick Mathewson/;'
	find . -type f -newer jan1 | xargs perl -i.bak -pe \
          's/Copyrigh[t] 2003.* Nick Mathewson/Copyright 2003-2007 Nick Mathewson/;'

longlines:
	find lib src \( -name '*.py' -or -name '*.[ch]' \) -print0 \
	   | xargs -0 grep '^................................................................................'
