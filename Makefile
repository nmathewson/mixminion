# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Makefile,v 1.27 2003/01/05 06:49:24 nickm Exp $

# Okay, we'll start with a little make magic.   The goal is to define the
# make variable '$(FINDPYTHON)' as a chunk of shell script that sets
# the shell variable '$PYTHON' to a working python2 interpreter.
#
# (This is nontrivial because not all python2 installers install a command
# called 'python2'.)
#
# (If anybody can think of a better way to do this, please let me know.)

# XXXX This fails when PYTHON is set to a version of Python earlier than 1.3

PYTHON_CANDIDATES = python2.2 python2.2x python2.1 python2.1x python2.0      \
	python2.0x python2 python
FINDPYTHON = \
   if [ 'x' = "x$$PYTHON" ]; then                                            \
	for n in $(PYTHON_CANDIDATES) ; do                                   \
	  if [ 'x' = "x$$PYTHON" ]; then                                     \
            if [ -x "`which $$n 2>&1`" ]; then                               \
	            PYTHON=$$n;                                              \
                fi;                                                          \
            fi;                                                              \
	done;                                                                \
	if [ 'x' = "x$$PYTHON" ]; then                                       \
	    echo "ERROR: couldn't find any of $(PYTHON_CANDIDATES) in PATH"; \
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
	@if [ ! -e ./contrib/openssl/libcrypto.a ]; then \
	   echo "I didn't find a prebuilt openssl in ./contrib/openssl." ;\
	   echo "If this build fails, try "\
	        "'make download-openssl; make build-openssl'"; \
	fi
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py build; \
	$$PYTHON setup.py build

clean:
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py clean; \
	$$PYTHON setup.py clean
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

test: do_build
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py run --subcommand=unittests; \
	$$PYTHON setup.py run --subcommand=unittests

time: do_build
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py run --subcommand=benchmarks; \
	$$PYTHON setup.py run --subcommand=benchmarks

#======================================================================
# Install target (minimal.)


install: do_build
	@$(FINDPYTHON); \
	if [ 'x' = "x$(PREFIX)" ] ; then                                     \
	  echo $$PYTHON setup.py install --compile --optimize=1;             \
	  $$PYTHON setup.py install --compile --optimize=1;                  \
	else                                                                 \
	  PREFIX=$(PREFIX);                                                  \
	  export PREFIX;                                                     \
	  echo $$PYTHON setup.py install --prefix=$(PREFIX) --compile --optimize=1; \
	  $$PYTHON setup.py install --prefix=$(PREFIX) --compile --optimize=1;\
	fi

#======================================================================
# Source dist target

sdist: clean
	@$(FINDPYTHON); \
	echo $$PYTHON setup.py sdist; \
	$$PYTHON setup.py sdist

#======================================================================
# OpenSSL-related targets

OPENSSL_URL = ftp://ftp.openssl.org/source/openssl-0.9.7.tar.gz
OPENSSL_FILE = openssl-0.9.7.tar.gz

download-openssl:
	@if [ -x "`which wget 2>&1`" ] ; then                             \
	  cd contrib; wget $(OPENSSL_URL);                                \
        elif [ -x "`which curl 2>&1`" ] ; then                            \
	  cd contrib; curl -o $(OPENSSL_FILE) $(OPENSSL_URL);             \
	else                                                              \
          echo "I can't find wget or curl.  I can't download openssl.";   \
	fi

destroy-openssl:
	cd ./contrib; \
	rm -rf `ls -d openssl* | grep -v .tar.gz`

build-openssl: ./contrib/openssl/libcrypto.a

./contrib/openssl/libcrypto.a: ./contrib/openssl/config
	cd ./contrib/openssl; \
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
	@cd ./contrib;                                                      \
	if [ -e ./openssl -a ! -L ./openssl ]; then                         \
	    echo "Ouch. contrib/openssl seems not to be a symlink: "        \
	         "I'm afraid to delete it." ;                               \
	    exit;                                                           \
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
	if [ ! -e $$UNPACKED ]; then                                        \
	    echo "Oops.  I unpacked $$TGZ, but didn't find $$UNPACKED.";    \
	fi;                                                                 \
	rm -f ./openssl;                                                    \
	ln -sf $$UNPACKED openssl

#======================================================================
# Coding style targets

pychecker: do_build
	( export PYTHONPATH=.; cd build/lib*; pychecker -F ../../pycheckrc \
	  ./mixminion/*.py ./mixminion/*/*.py )

lines: clean
	wc -l src/*.[ch] lib/*/*.py lib/*/*/*.py

xxxx:
	find lib src \( -name '*.py' -or -name '*.[ch]' \) -print0 \
	   | xargs -0 grep 'XXXX\|FFFF\|DOCDOC\|????'

xxxx002:
	find lib src \( -name '*.py' -or -name '*.[ch]' \) -print0 \
	   | xargs -0 grep 'XXXX00[12]\|FFFF00[12]\|DOCDOC\|????00[12]'

eolspace:
	perl -i.bak -pe 's/\s*\n$$/\n/;' ACKS HACKING LICENSE MANIFEST.in \
		Makefile README TODO pycheckrc setup.py src/*.[ch] \
		lib/mixminion/*.py lib/mixminion/*/*.py

longlines:
	find lib src \( -name '*.py' -or -name '*.[ch]' \) -print0 \
	   | xargs -0 grep '^................................................................................'
