
PYTHON=python2.2

all: do_build

do_build:
	$(PYTHON) setup.py build

clean:
	$(PYTHON) setup.py clean
	rm -rf build
	rm -f lib/mixminion/_unittest.py
	find . -name '*~' -print0 |xargs -0 rm -f

test: do_build
	( export PYTHONPATH=.; cd build/lib*; $(PYTHON) ./mixminion/test.py )

time: do_build
	( export PYTHONPATH=.; cd build/lib*; $(PYTHON) ./mixminion/benchmark.py)

lines:
	wc -l src/*.[ch] lib/*/*.py