# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: test.py,v 1.148 2003/08/25 21:05:34 nickm Exp $

"""mixminion.tests

   Unit tests for all Mixminion functionality.

   Usage:
   >>> import mixminion.tests
   >>> mixminion.tests.testAll()
   """

__pychecker__ = 'no-funcdoc maxlocals=100'

import base64
import cPickle
import cStringIO
import gzip
import os
import re
import socket
import stat
import sys
import threading
import time
import types
from string import atoi

# Not every post-2.0 version of Python has a working 'unittest' module, so
# we include a copy with mixminion, as 'mixminion._unittest'.
try:
    import unittest
except ImportError:
    import mixminion._unittest as unittest

import mixminion.testSupport
from mixminion.testSupport import mix_mktemp, suspendLog, resumeLog, \
     replaceAttribute, undoReplacedAttributes, replaceFunction, \
     getReplacedFunctionCallLog, clearReplacedFunctionCallLog

import mixminion.BuildMessage as BuildMessage
import mixminion.ClientMain
import mixminion.Config
import mixminion.Crypto as Crypto
import mixminion.Filestore
import mixminion.Fragments
import mixminion.MMTPClient
import mixminion.Packet
import mixminion.ServerInfo
import mixminion._minionlib as _ml
import mixminion.server.MMTPServer
import mixminion.server.Modules
import mixminion.server.ServerConfig
import mixminion.server.ServerKeys
import mixminion.server.ServerMain
import mixminion.directory.ServerList
import mixminion.directory.ServerInbox
import mixminion.directory.DirMain
import mixminion.directory.Directory
from mixminion.Common import *
from mixminion.Common import Log, _FileLogHandler, _ConsoleLogHandler
from mixminion.Config import _ConfigFile, ConfigError, _parseInt
from mixminion.Crypto import *
from mixminion.Packet import *
from mixminion.server.HashLog import HashLog
from mixminion.server.Modules import *
from mixminion.server.PacketHandler import *
from mixminion.server.ServerQueue import *
from mixminion.server.ServerKeys import generateServerDescriptorAndKeys, \
     generateCertChain

# Set this flag to 1 in order to have all RSA keys and diffie-hellman params
# generated independently.  Otherwise, we cache diffie-hellman parameters
# on disk, and only generate a small number of RSA keys.
USE_SLOW_MODE = 0

# Flag: are we on a platform with windowsy permissions?
ON_WINDOWS = (sys.platform in ('cygwin', 'win32'))

# Flag: are we on win32?
ON_WIN32 = (sys.platform == 'win32')


#----------------------------------------------------------------------
# Misc helper functions
def hexread(s):
    """Helper function.  Converts a hexidecimal string into a binary string.
       For example, hexread('0A0B') == '\x0A\x0B'."""
    assert (len(s) % 2) == 0
    s = s.upper()
    r = []
    hexvals = "0123456789ABCDEF"
    for i in range(len(s) / 2):
        v1 = hexvals.index(s[i*2])
        v2 = hexvals.index(s[i*2+1])
        c = (v1 << 4) + v2
        assert 0 <= c < 256
        r.append(chr(c))
    return "".join(r)

def findFirstDiff(s1, s2):
    """Helper function.  Returns the first index i for which s1[i] != s2[i],
       or -1 s1 == s2."""
    if s1 == s2:
        return -1
    last = min(len(s1), len(s2))
    for i in xrange(last):
        if s1[i] != s2[i]:
            return i
    return last

def floatEq(f1,f2):
    """Return true iff f1 is very close to f2."""
    if min(f1, f2) != 0:
        return abs(f1-f2)/min(f1,f2) < .00001
    else:
        return abs(f1-f2) < .00001

def fileURL(fname):
    """Return a file url suitable for a file named 'fname'"""
    fname = os.path.abspath(fname)
    return "file:%s"%fname

#----------------------------------------------------------------------
# RSA key caching functionality

# Map from (n, bits) to a RSA key with bits bits.  Used to cache RSA keys
# for different purposes.
_generated_rsa_keys = {}
_generated_rsa_keys[(0,2048)] = mixminion.testSupport.TEST_KEYS_2048[0]
_generated_rsa_keys[(1,2048)] = mixminion.testSupport.TEST_KEYS_2048[1]
_generated_rsa_keys[(2,2048)] = mixminion.testSupport.TEST_KEYS_2048[2]
def getRSAKey(n,bits):
    """Return the n'th of an arbitrary number of cached 'bits'-bit RSA keys,
       generating them as necessary."""
    try:
        return _generated_rsa_keys[(n,bits)]
    except KeyError:
        if bits > 1024:
            print "[generating %d-bit key #%d..."%(bits,n),
            sys.stdout.flush()
        k = _pk_generate_orig(bits)
        if bits > 1024:
            print "done]",
            sys.stdout.flush()
        _generated_rsa_keys[(n,bits)] = k
        return k

# Functions to override Crypto.pk_generate to avoid generating a zillion RSA
# keys.
_pk_generate_orig = Crypto.pk_generate
_pk_generate_idx = 0
def _pk_generate_replacement(bits=1024,e=65537):
    if bits == 1024:
        global _pk_generate_idx
        _pk_generate_idx = (_pk_generate_idx + 1) % 4
        return getRSAKey(_pk_generate_idx, bits)
    else:
        return getRSAKey(0, bits)

if not USE_SLOW_MODE:
    Crypto.pk_generate = _pk_generate_replacement

#----------------------------------------------------------------------
# Add some helpful functions to unittest.TestCase

class TestCase(unittest.TestCase):
    """Extended version of unittest.TestCase with a few extra
       'assertFoo' functions."""
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
    def assertFloatEq(self, f1, f2):
        """Fail unless f1 and f2 are very close to one another."""
        if not floatEq(f1, f2):
            self.fail("%s != %s" % (f1, f2))
    def assertLongStringEq(self, s1, s2):
        """Fail unless the string s1 equals the string s2.  If they aren't 
           equal, give a failure message that highlights the first point at
           which they differ."""
        if s1 != s2:
            d = findFirstDiff(s1, s2)
            self.fail("Strings unequal.  First difference at %s: %r vs %r"
                      % (d, s1[d:+10], s2[d:d+10]))
    def assertUnorderedEq(self, l1, l2):
        """Fail unless the lists l1 and l2 have the same elements.  The
           order of elements in the two lists need not be the same."""
        l1 = list(l1)[:]
        l2 = list(l2)[:]
        l1.sort()
        l2.sort()
        self.assertEquals(l1, l2)
    def assertStartsWith(self, s1, s2):
        """Fail unless string s1 begins with string s2."""
        if not s1.startswith(s2):
            if len(s1) > min(40, len(s2)+5):
                s1 = s1[:len(s2)+5]+"..."
            self.fail("%r does not start with %r"%(s1,s2))
    def assertEndsWith(self, s1, s2):
        """Fail unless string s1 ends with string s2."""
        if not s1.endswith(s2):
            if len(s1) > min(40, len(s2)+5):
                s1 = "..."+s1[-(len(s2)+5):]
            self.fail("%r does not end with %r"%(s1,s2))

#----------------------------------------------------------------------
# Tests for common functionality

class MiscTests(TestCase):
    def testDiv(self):
        self.assertEquals(floorDiv(10,1), 10)
        self.assertEquals(floorDiv(10,2), 5)
        self.assertEquals(floorDiv(10,3), 3)
        self.assertEquals(floorDiv(10,11), 0)
        self.assertEquals(floorDiv(0,11), 0)
        self.assertEquals(floorDiv(-1,1), -1)
        self.assertEquals(floorDiv(-1,2), -1)
        self.assertEquals(floorDiv(-10,3), -4)
        self.assertEquals(floorDiv(-10,-3), 3)

        self.assertEquals(ceilDiv(10,1), 10)
        self.assertEquals(ceilDiv(10,2), 5)
        self.assertEquals(ceilDiv(10,3), 4)
        self.assertEquals(ceilDiv(10,11), 1)
        self.assertEquals(ceilDiv(0,11), 0)
        self.assertEquals(ceilDiv(-1,1), -1)
        self.assertEquals(ceilDiv(-1,2), 0)
        self.assertEquals(ceilDiv(-10,3), -3)
        self.assertEquals(ceilDiv(-10,-3), 4)

    def testVersions(self):
        vstr = mixminion.version_tuple_to_string
        parse = mixminion.parse_version_string
        cmp = mixminion.cmp_versions
        last = None
        for t,s,c in [((1,0,0,100,-1),   "1.0.0",       None),
                      ((0,0,3,0,-1),     "0.0.3alpha",  '<'),
                      ((0,5,22,50,6),    "0.5.22beta6", '>'),
                      ((0,5,22,99,6),    "0.5.22rc6",   '>'),
                      ((0,5,22,99,6),    "0.5.22rc6",   '='),
                      ((0,0,3,100,9),    "0.0.3.9",     '<'),
                      ((0,0,3,66,9),     "0.0.3(66)9",  '<'),
                      ((0,0,3,66,-1),    "0.0.3(66)",   '<'),
                      ((0,0,3,66,0),     "0.0.3(66)0",  '>'),
                      ((0,0,3,'fred',-1),"0.0.3fred",   'EX'),
                      ((0,0,3,'fred',8), "0.0.3fred8",  '<'),
                      ((0,0,3,'fred',0), "0.0.3fred0",  '>'),
                      ((0,0,3,'code',0), "0.0.3code0",  "EX"),
                      ]:
            self.assertEquals(vstr(t), s)
            self.assertEquals(parse(s), t)
            if not last:
                continue

            if c == 'EX':
                self.assertRaises(ValueError, cmp, last, t)
            elif c == '<':
                self.assertEquals(cmp(last,t), -1)
            elif c == '=':
                self.assertEquals(cmp(last,t), 0)
            elif c == '>':
                self.assertEquals(cmp(last,t), 1)
            else:
                print "Huh?"

            last = t

    def testTimeFns(self):
        # This isn't a very good test.
        now = int(time.time())
        max_sec_per_day = 24*60*60+ 1
        # Sample 1000 evenly spaced points, making sure...
        for t in xrange(10, now, floorDiv(now, 1000)):
            yyyy,MM,dd,hh,mm,ss = time.gmtime(t)[:6]
            # 1. That previousMidnight returns the same day, at midnight.
            pm = previousMidnight(t)
            yyyy2,MM2,dd2,hh2,mm2,ss2 = time.gmtime(pm)[:6]
            self.assertEquals((yyyy2,MM2,dd2), (yyyy,MM,dd))
            self.assertEquals((0,0,0), (hh2,mm2,ss2))
            self.failUnless(pm <= t and 0 <= (t-pm) <= max_sec_per_day)
            # 2. That previousMidnight is repeatable
            self.assertEquals(previousMidnight(t), pm)
            # 3. That previousMidnight is idempotent
            self.assertEquals(previousMidnight(pm), pm)

            # 4. That succeedingMidnight returns the next day, at midnight.
            sm = succeedingMidnight(t)
            yyyy2,MM2,dd2,hh2,mm2,ss2 = time.gmtime(sm)[:6]
            self.assertEquals((0,0,0), (hh2, mm2, ss2))
            if dd2 == dd + 1:
                self.assertEquals((yyyy2, MM2), (yyyy, MM))
            elif MM2 == MM + 1:
                self.assertEquals((yyyy2, dd2), (yyyy, 1))
            else:
                self.assertEquals((yyyy2, MM2, dd2), (yyyy+1, 1, 1))
            # 5. That succeedingMidnight is repeatable
            self.assertEquals(succeedingMidnight(t), sm)
            # 6. That sm(pm(x)) = sm(x)
            self.assertEquals(succeedingMidnight(previousMidnight(t)),
                              succeedingMidnight(t))
            # 7. That pm(sm(x)) = sm(x)
            self.assertEquals(previousMidnight(succeedingMidnight(t)),
                              succeedingMidnight(t))

        now = time.time()
        ft = formatFnameTime(now)
        tm = time.localtime(now)
        self.assertEquals(ft, "%04d%02d%02d%02d%02d%02d" % tm[:6])

    def test_isSMTPMailbox(self):
        # Do we accept good addresses?
        for addr in ("Foo@bar.com", "a@b", "a@b.c.d.e", "a!b.c@d", "z@z",
                     "$@com"):
            self.assert_(isSMTPMailbox(addr))

        # Do we reject bad addresses?
        for addr in ("(foo)@bar.com", "z.d" "z@", "@z", "@foo.com", "aaa",
                     "foo.bar@", "foo\177@bar.com", "foo@bar\177.com",
                     "foo@bar;cat /etc/shadow;echo ","foo bar@baz.com",
                     "a@b@c", "foo@[127.0.0.1]", "foo@127.0.0.1", "foo@127"):
            self.assert_(not isSMTPMailbox(addr))

    def test_intervalset(self):
        eq = self.assertEquals
        nil = IntervalSet()
        nil2 = IntervalSet()
        nil._checkRep()
        self.assert_(nil.isEmpty())
        self.assert_(nil == nil2)
        eq(repr(nil), "IntervalSet([])")
        eq([], nil.getIntervals())
        nil3 = IntervalSet([(10, 0)])
        eq([], nil3.getIntervals())

        oneToTen = IntervalSet([(1,10)])
        fourToFive = IntervalSet([(4,5)])
        zeroToTen = IntervalSet([(0,10)])
        zeroToTwenty = IntervalSet([(0,20)])
        tenToTwenty = IntervalSet([(10,20)])
        oneToTwenty = IntervalSet([(1,20)])
        fifteenToFifty = IntervalSet([(15,50)])

        eq(zeroToTen.getIntervals(), [(0, 10)])
        for iset in oneToTen, fourToFive, zeroToTen, zeroToTwenty, oneToTwenty:
            iset._checkRep()

        checkEq = self._intervalEq

        # Tests for addition: A + B, where...
        #   1. A and B are empty.
        checkEq(nil+nil, nil, [])
        #   2. Just A or B is empty.
        checkEq(nil+oneToTen, oneToTen+nil, oneToTen, [(1,10)])
        #   3. A contains B, or vice versa.
        checkEq(oneToTen+fourToFive, fourToFive+oneToTen, oneToTen)
        checkEq(oneToTen+zeroToTwenty, zeroToTwenty)
        #   4. A == B
        checkEq(oneToTen+oneToTen, oneToTen)
        #   5. A and B are disjoint and don't touch.
        checkEq(oneToTen+fifteenToFifty, fifteenToFifty+oneToTen,
                [(1,10),(15,50)])
        #   6. A and B are disjoint and touch
        checkEq(oneToTen+tenToTwenty, tenToTwenty+oneToTen, oneToTwenty)
        #   7. A and B overlap on one side only.
        checkEq(oneToTwenty+fifteenToFifty,
                fifteenToFifty+oneToTwenty,
                "IntervalSet([(1,50)])")
        #   8. A nice complex situation.
        fromPrimeToPrime = IntervalSet([(2,3),(5,7),(11,13),(17,19),(23,29)])
        fromSquareToSquare = IntervalSet([(1,4),(9,16),(25,36)])
        fromFibToFib = IntervalSet([(1,1),(2,3),(5,8),(13,21),(34,55)])
        x = fromPrimeToPrime.copy()
        x += fromSquareToSquare
        x += fromSquareToSquare
        checkEq(fromPrimeToPrime+fromSquareToSquare,
                fromSquareToSquare+fromPrimeToPrime,
                x,
                [(1,4),(5,7),(9,16),(17,19),(23,36)])
        checkEq(fromSquareToSquare+fromFibToFib,
                [(1,4),(5,8),(9,21),(25,55)])
        checkEq(fromPrimeToPrime+fromFibToFib,
                [(2,3),(5,8),(11,21),(23,29),(34,55)])

        # Now, subtraction!
        #  1. Involving nil.
        checkEq(nil-nil, nil, [])
        checkEq(fromSquareToSquare-nil, fromSquareToSquare)
        checkEq(nil-fromSquareToSquare, nil)
        #  2. Disjoint ranges.
        checkEq(fourToFive-tenToTwenty, fourToFive)
        checkEq(tenToTwenty-fourToFive, tenToTwenty)
        #  3. Matching on one side
        checkEq(oneToTwenty-oneToTen, tenToTwenty)
        checkEq(oneToTwenty-tenToTwenty, oneToTen)
        checkEq(oneToTen-oneToTwenty, nil)
        checkEq(tenToTwenty-oneToTwenty, nil)
        #  4. Overlapping on one side
        checkEq(fifteenToFifty-oneToTwenty, [(20,50)])
        checkEq(oneToTwenty-fifteenToFifty, [(1,15)])
        #  5. Overlapping in the middle
        checkEq(oneToTen-fourToFive, [(1,4),(5,10)])
        checkEq(fourToFive-oneToTen, nil)
        #  6. Complicated
        checkEq(fromPrimeToPrime-fromSquareToSquare,
                [(5,7),(17,19),(23,25)])
        checkEq(fromSquareToSquare-fromPrimeToPrime,
                [(1,2),(3,4),(9,11),(13,16),(29,36)])
        checkEq(fromSquareToSquare-fromFibToFib,
                [(1,2),(3,4),(9,13),(25,34)])
        checkEq(fromFibToFib-fromSquareToSquare,
                [(5,8),(16,21),(36,55)])
        #  7. Identities
        for a in (fromPrimeToPrime, fromSquareToSquare, fromFibToFib, nil):
            for b in (fromPrimeToPrime, fromSquareToSquare, fromFibToFib, nil):
                checkEq(a-b+b, a+b)
                checkEq(a+b-b, a-b)

        ## Test intersection
        # 1. With nil
        checkEq(nil*nil, nil*fromFibToFib, oneToTen*nil, nil, [])
        # 2. Self
        for iset in oneToTen, fromSquareToSquare, fourToFive:
            checkEq(iset, iset*iset)
        # 3. A disjoint from B
        checkEq(oneToTen*fifteenToFifty, fifteenToFifty*oneToTen, nil)
        # 4. A disjoint from B but touching.
        checkEq(oneToTen*tenToTwenty, tenToTwenty*oneToTen, nil)
        # 5. A contains B at the middle.
        checkEq(oneToTen*fourToFive, fourToFive*oneToTen, fourToFive)
        # 6. A contains B at one end
        checkEq(oneToTen*oneToTwenty, oneToTwenty*oneToTen, oneToTen)
        checkEq(tenToTwenty*oneToTwenty, oneToTwenty*tenToTwenty, tenToTwenty)
        # 7. A and B overlap without containment.
        checkEq(fifteenToFifty*oneToTwenty, oneToTwenty*fifteenToFifty,
                [(15,20)])
        # 8. Tricky cases
        checkEq(fromPrimeToPrime*fromSquareToSquare,
                fromSquareToSquare*fromPrimeToPrime,
                [(2,3),(11,13),(25,29)])
        checkEq(fromPrimeToPrime*fromFibToFib,
                fromFibToFib*fromPrimeToPrime,
                [(2,3),(5,7),(17,19)])
        checkEq(fromSquareToSquare*fromFibToFib,
                fromFibToFib*fromSquareToSquare,
                [(2,3),(13,16),(34,36)])
        # 9. Identities
        for a in (fromPrimeToPrime, fromSquareToSquare, fromFibToFib, oneToTen,
                  fifteenToFifty, nil):
            self.assert_((not a) == a.isEmpty() == (a == nil))
            for b in (fromPrimeToPrime, fromSquareToSquare, fromFibToFib,
                      oneToTen, fifteenToFifty, nil):
                checkEq(a*b,b*a)
                checkEq(a-b, a*(a-b), (a-b)*a)
                checkEq(b*(a-b), (a-b)*b, nil)
                checkEq(a-b, a-a*b)
                checkEq((a-b)+a*b, a)
                checkEq((a-b)*(b-a), nil)
                checkEq((a-b)+(b-a)+a*b, a+b)

        ## Contains
        t = self.assert_
        # 1. With nil
        t(5 not in nil)
        t(oneToTen not in nil)
        t(fromFibToFib not in nil)
        # 2. Self in self
        for iset in nil, oneToTen, tenToTwenty, fromSquareToSquare:
            t(iset in iset)
        # 3. Simple sets: closed below, open above.
        t(1 in oneToTen)
        t(2 in oneToTen)
        t(9.9 in oneToTen)
        t(10 not in oneToTen)
        t(0 not in oneToTen)
        t(11 not in oneToTen)
        # 4. Simple sets: A contains B.
        t(fourToFive in oneToTen) # contained wholly
        t(oneToTen in zeroToTen) #contains on one side.
        t(oneToTwenty not in oneToTen) #disjoint on one side
        t(oneToTen not in tenToTwenty) #disjoint but touching
        t(fourToFive not in tenToTwenty) #disjoint, not touching
        # 5. Complex sets: closed below, open above
        t(0 not in fromSquareToSquare)
        t(1 in fromSquareToSquare)
        t(2 in fromSquareToSquare)
        t(4 not in fromSquareToSquare)
        t(8 not in fromSquareToSquare)
        t(9 in fromSquareToSquare)
        t(15 in fromSquareToSquare)
        t(16 not in fromSquareToSquare)
        t(35 in fromSquareToSquare)
        t(36 not in fromSquareToSquare)
        t(100 not in fromSquareToSquare)

    def _intervalEq(self, a, *others):
        eq = self.assertEquals
        for b in others:
            if isinstance(b, IntervalSet):
                eq(a,b)
                b._checkRep()
            elif isinstance(b, types.StringType):
                eq(repr(a), b)
            elif isinstance(b, types.ListType):
                eq(a.getIntervals(), b)
            else:
                raise MixError()
            a._checkRep()

    def test_openUnique(self):
        d = mix_mktemp()
        os.mkdir(d)
        dX = os.path.join(d,"X")
        f, fn = openUnique(dX)
        f.write("X")
        f.close()
        self.assertEquals(fn, dX)

        f, fn = openUnique(dX)
        f.write("X")
        f.close()
        self.assertEquals(fn, dX+".1")

        f, fn = openUnique(dX)
        f.write("X")
        f.close()
        self.assertEquals(fn, dX+".2")

    def test_lockfile(self):
        fn = mix_mktemp()
        LF1 = Lockfile(fn)
        LF2 = Lockfile(fn)
        LF1.acquire("LF1")
        if not ON_WINDOWS:
            self.assertEquals("LF1", readFile(fn))
        self.assertRaises(LockfileLocked, LF2.acquire, blocking=0)
        LF1.release()
        LF2.acquire("LF2",1)
        if not ON_WINDOWS:
            self.assertEquals("LF2", readFile(fn))
        self.assertRaises(LockfileLocked, LF1.acquire, blocking=0)

        # Now try recursivity.
        LF2.acquire()
        self.assertRaises(LockfileLocked, LF1.acquire, blocking=0)
        LF2.release()
        self.assertRaises(LockfileLocked, LF1.acquire, blocking=0)
        LF2.release()
        LF1.acquire(blocking=1)

        # Now try a blocking lock.  We need to block in another process
        # because of some platforms' implementations of threading.
        releasedFile = mix_mktemp()
        writeFile(releasedFile, "nobody")
        pid = os.fork()
        if pid == 0: # child
            LF2.acquire("LF2", blocking=1)
            if readFile(releasedFile) == 'parent':
                writeFile(releasedFile, "GOOD")
            else:
                writeFile(releasedFile, "BAD")
            os._exit(0)

        time.sleep(.1)
        writeFile(releasedFile, 'parent')
        LF1.release()
        os.waitpid(pid, 0)
        self.assertEquals("GOOD", readFile(releasedFile))

    def test_encodeBase64(self):
        longish = "xyzzyasjklsadjsakldjsakldjsakldjskljaskldjsadkljsa"*10
        d32 = encodeBase64(longish, lineWidth=32)
        d64 = encodeBase64(longish, lineWidth=64)
        self.assertEquals(longish, base64.decodestring(d32))
        self.assertEquals(longish, base64.decodestring(d64))
        for enc, max in ((d32, 33), (d64,65)):
            lines = enc.split("\n")
            for line in lines[-1]:
                self.assertEquals(len(line), max)
            self.assert_(len(lines[-1]) <= max)

    def test_armor(self):
        inp1 = "xyzzy111"*10
        inp2 = "Hello\nWorld!\n--Me.\n"
        # Simple base64
        self.assertEquals(armorText(inp1, "FOO BAR", (), 1),
"""-----BEGIN FOO BAR-----

eHl6enkxMTF4eXp6eTExMXh5enp5MTExeHl6enkxMTF4eXp6eTExMXh5enp5MTEx
eHl6enkxMTF4eXp6eTExMXh5enp5MTExeHl6enkxMTE=
-----END FOO BAR-----\n""")
        # With headers
        self.assertEquals(armorText(inp1, "FOO BAR",
                                    [("H1", "xyz"),("H2", "a b")], 1),
"""-----BEGIN FOO BAR-----
H1: xyz
H2: a b

eHl6enkxMTF4eXp6eTExMXh5enp5MTExeHl6enkxMTF4eXp6eTExMXh5enp5MTEx
eHl6enkxMTF4eXp6eTExMXh5enp5MTExeHl6enkxMTE=
-----END FOO BAR-----\n""")

        # No base64
        self.assertEquals(armorText(inp1, "FOO BAR", (), 0),
"""-----BEGIN FOO BAR-----

xyzzy111xyzzy111xyzzy111xyzzy111xyzzy111xyzzy111xyzzy111xyzzy111xyzzy111xyzzy111
-----END FOO BAR-----\n""")

        # No base64, hyphen escape.
        self.assertEquals(armorText(inp2, "FOO BAR", [("H3", "text")], 0),
"""-----BEGIN FOO BAR-----
H3: text

Hello
World!
- --Me.
-----END FOO BAR-----\n""")

        # Test unarmor, succeeding cases.
        for inp in inp1, inp2:
            for mode in 0,1:
                for headers in [], [("H-x", "abcde fg")]:
                    enc = armorText(inp, "THIS THAT", headers, mode)
                    enc = "asdasdkjlasd\nHey kids!\n"+enc
                    tp, h, b = unarmorText(enc, ["THIS THAT", "FRED"],
                                           mode)[0]
                    self.assertEquals(tp, "THIS THAT")
                    self.assertEquals(h, headers)
                    self.assertEquals(b.strip(), inp.strip())
                    if not mode:
                        self.assertEndsWith(b, "\n")

        # Test unarmor and [...]
        enc = armorText(inp2*50, "MUNGED", [], base64=1)
        enc = enc.split("\n")
        enc[-10:-5] = [ "[...]" ]
        enc = "\n".join(enc)
        self.assertRaises(ValueError, unarmorText, enc, ["MUNGED"], 1)

        # Test base64fn and concatenation.
        enc1 = armorText(inp2, "THIS THAT", [("H-64", "0")], 0)
        enc2 = armorText(inp2, "THIS THAT", [("H-64", "1")], 1)
        def base64fn(tp, h, assert_=self.assert_):
            assert_(tp=="THIS THAT")
            assert_(len(h) == 1)
            assert_(len(h[0]) == 2)
            assert_(h[0][0] == "H-64")
            return int(h[0][1])
        dec = unarmorText(enc1+enc2, ["THIS THAT"], base64fn=base64fn)
        self.assertEquals(len(dec), 2)
        for mode in 0, 1:
            tp,h,b = dec[mode]
            self.assertEquals(tp, "THIS THAT")
            self.assertEquals(h, [("H-64", str(mode))])
            self.assertEquals(b, inp2)

        # Test skipping unwanted types
        enc3 = armorText(inp2, "OTHER", [("H-64", "1")], 1)
        dec2 = unarmorText(enc1+enc3+enc2, ["THIS THAT"], base64fn=base64fn)
        self.assertEquals(dec2, dec)

        # Test skipping broken armor.
        self.assertRaises(ValueError,
                          unarmorText,"-----BEGIN X-----\n\n", ["Y"], 1)
        self.assertRaises(ValueError,
                          unarmorText,
                          "-----BEGIN X-----\n"
                          ":B:C\n\n"
                          "A B C\n-----END X-----\n", ["X"], 0)
        self.assertRaises(ValueError,
                          unarmorText,
                          "-----BEGIN X-----\n"
                          "A: X\n\n"
                          "A B C\n-----END X-----\n", ["X"], 1)
        
#----------------------------------------------------------------------

class MinionlibCryptoTests(TestCase):
    """Tests for cryptographic C extensions."""
    def test_sha1(self):
        s1 = _ml.sha1

        # A test vector from the SHA1 spec
        self.assertEquals(s1("abc"),
              hexread("A9993E364706816ABA3E25717850C26C9CD0D89D"))

        # Another test vector from the SHA1 spec
        s = s1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        self.assertEquals(s,
               hexread("84983E441C3BD26EBAAE4AA1F95129E5E54670F1"))

        # Make sure that we fail gracefully on non-string input.
        self.failUnlessRaises(TypeError, s1, 1)

    def test_xor(self):
        xor = _ml.strxor

        # Try a few known-value XORs.
        self.assertEquals(xor("abc", "\000\000\000"), "abc")
        self.assertEquals(xor("abc", "abc"), "\000\000\000")
        self.assertEquals(xor("\xEF\xF0\x12", "\x11\x22\x35"), '\xFE\xD2\x27')

        # Make sure that the C doesn't (cringe) modify the strings out from
        # under us.
        a = "aaaa"
        self.assertEquals(xor(a,"\000\000\000a"), "aaa\000")
        self.assertEquals(a, "aaaa")
        self.assertEquals(xor("\000\000\000a",a), "aaa\000")
        self.assertEquals(a, "aaaa")

        # Check for error msg on XORing strings of unequal length.
        self.failUnlessRaises(TypeError, xor, "a", "bb")

    def test_aes(self):
        crypt = _ml.aes_ctr128_crypt

        # First, try one of the test vectors from the AES spec.
        key = txt = "\x80" + "\x00" * 15
        key = _ml.aes_key(key)
        expected = hexread("8EDD33D3C621E546455BD8BA1418BEC8")
        self.failUnless(crypt(key, txt, 0) == expected)
        self.failUnless(crypt(key, txt) == expected)

        # Now, make sure that the counter implementation is sane.
        self.failUnless(crypt(key, " "*100, 0)[1:] == crypt(key, " "*99, 1))
        self.failUnless(crypt(key, " "*100, 0)[30:] == crypt(key, " "*70, 30))

        # Make sure ctr_crypt works the same everywhere.
        expected2 = hexread("351DA02F1CF68C4BED393BC71274D181892FC420CA9E9995"
                            "C6E5E9744920020DB854019CB1CEB6BAD055C64F60E63B91"
                            "5917930EB30972BCB3942E6904252F26")
        self.failUnless(crypt(key, " "*64, 0xABCD) == expected2)

        # Counter mode is its own inverse
        self.failUnless(crypt(key,crypt(key, " "*100, 0),0) == " "*100)

        # Try a different key to be sure.
        teststr = """I have seen the best ciphers of my generation
                     Destroyed by cryptanalysis, broken, insecure,
                     Implemented still in cryptographic libraries"""
        key2 = _ml.aes_key("xyzz"*4)
        self.assertEquals(teststr,crypt(key2,crypt(key2,teststr)))

        # Try generating the same test vector again, but this time in PRNG
        # mode
        expected2 = hexread("0EDD33D3C621E546455BD8BA1418BEC8")
        self.assertEquals(expected2, crypt(key, "", 0, len(expected2)))
        # PRNG mode ignores input.
        self.assertEquals(expected2, crypt(key, "Z", 0, len(expected2)))
        # Try an offset with prng mode.
        self.assertEquals(expected2[5:], crypt(key, "", 5, len(expected2)-5))
        # Make sure that PRNG mode with negative count yields ""
        self.assertEquals("", crypt(key,"",0,-1))

        # Can't use a non-key object.
        self.failUnlessRaises(TypeError, crypt, "a", teststr)
        # Can't make a key from a short string...
        self.failUnlessRaises(TypeError, _ml.aes_key, "a")
        # ...or a long string.
        self.failUnlessRaises(TypeError, _ml.aes_key, "a"*17)

    def test_openssl_seed(self):
        # Just try seeding openssl a couple of times, and make sure it
        # doesn't crash.
        _ml.openssl_seed("Hello")
        _ml.openssl_seed("")

    def test_oaep(self):
        _add = Crypto._add_oaep_padding
        _check = Crypto._check_oaep_padding
        # Perform OAEP tests with C implementation of OAEP and Python
        # implementation too.
        for add,check in ((_ml.add_oaep_padding, _ml.check_oaep_padding),
                          (_add, _check)):
            self.do_test_oaep(add, check)

        # Make sure they can invert one another.
        self.assertEquals("a",_check(_ml.add_oaep_padding("a", "b", 128),
                                         "b",128))
        self.assertEquals("a",_ml.check_oaep_padding(_add("a","b",128),
                                                         "b",128))

    def do_test_oaep(self, add, check):
        strxor = _ml.strxor
        # Check_oaep inverts add_oaep successfully.
        x = add("A", "B", 128)

        self.assertEquals("A",check(x, "B", 128))

        # 86 bytes can be used with size=128
        add("A"*86, "B",128)
        # But 300 is too much,
        self.failUnlessRaises(_ml.CryptoError,
                              add,"A"*300, "B", 128)
        # And so is even 87.
        self.failUnlessRaises(_ml.CryptoError,
                              add,"A"*87, "B", 128)
        # Changing a character at the beginning keeps it from checking.
        ch = strxor(x[0], '\x01')
        self.failUnlessRaises(_ml.CryptoError,
                              check,ch+x[1:],"B",128)
        # Changing a character at the end keeps it from checking.
        ch = strxor(x[-1], '\x01')
        self.failUnlessRaises(_ml.CryptoError,
                              check,x[:-1]+ch,"B",128)

    def test_rsa(self):
        p = getRSAKey(1,1024)

        #for all of SIGN, CHECK_SIG, ENCRYPT, DECRYPT...
        for pub1 in (0,1):
            for enc1 in (0,1):
                msg = "Now is the time for all anonymous parties"
                x = _ml.add_oaep_padding(msg, "B", 128)
                x2 = p.crypt(x, pub1, enc1);
                # ...Encryption inverts decryption...
                x3 = p.crypt(x2, [1,0][pub1], [1,0][enc1]);
                self.failUnless(x3 == x)
                # ...And oaep is preserved.
                x4 = _ml.check_oaep_padding(x3, "B", 128)
                self.failUnless(x4 == msg)

        # Fail if there is not enough padding
        self.failUnlessRaises(_ml.CryptoError,p.crypt,"X",1,1)
        # Fail if there is too much padding
        self.failUnlessRaises(_ml.CryptoError,p.crypt,x+"ZZZ",1,1)

        ###
        # Test key equality and fingerprinting.
        self.assert_(pk_same_public_key(p, p))
        self.assert_(not pk_same_public_key(p, getRSAKey(2,1024)))
        self.assert_(len(pk_fingerprint(p))==40)
        self.assertNotEquals(pk_fingerprint(p),
                             pk_fingerprint(getRSAKey(2,1024)))
        ####
        # Test key encoding
        padhello = _ml.add_oaep_padding("Hello", "B", 128)
        for public in (0,1):
            #encode(decode(encode(x))) == x.
            x = p.encode_key(public)
            p2 = _ml.rsa_decode_key(x,public)
            x3 = p2.encode_key(public)
            self.assertEquals(x,x3)
            # decode(encode(x)) encrypts the same as x.
            self.assertEquals(p.crypt(padhello,public,1),
                              p2.crypt(padhello,public,1))
            self.assert_(pk_same_public_key(p, p2))
            self.assertEquals(pk_fingerprint(p),
                              pk_fingerprint(p2))

        # encoding public keys to/from their moduli.
        self.assertEquals(p.get_modulus_bytes(),1024 >> 3)
        n,e = p.get_public_key()
        # Let p2 be the public portion of p.
        p2 = _ml.rsa_make_public_key(n,e)
        self.assertEquals((n,e), p2.get_public_key())
        self.assertEquals(65537,e)
        self.assertEquals(p.encode_key(1), p.encode_key(1))

        # Let P3 be the public key component of p.  Encrypt some messages
        # using p...
        p3 = _ml.rsa_decode_key(p.encode_key(1),1)
        msg1 = p.crypt(padhello, 1,1)
        msg2 = p.crypt(padhello, 1,1)
        msg3 = p.crypt(padhello, 1,1)
        self.assertEquals(padhello, p.crypt(msg1,0,0))
        self.assertEquals(padhello, p.crypt(msg2,0,0))
        self.assertEquals(padhello, p.crypt(msg3,0,0))
        # And make sure that neither p2 nor p3 can decode them.
        self.failUnlessRaises(TypeError, p2.crypt, msg1, 0, 0)
        self.failUnlessRaises(TypeError, p3.crypt, msg1, 0, 0)
        # And make sure that we can't encode either as a private key
        self.failUnlessRaises(TypeError, p2.encode_key, 0)
        self.failUnlessRaises(TypeError, p3.encode_key, 0)

        # Test PEM encoding (we need this encoding because it's the
        # most widely used way to store encrypted private keys.(
        tf = mix_mktemp()
        tf_pub = tf + "1"
        tf_prv = tf + "2"
        tf_enc = tf + "3"

        p.PEM_write_key(open(tf_pub,'w'), 1)
        p.PEM_write_key(open(tf_prv,'w'), 0)
        p.PEM_write_key(open(tf_enc,'w'), 0, "top sekrit")
        p2 = _ml.rsa_PEM_read_key(open(tf_pub, 'r'), 1)
        self.assertEquals(p.get_public_key(), p2.get_public_key())

        p2 = _ml.rsa_PEM_read_key(open(tf_prv, 'r'), 0)
        self.assertEquals(p.encode_key(0), p2.encode_key(0))

        self.failUnlessRaises(_ml.CryptoError,
                              _ml.rsa_PEM_read_key,
                              open(tf_enc, 'r'), 0)

        p2 = _ml.rsa_PEM_read_key(open(tf_prv, 'r'), 0, "top sekrit")
        self.assertEquals(p.encode_key(0), p2.encode_key(0))

#----------------------------------------------------------------------
class MinionlibFECTests(TestCase):
    def do_fec_test(self, k, n, sz):
        r = getCommonPRNG()

        eq = self.assertEquals
        fec = _ml.FEC_generate(k,n)
        eq((k,n), fec.getParameters())

        inpChunks = [ r.getBytes(sz) for i in xrange(k) ]
        inp = "".join(inpChunks)
        outChunks = [ fec.encode(i, inpChunks) for i in xrange(n) ]
        for i in xrange(n):
            if i < k:
                eq(outChunks[i], inpChunks[i])
            eq(len(outChunks[i]), sz)

        numberedChunks = [ (i, outChunks[i]) for i in xrange(n) ]

        for i in xrange(200):
            chk = r.shuffle(numberedChunks, k)
            #print [ i for i,_ in chk ]
            out = fec.decode(chk)
            eq(out, inpChunks)
            eq("".join(out), inp)
          
    def test_good_fec(self):
        self.do_fec_test(3,5,10)
        self.do_fec_test(10,20,1024)
        self.do_fec_test(30,40,1024)
        self.do_fec_test(30,40,1)
        self.do_fec_test(3,4,128)
        self.do_fec_test(3,3,2048)

    def test_bad_fec(self):
        
        self.assertRaises(_ml.FECError,_ml.FEC_generate,5,3)
        self.assertRaises(_ml.FECError,_ml.FEC_generate,0,10)
        self.assertRaises(_ml.FECError,_ml.FEC_generate,10,300)

        r = getCommonPRNG()
        fec = _ml.FEC_generate(3,5)
        inp = [ r.getBytes(256) for i in xrange(3) ]
        self.assertRaises(_ml.FECError,fec.encode, -1, inp)
        self.assertRaises(_ml.FECError,fec.encode, 5, inp)
        self.assertRaises(_ml.FECError,fec.encode, 1, inp[0:2])
        self.assertRaises(_ml.FECError,fec.encode, 1, inp*2)
        self.assertRaises(_ml.FECError,fec.encode, 1, inp[0:2]+[3])
        self.assertRaises(_ml.FECError,fec.encode, 1, 5)

        cInp = [ (i, fec.encode(i, inp)) for i in xrange(5) ]
        fec.decode(cInp[2:5])
        self.assertRaises(_ml.FECError,fec.decode, inp)
        self.assertRaises(_ml.FECError,fec.decode, [1,2,3])
        self.assertRaises(_ml.FECError,fec.decode, cInp)
        self.assertRaises(_ml.FECError,fec.decode, cInp[:-1])
        self.assertRaises(_ml.FECError,fec.decode, cInp[0:2]+[2,'x'])

#----------------------------------------------------------------------

class CryptoTests(TestCase):
    """Tests for Python cryptographic library"""
    def test_initcrypto(self):
        init_crypto()

    def test_wrappers(self):
        # Test simple wrappers over _minionlib functionality.  Mainly, just
        # test that _ml.foo and foo do the same thing.
        self.assertEquals(_ml.sha1("xyzzy"), sha1("xyzzy"))
        k = _ml.aes_key("xyzy"*4)
        self.assertEquals(_ml.aes_ctr128_crypt(k,"hello",0),
                          ctr_crypt("hello",k))
        self.assertEquals(_ml.aes_ctr128_crypt(k,"hello",99),
                          ctr_crypt("hello",k,99))
        self.assertEquals(_ml.aes_ctr128_crypt(k,"",0,99), prng(k,99))
        self.assertEquals(_ml.aes_ctr128_crypt(k,"",3,99), prng(k,99,3))
        self.assertEquals(prng(k,100,0),prng(k,50,0)+prng(k,50,50))

    def test_rsa(self):

        eq = self.assertEquals
        k512 = getRSAKey(0,512)
        k1024 = getRSAKey(0,1024)

        eq(512>>3, k512.get_modulus_bytes())
        eq(1024>>3, k1024.get_modulus_bytes())

        # Check pk_get_modulus sanity
        self.failUnless((1L<<511) < pk_get_modulus(k512) < (1L<<513))
        self.failUnless((1L<<1023) < pk_get_modulus(k1024) < (1L<<1024))
        self.assertEquals(pk_get_modulus(k512),
                        pk_get_modulus(pk_from_modulus(pk_get_modulus(k512))))

        # Make sure that public keys can be made from moduli, and used to
        # encrypt and decrypt.
        msg="Good hello"
        pub512 = pk_from_modulus(pk_get_modulus(k512))
        pub1024 = pk_from_modulus(pk_get_modulus(k1024))

        eq(msg, pk_decrypt(pk_encrypt(msg, k512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),k512))
        eq(msg, pk_decrypt(pk_encrypt(msg, k1024),k1024))
        eq(msg, pk_decrypt(pk_encrypt(msg, pub1024),k1024))

        # Make sure that CH_OAEP(RSA()) inverts pk_encrypt.
        eq(msg, _ml.check_oaep_padding(
                    k512.crypt(pk_encrypt(msg,k512), 0, 0),
                    Crypto.OAEP_PARAMETER, 64))

        # test signing
        eq(pk_check_signature(pk_sign(msg, k1024),pub1024), msg)
        eq(pk_check_signature(pk_sign(msg, k1024),k1024), msg)
        self.failUnlessRaises(TypeError,
                              pk_sign, msg, pub1024)
        self.failUnlessRaises(CryptoError,
                              pk_check_signature,
                              pk_sign(msg, k1024)+"X",
                              pub1024)

        # Make sure we can still encrypt after we've encoded/decoded a
        # key.
        encoded = pk_encode_private_key(k512)
        decoded = pk_decode_private_key(encoded)
        eq(msg, pk_decrypt(pk_encrypt(msg, pub512),decoded))

        # Test pickling
        init_crypto()
        s = cPickle.dumps(k512)
        self.assertEquals(cPickle.loads(s).get_public_key(),
                          k512.get_public_key())
        s = cPickle.dumps(k512, 1)
        self.assertEquals(cPickle.loads(s).get_public_key(),
                          k512.get_public_key())

    def test_trng(self):
        # Make sure that the true rng is at least superficially ok.
        self.assertNotEquals(trng(40), trng(40))

    def test_lioness(self):
        enc = lioness_encrypt
        dec = lioness_decrypt

        # Check basic cipher properties.
        key = ("ABCDE"*4, "ABCDF"*4, "DECBA"*4, "VWXYZ"*4)
        plain = "The more it snows the more it goes on snowing"*10
        self.assertNotEquals(plain, enc(plain,key))
        self.assertNotEquals(plain, dec(plain,key))
        self.assertEquals(len(plain), len(enc(plain,key)))
        self.assertEquals(len(plain), len(dec(plain,key)))
        self.assertEquals(plain, dec(enc(plain,key),key))
        self.assertEquals(plain, enc(dec(plain,key),key))

        # Walk through a LIONESS encryption to check for correct values.
        # Check getLionessKeys too.
        s = "ABCDE"*4
        key1 = sha1(s+"foo")
        key2 = key1[:-1]+strxor(key1[-1], chr(1))
        key3 = key1[:-1]+strxor(key1[-1], chr(2))
        key4 = key1[:-1]+strxor(key1[-1], chr(3))

        left = plain[:20]
        right = plain[20:]
        right = ctr_crypt(right, sha1(key1+left+key1)[:16])
        left  = strxor(left, sha1(key2+right+key2))
        right = ctr_crypt(right, sha1(key3+left+key3)[:16])
        left  = strxor(left, sha1(key4+right+key4))

        key = (key1,key2,key3,key4)
        self.assertEquals(left+right, lioness_encrypt(plain,key))
        self.assertEquals(key, Keyset("ABCDE"*4).getLionessKeys("foo"))

        u = "Hello world"*2
        w = whiten(u)
        self.assertNotEquals(w, u)
        self.assertEquals(unwhiten(w), u)
        u = "xyzprdlty"*100
        w = whiten(u)
        self.assertNotEquals(w, u)
        self.assertEquals(unwhiten(w), u)

    def test_bear(self):
        enc = bear_encrypt
        dec = bear_decrypt

        # Check basic cipher properties.
        key = ("ABCDE"*4, "QRSTU"*4)
        plain = "The more it snows the more it goes on snowing"*10
        self.assertNotEquals(plain, enc(plain,key))
        self.assertNotEquals(plain, dec(plain,key))
        self.assertEquals(len(plain), len(enc(plain,key)))
        self.assertEquals(len(plain), len(dec(plain,key)))
        self.assertEquals(plain, dec(enc(plain,key),key))
        self.assertEquals(plain, enc(dec(plain,key),key))

        # Walk through a BEAR encryption to check for correct values.
        # Check getLionessKeys too.
        s = "ABCDE"*4
        key1 = sha1(s+"foo")
        key2 = key1[:-1]+strxor(key1[-1], chr(1))

        left = plain[:20]
        right = plain[20:]
        left = strxor(left, sha1(key1+right+key1))
        right = ctr_crypt(right, sha1(left)[:16])
        left = strxor(left, sha1(key2+right+key2))

        key = (key1,key2)
        self.assertEquals(left+right, bear_encrypt(plain,key))
        self.assertEquals(key, Keyset("ABCDE"*4).getBearKeys("foo"))

    def test_keyset(self):
        s = sha1
        x = _ml.strxor
        # Make sure that keyset.get expected
        k = Keyset("a")
        eq = self.assertEquals
        eq(s("aFoo")[:10], k.get("Foo",10))
        eq(s("aBar")[:16], k.get("Bar"))

        # Make sure that keyset.getLionessKeys works as expected.
        z19 = "\x00"*19
        eq((s("aBaz"),               x(s("aBaz"), z19+"\x01"),
            x(s("aBaz"),z19+"\x02"), x(s("aBaz"), z19+"\x03")),
           k.getLionessKeys("Baz"))

    def test_aesprng(self):
        # Make sure that AESCounterPRNG is really repeatable.
        key ="aaab"*4
        PRNG = AESCounterPRNG(key)
        self.assert_(prng(key,100000) == (
                          PRNG.getBytes(5)+PRNG.getBytes(16*1024-5)+
                          PRNG.getBytes(50)+PRNG.getBytes(32*1024)+
                          PRNG.getBytes(9)+PRNG.getBytes(10)+
                          PRNG.getBytes(15)+PRNG.getBytes(16000)+
                          PRNG.getBytes(34764)))

        # Check getInt, getFloat.
        for i in xrange(1,10000,17):
            self.failUnless(0 <= PRNG.getInt(10) < 10)
            self.failUnless(0 <= PRNG.getInt(i) < i)
        
        # Check getNormal
        tot = 0
        for i in xrange(1,1000):
            v = PRNG.getNormal(5,1)
            self.failUnless(0 <= v <= 10)
            tot += v
        self.failUnless(4500<tot<5500)

##      itot=ftot=0
##      for i in xrange(1000000):
##          itot += PRNG.getInt(10)
##          ftot += PRNG.getFloat()

##      print "AVG INT", itot/1000000.0
##      print "AVG FLT", ftot/1000000.0

        for i in xrange(100):
            self.failUnless(0 <= PRNG.getFloat() < 1)

        # Test the pick method
        lst = [1, 2, 3]
        count = [0,0,0,0]
        for _ in xrange(100):
            count[PRNG.pick(lst)]+=1
        self.assert_(count[0]==0)
        self.assert_(0 not in count[1:])
        self.assertRaises(IndexError, PRNG.pick, [])

        lst = range(100)
        # Test shuffle(0)
        self.assertEquals(PRNG.shuffle(lst,0), [])
        self.assertEquals(lst, range(100))
        # Make sure shuffle only shuffles the last n.
        PRNG.shuffle(lst,10)
        later = [ item for item in lst[10:] if item >= 10 ]
        s = later[:]
        s.sort()
        self.failUnless(later == s)

        # Make sure shuffle actually shuffles all positions.
        lists = [  ]
        for i in xrange(6):
            lists.append(PRNG.shuffle(lst)[:])
        # This will fail accidentally once in 10,000,000,000 attempts.
        for crossSection in zip(*lists):
            allEq = 1
            for z in crossSection:
                if z != crossSection[0]: allEq = 0
            self.failIf(allEq)
        foundUnmoved = 0
        for lst in lists:
            for inorder, shuffled in zip(lst, range(100)):
                if inorder == shuffled:
                    foundUnmoved = 1
                    break
            if foundUnmoved: break
        self.failUnless(foundUnmoved)
        for lst in lists:
            self.assertUnorderedEq(lst, range(100))

#----------------------------------------------------------------------

class PacketTests(TestCase):
    def test_subheader(self):
        s = Subheader(3,0,"abcdeabcdeabcdef",
                      "ABCDEFGHIJABCDEFGHIJ",
                      1, "Hello")

        expected = "\003\000abcdeabcdeabcdef"+\
                   "ABCDEFGHIJABCDEFGHIJ\000\005\000\001Hello"
        # test packing
        self.assertEquals(s.pack(), expected)
        self.assertEquals(s.getOverflow(), "")
        self.assertEquals(s.getUnderflowLength(), 256 - 42 - 42 - 5)
        self.assertEquals(s.getOverflowLength(), 0)

        # test unpacking,
        for more in "", "There is more":
            s = parseSubheader(s.pack()+more)
            self.assertEquals(s.major, 3)
            self.assertEquals(s.minor, 0)
            self.assertEquals(s.secret, "abcde"*3+"f")
            self.assertEquals(s.digest, "ABCDEFGHIJ"*2)
            self.assertEquals(s.routingtype, 1)
            self.assertEquals(s.routinglen, 5)
            self.assertEquals(s.routinginfo, "Hello")
            self.assertEquals(s.pack(), expected)
            self.assertEquals(s.underflow, more)
            self.assertEquals(s.getUnderflowLength(), 256-42-42-s.routinglen)

        ts_eliot = ("Who is the third who walks always beside you? / "+
                    "When I count, there are only you and I together / "+
                    "But when I look ahead up the white road / "+
                    "There is always another one walking beside you")

        s = Subheader(3,9,"abcdeabcdeabcdef",
                      "ABCDEFGHIJABCDEFGHIJ",
                      300, ts_eliot, len(ts_eliot))

        self.assertEquals(len(ts_eliot), 186)

        # test extended subeaders
        expected = ("\003\011abcdeabcdeabcdefABCDEFGHIJABCDEFGHIJ"+
                    "\000\272\001\054Who is the third who walks always"+
                    " beside you? / When I count, there are only you and I"+
                    " together / But when I look ahead up the white road /"+
                    " There is always another one walk")
        self.assertEquals(len(expected), mixminion.Packet.MAX_SUBHEADER_LEN)
        self.assertEquals(s.pack(), expected)

        overflow = s.getOverflow()
        self.assertEquals(len(overflow), 14)
        self.assertEquals(overflow, "ing beside you")

        # test parsing extended subheaders
        s = parseSubheader(expected)
        self.assertEquals(s.major, 3)
        self.assertEquals(s.minor, 9)
        self.assertEquals(s.secret, "abcde"*3+"f")
        self.assertEquals(s.digest, "ABCDEFGHIJ"*2)
        self.assertEquals(s.routingtype, 300)
        self.assertEquals(s.routinglen, 186)
        self.assertEquals(s.getOverflowLength(), 14)

        s.appendOverflow("ing beside you")
        self.assertEquals(s.routinginfo, ts_eliot)
        self.assertEquals(s.getExitAddress(), ts_eliot[20:])
        self.assertEquals(s.getTag(), ts_eliot[:20])
        self.assertEquals(s.pack(), expected)

        # Underlong subheaders must fail
        self.failUnlessRaises(ParseError,
                              parseSubheader, "a"*(41))
        # overlong subheaders must fail
        self.failUnlessRaises(ParseError,
                              parseSubheader, "a"*(256))

    def test_message(self):
        # Make sure we can pull the headers and payload of a message apart
        # correctly.
        # (Generate a nice random string to make sure we're slicing right.)
        m = Crypto.prng("HappyFunAESKey!!", 32768)
        msg = parsePacket(m)
        self.assert_(msg.pack() == m)
        self.assert_(msg.header1 == m[:2048])
        self.assert_(msg.header2 == m[2048:4096])
        self.assert_(msg.payload == m[4096:])
        self.failUnlessRaises(ParseError, parsePacket, m[:-1])
        self.failUnlessRaises(ParseError, parsePacket, m+"x")

    def test_ipv4info(self):
        # Check the IPV4Info structure used to hold the addresses for the
        # FWD and SWAP_FWD routing types.
        ri = hexread("12F400BCBBE30011223344556677889900112233445566778899")
        inf = parseIPV4Info(ri)
        self.assertEquals(inf.ip, "18.244.0.188")
        self.assertEquals(inf.port, 48099)
        self.assertEquals(inf.keyinfo, ri[-20:])
        self.assertEquals(len(inf.pack()), 26)
        self.assertEquals(inf.pack(), ri)
        self.assertEquals(IPV4Info("18.244.0.188", 48099, ri[-20:]).pack(),
                          ri)

        self.failUnlessRaises(ParseError, parseIPV4Info, ri[:-1])
        self.failUnlessRaises(ParseError, parseIPV4Info, ri+"x")

    def test_replyblock(self):
        # Try parsing an example 'reply block' object
        key = "\x99"*16
        r = ("SURB\x00\x01"+"\x00\x00\x00\x00"+("Z"*2048)+"\x00\x0A"+"\x00\x01"
             +key+("F"*10))
        rb = parseReplyBlock(r)
        self.assertEquals(rb.timestamp, 0)
        self.assertEquals(rb.header, "Z"*2048)
        self.assertEquals(rb.routingType, 1)
        self.assertEquals(rb.routingInfo, "F"*10)
        self.assertEquals(rb.encryptionKey, key)
        self.assertEquals(r, rb.pack())
        # Now try regenerating it.
        rb = ReplyBlock(header="Z"*2048,useBy=0,rt=1,ri="F"*10,key=key)
        self.assertEquals(r, rb.pack())

        # Now try two blocks.
        r += ("SURB\x00\x01"+"\x00\x00\x00\x00"+("Z"*2048)+"\x00\x0A"+
              "\x00\x01"
             +key+("G"*10))
        rb = parseReplyBlocks(r)
        self.assertEquals(2, len(rb))
        self.assertEquals(rb[0].timestamp, 0)
        self.assertEquals(rb[1].routingInfo, "G"*10)

    def test_payloads(self):
        # Checks for payload structure functions.

        # First, generate some plausible singleton payloads.
        contents = ("payload"*(4*1024))[:28*1024 - 22]
        hash = "HASH"*5
        singleton_payload_1 = "\x00\xff"+hash+contents
        singleton_payload_2 = singleton_payload_1[:-38] #efwd overhead
        # Make sure that parsePayload works as expected.
        p1 = parsePayload(singleton_payload_1)
        p2 = parsePayload(singleton_payload_2)
        self.failUnless(p1.isSingleton() and p2.isSingleton())
        self.assertEquals(p1.size,255)
        self.assertEquals(p2.size,255)
        self.assertEquals(p1.hash,hash)
        self.assertEquals(p2.hash,hash)
        self.assertEquals(p1.data,contents)
        self.assertEquals(p2.data,contents[:-38])
        self.assertEquals(p1.getContents(), contents[:255])
        self.assertEquals(p2.getContents(), contents[:255])
        self.assertEquals(p1.pack(),singleton_payload_1)
        self.assertEquals(p2.pack(),singleton_payload_2)

        # Try SingletonPayload constructor and pack functions
        self.assertEquals(singleton_payload_1,
                          SingletonPayload(255, hash, contents).pack())
        self.assertEquals(singleton_payload_2,
                          SingletonPayload(255, hash, contents[:-38]).pack())

        # Impossible payload lengths
        self.failUnlessRaises(ParseError,parsePayload,singleton_payload_1+"a")
        self.failUnlessRaises(ParseError,parsePayload,singleton_payload_2+"a")
        self.failUnlessRaises(ParseError,parsePayload,singleton_payload_2[:-1])
        # Impossible value for size field
        bad = "\x7fff" + singleton_payload_1[2:]
        self.failUnlessRaises(ParseError,parsePayload,bad)

        ## Now, for the fragment payloads.
        msgID = "This is a message123"
        assert len(msgID) == 20
        contents = contents[:28*1024 - 47]
        frag_payload_1 = "\x80\x00\x02"+hash+msgID+"\x00\x01\x00\x00"+contents
        frag_payload_2 = frag_payload_1[:-38] # efwd overhead
        p1 = parsePayload(frag_payload_1)
        p2 = parsePayload(frag_payload_2)
        self.failUnless(not p1.isSingleton() and not p2.isSingleton())
        self.assertEquals(p1.index,2)
        self.assertEquals(p2.index,2)
        self.assertEquals(p1.hash,hash)
        self.assertEquals(p2.hash,hash)
        self.assertEquals(p1.msgID,msgID)
        self.assertEquals(p2.msgID,msgID)
        self.assertEquals(p1.msgLen,64*1024)
        self.assertEquals(p2.msgLen,64*1024)
        self.assertEquals(p1.data,contents)
        self.assertEquals(p2.data,contents[:-38])
        self.assertEquals(p1.pack(),frag_payload_1)
        self.assertEquals(p2.pack(),frag_payload_2)

        self.assertEquals(frag_payload_1,
                  FragmentPayload(2,hash,msgID,64*1024,contents).pack())
        self.assertEquals(frag_payload_2,
                  FragmentPayload(2,hash,msgID,64*1024,contents[:-38]).pack())

        # Impossible payload lengths
        self.failUnlessRaises(ParseError,parsePayload,frag_payload_1+"a")
        self.failUnlessRaises(ParseError,parsePayload,frag_payload_2+"a")
        self.failUnlessRaises(ParseError,parsePayload,frag_payload_2[:-1])

        # Impossible message sizes
        min_payload_1 = "\x80\x00\x02"+hash+msgID+"\x00\x00\x6F\xD2"+contents
        bad_payload_1 = "\x80\x00\x02"+hash+msgID+"\x00\x00\x6F\xD1"+contents
        min_payload_2 = "\x80\x00\x02"+hash+msgID+"\x00\x00\x6F\xAC"+contents[:-38]
        bad_payload_2 = "\x80\x00\x02"+hash+msgID+"\x00\x00\x6F\xAB"+contents[:-38]
        min_payload_3 = "\x80\x00\x02"+hash+msgID+"\x00\x00\x6F\xD1"+contents[:-38]
        parsePayload(min_payload_1)
        parsePayload(min_payload_2)
        parsePayload(min_payload_3)
        self.failUnlessRaises(ParseError,parsePayload,bad_payload_1)
        self.failUnlessRaises(ParseError,parsePayload,bad_payload_2)

    def testTextEncodedMessage(self):
        tem = TextEncodedMessage
        ptem = parseTextEncodedMessages
        eq = self.assertEquals
        start = "-----BEGIN TYPE III ANONYMOUS MESSAGE-----\n"
        pt = "Message-type: plaintext\n"
        end =   "-----END TYPE III ANONYMOUS MESSAGE-----\n"

        # Test generation: text case
        mt1 = tem("Hello, whirled","TXT")
        eq(mt1.pack(), start+pt+"\nHello, whirled\n"+end)
        mt2 = tem("Hello, whirled\n", "TXT")
        eq(mt2.pack(), start+pt+"\nHello, whirled\n"+end)
        mt3 = tem("Decoding-handle: gotcha!\nFoobar\n", "TXT")
        eq(mt3.pack(), start+pt+"\nDecoding-handle: gotcha!\nFoobar\n"+end)
        # Text generation: binary case
        v = hexread("00D1E50FED1F1CE5")*12
        v64 = encodeBase64(v)
        mb1 = tem(v, "BIN")
        eq(mb1.pack(), start+"""\
Message-type: binary

ANHlD+0fHOUA0eUP7R8c5QDR5Q/tHxzlANHlD+0fHOUA0eUP7R8c5QDR5Q/tHxzl
ANHlD+0fHOUA0eUP7R8c5QDR5Q/tHxzlANHlD+0fHOUA0eUP7R8c5QDR5Q/tHxzl
"""+end)
        eq(mb1.pack(), start+"Message-type: binary\n\n"+v64+end)
        # Overcompressed
        ml1 = tem(v, "LONG")
        eq(ml1.pack(), start+"Message-type: overcompressed\n\n"+v64+end)
        # Encoded
        menc1 = tem(v, "ENC", "9"*20)
        tag64 = base64.encodestring("9"*20).strip()
        eq(menc1.pack(), start+
           "Message-type: encrypted\nDecoding-handle: "+tag64+"\n\n"+v64+end)

        # Test parsing: successful cases
        p = ptem(mt1.pack())[0]
        eq(p.pack(), mt1.pack())
        eq(p.getContents(), "Hello, whirled\n")
        self.assert_(p.isText())
        p = ptem("This message is a test of the emergent broadcast system?\n"
                 +mt2.pack())[0]
        eq(p.pack(), mt2.pack())
        eq(p.getContents(), "Hello, whirled\n")
        # Two concatenated message.
        s = mb1.pack() + "\n\n" + ml1.pack()
        p, p2 = ptem(s)
        eq(p.pack(), mb1.pack())
        self.assert_(p.isBinary())
        eq(p.getContents(), v)
        eq(p2.pack(), ml1.pack())
        self.assert_(p2.isOvercompressed())
        eq(p2.getContents(), v)
        # An encoded message
        p = ptem(menc1.pack())[0]
        eq(p.pack(), menc1.pack())
        eq(p.getContents(), v)
        self.assert_(p.isEncrypted())
        eq(p.getTag(), "9"*20)

    def testHeaders(self):
        emh = encodeMessageHeaders
        eMh = encodeMailHeaders
        pmh = parseMessageAndHeaders
        eq = self.assertEquals

        # Nil headers
        eq(emh({}), "\n")

        # Parse and unparse headers
        encoded = emh({"ABC": "x y zzy", "X": "<42>"}) + "Hello whirled"
        eq(encoded, "ABC:x y zzy\nX:<42>\n\nHello whirled")
        m,h = pmh(encoded)
        eq(m, "Hello whirled")
        eq(h, {"ABC": "x y zzy", "X": "<42>"})

        # Handle leading newlines properly
        encoded = emh({}) + "A short message"
        eq(encoded, "\nA short message")
        eq(("A short message", {}), pmh(encoded))
        eq(("\nA short message", {}), pmh("\n"+encoded))

        # Parse headers with problems.
        try:
            suspendLog()
            m,h = pmh("A message that doesn't start with a header")
            eq(m, "A message that doesn't start with a header")
            eq(h, {})
            # Over-long header gets skipped.
            encoded = "X:"+("Y"*1000)+"\nY:X\n\nZ"
            m,h = pmh(encoded)
            eq(h, {"Y": "X"})
            eq(m, "Z")
        finally:
            resumeLog()

        eq("\n", eMh())
        eq("SUBJECT:foo\n\n", eMh(subject='foo'))
        eq("FROM:fred@bluto\n\n", eMh(fromAddr='fred@bluto'))
        eq("FROM:a\nIN-REPLY-TO:b\nREFERENCES:c\nSUBJECT:d\n\n",
           eMh(fromAddr='a',inReplyTo='b',references='c',subject='d'))
        self.assertRaises(MixError, eMh, fromAddr='fred"')
        self.assertRaises(MixError, eMh, subject=("X"*910))

#----------------------------------------------------------------------
class HashLogTests(TestCase):
    def test_hashlog(self):
        # Create a new,empty hashlog.
        fname = mix_mktemp(".db")

        # (We put the hashlog in a list so that we can pass the list to our
        #  internal helper functions, and change its contents later on.  If
        #  only we could rely on nested scopes (added to Python 2.1), this
        #  would be easier.)
        h = [HashLog(fname, "Xyzzy")]

        notseen=lambda hash,self=self,h=h:self.assert_(not h[0].seenHash(hash))
        seen = lambda hash,self=self,h=h: self.assert_(h[0].seenHash(hash))
        log = lambda hash,h=h: h[0].logHash(hash)

        # Make sure that an empty hash contains nothing, including NUL strings
        # and high-ascii strings.
        notseen("a"*20)
        notseen("\000"*20)
        notseen("\277"*20)
        # Log a value, and make sure that only that value is now in the log
        log("a"*20)
        notseen("\000"*20)
        notseen("b"*20)
        seen("a"*20)

        # Try a second value; make sure both values are now there.
        log("b"*20)
        seen("b"*20)
        seen("a"*20)

        # Try logging a string of NULs
        log("\000"*20)
        seen("\000"*20)
        notseen("\001"*20)
        notseen(("\000"*19)+"\001")
        notseen("\001"+("\000"*19))

        # Try double-logging.
        log("\000"*20)
        seen("\000"*20)

        # Try logging a string of ESCs
        log("\277"*20)
        seen("\277"*20)

        # And a nice plain ascii string
        log("abcde"*4)
        seen("abcde"*4)
        seen("a"*20)
        h[0].sync()
        seen("a"*20)

        # Now reopen the log, and make sure it has all its original contents.
        h[0].close()
        h[0] = HashLog(fname, "Xyzzy")
        seen("a"*20)
        seen("b"*20)
        seen("\277"*20)
        seen("abcde"*4)
        seen("\000"*20)
        # (and no other contents)
        notseen(" "*20)
        notseen("\001"*20)

        # Now add more, close again, and see if our latest adddition went in.
        notseen("ddddd"*4)
        log("ddddd"*4)
        seen("ddddd"*4)

        h[0].sync()
        h[0].close()
        h[0] = HashLog(fname, "Xyzzy")
        seen("ddddd"*4)

        # Make sure that hashlog still works when we sync.
        log("Abcd"*5)
        log("Defg"*5)
        seen("Abcd"*5)
        seen("Defg"*5)
        h[0].sync()
        #   (This violates HashLog's encapsulation, but let's make double-sure
        #    that we've really flushed the journal to disk.)
        self.assertEquals(0, len(h[0].journal))
        seen("Abcd"*5)
        seen("Defg"*5)
        log("Ghij"*5)
        seen("Ghij"*5)

        h[0].close()

#----------------------------------------------------------------------

# Dummy PRNG class that just returns 0-valued bytes.  We use this to make
# generated padding predictable in our BuildMessage tests below.
class FakePRNG:
    def getBytes(self,n):
        return "\x00"*n

class FakeServerInfo:
    """Represents a Mixminion server, and the information needed to send
       messages to it."""
    def __init__(self, addr, port, key, keyid):
        assert key.get_modulus_bytes() == 256
        self.addr = addr
        self.port = port
        self.key = key
        self.keyid = keyid

    def getNickname(self): return "N(%s:%s)"%(self.addr,self.port)
    def getAddr(self): return self.addr
    def getPort(self): return self.port
    def getPacketKey(self): return self.key
    def getKeyID(self): return self.keyid

    def getRoutingInfo(self):
        """Returns a mixminion.Packet.IPV4Info object for routing messages
           to this server."""
        return IPV4Info(self.addr, self.port, self.keyid)

class BuildMessageTests(TestCase):
    def setUp(self):
        self.pk1 = getRSAKey(0,2048)
        self.pk2 = getRSAKey(1,2048)
        self.pk3 = getRSAKey(2,2048)
        self.pk512 = getRSAKey(0,512)
        self.server1 = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        self.server2 = FakeServerInfo("127.0.0.2", 3, self.pk2, "Z"*20)
        self.server3 = FakeServerInfo("127.0.0.3", 5, self.pk3, "Q"*20)

    def test_compression(self):
        # Make sure that our compression helper functions work properly.

        p = AESCounterPRNG()
        longMsg = p.getBytes(100)*2 + str(dir(Crypto))

        # Make sure compression is reversible.
        for m in ("", "a", "\000", "xyzzy"*10, ("glossy glossolalia.."*2)[32],
                  longMsg):
            c = BuildMessage.compressData(m)
            self.assertEquals(m, uncompressData(c))

        self.failUnlessRaises(ParseError, uncompressData, "3")

        for _ in xrange(20):
            for _ in xrange(20):
                m = p.getBytes(p.getInt(1000))
                try:
                    uncompressData(m)
                except ParseError:
                    pass
        #FFFF Find a decent test vector.

    def test_payload_helpers(self):
        "test helpers for payload encoding"
        
        p = AESCounterPRNG()
        for _ in xrange(10):
            t = BuildMessage._getRandomTag(p)
            self.assertEquals(20, len(t))
            self.assertEquals(0, ord(t[0])&0x80)

        b = p.getBytes(28*1024)
        self.assert_(not BuildMessage._checkPayload(b))

        for m in (p.getBytes(3000), p.getBytes(10000), "", "q", "blznerty"):
            for ov in 0, 42-20+16: # encrypted forward overhead
                plds = BuildMessage.encodeMessage(m,ov,"",p)
                assert len(plds) == 1
                pld = plds[0]
                self.assertEquals(28*1024, len(pld)+ov)
                comp = compressData(m)
                self.assertStartsWith(pld[22:], comp)
                self.assertEquals(sha1(pld[22:]),pld[2:22])
                self.assert_(BuildMessage._checkPayload(pld))
                self.assertEquals(len(comp), ord(pld[0])*256+ord(pld[1]))
                self.assertEquals(0, ord(pld[0])&0x80)
                py = mixminion.Packet.parsePayload(pld)
                self.assertEquals(m, py.getUncompressedContents())

        self.failUnlessRaises(MixError, BuildMessage._decodeForwardPayload, b)

        # Check impossibly long messages
        pldSize = "\x7f\xff"+pld[2:] #sha1(pld[22:])+pld[22:]
        self.failUnlessRaises(ParseError,
                              BuildMessage._decodeForwardPayload,pldSize)

    def test_buildheader_1hop(self):
        bhead = BuildMessage._buildHeader

        head = bhead([self.server1], ["9"*16], 99, "Hi mom", AESCounterPRNG())
        self.do_header_test(head,
                            (self.pk1,),
                            ["9"*16,],
                            (99,),
                            ("Hi mom",))

    def test_buildheader_2hops(self):
        bhead = BuildMessage._buildHeader
        # 2 hops
        head = bhead([self.server1, self.server2],
                     ["9"*16, "1"*16], 99, "Hi mom", AESCounterPRNG())

        ipv4 = mixminion.Packet.IPV4Info
        self.do_header_test(head,
                            (self.pk1, self.pk2),
                            ["9"*16, "1"*16],
                            (FWD_TYPE, 99),
                            (ipv4("127.0.0.2",3,"Z"*20).pack(),
                             "Hi mom"))

    def test_buildheader_3hops(self):
        bhead = BuildMessage._buildHeader
        # 3 hops
        secrets = ["9"*16, "1"*16, "z"*16]
        head = bhead([self.server1, self.server2, self.server3], secrets,
                      99, "Hi mom", AESCounterPRNG())
        pks = (self.pk1,self.pk2,self.pk3)
        rtypes = (FWD_TYPE, FWD_TYPE, 99)
        rinfo = (mixminion.Packet.IPV4Info("127.0.0.2", 3, "Z"*20).pack(),
                 mixminion.Packet.IPV4Info("127.0.0.3", 5, "Q"*20).pack(),
                 "Hi mom")
        self.do_header_test(head, pks, secrets, rtypes, rinfo)

    def do_header_test(self, head, pks, secrets, rtypes, rinfo):
        """Unwraps and checks the layers of a single header.
                    head: the header to check
                    pks: sequence of public keys for hops in the path
                    secrets: sequence of master secrets for the subheaders
                    rtypes: sequenece of expected routing types
                    rinfo: sequenece of expected routing info's.

           If secrets is None, takes secrets from the headers without
             checking.

           Returns a tuple of (a list of the secrets encountered,
                               a list of routinginfo strings,
                               the tag from the last routinginfo)
        """
        tag = None
        retsecrets = []
        retinfo = []
        if secrets is None:
            secrets = [None] * len(pks)
        # Is the header the right length?
        self.assertEquals(len(head), mixminion.Packet.HEADER_LEN)
        # Go through the hops one by one, simulating the decoding process.
        for pk, secret, rt, ri in zip(pks, secrets,rtypes,rinfo):
            # Decrypt the first subheader.
            subh = mixminion.Packet.parseSubheader(pk_decrypt(head[:256], pk))
            # If we're expecting a given secret in this subheader, check it.
            if secret:
                self.assertEquals(subh.secret, secret)
            else:
                secret = subh.secret
            retsecrets.append(secret)
            # Check the version, the digest, and the routing type.
            self.assertEquals(subh.major, mixminion.Packet.MAJOR_NO)
            self.assertEquals(subh.minor, mixminion.Packet.MINOR_NO)
            self.assertEquals(subh.digest, sha1(head[256:]))
            self.assertEquals(subh.routingtype, rt)

            # Key to decrypt the rest of the header
            ks = Keyset(secret)
            key = ks.get(HEADER_SECRET_MODE)

            # If we have an exit type, the first 20 bytes of the routinginfo
            # are a decoding tag; extract it.
            if rt < 0x100: # extra bytes for tag
                ext = 0
            else:
                ext = 20
                if ri:
                    tag = subh.routinginfo[:20]

            # Check the routinginfo.  This is a little different for regular
            # and extended subheaders...
            if not subh.getOverflowLength():
                if ri:
                    self.assertEquals(subh.routinginfo[ext:], ri)
                    self.assertEquals(subh.routinglen, len(ri)+ext)
                else:
                    retinfo.append(subh.routinginfo)
                size = 256
            else:
                more = ctr_crypt(head[256:256+subh.getOverflowLength()], key)
                self.assert_(len(ri+more)>
                             mixminion.Packet.MAX_ROUTING_INFO_LEN)
                subh.appendOverflow(more)
                size = 256 + subh.getOverflowLength()
                if ri:
                    self.assertEquals(subh.routinginfo[ext:], ri)
                    self.assertEquals(subh.routinglen, len(ri)+ext)
                else:
                    retinfo.append(subh.routinginfo)

            # Decrypt and pad the rest of the header.
            prngkey = ks.get(RANDOM_JUNK_MODE)
            head = ctr_crypt(head[size:]+
                       prng(prngkey,size-len(subh.underflow)), key, size-256)
            head = subh.underflow + head
            self.assertEquals(len(head), 2048)

        return retsecrets, retinfo, tag

    def test_header_overflow(self):
        bhead = BuildMessage._buildHeader

        secrets = ["9"*16]
        longStr = "Foo"*100
        head = bhead([self.server1], secrets, 99, longStr, AESCounterPRNG())
        pks = (self.pk1,)
        rtypes = (99,)
        rinfo = (longStr,)

        self.do_header_test(head, pks, secrets, rtypes, rinfo)

        # Now try a header with extended **intermediate** routing info.
        # Since this never happens in the wild, we fake it.
        tag = "dref"*5
        longStr2 = "BAR"*100

        def getLongRoutingInfo(longStr2=longStr2,tag=tag):
            return MBOXInfo(tag+longStr2)

        server4 = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        server4.getRoutingInfo = getLongRoutingInfo

        secrets.append("1"*16)
        head = bhead([self.server2, server4], secrets, 99,
                     longStr,
                     AESCounterPRNG())
        pks = (self.pk2,self.pk1)
        rtypes = (FWD_TYPE,99)
        rinfo = (tag+longStr2,longStr)
        self.do_header_test(head, pks, secrets, rtypes, rinfo)

        # Now we make sure that overlong routing info fails.
        self.failUnlessRaises(MixError, bhead,
                              [self.server2, server4], secrets, 99, "Z"*2048,
                              AESCounterPRNG())

    def test_constructmessage(self):
        consMsg = BuildMessage._constructMessage

        h1 = "abcdefgh"*(2048 >> 3)
        h2 = "aBcDeFgH"*(2048 >> 3)

        ######
        ### non-reply case
        secrets1 = [ x * 16 for x in ("s","q","m","s","h")]
        secrets2 = [ x * 16 for x in ("o","s","f","r","g")]
        pld = """
           Everyone has the right to freedom of opinion and expression; this
           right includes freedom to hold opinions without interference and
           to seek, receive and impart information and ideas through any
           media and regardless of frontiers.
           """
        pld += "\000"*(28*1024-len(pld))

        message = consMsg(secrets1, secrets2, h1, h2, pld)

        self.assertEquals(len(message), mixminion.Packet.MESSAGE_LEN)
        msg = mixminion.Packet.parsePacket(message)
        head1, head2, payload = msg.header1, msg.header2, msg.payload
        self.assert_(h1 == head1)

        for path in secrets1, secrets2:
            for s in path:
                ks = Keyset(s)
                hkey = ks.getLionessKeys(HEADER_ENCRYPT_MODE)
                pkey = ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE)
                if path is secrets1:
                    head2 = lioness_decrypt(head2, hkey)
                payload = lioness_decrypt(payload, pkey)

            if path is secrets1:
                swapkey = Crypto.lioness_keys_from_header(head2)
                payload = lioness_decrypt(payload, swapkey)

                swapkey = Crypto.lioness_keys_from_payload(payload)
                head2 = lioness_decrypt(head2, swapkey)

        self.assert_(head2 == h2)
        self.assert_(payload == pld)

        ######
        ### Reply case
        message = consMsg(secrets1, None, h1, h2, pld)
        self.assertEquals(len(message), mixminion.Packet.MESSAGE_LEN)
        msg = mixminion.Packet.parsePacket(message)
        head1, head2, payload = msg.header1, msg.header2, msg.payload
        self.assert_(h1 == head1)

        for s in secrets1:
            ks = Keyset(s)
            hkey = ks.getLionessKeys(HEADER_ENCRYPT_MODE)
            pkey = ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE)
            head2 = lioness_decrypt(head2, hkey)
            payload = lioness_decrypt(payload, pkey)

        swapkey = Crypto.lioness_keys_from_header(head2)
        payload = lioness_decrypt(payload, swapkey)

        swapkey = Crypto.lioness_keys_from_payload(payload)
        head2 = lioness_decrypt(head2, swapkey)

        self.assert_(head2 == h2)
        self.assert_(payload == pld)

    def do_message_test(self, msg,
                        header_info_1,
                        header_info_2,
                        payload, decoder=None):
        """Decrypts the layers of a message one by one, checking them for
           correctness.
                      msg: the message to examine
                      header_info_1: a tuple of (pks,secrets,rtypes,rinfo)
                            as used by do_header_test for the first header.
                      header_info_2: a tuple of (pks,secrets,rtypes,rinfo)
                            as used by do_header_test for the second header.
                      payload: The beginning of the expected decrypted payload.
                      decoder: A function to call on the exit payload before
                            comparing it to 'payload'.  Takes payload,tag;
                            returns string.
           """
        # Check header 1, and get secrets
        sec, _, _ = self.do_header_test(msg[:2048], *header_info_1)
        h2 = msg[2048:4096]
        p = msg[4096:]
        # Do decryption steps for header 1.
        for s in sec:
            ks = Keyset(s)
            p = lioness_decrypt(p,ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))
            h2 = lioness_decrypt(h2,ks.getLionessKeys(HEADER_ENCRYPT_MODE))
        p = lioness_decrypt(p,Crypto.lioness_keys_from_header(h2))
        h2 = lioness_decrypt(h2,Crypto.lioness_keys_from_payload(p))

        sec, _, tag = self.do_header_test(h2, *header_info_2)
        for s in sec:
            ks = Keyset(s)
            p = lioness_decrypt(p,ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))

        if decoder is None:
            p = BuildMessage._decodeForwardPayload(p).getUncompressedContents()
        else:
            p = decoder(p, tag)

        self.assertEquals(payload, p[:len(payload)])

    def test_build_fwd_message(self):
        
        bfm = BuildMessage.buildForwardMessage
        befm = BuildMessage.buildEncryptedForwardMessage
        payload = "Hello!!!!"

        m = bfm(payload, 500, "Goodbye",
                [self.server1, self.server2],
                [self.server3, self.server2])

        self.do_message_test(m,
                             ( (self.pk1, self.pk2), None,
                               (FWD_TYPE, SWAP_FWD_TYPE),
                               (self.server2.getRoutingInfo().pack(),
                                self.server3.getRoutingInfo().pack()) ),
                             ( (self.pk3, self.pk2), None,
                               (FWD_TYPE, 500),
                               (self.server2.getRoutingInfo().pack(),
                                "Goodbye") ),
                             "Hello!!!!")
        m = bfm(payload, 500, "Goodbye", [self.server1], [self.server3])
        
        messages = {}

        def decoder0(p,t,messages=messages):
            messages['fwd'] = (p,t)
            return BuildMessage._decodeForwardPayload(p).getUncompressedContents()

        self.do_message_test(m,
                             ( (self.pk1,), None,
                               (SWAP_FWD_TYPE,),
                               (self.server3.getRoutingInfo().pack(),) ),
                             ( (self.pk3,), None,
                               (500,),
                               ("Goodbye",) ),
                             "Hello!!!!",
                             decoder=decoder0)
        
        # Drop message gets no tag, random payload
        m = bfm(payload, DROP_TYPE, "", [self.server1], [self.server3])

        def decoderDrop(p,t,self=self):
            self.assertEquals(None, t)
            self.failIf(BuildMessage._checkPayload(p))
            return ""

        self.do_message_test(m,
                             ( (self.pk1,), None,
                               (SWAP_FWD_TYPE,),
                               (self.server3.getRoutingInfo().pack(),) ),
                             ( (self.pk3,), None,
                               (DROP_TYPE,),
                               ("",) ),
                             "",
                             decoder=decoderDrop)


        # Encrypted forward message
        rsa1, rsa2 = self.pk1, self.pk512
        payload = "<<<<Hello>>>>" * 100
        for rsakey in rsa1,rsa2:
            m = befm(payload, 500, "Phello",
                     [self.server1, self.server2],
                     [self.server3, self.server2],
                     rsakey)
            def decoder(p,t,key=rsakey,messages=messages):
                messages['efwd'+str(key.get_modulus_bytes())] = (p,t)
                payload = BuildMessage._decodeEncryptedForwardPayload(p,t,key)
                return payload.getUncompressedContents()
            self.do_message_test(m,
                                 ( (self.pk1, self.pk2), None,
                                   (FWD_TYPE, SWAP_FWD_TYPE),
                                   (self.server2.getRoutingInfo().pack(),
                                    self.server3.getRoutingInfo().pack()) ),
                                 ( (self.pk3, self.pk2), None,
                                   (FWD_TYPE, 500),
                                   (self.server2.getRoutingInfo().pack(),
                                    "Phello") ),
                                 payload,
                                 decoder=decoder)
            
        # Now do more tests on final messages: is the format as expected?
        p,t = messages['fwd']
        self.assertEquals(20, len(t))
        self.assertEquals(28*1024,len(p))
        self.assertEquals(0, ord(t[0]) & 0x80)
        comp = compressData("Hello!!!!")
        self.assertEquals(len(comp), ord(p[0])*256 +ord(p[1]))
        self.assertStartsWith(p[22:], comp)
        self.assertEquals(sha1(p[22:]), p[2:22])

        for rsakey in (rsa1, rsa2):
            n = rsakey.get_modulus_bytes()
            p,t = messages['efwd'+str(n)]
            mrsa, mrest = t+p[:n-20], p[n-20:]
            mrsa = pk_decrypt(mrsa, rsakey)
            sessionkey, rsa_rest = mrsa[:16], mrsa[16:]
            ks = Keyset(sessionkey)
            msg = rsa_rest + lioness_decrypt(mrest,
                              ks.getLionessKeys("END-TO-END ENCRYPT"))
            comp = compressData(payload)
            self.assert_(len(comp), ord(msg[0])*256 + ord(msg[1]))
            self.assertEquals(sha1(msg[22:]), msg[2:22])
            self.assertStartsWith(msg[22:], comp)

    def test_buildreply(self):
        brbi = BuildMessage._buildReplyBlockImpl
        brb = BuildMessage.buildReplyBlock
        brm = BuildMessage.buildReplyMessage

        ## Stateful reply blocks.
        reply, secrets_1, tag_1 = \
             brbi([self.server3, self.server1, self.server2,
                  self.server1, self.server3],
                 SMTP_TYPE,
                 "no-such-user@invalid", tag=("+"*20))
        hsecrets = secrets_1[:-1]
        hsecrets.reverse()

        pks_1 = (self.pk3, self.pk1, self.pk2, self.pk1, self.pk3)
        infos = (self.server1.getRoutingInfo().pack(),
                 self.server2.getRoutingInfo().pack(),
                 self.server1.getRoutingInfo().pack(),
                 self.server3.getRoutingInfo().pack())

        self.assert_(reply.routingInfo == self.server3.getRoutingInfo().pack())

        m = brm("Information???",
                [self.server3, self.server1],
                reply)

        messages = {}
        def decoder(p,t,secrets=secrets_1,messages=messages):
            messages['repl'] = p,t
            payload = BuildMessage._decodeReplyPayload(p,secrets)
            return payload.getUncompressedContents()

        self.do_message_test(m,
                             ((self.pk3, self.pk1), None,
                              (FWD_TYPE,SWAP_FWD_TYPE),
                              (self.server1.getRoutingInfo().pack(),
                               self.server3.getRoutingInfo().pack())),
                             (pks_1, hsecrets,
                              (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,SMTP_TYPE),
                              infos+("no-such-user@invalid",)),
                             "Information???",
                             decoder=decoder)
        ## Stateless replies
        reply = brb([self.server3, self.server1, self.server2,
                      self.server1, self.server3], MBOX_TYPE,
                     "fred", "Tyrone Slothrop", 3)

        sec,(loc,), _ = self.do_header_test(reply.header, pks_1, None,
                            (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,MBOX_TYPE),
                            infos+(None,))

        self.assertEquals(loc[20:], "fred")

        # (Test reply block formats)
        self.assertEquals(reply.timestamp, 3)
        self.assertEquals(reply.routingType, SWAP_FWD_TYPE)
        self.assertEquals(reply.routingInfo,
                          self.server3.getRoutingInfo().pack())
        self.assertEquals(reply.pack(),
                          "SURB\x00\x01\x00\x00\x00\x03"+reply.header+
                         "\x00"+chr(len(self.server3.getRoutingInfo().pack()))+
                          "\x00\x02"+reply.encryptionKey+
                          self.server3.getRoutingInfo().pack())
        self.assertEquals(reply.pack(), parseReplyBlock(reply.pack()).pack())
        txt = reply.packAsText()
        self.assertStartsWith(txt,
            "-----BEGIN TYPE III REPLY BLOCK-----\nVersion: 0.2\n\n")
        self.assertEndsWith(txt,
            "-----END TYPE III REPLY BLOCK-----\n")
        parsed = parseTextReplyBlocks(txt)
        self.assertEquals(1, len(parsed))
        self.assertEquals(reply.pack(), parsed[0].pack())
        parsed2 = parseTextReplyBlocks((txt+"   9999 \n")*2)
        self.assertEquals(2, len(parsed2))
        self.assertEquals(reply.pack(), parsed2[1].pack())

        self.assertEquals([], parseTextReplyBlocks("X"))

        # test failing cases for parseTextReplyBlocks
        def fails(s, p=parseTextReplyBlocks, self=self):
            self.assertRaises(ParseError, p, s)

        fails("-----BEGIN TYPE III REPLY BLOCK-----\n"+
              "Version: 0.2\n\n"+
              "xyz\n"+
              "-----END TYPE III REPLY BLOCK-----\n")

        # Test decoding
        seed = loc[:20]
        prng = AESCounterPRNG(sha1(seed+"Tyrone SlothropGenerate")[:16])
        sec.reverse()
        self.assertEquals(sec, [ prng.getBytes(16) for _ in range(len(sec)) ])

        # _Gravity's Rainbow_, page 258.
        payload = '''
              "...Is it any wonder the world's gone insane, with information
            come to the be the only medium of exchange?"
              "I thought it was cigarettes."
              "You dream."
                  -- Gravity's Rainbow, p.258 ''' # " <- for emacs python-mode
        m = brm(payload,
                [self.server3, self.server1],
                reply)

        def decoder2(p,t,messages=messages):
            messages['srepl'] = p,t
            payload = BuildMessage._decodeStatelessReplyPayload(p,t,
                                                         "Tyrone Slothrop")
            return payload.getUncompressedContents()
        
        self.do_message_test(m,
                             ((self.pk3, self.pk1), None,
                              (FWD_TYPE,SWAP_FWD_TYPE),
                              (self.server1.getRoutingInfo().pack(),
                               self.server3.getRoutingInfo().pack())),
                             (pks_1, None,
                              (FWD_TYPE,FWD_TYPE,FWD_TYPE,FWD_TYPE,MBOX_TYPE),
                              infos+("fred",)),
                             payload,
                             decoder=decoder2)

        # Now test format of generated messages.
        p,t = messages['repl']
        self.assertEquals(t, tag_1)
        for s in secrets_1:
            ks = Keyset(s)
            p = lioness_encrypt(p, ks.getLionessKeys(
                               Crypto.PAYLOAD_ENCRYPT_MODE))
        comp = compressData('Information???')
        self.assertEquals(len(comp), ord(p[0])*256 +ord(p[1]))
        self.assertStartsWith(p[22:], comp)
        self.assertEquals(sha1(p[22:]), p[2:22])

        p,t = messages['srepl']
        self.assertEquals('\000', sha1(t+"Tyrone SlothropValidate")[-1])
        prng = AESCounterPRNG(sha1(t+"Tyrone SlothropGenerate")[:16])
        for _ in xrange(6): # 5 hops plus end-to-end
            s = prng.getBytes(16)
            ks = Keyset(s)
            p = lioness_encrypt(p, ks.getLionessKeys(
                                      Crypto.PAYLOAD_ENCRYPT_MODE))
        comp = compressData(payload)
        self.assertEquals(len(comp), ord(p[0])*256 +ord(p[1]))
        self.assertStartsWith(p[22:], comp)
        self.assertEquals(sha1(p[22:]), p[2:22])

    def assertPayloadDecodesTo(self, decoded, encoded, tag, key, userKeys):
        p = BuildMessage.decodePayload(encoded, tag, key, userKeys)
        if p is None:
            self.assertEquals(decoded, p)
        else:
            self.assertEquals(decoded, p.getUncompressedContents())

    def test_decoding(self):
        # Now we create a bunch of fake payloads and try to decode them.

        # Successful messages:
        payload = "All dreamers and sleepwalkers must pay the price, and "+\
          "even the invisible victim is responsible for the fate of all.\n"+\
          "   -- _Invisible Man_"

        comp = compressData(payload)
        self.assertEquals(len(comp), 109)
        encoded1 = (comp+ "RWE/HGW"*4096)[:28*1024-22]
        encoded1 = '\x00\x6D'+sha1(encoded1)+encoded1

        # Forward message.
        self.assertEquals(payload,
                          BuildMessage._decodeForwardPayload(encoded1).getUncompressedContents())
        # Encoded forward message
        efwd = (comp+"RWE/HGW"*4096)[:28*1024-22-38]
        efwd = '\x00\x6D'+sha1(efwd)+efwd
        rsa1 = getRSAKey(0,1024)
        key1 = Keyset("RWE "*4).getLionessKeys("END-TO-END ENCRYPT")
        efwd_rsa = pk_encrypt(("RWE "*4)+efwd[:70], rsa1)
        efwd_lioness = lioness_encrypt(efwd[70:], key1)
        efwd_t = efwd_rsa[:20]
        efwd_p = efwd_rsa[20:]+efwd_lioness
        self.assertEquals(payload,
             BuildMessage._decodeEncryptedForwardPayload(efwd_p,efwd_t,rsa1).getUncompressedContents())

##      # Stateful reply
##      secrets = [ "Is that you, Des","troyer?Rinehart?" ]
##      sdict = { 'tag1'*5 : secrets }
##      ks = Keyset(secrets[1])
##      m = lioness_decrypt(encoded1, ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))
##      ks = Keyset(secrets[0])
##      m = lioness_decrypt(m, ks.getLionessKeys(PAYLOAD_ENCRYPT_MODE))
##      self.assertEquals(payload, BuildMessage._decodeReplyPayload(m,secrets))
##      repl1 = m

        # Stateless reply
        tag = "To light my way out\xBE"
        passwd = "out I would have to burn every paper in the briefcase"
        self.assertEquals('\000', sha1(tag+passwd+"Validate")[-1])
        prng = AESCounterPRNG(sha1(tag+passwd+"Generate")[:16])
        secrets2 = [ prng.getBytes(16) for _ in xrange(5) ]
        m = encoded1
        s = secrets2[:]
        s.reverse()
        for k in s:
            key = Keyset(k).getLionessKeys(PAYLOAD_ENCRYPT_MODE)
            m = lioness_decrypt(m,key)
        self.assertEquals(payload,
                     BuildMessage._decodeStatelessReplyPayload(m,tag,passwd).getUncompressedContents())
        repl2, repl2tag = m, tag

        # Okay, now let's try out 'decodePayload' (and thereby test its
        # children).  First, we test all the cases that succeed; or that
        # fail and return None to indicate that another key might decrypt
        # the message.
        decodePayload = BuildMessage.decodePayload
        # fwd
        for pk in (self.pk1, None):
            ##for d in (sdict, None): # stateful replies disabled.
                for p in (passwd, None):
                    for tag in ("zzzz"*5, "pzzz"*5):
                        self.assertPayloadDecodesTo(payload,
                                                    encoded1, tag, pk, p)

        # efwd
        ##for d in (sdict, None): # stateful replies disabled
        if 1:
            for p in (passwd, None):
                self.assertPayloadDecodesTo(payload, efwd_p, efwd_t, rsa1, p)
                self.assertPayloadDecodesTo(None, efwd_p, efwd_t, None, p)
                self.assertPayloadDecodesTo(None, efwd_p, efwd_t, self.pk2, p)

        # Stateful replies are disabled.

        # repl (stateless)
        for pk in (self.pk1, None):
            #for sd in (sdict, None): #Stateful replies are disabled
                self.assertPayloadDecodesTo(payload,
                                            repl2, repl2tag, pk, passwd)
                try:
                    suspendLog("INFO")
                    self.assertPayloadDecodesTo(payload, repl2, repl2tag, pk,
                                     userKeys={ "Fred": passwd, "": "z"*20 })
                finally:
                    s = resumeLog()
                self.assert_(stringContains(s,
                               "Decoded reply message to identity 'Fred'"))
                self.assertPayloadDecodesTo(None,
                                            repl2, repl2tag, pk, "Bliznerty")
                self.assertPayloadDecodesTo(None, repl2, repl2tag, pk,
                                   userKeys={ "Fred":"Bliznerty", "":"z"*20})
                self.assertPayloadDecodesTo(None, repl2, repl2tag, pk, None)

        # Try decoding a payload that looks like a zlib bomb.  An easy way to
        # get such a payload is to compress 25K of zeroes.
        nils = "\x00"*(25*1024)
        overcompressed_payload = \
             BuildMessage.encodeMessage(nils, 0)[0]
        p = BuildMessage.decodePayload(overcompressed_payload, "X"*20)
        self.failUnlessRaises(CompressedDataTooLong,
                              p.getUncompressedContents)

        # And now the cases that fail hard.  This can only happen on:
        #   1) *: Hash checks out, but zlib or size is wrong.  Already tested.
        #   2) EFWD: OAEP checks out, but hash is wrong.
        #   3) <omitted; stateful replies are gone>
        #   4) SREPLY: ---.

        # Bad efwd
        efwd_pbad = efwd_p[:-1] + chr(ord(efwd_p[-1])^0xaa)
        self.failUnlessRaises(MixError,
                              BuildMessage._decodeEncryptedForwardPayload,
                              efwd_pbad, efwd_t, rsa1)

        for p in (passwd, None):
            self.failUnlessRaises(MixError, decodePayload,
                                  efwd_pbad, efwd_t, rsa1, p)
            self.assertPayloadDecodesTo(None, efwd_pbad, efwd_t, self.pk2, p)

        # Bad repl
        repl2_bad = repl2[:-1] + chr(ord(repl2[-1])^0xaa)
        self.assertPayloadDecodesTo(None, repl2_bad, repl2tag, None, passwd)

#----------------------------------------------------------------------
# Having tested BuildMessage without using PacketHandler, we can now use
# BuildMessage to see whether PacketHandler is doing the right thing.
#
# (of course, we still need to build failing messages by hand)

class PacketHandlerTests(TestCase):
    def setUp(self):
        self.pk1 = getRSAKey(0,2048)
        self.pk2 = getRSAKey(1,2048)
        self.pk3 = getRSAKey(2,2048)
        self.tmpfile = mix_mktemp(".db")
        h = self.hlog = HashLog(self.tmpfile, "Z"*20)

        self.server1 = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        self.server2 = FakeServerInfo("127.0.0.2", 3, self.pk2, "Z"*20)
        self.server3 = FakeServerInfo("127.0.0.3", 5, self.pk3, "Q"*20)
        self.sp1 = PacketHandler([self.pk1], [h])
        self.sp2 = PacketHandler([self.pk2], [h])
        self.sp3 = PacketHandler([self.pk3], [h])
        self.sp2_3 = PacketHandler((self.pk2,self.pk3), (h,h))

    def tearDown(self):
        self.hlog.close()

    def do_test_chain(self, m, sps, routingtypes, routinginfo, payload,
                      appkey=None):
        """Routes a message through a series of servers, making sure that
           each one decrypts it properly and routes it correctly to the
           next.
                    m: the message to test
                    sps: sequence of PacketHandler objects for m's path
                    routingtypes: sequence of expected routingtype
                    routinginfo: sequence of expected routinginfo, excl tags
                    payload: beginning of expected final payload."""
        for sp, rt, ri in zip(sps,routingtypes,routinginfo):
            res = sp.processMessage(m)
            self.assert_(isinstance(res, DeliveryPacket) or
                         isinstance(res, RelayedPacket))
            if rt in (FWD_TYPE, SWAP_FWD_TYPE):
                self.assert_(not res.isDelivery())
                self.assertEquals(res.getAddress().pack(), ri)
                m = res.getPacket()
            else:
                self.assert_(res.isDelivery())
                self.assertEquals(res.getExitType(), rt)
                self.assertEquals(res.getAddress(), ri)
                if appkey:
                    self.assertEquals(res.getApplicationKey(), appkey)

                self.assertStartsWith(res.getContents(), payload)
                break
        return res

    def test_successful(self):
        bfm = BuildMessage.buildForwardMessage
        # A two-hop/one-hop message.
        p = "Now is the time for all good men to come to the aid"
        m = bfm("\n"+p, SMTP_TYPE, "nobody@invalid",
                [self.server1, self.server2], [self.server3])

        self.do_test_chain(m,
                           [self.sp1,self.sp2,self.sp3],
                           [FWD_TYPE, FWD_TYPE, SMTP_TYPE],
                           [self.server2.getRoutingInfo().pack(),
                            self.server3.getRoutingInfo().pack(),
                            "nobody@invalid"],
                           p)

        # A one-hop/one-hop message.
        m = bfm("\n"+p,
                SMTP_TYPE, "nobody@invalid", [self.server1], [self.server3])

        self.do_test_chain(m,
                           [self.sp1,self.sp3],
                           [FWD_TYPE, SMTP_TYPE],
                           [self.server3.getRoutingInfo().pack(),
                            "nobody@invalid"],
                           p)

        # Try servers with multiple keys
        m = bfm("\n"+p,
                SMTP_TYPE, "nobody@invalid", [self.server2], [self.server3])
        self.do_test_chain(m, [self.sp2_3, self.sp2_3], [FWD_TYPE, SMTP_TYPE],
                           [self.server3.getRoutingInfo().pack(),
                            "nobody@invalid"], p)

        # A 3/3 message with a long exit header.
        for i in (100,300):
            longemail = "f"*i+"@invalid"
            m = bfm("\n"+p, SMTP_TYPE, longemail,
                    [self.server1, self.server2, self.server1],
                    [self.server3, self.server1, self.server2])

            self.do_test_chain(m,
                               [self.sp1,self.sp2,self.sp1,
                                self.sp3,self.sp1,self.sp2],
                               [FWD_TYPE,FWD_TYPE,FWD_TYPE,
                                FWD_TYPE,FWD_TYPE,SMTP_TYPE],
                               [self.server2.getRoutingInfo().pack(),
                                self.server1.getRoutingInfo().pack(),
                                self.server3.getRoutingInfo().pack(),
                                self.server1.getRoutingInfo().pack(),
                                self.server2.getRoutingInfo().pack(),
                                longemail],
                               p)

    def test_deliverypacket(self):
        # Test out DeliveryPacket.*: with a plaintext ascii packet.
        bfm = BuildMessage.buildForwardMessage
        befm = BuildMessage.buildEncryptedForwardMessage

        h = "SUBJECT:cooper\n\n"
        p = "That gum you like, it's coming back in style."
        m = bfm(h+p, SMTP_TYPE, "nobody@invalid", [self.server1],
                [self.server3])

        pkt = self.do_test_chain(m,
                                 [self.sp1,self.sp3],
                                 [FWD_TYPE, SMTP_TYPE],
                                 [self.server3.getRoutingInfo().pack(),
                                  "nobody@invalid"],
                                 p)

        self.assertEquals(SMTP_TYPE, pkt.getExitType())
        self.assertEquals("nobody@invalid", pkt.getAddress())
        self.assertEquals(20, len(pkt.getTag()))
        self.assertEquals(p, pkt.getContents())
        self.assert_(pkt.isDelivery())
        self.assert_(pkt.isPlaintext())
        self.failIf(pkt.isOvercompressed())
        self.assert_(pkt.isPrintingAscii())
        self.failIf(pkt.isError())
        self.assertEquals(p, pkt.getAsciiContents())
        self.assertEquals(base64.encodestring(pkt.getTag()).strip(),
                          pkt.getAsciiTag())
        self.assertEquals({"SUBJECT":"cooper"}, pkt.getHeaders())
        # with a plaintext, nonascii packet.
        pbin = hexread("0123456789ABCDEFFEDCBA9876543210")
        m = bfm("\n"+pbin, SMTP_TYPE, "nobody@invalid",
                [self.server1], [self.server3])
        pkt = self.do_test_chain(m,
                                 [self.sp1,self.sp3],
                                 [FWD_TYPE, SMTP_TYPE],
                                 [self.server3.getRoutingInfo().pack(),
                                  "nobody@invalid"],
                                 pbin)
        self.assertEquals(pbin, pkt.getContents())
        self.assert_(pkt.isPlaintext())
        self.failIf(pkt.isPrintingAscii())
        self.assertEquals(encodeBase64(pkt.getContents()),
                          pkt.getAsciiContents())
        # with an overcompressed content
        pcomp = "          "*4096
        #      (forward, overcompressed)
        m = bfm(pcomp, SMTP_TYPE, "nobody@invalid",
                [self.server1], [self.server3])
        pkt = self.do_test_chain(m,
                                 [self.sp1,self.sp3],
                                 [FWD_TYPE, SMTP_TYPE],
                                 [self.server3.getRoutingInfo().pack(),
                                  "nobody@invalid"],
                                 "")
        self.assert_(not pkt.isPlaintext())
        self.assert_(pkt.isOvercompressed())
        self.assert_(pkt.getAsciiContents(),
             encodeBase64(compressData(pcomp)))

        #      (enc-forward, overcompressed)
        m = befm(p, SMTP_TYPE, "nobody@invalid", [self.server1],
                 [self.server3], getRSAKey(0,1024))
        pkt = self.do_test_chain(m,
                                 [self.sp1,self.sp3],
                                 [FWD_TYPE, SMTP_TYPE],
                                 [self.server3.getRoutingInfo().pack(),
                                  "nobody@invalid"],
                                 "")
        self.assert_(pkt.isEncrypted())
        self.assert_(not pkt.isPrintingAscii())
        self.assertEquals(len(pkt.getContents()), 28*1024)
        self.assertEquals(encodeBase64(pkt.getContents()),
                          pkt.getAsciiContents())

        # Header features
        #
        #    (ASCII msg with headers)
        h = {"FROM":'fred@foo', "SUBJECT":'Stuff'}
        p = encodeMessageHeaders(h) + "This is the message.\n"
        m = bfm(p, SMTP_TYPE, "nobody@invalid",[self.server1], [self.server3])
        pkt = self.do_test_chain(m, 
                                 [self.sp1, self.sp3],
                                 [FWD_TYPE, SMTP_TYPE],
                                 [self.server3.getRoutingInfo().pack(),
                                  "nobody@invalid"],
                                 "")
        self.assert_(pkt.isPrintingAscii())
        self.assert_(not pkt.isEncrypted())
        self.assertEquals(pkt.getContents(), "This is the message.\n")
        self.assertEquals(pkt.getHeaders(), h)
        
        #    (binary msg with headers.)
        body = "\x01\x02\x03\x04"*10
        p = encodeMessageHeaders(h) + body
        m = bfm(p, SMTP_TYPE, "nobody@invalid",[self.server1], [self.server3])
        pkt = self.do_test_chain(m, 
                                 [self.sp1, self.sp3],
                                 [FWD_TYPE, SMTP_TYPE],
                                 [self.server3.getRoutingInfo().pack(),
                                  "nobody@invalid"],
                                 "")
        self.assert_(not pkt.isPrintingAscii())
        self.assert_(not pkt.isEncrypted())
        self.assertEquals(pkt.getContents(), body)
        self.assertEquals(pkt.getHeaders(), h)


    def test_rejected(self):
        bfm = BuildMessage.buildForwardMessage
        brm = BuildMessage.buildReplyMessage
        brbi = BuildMessage._buildReplyBlockImpl

        # A long intermediate header needs to fail.
        server1X = FakeServerInfo("127.0.0.1", 1, self.pk1, "X"*20)
        class _packable:
            def pack(self): return "x"*200
        server1X.getRoutingInfo = lambda _packable=_packable: _packable()

        m = bfm("Z", MBOX_TYPE, "hello\000bye",
                [self.server2, server1X, self.server3],
                [server1X, self.server2, self.server3])
        self.failUnlessRaises(ParseError, self.sp2.processMessage, m)

        # Duplicate messages need to fail.
        m = bfm("Z", SMTP_TYPE, "nobody@invalid",
                [self.server1, self.server2], [self.server3])
        self.sp1.processMessage(m)
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m)

        # Duplicate reply blocks need to fail
        reply,s,tag = brbi([self.server3], SMTP_TYPE, "fred@invalid")
        m = brm("Y", [self.server2], reply)
        m2 = brm("Y", [self.server1], reply)
        m = self.sp2.processMessage(m).getPacket()
        self.sp3.processMessage(m)
        m2 = self.sp1.processMessage(m2).getPacket()
        self.failUnlessRaises(ContentError, self.sp3.processMessage, m2)

        # Even duplicate secrets need to go.
        prng = AESCounterPRNG(" "*16)
        reply1,s,t = brbi([self.server1], SMTP_TYPE, "fred@invalid",0,prng)
        prng = AESCounterPRNG(" "*16)
        reply2,s,t = brbi([self.server2], MBOX_TYPE, "foo",0,prng)
        m = brm("Y", [self.server3], reply1)
        m2 = brm("Y", [self.server3], reply2)
        m = self.sp3.processMessage(m).getPacket()
        self.sp1.processMessage(m)
        m2 = self.sp3.processMessage(m2).getPacket()
        self.failUnlessRaises(ContentError, self.sp2.processMessage, m2)

        # Drop gets dropped.
        m = bfm("Z", DROP_TYPE, "", [self.server2], [self.server2])
        m = self.sp2.processMessage(m).getPacket()
        res = self.sp2.processMessage(m)
        self.assertEquals(res,None)

        # Wrong server.
        m = bfm("Z", DROP_TYPE, "", [self.server1], [self.server2])
        self.failUnlessRaises(CryptoError, self.sp2.processMessage, m)
        self.failUnlessRaises(CryptoError, self.sp2_3.processMessage, m)

        # Plain junk in header
        m_x = ("XY"*64)+m[128:]
        self.failUnlessRaises(CryptoError, self.sp1.processMessage, m_x)

        # Bad message length
        m_x = m+"Z"
        self.failUnlessRaises(ParseError, self.sp1.processMessage, m_x)

        # Bad internal type
        try:
            # (We temporarily override the setting from 'BuildMessage',
            #  not Packet; BuildMessage has already imported a copy of this
            #  constant.)
            save = mixminion.BuildMessage.SWAP_FWD_TYPE
            mixminion.BuildMessage.SWAP_FWD_TYPE = 50
            m_x = bfm("Z", 500, "", [self.server1], [self.server2])
        finally:
            mixminion.BuildMessage.SWAP_FWD_TYPE = save
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Subhead we can't parse
        m_x = pk_encrypt("foo", self.pk1)+m[256:]
        self.failUnlessRaises(ParseError, self.sp1.processMessage, m_x)

        # Bad IPV4 info
        subh_real = pk_decrypt(m[:256], self.pk1)
        subh = parseSubheader(subh_real)
        subh.setRoutingInfo(subh.routinginfo + "X")
        m_x = pk_encrypt(subh.pack()+subh.underflow[:-1], self.pk1)+m[256:]
        self.failUnlessRaises(ParseError, self.sp1.processMessage, m_x)

        # Bad Major or Minor
        subh = parseSubheader(subh_real)
        subh.major = 255
        m_x = pk_encrypt(subh.pack()+subh.underflow, self.pk1)+m[256:]
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Bad digest
        subh = parseSubheader(subh_real)
        subh.digest = " "*20
        m_x = pk_encrypt(subh.pack()+subh.underflow, self.pk1)+m[256:]
        self.failUnlessRaises(ContentError, self.sp1.processMessage, m_x)

        # Corrupt payload
        m = bfm("Z", MBOX_TYPE, "Z", [self.server1, self.server2],
                [self.server3])
        m_x = m[:-30] + " "*30
        assert len(m_x) == len(m)
        m_x = self.sp1.processMessage(m_x).getPacket()
        m_x = self.sp2.processMessage(m_x).getPacket()
        self.failUnlessRaises(CryptoError, self.sp3.processMessage, m_x)

#----------------------------------------------------------------------
# FILESTORE and QUEUE

class TestDeliveryQueue(DeliveryQueue):
    def __init__(self,d,now=None):
        DeliveryQueue.__init__(self,d,now=now)
        self._msgs = None
    def sendReadyMessages(self, *x, **y):
        self._msgs = None
        DeliveryQueue.sendReadyMessages(self, *x,**y)
    def _deliverMessages(self, msgList):
        self._msgs = msgList

class FStoreTestBase(TestCase):
    def unlink(self, fns):
        for f in fns:
            os.unlink(f)

class FilestoreTests(FStoreTestBase):
    def setUp(self):
        mixminion.Common.installSIGCHLDHandler()
        self.d1 = mix_mktemp("q1")
        self.d2 = mix_mktemp("q2")
        self.d3 = mix_mktemp("q3")
    def testCreateStore(self):
        Store = mixminion.Filestore.MixedStore
        
        # Nonexistent dir.
        self.failUnlessRaises(MixFatalError, Store, self.d1)
        # File in place of dir
        writeFile(self.d1, "   ")
        self.failUnlessRaises(MixFatalError, Store, self.d1)
        self.failUnlessRaises(MixFatalError, Store, self.d1, create=1)
        os.unlink(self.d1)

        # Try to create
        queue = Store(self.d1, create=1)
        self.failUnless(os.path.isdir(self.d1))
        if not ON_WINDOWS:
            self.assertEquals(0700, os.stat(self.d1)[stat.ST_MODE] & 0777)
        self.assertEquals(0, len(os.listdir(self.d1)))
        queue.queueMessage("Hello world 1")
        h2 = queue.queueMessage("Hello world 2")
        self.assertEquals(2, len(os.listdir(self.d1)))
        self.assertEquals(2, queue.count())

        # Make sure recreate doesn't bonk
        queue = Store(self.d1, create=1)

        # Use a queue we haven't just made.
        queue = Store(self.d1)
        self.assertEquals(2, queue.count())
        self.assertEquals(queue.messageContents(h2), "Hello world 2")
        queue.removeMessage(h2)
        self.assertEquals(1, queue.count())

        queue.removeAll(self.unlink)

    def testStoreOps(self):
        Store = mixminion.Filestore.MixedStore
        
        queue1 = Store(self.d2, create=1)
        queue2 = Store(self.d3, create=1)

        # Put 100 messages in queue1
        handles = [queue1.queueMessage("Sample message %s" % i)
                   for i in range(100)]
        hdict = {}
        for i in range(100): hdict[handles[i]] = i
        # Make sure that queue1 has all 100 elements
        self.assertEquals(queue1.count(), 100)
        self.assertEquals(len(handles), 100)

        # Get the messages in random order, and make sure the contents
        # of each one are correct
        foundHandles = queue1.pickRandom(100)
        self.assertEquals(len(foundHandles), 100)
        for h in foundHandles:
            self.failUnless(hdict.has_key(h))
            i = hdict[h]
            self.assertEquals("Sample message %s" %i,
                              queue1.messageContents(h))

        assert len(hdict) == len(handles) == 100

        # Move the first 30 messages to queue2
        q2h = []
        for h in handles[:30]:
            nh = queue2.queueMessage(queue1.messageContents(h))
            queue1.removeMessage(h)
            q2h.append(nh)

        # Look at the messages in queue2, 15 then 30 at a time.
        for group in queue2.pickRandom(15), queue2.pickRandom(30):
            seen = {}
            for h in group:
                c = queue2.messageContents(h)
                self.assertStartsWith(c, "Sample message ")
                i = atoi(c[15:])
                self.failIf(seen.has_key(i))
                seen[i]=1

        # Make sure that we got all 30 messages
        for i in range(30):
            self.failUnless(seen.has_key(i))

        # Remove messages 30..59 from queue1.
        for h in handles[30:60]:
            queue1.removeMessage(h)
        self.assertEquals(40, queue1.count())

        # Make sure that smaller pickRandoms work.
        L1 = queue1.pickRandom(10)
        L2 = queue1.pickRandom(10)
        self.failUnless(len(L1) == 10)
        self.failUnless(len(L2) == 10)
        self.failUnless(L1 != L2)

        # Test 'openMessage'
        f = queue1.openMessage(handles[60])
        s = f.read()
        f.close()
        self.assertEquals(s, "Sample message 60")

        # test successful 'openNewMessage'
        f, h = queue1.openNewMessage()
        f.write("z"*100)
        self.failUnlessRaises(IOError, queue1.messageContents, h)
        self.assertEquals(queue1.count(), 40)
        queue1.finishMessage(f,h)
        self.assertEquals(queue1.messageContents(h), "z"*100)
        self.assertEquals(queue1.count(), 41)

        # test aborted 'openNewMessage'
        f, h = queue1.openNewMessage()
        f.write("z"*100)
        queue1.abortMessage(f,h)
        self.failUnlessRaises(IOError, queue1.messageContents, h)
        self.assertEquals(queue1.count(), 41)
        self.assert_(not os.path.exists(os.path.join(self.d2, "msg_"+h)))

        # Test object functionality
        obj = [ ("A pair of strings", "in a tuple in a list") ]
        h1 = queue1.queueObject(obj)
        h2 = queue1.queueObject(6060842)
        self.assertEquals(obj, queue1.getObject(h1))
        self.assertEquals(6060842, queue1.getObject(h2))
        self.assertEquals(obj, cPickle.loads(queue1.messageContents(h1)))

        # Scrub both queues.
        queue1.removeAll(self.unlink)
        queue2.removeAll(self.unlink)
        queue1.cleanQueue(self.unlink)
        queue2.cleanQueue(self.unlink)

    def testMetadataStores(self):
        d_d = mix_mktemp("q_md")
        Store = mixminion.Filestore.StringMetadataStore

        queue = Store(d_d, create=1)
        h1 = queue.queueMessageAndMetadata("abc", [2,3])
        self.assertEquals(readPickled(os.path.join(d_d, "meta_"+h1)), [2,3])
        self.assertEquals(queue.getMetadata(h1), [2,3])
        h2 = queue.queueMessageAndMetadata("def", [5,6])
        h3 = queue.queueMessageAndMetadata("ghi", None)
        self.assertEquals(queue._metadata_cache, { h1 : [2,3], h2 : [5,6],
                                                   h3 : None })
        os.unlink(os.path.join(d_d, "meta_"+h3))
        queue = Store(d_d, create=0)
        self.assertEquals(queue.getMetadata(h2), [5,6])
        self.assertEquals(queue._metadata_cache, { h2 : [5,6] })
        try:
            suspendLog()
            queue.loadAllMetadata(lambda h: h)
        finally:
            s = resumeLog()
        self.assertEndsWith(s, "Missing metadata for file %s\n"%h3)
        self.assertEquals(queue._metadata_cache, { h1 : [2,3], h2 : [5,6],
                                                   h3: h3})
        self.assertEquals(readPickled(os.path.join(d_d, "meta_"+h3)), h3)
        queue.removeMessage(h2)
        self.assertEquals(queue._metadata_cache, { h1 : [2,3], h3: h3 })
        self.assert_(os.path.exists(os.path.join(d_d, "rmvm_"+h2)))
        self.assert_(os.path.exists(os.path.join(d_d, "rmv_"+h2)))
        queue.cleanQueue()
        self.assert_(not os.path.exists(os.path.join(d_d, "rmvm_"+h2)))
        self.assert_(not os.path.exists(os.path.join(d_d, "rmv_"+h2)))

    def testDBWrappers(self):
        d_parent = mix_mktemp("db")
        loc = os.path.join(d_parent, "db0")
        # Test unjournaled DB.
        class NumDB(mixminion.Filestore.DBBase):
            def __init__(self,loc):
                mixminion.Filestore.DBBase.__init__(self, loc, "numbers")
            def _encodeKey(self,k):
                return str(k)
            def _decodeKey(self,k):
                return int(k)
            def _encodeVal(self,v):
                return v.upper()
            def _decodeVal(self,v):
                return v.lower()
        db0 = NumDB(loc)
        db0[3] = 'three'
        db0[99] = 'Ninety-nine'
        self.assertEquals(db0[3], 'three')
        self.assertEquals(db0[99], 'ninety-nine')
        self.assertRaises(KeyError, lambda db0=db0:db0[10])
        self.assertRaises(KeyError, lambda db0=db0:db0["10"])
        self.assertEquals(db0.log["3"], 'THREE')
        db0[3] = 'iii'
        self.assertEquals(db0.log["3"], 'III')
        self.assertEquals(db0["3"], 'iii')
        self.assertEquals(db0.get(10), None)
        self.assertEquals(db0.get(10, "hi"), "hi")
        self.assert_(db0.has_key(3))
        self.assert_(not db0.has_key(" 3"))
        self.assert_(not db0.has_key("10"))
        db0[6]='six'
        del db0[6]
        self.assert_(not db0.has_key(6))
        self.assert_(not db0.log.has_key("6"))
        self.assertRaises(KeyError, lambda db0=db0:db0[6])
        self.assertUnorderedEq([3, 99], db0.keys())
        db0.close()
        db0 = NumDB(loc)
        self.assertUnorderedEq([3, 99], db0.keys())
        self.assert_(not db0.has_key(6))
        self.assertEquals(db0["3"], 'iii')
        db0.sync()
        db0[3] = 'three'
        db0.close()

        for fn in os.listdir(d_parent):
            self.assertStartsWith(fn, "db0")
            os.unlink(os.path.join(d_parent,fn))
        
        # Test journaled DB.
        loc = os.path.join(d_parent, "db1")
        jloc = loc+"_jrnl"
        class JNumDB(mixminion.Filestore.JournaledDBBase):
            def __init__(self,loc):
                mixminion.Filestore.JournaledDBBase.__init__(
                    self, loc, "numbers", 5, 20, None)
            def _encodeKey(self,k): return str(k)
            def _decodeKey(self,k): return int(k)
            def _encodeVal(self,v): return v
            def _decodeVal(self,v): return v
            def _jEncodeKey(self,k): return "%05d"%k
            def _jDecodeKey(self,k): return int(k)
            def _jEncodeVal(self,v): return "%20s"%v
            def _jDecodeVal(self,v): return v.strip()

        db1 = JNumDB(loc)
        db1[3] = "three"
        db1[10] = "ten"
        db1[8] = "eight"
        self.assertEquals(readFile(jloc),
                          "00003               three"
                          "00010                 ten"
                          "00008               eight")
        self.assertUnorderedEq(db1.log.keys(), [])
        self.assertUnorderedEq(db1.keys(), [10, 3, 8])
        self.assertEquals(db1[3], "three")
        self.assertEquals(db1[10], "ten")
        self.assertEquals(db1[8], "eight")
        self.assertRaises(KeyError, lambda db1=db1:db1[7])
        self.assert_(db1.has_key(8))
        self.assert_(not db1.has_key(5))
        db1.close()
        db1 = JNumDB(loc)
        self.assertUnorderedEq(db1.log.keys(), ['10', '3', '8'])
        self.assertUnorderedEq(db1.keys(), [10, 3, 8])
        self.assertUnorderedEq(db1.journal.keys(), [])
        self.assertEquals(readFile(jloc), "")
        self.assertEquals(db1[3], "three")
        self.assertEquals(db1[10], "ten")
        self.assertEquals(db1[8], "eight")
        self.assertRaises(KeyError, lambda db1=db1:db1[7])
        self.assert_(db1.has_key(8))
        self.assert_(not db1.has_key(5))
        db1[9] = "nine"
        self.assertEquals(readFile(jloc),
                          "00009                nine")
        self.assertEquals(db1[9], "nine")
        db1.sync()
        self.assertEquals(db1[9], "nine")
        self.assertEquals(db1[10], "ten")
        db1.close()
        for fn in os.listdir(d_parent):
            self.assertStartsWith(fn, "db1")
            os.unlink(os.path.join(d_parent,fn))

        # Test journaled value-less DB
        loc = os.path.join(d_parent, "db2")
        jloc = loc+"_jrnl"
        db2 = mixminion.Filestore.BooleanJournaledDBBase(loc, "numbers", 2)
        db2["02"] = 1
        db2["03"] = 1
        db2["05"] = 1
        db2["07"] = 1
        db2["11"] = 1
        db2["13"] = 1
        self.assertEquals(1, db2["02"])
        self.assertEquals(readFile(jloc), "020305071113")
        db2.close()
        db2 = mixminion.Filestore.BooleanJournaledDBBase(loc, "numbers", 2)
        self.assertEquals(readFile(jloc), "")
        self.assertEquals(1, db2["13"])
        self.assert_(db2.has_key("07"))
        self.assert_(not db2.has_key("08"))
        db2.close()

        # Test migration from unjournaled to journaled.
        loc = os.path.join(d_parent, "db3")
        jloc = loc+"_jrnl"
        db3 = NumDB(loc)
        db3[9] = "nine"
        db3[10] = "ten"
        db3[11] = "eleven"
        db3.close()
        db3 = JNumDB(loc)
        self.assertEquals(readFile(jloc), "")
        db3[12] = 'twelve'
        self.assertEquals(readFile(jloc), "00012              twelve")
        self.assertEquals(db3[10], "TEN")
        self.assertEquals(db3[12], "twelve")
        db3.close()
        for fn in os.listdir(d_parent):
            os.unlink(os.path.join(d_parent,fn))

class QueueTests(FStoreTestBase):
    def setUp(self):
        mixminion.Common.installSIGCHLDHandler()
    def testDeliveryQueues(self):
        d_d = mix_mktemp("qd")

        now = 10000 # time.time()
        queue = TestDeliveryQueue(d_d, now)
        queue.setRetrySchedule([10, 10, 10, 10]) # Retry up to 40 sec.
        # First, make sure the queue stores messages correctly.
        h1 = queue.queueDeliveryMessage("Message 1", now=now)
        h2 = queue.queueDeliveryMessage("Message 2", now=now)
        self.assertEquals(("Message 1", now, None, now), queue._inspect(h1))
        self.assertEquals(("Message 2", now, None, now), queue._inspect(h2))

        # Call sendReadyMessages to begin 'sending' msg1 and msg2.
        queue.sendReadyMessages(now)
        msgs = [ (msg.getHandle(), msg.getMessage()) for msg in queue._msgs ]
        self.assertEquals(2, len(msgs))
        # _deliverMessages should have gotten them both.
        self.failUnless((h1, "Message 1") in msgs)
        self.failUnless((h2, "Message 2") in msgs)
        # Add msg3, and acknowledge that msg1 succeeded.  msg2 is now in limbo
        h3 = queue.queueDeliveryMessage("Message 3", now=now)
        queue.deliverySucceeded(h1)
        # Only msg3 should get sent out, since msg2 is still in progress.
        queue.sendReadyMessages(now+1)
        msgs = [ (msg.getHandle(), msg.getMessage()) for msg in queue._msgs ]
        self.assertEquals([(h3, "Message 3")], msgs)

        # Now, make sure that msg1 is gone from the pool.
        self.assertUnorderedEq(queue.getAllMessages(), [h2, h3])

        # Now, fail msg2 retriably, and fail msg3 hard.  Only one message
        # should be left.  (It will have a different handle from the old
        # msg2.)
        queue.deliveryFailed(h2, retriable=1, now=now+4)
        queue.deliveryFailed(h3, retriable=0, now=now+4)
        allHandles = queue.getAllMessages()
        h4 = allHandles[0]
        queue.cleanQueue(self.unlink)
        self.assertUnorderedEq(os.listdir(d_d), ["meta_"+h4, "msg_"+h4])
        self.assertEquals([h4], queue.getAllMessages())
        self.assertEquals(("Message 2", now, now, now+10), queue._inspect(h2))

        # Reload the queue; and try that again.
        queue = TestDeliveryQueue(d_d, now+4)
        queue.setRetrySchedule([10, 10, 10, 10]) # Retry up to 40 sec.
        self.assertEquals([h4], queue.getAllMessages())
        self.assertEquals(("Message 2", now, now, now+10), queue._inspect(h2))

        # When we try to send messages again after 5 seconds, nothing happens.
        queue.sendReadyMessages(now+5)
        self.assertEquals(None, queue._msgs)
        # When we try to send again after after 11 seconds, message 2 fires.
        queue.sendReadyMessages(now+11)
        msgs = [ (msg.getHandle(), msg.getMessage()) for msg in queue._msgs ]
        self.assertEquals([(h4, "Message 2")], msgs)
        self.assertEquals(h2, h4)
        queue._msgs[0].failed(retriable=1, now=now+15)
        self.assertEquals(("Message 2", now, now+11, now+20),
                          queue._inspect(h2))
        # At 31 seconds, message 2 fires.
        h5 = queue.getAllMessages()[0]
        queue.sendReadyMessages(now+31)
        msgs = [ (msg.getHandle(), msg.getMessage()) for msg in queue._msgs ]
        self.assertEquals([(h5, "Message 2")], msgs)
        self.assertEquals(h5, h4)
        queue.deliveryFailed(h5, retriable=1, now=now+33)
        self.assertEquals(("Message 2", now, now+31, now+40),
                          queue._inspect(h2))
        # At 45 sec, it fires one last time.  It will have gotten up to #4
        # already.
        h6 = queue.getAllMessages()[0]
        queue.sendReadyMessages(now+45)
        msgs = [ (msg.getHandle(), msg.getMessage()) for msg in queue._msgs ]
        self.assertEquals([(h6, "Message 2")], msgs)
        self.assertEquals(h6, h5)
        queue.deliveryFailed(h6, retriable=1, now=now+100)
        # Now Message 2 is timed out.
        self.assertEquals([], queue.getAllMessages())

        queue.removeAll(self.unlink)
        queue.cleanQueue(self.unlink)

    def testMixPools(self):
        d_m = mix_mktemp("qm")

        # Trivial 'TimedMixPool'
        queue = TimedMixPool(d_m)
        h1 = queue.queueObject("Hello1")
        h2 = queue.queueObject("Hello2")
        h3 = queue.queueObject("Hello3")
        self.assertUnorderedEq(queue.getBatch(), [h1,h2,h3])

        # Now, test the CottrellMixPool.
        cmq = CottrellMixPool(d_m, 600, 6, sendRate=.3)
        # Not enough messages (<= 6) -- none will be sent.
        self.assertEquals([], cmq.getBatch())
        self.assertEquals([], cmq.getBatch())
        # 8 messages: 2 get sent
        for i in range(5):
            cmq.queueObject("Message %s"%i)
        self.assertEquals(8, cmq.count())
        b1, b2, b3 = cmq.getBatch(), cmq.getBatch(), cmq.getBatch()
        self.assertEquals(2, len(b1))
        self.assertEquals(2, len(b2))
        self.assertEquals(2, len(b3))

        # Make sure that all message batches are different.
        allEq = 1
        for x in xrange(13): #fails <one in a trillion
            b = cmq.getBatch()
            if b != b1:
                allEq = 0; break
        self.failIf(allEq)

        # Send 30 when there are 100 messages.
        for x in xrange(92):
            cmq.queueObject("Hello2 %s"%x)
        for x in xrange(10):
            self.assertEquals(30, len(cmq.getBatch()))

        # Binomial Cottrell pool
        bcmq = BinomialCottrellMixPool(d_m, 600, 6, sendRate=.3)
        # (Just make sure that we don't always return the same number of
        #  messages each time.)
        messageLens = []
        for i in range(31):
            b = bcmq.getBatch()
            messageLens.append(len(b))
        messageLens.sort()
        self.failIf(messageLens[0] == messageLens[-1])
        # (Fails less than once in 2 **30 tests.)
        self.assert_(messageLens[0] <= 30)
        self.assert_(messageLens[-1] >= 30)

        bcmq.removeAll(self.unlink)
        bcmq.cleanQueue(self.unlink)

#---------------------------------------------------------------------
# LOGGING
class LogTests(TestCase):
    def testLogging(self):

        # Create a new loghandler, and try sending a few messages to it.
        log = Log("INFO")
        self.assertEquals(log.getMinSeverity(), "INFO")
        log.handlers = []
        log.log("WARN", "This message should not appear")
        buf = cStringIO.StringIO()
        log.addHandler(_ConsoleLogHandler(buf))
        log.trace("Foo")
        self.assertEquals(buf.getvalue(), "")
        log.log("WARN", "Hello%sworld", ", ")
        self.assertEndsWith(buf.getvalue(), "[WARN] Hello, world\n")
        self.failUnless(buf.getvalue().index('\n') == len(buf.getvalue())-1)
        log.error("All your anonymity are belong to us")
        self.assertEndsWith(buf.getvalue(), 
            "[ERROR] All your anonymity are belong to us\n")

        buf.truncate(0)

        # Try out error_exc.
        try:
            raise MixError()
        except:
            inf = sys.exc_info()
        log.error_exc(inf)
        log.error_exc(inf, "And so on")
        log.error_exc(inf, "And so %s", "on")

        # Try out file logging
        t = mix_mktemp("log")
        t1 = t+"1"

        log.addHandler(_FileLogHandler(t))
        log.info("Abc")
        log.info("Def")
        if ON_WIN32: #WWWW
            log.close()
            return
        
        os.rename(t,t1)
        log.info("Ghi")
        log.reset()
        log.info("Klm")
        log.close()
        self.assertEquals(readFile(t).count("\n") , 1)
        self.assertEquals(readFile(t1).count("\n"), 3)

    def testLogStream(self):
        stream = mixminion.Common.LogStream("STREAM", "WARN")
        suspendLog()
        try:
            print >>stream, "Testing", 1,2,3
            print >>stream
            print >>stream, "A\nB\nC"
            print >>stream, "X",
            print >>stream, "Y"
        finally:
            r = resumeLog()
        lines = [ l[20:] for l in r.split("\n") ]
        self.assertEquals(lines[0], "[WARN] ->STREAM: Testing 1 2 3")
        self.assertEquals(lines[1], "[WARN] ->STREAM: ")
        self.assertEquals(lines[2], "[WARN] ->STREAM: A")
        self.assertEquals(lines[3], "[WARN] ->STREAM: B")
        self.assertEquals(lines[4], "[WARN] ->STREAM: C")
        self.assertEquals(lines[5], "[WARN] ->STREAM: X Y")

#----------------------------------------------------------------------
# File paranoia


class FileParanoiaTests(TestCase):
    def ensureParanoia(self, whatkind):
        tempdir = mixminion.testSupport._MM_TESTING_TEMPDIR

        # If our tempdir doesn't exist and isn't private, we can't go on.
        try:
            checkPrivateDir(tempdir)
        except MixFatalError, e:
            self.fail(("Can't test %s paranoia, because something's\n"
                      +" wrong with %s: %s")%(whatkind, tempdir, str(e)))

    def testPrivateDirs(self):
        self.ensureParanoia("directory")

        # Pick a private directory under tempdir, but don't create it.
        noia = mix_mktemp("noia")
        subdir = os.path.join(noia, "subdir")

        # Nonexistent directory.
        self.failUnlessRaises(MixFatalError, checkPrivateDir, noia)
        # Bad permissions.
        os.mkdir(noia)
        if not ON_WINDOWS:
            os.chmod(noia, 0777)
            self.failUnlessRaises(MixFatalError, checkPrivateDir, noia)
            # Bad permissions on parent
            os.mkdir(subdir, 0700)
            self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
            os.chmod(noia, 0755)
            checkPrivateDir(subdir)
            os.chmod(noia, 0700)
            checkPrivateDir(subdir)
            # Not writable by self
            os.chmod(subdir, 0600)
            self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
            os.rmdir(subdir)
        # Not a directory
        writeFile(subdir, "x")
        os.chmod(subdir, 0700)
        self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
        os.unlink(subdir)
        os.mkdir(subdir, 0700)

        # Helper fn: return mode,uid,isdir
        def mud(f):
            st = os.stat(f)
            return st[stat.ST_MODE]&0777, st[stat.ST_UID], os.path.isdir(f)

        # Now we test a directory we don't own...
        if not ON_WIN32 and os.getuid() == 0: 
            # If we're root, we can play with chown!
            # We don't own the directory
            os.chown(subdir, 1, 1)
            self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
            os.chown(subdir, 0, os.getgid())
            # We don't own the parent
            os.chown(noia, 1, 1)
            self.failUnlessRaises(MixFatalError, checkPrivateDir, subdir)
            os.chown(noia, 0, os.getgid())
        elif not ON_WIN32:
            # We're not root.  We can't reliably find or make a directory
            # that's non-root and non-us.  Let's just make sure we don't
            # own temp.
            if os.path.exists("/tmp") and mud("/tmp")[1] != os.getuid():
                self.failUnlessRaises(MixFatalError, checkPrivateDir, "/tmp")

        if ON_WINDOWS:
            private = permissive = public = 0777
        else:
            private, permissive, public = 0700, 0777, 0755
	
        # Okay.  Now we try createPrivateDir a couple of times...
        old_mask = None
        try:
            # Make sure umask is lenient, so we can tell whether c-p-d is
            # strict.
            old_mask = os.umask(022)
            # 1. Create the world.
            os.rmdir(subdir)
            os.rmdir(noia)
            createPrivateDir(subdir)
            if not ON_WINDOWS:
                self.assertEquals((private,os.getuid(),1), mud(subdir))
                self.assertEquals((private,os.getuid(),1), mud(noia))
                # 2. Just create one dir.
                os.rmdir(subdir)
                os.chmod(noia, public)
                createPrivateDir(subdir)
                self.assertEquals((private,os.getuid(),1), mud(subdir))
                self.assertEquals((public,os.getuid(),1), mud(noia))
                # 3. Fail to create because of bad permissions
                os.rmdir(subdir)
                os.chmod(noia, permissive)
                self.failUnlessRaises(MixFatalError, createPrivateDir, subdir)
            # 4. Fail to create because of OSError
            os.rmdir(subdir)
            writeFile(subdir, 'W')
            self.failUnlessRaises(MixFatalError, createPrivateDir, subdir)
            os.unlink(subdir)
            # 5. Succeed: it's already there.
            os.chmod(noia, private)
            os.mkdir(subdir, private)
            createPrivateDir(subdir)
            # 6. Fail: it's already there, but has bad permissions
            if not ON_WINDOWS:
                os.chmod(subdir, permissive)
                self.failUnlessRaises(MixFatalError, createPrivateDir, subdir)
                os.chmod(subdir, private)
        finally:
            if old_mask is not None:
                os.umask(old_mask)

    def testPrivateFiles(self):
        self.ensureParanoia("file")
        dir = mix_mktemp()
        os.mkdir(dir, 0700)
        subdir = os.path.join(dir, "subdir")
        os.mkdir(subdir, 0777)

        # File doesn't exist.
        self.failUnlessRaises(MixFatalError,
                              checkPrivateFile, os.path.join(dir, "x"))

        # Parent not private.
        subdir_x = os.path.join(subdir, "x")
        writeFile(subdir_x, "zzz")
        os.chmod(subdir_x, 0600)
        if not ON_WINDOWS:
            self.failUnlessRaises(MixFatalError,
                                  checkPrivateFile, subdir_x)

        # File not owned by us. (???)
        if not ON_WINDOWS and os.getuid() == 0:
            os.chmod(subdir_x, 0600)
            os.chown(subdir_x, 1, 1)
            self.failUnlessRaises(MixFatalError, checkPrivateFile, subdir_x)
            os.chown(subdir_x, 0, os.getgid())
        else:
            if os.path.exists("/etc/shadow"):
                self.failUnlessRaises(MixFatalError, checkPrivateFile,
                                      "/etc/shadow")

        # File not private (fix, noex)
        os.chmod(subdir, 0700)
        os.chmod(subdir_x, 0777)
        try:
            suspendLog()
            checkPrivateFile(subdir_x)
        finally:
            s = resumeLog()
        if not ON_WINDOWS:
            self.assertEquals(0700, os.stat(subdir_x)[stat.ST_MODE] & 0777)
            self.assert_(stringContains(s,
                                 "Repairing permissions on file "+subdir_x))

        os.chmod(subdir_x, 0606)
        try:
            suspendLog()
            checkPrivateFile(subdir_x)
        finally:
            s = resumeLog()
        if not ON_WINDOWS:
            self.assertEquals(0600, os.stat(subdir_x)[stat.ST_MODE] & 0777)
            self.assert_(stringContains(s,
                                 "Repairing permissions on file "+subdir_x))

        # File not private, nofix.
        os.chmod(subdir_x, 0701)
        if not ON_WINDOWS:
            self.failUnlessRaises(MixFatalError, checkPrivateFile, subdir_x, 0)

#----------------------------------------------------------------------
# SIGHANDLERS
# FFFF Write tests here


#----------------------------------------------------------------------
# MMTP

# Run on a different port so we don't conflict with any actual servers
# running on this machine.
TEST_PORT = 40199

dhfile = pkfile = certfile = None

def _getTLSContext(isServer):
    "Helper function: create a new TLSContext object."
    global dhfile
    global pkfile
    global certfile
    if isServer:
        if dhfile is None:
            f = mix_mktemp()
            dhfile = f+"_dh"
            pkfile = f+"_pk"
            certfile = f+"_cert"
            dh_fname = os.environ.get("MM_TEST_DHPARAMS")
            if dh_fname and not USE_SLOW_MODE:
                dhfile = dh_fname
                if not os.path.exists(dh_fname):
                    print "[Generating DH parameters...",
                    sys.stdout.flush()
                    _ml.generate_dh_parameters(dhfile, 0)
                    print "done.]",
                    sys.stdout.flush()
            else:
                print "[Generating DH parameters (not caching)...",
                sys.stdout.flush()
                _ml.generate_dh_parameters(dhfile, 0)
                print "done.]",
                sys.stdout.flush()
            pk = getRSAKey(3,1024)
            pk.PEM_write_key(open(pkfile, 'w'), 0)
            ident = getRSAKey(0,2048)
            generateCertChain(certfile, pk, ident, "<testing>",
                              time.time(), time.time()+365*24*60*60)

        pk = _ml.rsa_PEM_read_key(open(pkfile, 'r'), 0)
        return _ml.TLSContext_new(certfile, pk, dhfile)
    else:
        return _ml.TLSContext_new()

def _getTLSContextKeyID():
    ident = getRSAKey(0,2048)
    keyid = sha1(ident.encode_key(1))
    return keyid

def _getMMTPServer(minimal=0,reject=0,port=TEST_PORT):
    """Helper function: create a new MMTP server with a listener connection
       Return a tuple of AsyncServer, ListenerConnection, list of received
       messages, and keyid."""
    server = mixminion.server.MMTPServer.AsyncServer()
    messagesIn = []
    def receivedHook(pkt,m=messagesIn):
        m.append(pkt)
    server.nJunkPackets = 0
    def junkCallback(server=server): server.nJunkPackets += 1
    def conFactory(sock, context=_getTLSContext(1),
                   receiveMessage=receivedHook,junkCallback=junkCallback,
                   reject=reject):
        tls = context.sock(sock, serverMode=1)
        sock.setblocking(0)
        con = mixminion.server.MMTPServer.MMTPServerConnection(sock,tls,
                                                               receiveMessage,
                                                         rejectPackets=reject)
        con.junkCallback = junkCallback
        return con
    def conFactoryMin(sock, context=_getTLSContext(1)):
        tls = context.sock(sock, serverMode=1)
        sock.setblocking(0)
        con = mixminion.server.MMTPServer.MMTPServerConnection(sock,tls,
                                                               lambda m:None)
        con.junkCallback = lambda:None
        return con
    if minimal:
        conFactory = conFactoryMin
    listener = mixminion.server.MMTPServer.ListenConnection("127.0.0.1",
                                                          port, 5, conFactory)
    listener.register(server)
    keyid = _getTLSContextKeyID()

    return server, listener, messagesIn, keyid

class FakeDeliverable:
    def __init__(self, s):
        self._failed = self._succeeded = 0
        self._retriable = -1
        self._contents = s
    def getContents(self):
        return self._contents
    def failed(self, retriable):
        assert not (self._failed or self._succeeded)
        self._failed = 1
        self._retriable = retriable
    def succeeded(self):
        assert not (self._failed or self._succeeded)
        self._succeeded = 1

class MMTPTests(TestCase):
    #XXXX This class is bulky, and has lots of cut-and-paste.  It could do
    #XXXX with a refactoring.
    def doTest(self, fn):
        """Wraps an underlying test function 'fn' to make sure we kill the
           MMTPServer, but don't block."""
        self.listener = self.server = None
        try:
            fn()
        finally:
            if self.listener is not None:
                self.listener.shutdown()
            if self.server is not None:
                count = 0
                while count < 100 and (self.server.readers or
                                       self.server.writers):
                    self.server.process(0.1)
                    count = count + 1

    def testBlockingTransmission(self):
        self.doTest(self._testBlockingTransmission)

    def testNonblockingTransmission(self):
        self.doTest(self._testNonblockingTransmission)

    def testTimeout(self):
        self.doTest(self._testTimeout)

    def testRejected(self):
        self.doTest(self._testRejected)

    def _testBlockingTransmission(self):
        server, listener, messagesIn, keyid = _getMMTPServer()
        self.listener = listener
        self.server = server

        messages = ["helloxxx"*4096, "helloyyy"*4096]

        # Send m1, then junk, then renegotiate, then m2.
        server.process(0.1)
        routing = IPV4Info("127.0.0.1", TEST_PORT, keyid)
        t = threading.Thread(None,
                             mixminion.MMTPClient.sendMessages,
                             args=(routing,
                             [messages[0],"JUNK","RENEGOTIATE",messages[1]]))
        t.start()
        while len(messagesIn) < 2:
            server.process(0.1)
        t.join()

        for _ in xrange(3):
            server.process(0.1)

        self.failUnless(messagesIn == messages)
        self.assertEquals(1, server.nJunkPackets)

        # Now, with bad keyid.
        routing = IPV4Info("127.0.0.1", TEST_PORT, "Z"*20)
        t = threading.Thread(None,
                             self.failUnlessRaises,
                             args=(MixProtocolError,
                                   mixminion.MMTPClient.sendMessages,
                                   routing, messages))
        t.start()
        while t.isAlive():
            server.process(0.1)
        t.join()

    def testStallingTransmission(self):
        # XXXX I know this works, but there doesn't seem to be a good
        # XXXX way to test it.  It's hard to open a connection that
        # XXXX will surely stall.  For now, I'm disabling this test.
        if 1:
            return

        def threadfn(pausing):
            # helper fn to run in a different thread: bind a socket,
            # but don't listen.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", TEST_PORT))
            #sock.listen(5)
            #s, _ = sock.accept()
            while pausing[0] > 0:
                time.sleep(.1)
                pausing[0] -= .1
            time.sleep(2)
            #s.close()
            sock.close()
        pausing = [4]
        t = threading.Thread(None, threadfn, args=(pausing,))
        t.start()

        now = time.time()
        timedout = 0
        try:
            try:
                routing = IPV4Info("127.0.0.1", TEST_PORT, "Z"*20)
                mixminion.MMTPClient.sendMessages(routing, ["JUNK"],
                                                   connectTimeout=1)
                timedout = 0
            except mixminion.MMTPClient.TimeoutError:
                timedout = 1
        finally:
            passed = time.time() - now
            pausing[0] = 0
            t.join()

        self.assert_(passed < 2)
        self.assert_(timedout)

    def _testNonblockingTransmission(self):
        server, listener, messagesIn, keyid = _getMMTPServer()
        self.listener = listener
        self.server = server

        # Send m1, then junk, then renegotiate, then junk, then m2.
        tlscon = mixminion.server.MMTPServer.SimpleTLSConnection
        messages = ["helloxxx"*4096, "helloyyy"*4096]
        deliv = [FakeDeliverable(m) for m in messages]
        async = mixminion.server.MMTPServer.AsyncServer()
        clientcon = mixminion.server.MMTPServer.MMTPClientConnection(
           _getTLSContext(0), "127.0.0.1", TEST_PORT, keyid,
           [deliv[0],"JUNK","RENEGOTIATE","JUNK",deliv[1]],
           None)
        clientcon.register(async)
        def clientThread(clientcon=clientcon, async=async):
            while not clientcon.isShutdown():
                async.process(2)

        server.process(0.1)
        startTime = time.time()
        t = threading.Thread(None, clientThread)

        c = None
        t.start()
        while len(messagesIn) < 2:
            if c is None and len(server.readers) > 1:
                c = [ c for c in server.readers.values() if
                      isinstance(c, tlscon) ]
            server.process(0.1)
        while t.isAlive():
            server.process(0.1)
        t.join()
        endTime = time.time()

        self.assertEquals(len(messagesIn), len(messages))
        self.failUnless(messagesIn == messages)
        self.failUnless(c is not None)
        self.failUnless(len(c) == 1)
        self.failUnless(startTime <= c[0].lastActivity <= endTime)
        self.assertEquals(2, server.nJunkPackets)
        self.assert_(deliv[0]._succeeded)
        self.assert_(deliv[1]._succeeded)

        # Again, with bad keyid.
        deliv = [FakeDeliverable(m) for m in messages]
        clientcon = mixminion.server.MMTPServer.MMTPClientConnection(
            _getTLSContext(0), "127.0.0.1", TEST_PORT, "Z"*20,
            deliv[:], None)
        clientcon.register(async)
        def clientThread2(clientcon=clientcon, async=async):
            while not clientcon.isShutdown():
                async.process(2)

        try:
            suspendLog() # suppress warning
            server.process(0.1)
            t = threading.Thread(None, clientThread2)

            t.start()
            while t.isAlive():
                server.process(0.1)
            t.join()
        finally:
            resumeLog()  #unsuppress warning

        self.assert_(deliv[0]._failed)
        self.assert_(deliv[1]._failed)

    def _testTimeout(self):
        server, listener, messagesIn, keyid = _getMMTPServer()
        self.listener = listener
        self.server = server

        # This function wraps MMTPClient.sendMessages, but catches exceptions.
        # Since we're going to run this function in a thread, we pass the
        # exception back through a list argument.
        def sendSlowlyAndCaptureException(exlst, pausing, targetIP, targetPort,
                                          targetKeyID, msgFast, msgSlow):
            try:
                con = mixminion.MMTPClient.BlockingClientConnection(
                    targetIP,targetPort,targetKeyID)
                con.connect()
                con.sendPacket(msgFast)
                while pausing[0] > 0:
                    time.sleep(.1)
                    pausing[0] -= .1
                con.sendPacket(msgSlow)
                con.close()
            except:
                exlst.append(sys.exc_info())

        # Manually set the server's timeout threshold to 600 msec.
        server._timeout = 0.6
        server.process(0.1)
        excList = []
        pausing = [10]
        t = threading.Thread(None,
              sendSlowlyAndCaptureException,
              args=(excList, pausing, "127.0.0.1", TEST_PORT, keyid,
                    "helloxxx"*4096, "helloyyy"*4096))
        t.start()
        timedOut = 0 # flag: have we really timed out?
        try:
            suspendLog() # stop logging, but wait for the timeout message.
            while len(messagesIn) < 2:
                server.process(0.1)
                # If the number of connections changes around the call
                # to tryTimeout, the timeout has occurred.
                nConnections = len(server.readers)+len(server.writers)
                server.tryTimeout(time.time())
                if len(server.readers)+len(server.writers) < nConnections:
                    timedOut = 1
                    break
            # Did we really time out the connection, or did we end normally?
            self.assert_(timedOut)
        finally:
            logMessage = resumeLog()
        # Did we log the timeout?
        self.assert_(stringContains(logMessage, "timed out"))
        # Was the one message we expected in fact transmitted?
        self.assertEquals([messagesIn[0]], ["helloxxx"*4096])

        # Now stop the transmitting thread.  It will notice that its
        # connection has been forcibly closed.
        pausing[0] = 0
        t.join()
        # Was an exception raised?
        self.assertEquals(1, len(excList))
        # Was it the right exception?
        ex = excList[0][1]
        self.assert_(isinstance(ex, MixError))
        self.assert_(isinstance(ex.base, _ml.TLSClosed))

        for _ in xrange(3):
            server.process(0.1)

    def _testRejected(self):
        server, listener, messagesIn, keyid = _getMMTPServer(reject=1)
        self.listener = listener
        self.server = server

        messages = ["helloxxx"*4096, "helloyyy"*4096]
        # Send 2 messages -- both should be rejected.
        server.process(0.1)
        routing = IPV4Info("127.0.0.1", TEST_PORT, keyid)
        ok=[0];done=[0]
        def _t(routing=routing, messages=messages,ok=ok,done=done):
            try:
                mixminion.MMTPClient.sendMessages(routing,messages)
            except mixminion.Common.MixProtocolReject:
                ok[0] = 1
            done[0] = 1

        t = threading.Thread(None, _t)
        t.start()
        while not done[0]:
            server.process(0.1)
        t.join()
        for _ in xrange(3):
            server.process(0.1)

        self.failUnless(ok[0])
        self.failUnless(len(messagesIn) == 0)

        # Send m1, then junk, then renegotiate, then junk, then m2.
        messages = ["helloxxx"*4096, "helloyyy"*4096]
        deliv = [FakeDeliverable(m) for m in messages]
        async = mixminion.server.MMTPServer.AsyncServer()

        clientcon = mixminion.server.MMTPServer.MMTPClientConnection(
           _getTLSContext(0), "127.0.0.1", TEST_PORT, keyid,
           deliv)
        clientcon.register(async)
        def clientThread(clientcon=clientcon, async=async):
            while not clientcon.isShutdown():
                async.process(2)

        t = threading.Thread(None, clientThread)
        t.start()
        while not clientcon.isShutdown():
            server.process(0.1)
        while t.isAlive():
            server.process(0.1)
        t.join()
        self.assertEquals(len(messagesIn), 0)
        self.assertEquals(deliv[0]._retriable, 1)
        self.assertEquals(deliv[1]._retriable, 1)

#----------------------------------------------------------------------
# Config files

class TestConfigFile(_ConfigFile):
    _syntax = { 'Sec1' : {'__SECTION__': ('REQUIRE', None, None),
                          'Foo': ('REQUIRE', None, None),
                          'Bar': ('ALLOW', None, "default"),
                          'Baz': ('ALLOW', None, None),},
                'Sec2' : {'Fob': ('ALLOW*', None, None),
                          'Bap': ('REQUIRE', None, None),
                          'Quz': ('REQUIRE*', None, None), },
                'Sec3' : {'IntAS': ('ALLOW', _parseInt, None),
                          'IntAS2': ('ALLOW', _parseInt, None),
                          'IntASD': ('ALLOW', _parseInt, "5"),
                          'IntASD2': ('ALLOW', _parseInt, "5"),
                          'IntAM': ('ALLOW*', _parseInt, None),
                          'IntAMD': ('ALLOW*', _parseInt, ["5", "2"]),
                          'IntAMD2': ('ALLOW*', _parseInt, ["5", "2"]),
                          'IntRS': ('REQUIRE', _parseInt, None) }
                }
    def __init__(self, fname=None, string=None, restrict=0):
        self._restrictFormat = restrict
        _ConfigFile.__init__(self,fname,string)

class ConfigFileTests(TestCase):
    def testValidFiles(self):
        
        TCF = TestConfigFile
        # Try a minimal file.
        shorterString = """[Sec1]\nFoo a\n"""
        f = TCF(string=shorterString)
        self.assertEquals(f['Sec1']['Foo'], 'a')
        # Try a slightly more spaceful version of the above.
        f = TCF(string="""\n\n[ Sec1 ]  \n  \n\nFoo a  \n""")
        self.assertEquals(f['Sec1']['Foo'], 'a')
        self.assertEquals(f['Sec2'], {})

        # Now, try all the syntactical possibilities, and all the fields
        longerString = """[Sec1]

Foo=  abcde f

Bar bar
Baz:
  baz
  and more baz
  and more baz
[Sec2]

# Comment
Bap +
Quz 99 99


Fob=1
Quz : 88
     88

[Sec3]
IntAS=9
IntASD=10
IntAMD=8
IntAMD=10
IntRS=5

  """

        f = TCF(string=longerString)
        self.assertEquals(f['Sec1']['Foo'], 'abcde f')
        self.assertEquals(f['Sec1']['Bar'], 'bar')
        self.assertEquals(f['Sec1']['Baz'], ' baz and more baz and more baz')
        self.assertEquals(f['Sec2']['Bap'], '+')
        self.assertEquals(f['Sec2']['Fob'], ['1'])
        self.assertEquals(f['Sec2']['Quz'], ['99 99', '88 88'])
        self.assertEquals(f.getSectionItems('Sec2'),
                          [ ('Bap', '+'),
                            ('Quz', '99 99'),
                            ('Fob', '1'),
                            ('Quz', '88 88') ])

        # Make sure that str(f) works.
        self.assertEquals(str(f),
           ("[Sec1]\nFoo: abcde f\nBar: bar\nBaz:  baz and more baz"+
            " and more baz\n\n[Sec2]\nBap: +\nQuz: 99 99\nFob: 1\n"+
            "Quz: 88 88\n\n[Sec3]\nIntAS: 9\nIntASD: 10\nIntAMD: 8\n"+
            "IntAMD: 10\nIntRS: 5\n\n"))
        # Test file input
        fn = mix_mktemp()

        writeFile(fn, longerString)
        f = TCF(fname=fn)
        self.assertEquals(f['Sec1']['Bar'], 'bar')
        self.assertEquals(f['Sec2']['Quz'], ['99 99', '88 88'])

        self.assertEquals(f['Sec3']['IntAS'], 9)
        self.assertEquals(f['Sec3']['IntAS2'], None)
        self.assertEquals(f['Sec3']['IntASD'], 10)
        self.assertEquals(f['Sec3']['IntASD2'], 5)
        self.assertEquals(f['Sec3']['IntAM'], [])
        self.assertEquals(f['Sec3']['IntAMD'], [8,10])
        self.assertEquals(f['Sec3']['IntAMD2'], [5,2])
        self.assertEquals(f['Sec3']['IntRS'], 5)

        # Test restricted mode
        s = "[Sec1]\nFoo: Bar\nBaz: Quux\n[Sec3]\nIntRS: 9\n"
        f = TCF(string=s, restrict=1)
        self.assertEquals(f['Sec1']['Foo'], "Bar")
        self.assertEquals(f['Sec3']['IntRS'], 9)

    def testBadFiles(self):
        def fails(string, self=self):
            self.failUnlessRaises(ConfigError, TestConfigFile, None, string)


        # Missing section header
        fails("Foo = Bar\n")
        # Invalid indentation on key
        fails("[Sec1]\n  Foo = Bar\n")
        # Invalid indentation on header
        fails("  [Sec1]\n  Foo = Bar\n")
        # Unrecognized key
        fails("[Sec1]\nFoo! Bar\n")

        fails("[Sec1]\nFoob: Bar\n") # No such key
        fails("[Sec1]\nFoo: Bar\nFoo: Bar\n") #  Duplicate key
        fails("[Sec1]\nBaz: 3\n") # Missing key
        fails("[Sec2]\nBap = 9\nQuz=6\n") # Missing section
        fails("[Sec1]\nFoo 1\n[Sec2]\nBap = 9\n") # Missing require*
        fails("[Sec1]\nFoo: Bar\n[Sec3]\nIntRS=Z\n") # Failed validation

        # now test the restricted format
        def failsR(string, self=self):
            self.failUnlessRaises(ConfigError, TestConfigFile, None, string, 1)
        failsR("[Sec1]\nFoo=Bar\n")
        failsR("[Sec1]\nFoo Bar\n")
        failsR("[Sec1]\n\nFoo: Bar\n")
        failsR("\n[Sec1]\nFoo: Bar\n")
        failsR("\n[Sec1]\nFoo: Bar\n\n")

    def testValidationFns(self):
        import mixminion.Config as C

        ## First, check valid cases.
        # boolean
        self.assertEquals(C._parseBoolean("yes"), 1)
        self.assertEquals(C._parseBoolean(" NO"), 0)
        # severity
        self.assertEquals(C._parseSeverity("error"), "ERROR")
        # serverMode
        self.assertEquals(C._parseServerMode(" relay "), "relay")
        self.assertEquals(C._parseServerMode("Local"), "local")
        # interval
        self.assertEquals(str(C._parseInterval(" 1 sec ")),"1 second")
        self.assertEquals(str(C._parseInterval(" 99 sec ")),"99 seconds")
        self.assertFloatEq(float(C._parseInterval("1.5 minutes")), 90)
        h2 = C._parseInterval("2 houRS")
        m120 = C._parseInterval("120 minutes")
        self.assertEquals(str(h2), "2 hours")
        self.assertEquals(str(m120), "120 minutes")
        self.assert_(int(h2) == int(m120) == 7200)
        m120.reduce()
        self.assertEquals(str(m120), "2 hours")
        # size
        self.assertEquals(C._parseSize(" 30 bytes"), 30L)
        self.assertEquals(C._parseSize(" 3000 b"), 3000L)
        self.assertEquals(C._parseSize("50k"), 50*1024L)
        self.assertEquals(C._parseSize("50k "), 50*1024L)
        self.assertEquals(C._parseSize("50 "), 50L)
        self.assertEquals(C._parseSize("50"), 50L)
        self.assertEquals(C._parseSize("12.3M"), long(12.3*(1<<20L)))
        # IntervalList
        self.assertEquals(C._parseIntervalList(" 5 sec, 1 min, 2 hours"),
                          [ 5, 60, 7200 ])
        self.assertEquals([5,5,5,5,5,5, 8*3600,8*3600,8*3600,8*3600,],
              C._parseIntervalList("5 sec for 30 sec, 8 hours for 1.3 days"))
        self.assertEquals([60], C._parseIntervalList("1 min for 1 min"))
        self.assertEquals([60,60], C._parseIntervalList("1 min for 1.5 min"))
        self.assertEquals([60,60],
               C._parseIntervalList("EVERY  1 min for 1.5 min"))
        # int
        self.assertEquals(C._parseInt("99"), 99)
        # IP
        self.assertEquals(C._parseIP("192.168.0.1"), "192.168.0.1")
        # AddressSet
        pa = C._parseAddressSet_allow
        self.assertEquals(pa("*"), ("0.0.0.0", "0.0.0.0", 48099, 48099))
        self.assertEquals(pa("192.168.0.1/255.255.0.0"),
                          ("192.168.0.1", "255.255.0.0", 48099, 48099))
        self.assertEquals(pa("192.168.0.1 /  255.255.0.0  23-99"),
                          ("192.168.0.1", "255.255.0.0", 23, 99))
        self.assertEquals(pa("192.168.0.1 /  255.255.0.0  23"),
                          ("192.168.0.1", "255.255.0.0", 23, 23))
        self.assertEquals(pa("192.168.0.1"),
                          ("192.168.0.1", "255.255.255.255", 48099, 48099))
        self.assertEquals(pa("192.168.0.1",0),
                          ("192.168.0.1", "255.255.255.255", 0, 65535))

        # Command
        if not sys.platform == 'win32':
            # WIN32 This should get implemented for Windows.
            c = C._parseCommand("ls -l")
            self.assert_(os.path.exists(c[0]) and c[0].endswith("/ls"))
            self.assertEquals(c[1], ['-l'])
            c = C._parseCommand("rm")
            self.assert_(os.path.exists(c[0]) and c[0].endswith("/rm"))
            self.assertEquals(c[1], [])
            self.assertEquals(C._parseCommand("/bin/ls"), ("/bin/ls", []))
            self.failUnless(C._parseCommand("python")[0] is not None)

        # Base64
        self.assertEquals(C._parseBase64(" YW\nJj"), "abc")
        self.assertEquals(C._parseBase64(" Y W\nJ j"), "abc")
        # Hex
        self.assertEquals(C._parseHex(" C0D0"), "\xC0\xD0")
        self.assertEquals(C._parseHex(" C0\n D 0"), "\xC0\xD0")
        # Date
        tm = C._parseDate("2002/05/30")
        self.assertEquals(time.gmtime(tm)[:6], (2002,5,30,0,0,0))
        tm = C._parseDate("2000/01/01")
        self.assertEquals(time.gmtime(tm)[:6], (2000,1,1,0,0,0))
        tm = C._parseDate("2000-05-03")
        self.assertEquals(time.gmtime(tm)[:6], (2000,5,3,0,0,0))
        # Time
        tm = C._parseTime("2001/12/25 06:15:10")
        self.assertEquals(time.gmtime(tm)[:6], (2001,12,25,6,15,10))
        tm = C._parseTime("2001-12-25 06:15:10.623")
        self.assertEquals(time.gmtime(tm)[:6], (2001,12,25,6,15,10))
        # nicknames
        self.assertEquals(C._parseNickname("Mrs.Premise"), "Mrs.Premise")
        # Filenames
        self.assertEquals(C._parseFilename(" ab/c/d"), "ab/c/d")
        self.assertEquals(C._parseFilename("  ~/ab/c/d"),
                          os.path.expanduser("~/ab/c/d"))
        self.assertEquals(C._parseFilename(" 'ab/c d/d' "), "ab/c d/d")
        self.assertEquals(C._parseFilename('  "ab/c d/d" '), "ab/c d/d")

        SC = mixminion.server.ServerConfig
        # Fractions
        self.assertFloatEq(SC._parseFraction("90 %"), .90)
        self.assertFloatEq(SC._parseFraction(" 90%"), .90)
        self.assertFloatEq(SC._parseFraction(".02"), .02)
        self.assertFloatEq(SC._parseFraction("1"), 1)
        self.assertFloatEq(SC._parseFraction("0"), 0)
        self.assertFloatEq(SC._parseFraction("100%"), 1)
        self.assertFloatEq(SC._parseFraction("0%"), 0)
        # Mix algorithms
        self.assertEquals(SC._parseMixRule(" Cottrell"), "CottrellMixPool")
        self.assertEquals(SC._parseMixRule("binomialCottrell"),
                          "BinomialCottrellMixPool")
        self.assertEquals(SC._parseMixRule("TIMED"), "TimedMixPool")
        

        ##
        # Now, try the failing cases.
        def fails(fn, val, self=self):
            self.failUnlessRaises(ConfigError, fn, val)

        fails(C._parseBoolean, "yo")
        fails(C._parseBoolean, "'yo'")
        fails(C._parseBoolean, "")
        fails(C._parseSeverity, "really bad")
        fails(C._parseServerMode, "whatever")
        fails(C._parseInterval, "seconds")
        fails(C._parseInterval, "15")
        fails(C._parseInterval, " 10 intervals")
        fails(C._parseIntervalList, "1 min for 1 min for 1 min")
        fails(C._parseIntervalList, "1 min for 2 fnords")
        fails(C._parseIntervalList, "0 min for 2 hours")
        fails(C._parseIntervalList, "every 30 minutes")
        fails(C._parseInt, "9.9")
        fails(C._parseInt, "9abc")
        fails(C._parseIP, "256.0.0.1")
        fails(C._parseIP, "192.0.0")
        fails(C._parseIP, "192.0.0.0.0")
        fails(C._parseIP, "A.0.0.0")
        fails(pa, "1/1")
        fails(pa, "192.168.0.1 50-40")
        fails(pa, "192.168.0.1 50-9999999")
        fails(C._parseBase64, "Y")
        fails(C._parseHex, "Z")
        fails(C._parseHex, "A")
        fails(C._parseDate, "2000/1/1")
        fails(C._parseDate, "2000/10-10")
        fails(C._parseDate, "2000-10/10")
        fails(C._parseDate, "2000/50/01")
        fails(C._parseDate, "2000/50/01 12:12:12")
        fails(C._parseTime, "2000/50-01 12:12:12")
        fails(C._parseDate, "2000-50/01 12:12:12")
        fails(C._parseDate, "2000-50-01 12:12:12.3")
        fails(C._parseTime, "2000/50/01 12:12:99")
        fails(C._parseNickname, "Mrs Premise")
        fails(C._parseNickname, "../../../AllYourBase")
        fails(C._parseNickname, "Z"*129)
        fails(C._parseNickname, ""*129)
        fails(C._parseNickname, "; rm -f /etc/important;")

        nonexistcmd = '/file/that/does/not/exist'
        if not os.path.exists(nonexistcmd):
            fails(C._parseCommand, nonexistcmd)
        else:
            print 'Whoa. Kurt Go"del would be proud of you.'

        # Nobody would ever have an executable named after my sister's
        # cats, would they?
        nonexistcmd = 'LindenAndPierre -meow'
        try:
            cmd, opts = C._parseCommand(nonexistcmd)
            if os.path.exists(cmd):
                # Ok, I guess they would.
                self.assertEquals(opts, ["-meow"])
            else:
                self.fail("_parseCommand is not working as expected")
        except ConfigError:
            # This is what we expect
            pass

        # Filenames:
        fails(C._parseFilename, " 'ab/cd")

        # IntervalSet validation
        def warns(mixInterval, retryList, self=self):
            ent = mixminion.Config._parseIntervalList(retryList)
            try:
                suspendLog()
                mixminion.server.ServerConfig._validateRetrySchedule(
                    mixInterval, ent, "Section")
            finally:
                r = resumeLog()
            self.assert_(stringContains(r, "[WARN]"))
        warns(30*60, "every .6 hour for 20 hours") # < 1day
        warns(30*60, "every 4 days for 1 month") # > 2 weeks
        warns(30*60, "every 2 days for 4 days") # < twice
        warns(30*60, "every .2 hours for 1 hour, every 1 day for 1 week")#<mix
        warns(30*60, "every 5 days for 1 week") # too few attempts
        warns(30*60, "every 1 hour for 1 week") # too many attempts

        # Fractions
        fails(SC._parseFraction, "90")
        fails(SC._parseFraction, "-.01")
        fails(SC._parseFraction, "101%")
        fails(SC._parseFraction, "1.01")
        fails(SC._parseFraction, "5")
        # Mix algorithms
        fails(SC._parseMixRule, "")
        fails(SC._parseMixRule, "nonesuch")

#----------------------------------------------------------------------
# Server descriptors
SERVER_CONFIG = """
[Server]
EncryptIdentityKey: no
PublicKeyLifetime: 10 days
EncryptPrivateKey: no
Homedir: %s
Mode: relay
Nickname: The_Server
Contact-Email: a@b.c
Comments: This is a test of the emergency
   broadcast system

[Incoming/MMTP]
Enabled = yes
IP: 192.168.0.1
Allow: 192.168.0.16 1-1024
Deny: 192.168.0.16
Allow: *

[Outgoing/MMTP]
Enabled = yes
Allow: *
Retry: every 1 hour for 1 day, every 1 day for 1 week

[Delivery/MBOX]
Enabled: no
Retry: every 1 hour for 1 day, every 1 day for 1 week

"""

SERVER_CONFIG_SHORT = """
[Server]
EncryptIdentityKey: no
PublicKeyLifetime: 10 days
EncryptPrivateKey: no
Homedir: %s
Mode: relay
Nickname: fred-the-bunny
"""

class ServerInfoTests(TestCase):
    def test_ServerInfo(self):
        # Try generating a serverinfo and see if its values are as expected.
        identity = getRSAKey(1, 2048)
        d = mix_mktemp()
        try:
            suspendLog()
            conf = mixminion.server.ServerConfig.ServerConfig(string=(SERVER_CONFIG % mix_mktemp()))
        finally:
            resumeLog()
        if not os.path.exists(d):
            os.mkdir(d, 0700)

        inf = generateServerDescriptorAndKeys(conf,
                                              identity,
                                              d,
                                              "key1",
                                              d)
        info = mixminion.ServerInfo.ServerInfo(string=inf)
        eq = self.assertEquals
        eq(info['Server']['Descriptor-Version'], "0.2")
        eq(info['Incoming/MMTP']['IP'], "192.168.0.1")
        eq(info['Server']['Nickname'], "The_Server")
        self.failUnless(0 <= time.time()-info['Server']['Published'] <= 120)
        self.failUnless(0 <= time.time()-info['Server']['Valid-After']
                          <= 24*60*60)
        eq(info['Server']['Valid-Until']-info['Server']['Valid-After'],
           10*24*60*60)
        eq(info['Server']['Contact'], "a@b.c")
        eq(info['Server']['Software'], "Mixminion %s"%mixminion.__version__)
        eq(info['Server']['Packet-Formats'], "0.3")
        eq(info['Server']['Comments'],
           "This is a test of the emergency broadcast system")

        eq(info['Incoming/MMTP']['Version'], "0.1")
        eq(info['Incoming/MMTP']['Port'], 48099)
        eq(info['Incoming/MMTP']['Protocols'], "0.3")
        eq(info['Outgoing/MMTP']['Version'], "0.1")
        eq(info['Outgoing/MMTP']['Protocols'], "0.3")
        eq(info['Incoming/MMTP']['Allow'], [("192.168.0.16", "255.255.255.255",
                                            1,1024),
                                           ("0.0.0.0", "0.0.0.0",
                                            48099, 48099)] )
        eq(info['Incoming/MMTP']['Deny'], [("192.168.0.16", "255.255.255.255",
                                            0,65535),
                                           ])
        eq(info['Delivery/MBOX'].get('Version'), None)
        # Check the more complex helpers.
        self.assert_(info.isValidated())
        self.assertEquals(info.getIntervalSet(),
                          IntervalSet([(info['Server']['Valid-After'],
                                        info['Server']['Valid-Until'])]))

        self.assert_(not info.isExpiredAt(time.time()))
        self.assert_(not info.isExpiredAt(time.time()-25*60*60))
        self.assert_(info.isExpiredAt(time.time()+24*60*60*30))

        self.assert_(info.isValidAt(time.time()))
        self.assert_(not info.isValidAt(time.time()-25*60*60))
        self.assert_(not info.isValidAt(time.time()+24*60*60*30))

        self.assert_(info.isValidFrom(time.time(), time.time()+60*60))
        self.assert_(not info.isValidFrom(time.time()-25*60*60,
                                          time.time()+60*60))
        self.assert_(not info.isValidFrom(time.time()-25*60*60,
                                          time.time()+24*60*60*30))
        self.assert_(not info.isValidFrom(time.time(),
                                          time.time()+24*60*60*30))
        self.assert_(not info.isValidFrom(time.time()-25*60*60,
                                          time.time()-23*60*60))
        self.assert_(not info.isValidFrom(time.time()+24*60*60*30,
                                          time.time()+24*60*60*31))

        self.assert_(info.isValidAtPartOf(time.time(), time.time()+60*60))
        self.assert_(info.isValidAtPartOf(time.time()-25*60*60,
                                          time.time()+60*60))
        self.assert_(info.isValidAtPartOf(time.time()-25*60*60,
                                          time.time()+24*60*60*30))
        self.assert_(info.isValidAtPartOf(time.time(),
                                          time.time()+24*60*60*30))
        self.assert_(not info.isValidAtPartOf(time.time()-40*60*60,
                                              time.time()-39*60*60))
        self.assert_(not info.isValidAtPartOf(time.time()+24*60*60*30,
                                              time.time()+24*60*60*31))

        self.assert_(info.isNewerThan(time.time()-60*60))
        self.assert_(not info.isNewerThan(time.time()+60))

        # Now check whether we still validate the same after some corruption
        self.assertStartsWith(inf, "[Server]\n")
        self.assertEndsWith(inf, "\n")
        self.assert_(stringContains(inf, "b.c\n"))
        inf2 = inf.replace("[Server]\n", "[Server] \r")
        inf2 = inf2.replace("b.c\n", "b.c\r\n")
        inf2 = inf2.replace("0.1\n", "0.1  \n")
        mixminion.ServerInfo.ServerInfo(string=inf2)

        # Make sure we accept an extra key.
        inf2 = inf+"Unexpected-Key: foo\n"
        inf2 = mixminion.ServerInfo.signServerInfo(inf2, identity)
        try:
            suspendLog()
            mixminion.ServerInfo.ServerInfo(string=inf2)
        finally:
            s = resumeLog()
        self.assert_(stringContains(s,"Unrecognized key Unexpected-Key on line"))

        # Now make sure everything was saved properly
        keydir = os.path.join(d, "key_key1")
        eq(inf, readFile(os.path.join(keydir, "ServerDesc")))
        mixminion.server.ServerKeys.ServerKeyset(d, "key1", d) # Can we load?
        packetKey = Crypto.pk_PEM_load(
            os.path.join(keydir, "mix.key"))
        eq(packetKey.get_public_key(),
           info['Server']['Packet-Key'].get_public_key())
        eq(Crypto.sha1(identity.encode_key(1)),
           info['Incoming/MMTP']['Key-Digest'])

        # Now check the digest and signature
        identityPK = info['Server']['Identity']
        pat = re.compile(r'^(Digest:|Signature:).*$', re.M)
        x = sha1(pat.sub(r'\1', inf))

        eq(info['Server']['Digest'], x)
        eq(x, Crypto.pk_check_signature(info['Server']['Signature'],
                                                  identityPK))

        # Now check pickleability
        pickled = cPickle.dumps(info, 1)
        loaded = cPickle.loads(pickled)
        eq(info['Server']['Digest'], loaded['Server']['Digest'])
        eq(info['Server']['Identity'].get_public_key(),
           loaded['Server']['Identity'].get_public_key())
        eq(info['Server']['Published'], loaded['Server']['Published'])
        eq(info.isValidated(), loaded.isValidated())

        # Now with a shorter configuration
        try:
            suspendLog()
            conf = mixminion.server.ServerConfig.ServerConfig(string=(SERVER_CONFIG_SHORT%mix_mktemp())+
                                           """[Incoming/MMTP]
Enabled: yes
IP: 192.168.0.99
""")
        finally:
            resumeLog()
        generateServerDescriptorAndKeys(conf,
                                        identity,
                                        d,
                                        "key2",
                                        d)
        # Now with a bad signature
        sig2 = Crypto.pk_sign(sha1("Hello"), identity)
        sig2 = base64.encodestring(sig2).replace("\n", "")
        sigpat = re.compile('^Signature:.*$', re.M)
        badSig = sigpat.sub("Signature: %s" % sig2, inf)
        self.failUnlessRaises(ConfigError,
                              mixminion.ServerInfo.ServerInfo,
                              None, badSig)

        # But make sure we don't check the sig on assumeValid
        mixminion.ServerInfo.ServerInfo(None, badSig, assumeValid=1)

        # Now with a bad digest
        badSig = inf.replace("a@b.c", "---")
        self.failUnlessRaises(ConfigError,
                              mixminion.ServerInfo.ServerInfo,
                              None, badSig)

        # Test superseding
        ServerInfo = mixminion.ServerInfo.ServerInfo
        examples = getExampleServerDescriptors()
        bobs = [ ServerInfo(string=s, assumeValid=1) for s in examples["Bob"] ]
        freds= [ ServerInfo(string=s, assumeValid=1) for s in examples["Fred"]]
        self.assert_(bobs[1].isSupersededBy([bobs[3], bobs[4]]))
        self.assert_(not bobs[1].isSupersededBy([bobs[3], bobs[5]]))
        self.assert_(not bobs[1].isSupersededBy([]))
        self.assert_(not bobs[1].isSupersededBy([bobs[1]]))
        self.assert_(not bobs[1].isSupersededBy([freds[2]]))

        # Test whether we ignore server descriptors with unknown versions.
        try:
            inf2 = inf.replace("Descriptor-Version: 0.2\n",
                               "Descriptor-Version: 0.99\n")
            inf2 = inf2.replace("\nIP: ", "\nIP: x.")
            inf2 = inf2.replace("\nNickname: ", "\nNickname-XX: ")
            ServerInfo(string=inf2)
            self.fail("Missing ConfigError")
        except ConfigError, p:
            self.assertEquals(str(p), "Unrecognized descriptor version: 0.99")

        # Try regenerating server descriptor with existing keys.
        key2 = mixminion.server.ServerKeys.ServerKeyset(d, "key2", d)
        key2.load()
        try:
            suspendLog()
            conf = mixminion.server.ServerConfig.ServerConfig(
                string=(SERVER_CONFIG_SHORT%mix_mktemp())+
                                           """[Incoming/MMTP]
Enabled: yes
IP: 192.168.100.3
[Delivery/SMTP]
Enabled: yes
ReturnAddress: X@Y.Z
""")
            conf2 =  mixminion.server.ServerConfig.ServerConfig(
                string=(SERVER_CONFIG_SHORT%mix_mktemp())+
                                           """[Incoming/MMTP]
Enabled: yes
IP: 192.168.100.4
""")
        finally:
            resumeLog()

        _ = generateServerDescriptorAndKeys(conf,
                                            identity,
                                            d,
                                            "key2",
                                            d,
                                            useServerKeys=1)

        key3 = mixminion.server.ServerKeys.ServerKeyset(d, "key2", d)
        key3.load()
        info3 = key3.getServerDescriptor()
        self.assertEquals(key3.getMMTPKey().get_public_key(),
                          key2.getMMTPKey().get_public_key())
        self.assertEquals(key3.getPacketKey().get_public_key(),
                          key2.getPacketKey().get_public_key())
        eq(info3['Incoming/MMTP']['IP'], "192.168.100.3")
        self.assert_('smtp' in info3.getCaps())

        key3.regenerateServerDescriptor(conf2, identity)
        info3 = key3.getServerDescriptor()
        eq(info3['Incoming/MMTP']['IP'], "192.168.100.4")

    def test_directory(self):
        eq = self.assertEquals
        examples = getExampleServerDescriptors()
        ServerList = mixminion.directory.ServerList.ServerList
        ServerDirectory = mixminion.ServerInfo.ServerDirectory
        baseDir = mix_mktemp()
        dirArchiveDir = os.path.join(baseDir, "dirArchive")
        lst = ServerList(baseDir)

        identity = Crypto.pk_generate(2048)

        now = time.time()
        dayLater = now + 60*60*24
        # Try a couple of simple inserts
        lst.importServerInfo(examples["Fred"][1]) # from day -9 through day 0.
        lst.importServerInfo(examples["Fred"][3]) # from day 11 through day 20
        lst.importServerInfo(examples["Lola"][0]) # from day -2 through day 2
        lst.importServerInfo(examples["Lola"][1]) # From day 0 through day 4.
        # Now, check whether the guts of lst are correct.
        eq(len(lst.servers), 4)
        eq(len(lst.serversByNickname), 2)
        eq(len(lst.serversByNickname['fred']), 2)
        eq(len(lst.serversByNickname['lola']), 2)
        eq(readFile(os.path.join(baseDir, "servers",
                                 lst.serversByNickname['fred'][0])),
           examples["Fred"][1])
        # Now generate a directory...
        lst.generateDirectory(now, dayLater, 0,
                              identity, now)
        # (Fred1, and Lola1 should get included.)
        d = readFile(lst.getDirectoryFilename())
        self.assertStartsWith(d, "[Directory]\n")
        eq(2, d.count("[Server]\n"))
        self.assert_(stringContains(d, examples["Fred"][1]))
        self.assert_(stringContains(d, examples["Lola"][1]))

        # Did a backup directory get made?
        eq(1, len(os.listdir(dirArchiveDir)))
        # Validate the directory, and check that values are as expected.
        sd = ServerDirectory(d)
        eq(len(sd.getServers()), 2)
        eq(sd["Directory"]["Version"], "0.2")
        eq(sd["Directory"]["Published"], int(now))
        eq(sd["Directory"]["Valid-After"], previousMidnight(now))
        eq(sd["Directory"]["Valid-Until"], previousMidnight(dayLater+1))
        eq(sd["Signature"]["DirectoryIdentity"].get_public_key(),
           identity.get_public_key())

        # Try changing the directory, and verify that it doesn't check out
        dBad = d.replace("Fred", "Dref")
        self.failUnlessRaises(ConfigError, ServerDirectory, dBad)
        # Bad digest.
        dBad = re.compile(r"^DirectoryDigest: ........", re.M).sub(
            "DirectoryDigest: ZZZZZZZZ", d)
        self.failUnlessRaises(ConfigError, ServerDirectory, dBad)
        # Bad signature.
        dBad = re.compile(r"^DirectorySignature: ........", re.M).sub(
            "DirectorySignature: ZZZZZZZZ", d)
        self.failUnlessRaises(ConfigError, ServerDirectory, dBad)

        # Can we use messed-up spaces and line-endings?
        ServerDirectory(d.replace("\n", "\r\n"))
        ServerDirectory(d.replace("\n", "\r"))
        ServerDirectory(re.sub(r"Fred$", "Fred  ", d))

        ### Now, try rescanning the directory.
        lst = ServerList(baseDir)
        eq(len(lst.servers), 4)
        eq(len(lst.serversByNickname), 2)
        eq(len(lst.serversByNickname['fred']), 2)
        eq(len(lst.serversByNickname['lola']), 2)
        lst.generateDirectory(now, dayLater, 0,
                              identity)
        d2 = readFile(lst.getDirectoryFilename())
        sd2 = ServerDirectory(d2)
        self.assertEquals(2, len(sd2.getServers()))

        # Now try cleaning servers.   First, make sure we can't insert
        # an expired server.
        self.failUnlessRaises(MixError,
                              lst.importServerInfo, examples["Fred"][0])
        # Now, make sure we can't insert a superseded server.
        lst.importServerInfo(examples["Bob"][3])
        lst.importServerInfo(examples["Bob"][4])
        self.failUnlessRaises(MixError,
                              lst.importServerInfo, examples["Bob"][1])
        # Now, start with a fresh list, so we can try superseding bob later.
        baseDir = mix_mktemp()
        archiveDir = os.path.join(baseDir, "archive")
        serverDir = os.path.join(baseDir, "servers")
        lst = ServerList(baseDir)
        # Make sure that when we remove the last of a given server, we
        # still know its ID.
        lst.importServerInfo(examples["Lisa"][1]) # Valid for 2 days.
        lst.clean(now=now+60*60*24*100) # Very far in the future
        eq(0, len(lst.servers))
        eq(1, len(os.listdir(archiveDir)))
        lst.rescan()
        eq(0, len(lst.servers))
        self.assertNotEquals(None, lst.serverIDs.get('lisa'))
        # But we _do_ remove expired servers if others exist.
        lst.importServerInfo(examples["Lisa"][2]) # Valid from 5...7.
        eq(1, len(lst.servers))
        eq(1, len(lst.serversByNickname["lisa"]))
        lst.clean(now=now+60*60*24*100) # Very far in the future.
        eq(0, len(lst.servers))
        eq(0, len(lst.serversByNickname.get("lisa",[])))

        # (Make sure that knownOnly works: failing case.)
        self.failUnlessRaises(MixError, lst.importServerInfo,
                              examples["Bob"][0], 1)

        ### Now test the removal of superseded servers.
        # Clean out archiveDir first so we can see what gets removed.
        for a in os.listdir(archiveDir):
            os.unlink(os.path.join(archiveDir, a))

        # Add a bunch of unconflicting Bobs.
        lst.importServerInfo(examples["Bob"][0]) # From -2 to 1
        # (Make sure that knownOnly works: succeeding case.
        lst.importServerInfo(examples["Bob"][1], 1) # From  2 to 5
        lst.importServerInfo(examples["Bob"][2]) # From  6 to 9
        lst.importServerInfo(examples["Bob"][3]) # Newer, from 0 to 3
        eq(4, len(lst.servers))
        # Right now, nothing is superseded or expired
        lst.clean()
        eq(4, len(os.listdir(serverDir)))
        eq(4, len(lst.serversByNickname["bob"]))
        lst.importServerInfo(examples["Bob"][4]) # Newer, from 4 to 7.
        # Now "Bob1" is superseded.
        lst.clean()
        eq(1, len(os.listdir(archiveDir)))
        eq(4, len(lst.serversByNickname["bob"]))
        eq(4, len(os.listdir(serverDir)))
        eq(4, len(lst.servers))
        eq(readFile(os.path.join(archiveDir, os.listdir(archiveDir)[0])),
           examples["Bob"][1])
        for fn in lst.serversByNickname["bob"]:
            fn = os.path.join(serverDir, fn)
            self.assertNotEquals(readFile(fn), examples["Bob"][1])
        # Now try rescanning...
        lst = ServerList(baseDir)
        eq(4, len(lst.servers))
        eq(4, len(lst.serversByNickname["bob"]))
        # ... adding a new bob...
        lst.importServerInfo(examples["Bob"][5])
        eq(5, len(lst.servers))
        # ... and watching another old bob get bonked off.
        lst.clean()
        eq(4, len(lst.servers))
        eq(2, len(os.listdir(archiveDir)))


#----------------------------------------------------------------------
# EventStats
class EventStatsTests(TestCase):
    def testNilLog(self):
        import mixminion.server.EventStats as ES
        ES.configureLog({'Server': {'LogStats' : 0}})
        self.failUnless(isinstance(ES.log, ES.NilEventLog))
        ES.log.receivedPacket()
        ES.log.attemptedRelay()
        ES.log.failedRelay()
        ES.log.unretriableRelay()

    def testEventLog(self):
        import mixminion.server.EventStats as ES
        tm = time.time()
        eq = self.assertEquals
        homedir = mix_mktemp()
        ES.configureLog({'Server':
                         {'LogStats' : 1,
                          'Homedir' : homedir,
                 'StatsInterval' : mixminion.Config._parseInterval("1 hour")}})
        self.failUnless(isinstance(ES.log, ES.EventLog))
        # Test all commands
        ES.log.receivedPacket()
        ES.log.attemptedRelay()
        ES.log.failedRelay()
        ES.log.unretriableRelay()
        ES.log.attemptedDelivery()
        ES.log.attemptedDelivery()
        ES.log.attemptedDelivery("Y")
        ES.log.attemptedDelivery("Y")
        ES.log.successfulDelivery()
        ES.log.failedDelivery()
        ES.log.failedDelivery("Y")
        ES.log.unretriableDelivery("Y")
        ES.log.save(now=tm)
        eq(ES.log.count['UnretriableDelivery']['Y'], 1)
        eq(ES.log.count['AttemptedDelivery'][None], 2)
        # Test reload.
        ES.configureLog({'Server':
                         {'LogStats' : 1,
                          'Homedir' : homedir,
                 'StatsInterval' : mixminion.Config._parseInterval("1 hour")}})
        eq(ES.log.count['AttemptedDelivery']['Y'], 2)
        # Test dump
        buf = cStringIO.StringIO()
        ES.log.dump(buf)
        sOrig = buf.getvalue()
        s = "\n".join(sOrig.split("\n")[1:])
        expected = """\
  ReceivedPacket: 1
  ReceivedConnection: 0
  AttemptedConnect: 0
  SuccessfulConnect: 0
  FailedConnect: 0
  AttemptedRelay: 1
  SuccessfulRelay: 0
  FailedRelay: 1
  UnretriableRelay: 1
  AttemptedDelivery:
     {Unknown}: 2
             Y: 2
         Total: 4
  SuccessfulDelivery: 1
  FailedDelivery:
     {Unknown}: 1
             Y: 1
         Total: 2
  UnretriableDelivery:
             Y: 1
         Total: 1
"""
        eq(s, expected)
        # Test time accumulation.
        ES.log.save(now=tm+1800)
        self.assert_(abs(1800-ES.log.accumulatedTime) < 10)
        self.assertEquals(ES.log.lastSave, tm+1800)
        ES.log.lastSave = tm+1900
        ES.log.save(now=tm+2000)
        self.assert_(abs(1900-ES.log.accumulatedTime) < 10)
        # Test rotate
        ES.log.rotate(now=tm+3600*24)
        s2 = readFile(os.path.join(homedir, "stats"))
        eq(s2.split("\n")[1:], sOrig.split("\n")[1:])
        eq(ES.log.count['UnretriableDelivery'], {})
        eq(ES.log.lastSave, tm+3600*24)
        eq(ES.log.accumulatedTime, 0)
        self.assert_((ES.log.nextRotation - (tm+3600*25)) < 3600)
        ES.configureLog({'Server':
                         {'LogStats' : 1,
                          'Homedir' : homedir,
                 'StatsInterval' : mixminion.Config._parseInterval("1 hour")}})
        eq(ES.log.count['UnretriableDelivery'], {})
        self.assertFloatEq(ES.log.lastSave, time.time())

        # Test time configured properly.
        # 1) Rotation interval is a multiple of hours.
        pm = previousMidnight(tm)
        ES.log.rotateInterval = 2*60*60
        # 1A) Accumulated time << interval.  We rotated at 23:00.  We were
        #   only up for a few minutes (10), and have accumulated no more time
        #   since the last rotation.  We just reloaded; now it's 2:00.  We
        #   should next rotate at 4 -- since it will take us until 3:20 to
        #   be up for 75% of an interval, and we round up.
        ES.log.lastRotation = pm - 60*60
        ES.log.accumulatedTime = 10*60
        ES.log.lastSave = pm+7200
        ES.log._setNextRotation(now=pm+7200)
        eq(ES.log.getNextRotation(), pm+4*60*60)
        # But suppose that it's 2:45. We should next rotate at 5 (rounding up).
        ES.log.lastSave = pm+7200+45*60
        ES.log._setNextRotation(now=pm+7200+45*60)
        eq(ES.log.getNextRotation(), pm+5*60*60)

        # 1B) Accumulated time ~~ interval
        # Now suppose the same situation as above, but we've been up 100
        #  minutes total.  We rotate *now*.
        ES.log.accumulatedTime = 100*60
        ES.log.lastSave = pm+7200
        ES.log._setNextRotation(now=pm+7200)
        eq(ES.log.getNextRotation(), pm+7200)

        # 1C) Suppose all went well, and it's 23:30: Rotate at 1.
        ES.log.accumulatedTime = 1800
        ES.log.lastSave = pm-1800
        ES.log._setNextRotation(now=pm-1800)
        eq(ES.log.getNextRotation(), pm+3600)

        # 2) Rotation interval is not a multiple of hours: We don't round
        # 2A) Accumulated time << interval
        ES.log.rotateInterval = 40*60
        ES.log.lastSave = pm+7200
        ES.log.accumulatedTime = 10*60
        ES.log._setNextRotation(now=pm+7200)
        eq(ES.log.getNextRotation(), pm+7200+20*60)
        # 2B) Accumulated time ~~ interval
        ES.log.accumulatedTime = 35*60
        ES.log.lastSave = pm+7200
        ES.log._setNextRotation(now=pm+7200)
        eq(ES.log.getNextRotation(), pm+7200)

#----------------------------------------------------------------------
# Modules and ModuleManager

# Text of an example module that we load dynamically.
EXAMPLE_MODULE_TEXT = \
"""
import mixminion.server.Modules
from mixminion.Config import ConfigError

class TestModule(mixminion.server.Modules.DeliveryModule):
    def __init__(self):
        self.processedMessages = []
        self.processedAll = []
    def getName(self):
        return "TestModule"
    def getConfigSyntax(self):
        return { "Example" : { "Foo" : ("REQUIRE",
                                        mixminion.Config._parseInt, None) } }
    def validateConfig(self, cfg, lines, contents):
        if cfg['Example'] is not None:
            if cfg['Example'].get('Foo',1) % 2 == 0:
                raise ConfigError("Foo was even")
    def getRetrySchedule(self):
        return [.1] *100
    def configure(self,cfg, manager):
        if cfg['Example']:
            self.enabled = 1
            self.foo = cfg['Example'].get('Foo',1)
            manager.enableModule(self)
        else:
            self.foo = None
            self.enabled = 0
    def getServerInfoBlock(self):
        if self.enabled:
            return "[Example]\\nFoo: %s\\n" % self.foo
        else:
            return None
    def getExitTypes(self):
        return (1234,)
    def processMessage(self, packet):
        self.processedMessages.append(packet.getContents())
        self.processedAll.append( packet )
        exitInfo = packet.getAddress()
        if exitInfo == 'fail?':
            return mixminion.server.Modules.DELIVER_FAIL_RETRY
        elif exitInfo == 'fail!':
            return mixminion.server.Modules.DELIVER_FAIL_NORETRY
        else:
            return mixminion.server.Modules.DELIVER_OK
"""

class ModuleManagerTests(TestCase):
    def testModuleManager(self):
        FDP = FakeDeliveryPacket
        mod_dir = mix_mktemp()
        home_dir = mix_mktemp()

        # Create an example module, and try to load it.
        os.mkdir(mod_dir, 0700)
        writeFile(os.path.join(mod_dir, "ExampleMod.py"),
                  EXAMPLE_MODULE_TEXT)

        cfg_test = (SERVER_CONFIG_SHORT%home_dir) + """
ModulePath = %s
Module ExampleMod.TestModule
[Example]
Foo: 99
[Incoming/MMTP]
Enabled: yes
IP: 1.0.0.1
""" % (mod_dir)

        try:
            suspendLog()
            conf = mixminion.server.ServerConfig.ServerConfig(string=cfg_test)
        finally:
            resumeLog()
        manager = conf.getModuleManager()
        exampleMod = None
        for m in manager.modules:
            if m.getName() == "TestModule":
                exampleMod = m
        self.failUnless(exampleMod is not None)
        # Configure the new module, and make sure it recognizes its own config.
        manager.configure(conf)

        # Make sure the module enables itself.
        self.failUnless(exampleMod is manager.typeToModule[1234])

        # Try sending a few messages to the module.
        t = "ZZZZ"*5
        manager.queueDecodedMessage(FDP('plain',1234,'fail!',"Hello 1", t))
        manager.queueDecodedMessage(FDP('plain',1234,'fail?',"Hello 2", t))
        manager.queueDecodedMessage(FDP('plain',1234,'good',"Hello 3", t))
        manager.queueDecodedMessage(FDP('plain',
                                        mixminion.Packet.DROP_TYPE, "",
                                        "Drop very much", t))
        queue = manager.queues['TestModule']
        # Did the test module's delivery queue get the messages?
        self.failUnless(isinstance(queue,
                           mixminion.server.Modules.SimpleModuleDeliveryQueue))
        self.assertEquals(3, queue.count())
        # Has it processed any yet? (No.)
        self.assertEquals(exampleMod.processedMessages, [])
        # Now, tell the module to deliver the messages.
        try:
            suspendLog()
            manager.sendReadyMessages()
        finally:
            resumeLog()
        # There should be one message (the retriable one) left in the queue.
        self.assertEquals(1, queue.count())
        # It should have processed all three.
        self.assertEquals(3, len(exampleMod.processedMessages))
        # If we try to send again, the second message should get re-sent.
        time.sleep(.15) # so we retry.
        manager.sendReadyMessages()
        self.assertEquals(1, queue.count())
        self.assertEquals(4, len(exampleMod.processedMessages))
        self.assertEquals("Hello 2", exampleMod.processedMessages[-1])

        self.assert_(exampleMod.processedAll[0].isPlaintext())

        # Check serverinfo generation.
        try:
            suspendLog()
            info = generateServerDescriptorAndKeys(
                conf, getRSAKey(0,2048), home_dir, "key11", home_dir)
            self.failUnless(stringContains(info,"\n[Example]\nFoo: 99\n"))
        finally:
            resumeLog()

        # Try again, this time with the test module disabled.
        #
        cfg_test = (SERVER_CONFIG_SHORT%home_dir) + """
ModulePath = %s
Module ExampleMod.TestModule
""" % (mod_dir)

        try:
            suspendLog()
            conf = mixminion.server.ServerConfig.ServerConfig(string=cfg_test)
        finally:
            resumeLog()
        manager = conf.getModuleManager()
        exampleMod = None
        for m in manager.modules:
            if m.getName() == "TestModule":
                exampleMod = m
        self.failUnless(exampleMod is not None)
        manager.configure(conf)

        self.failIf(exampleMod is manager.typeToModule.get(1234))

        # Failing validation
        cfg_test = SERVER_CONFIG_SHORT%home_dir + """
ModulePath = %s
Module ExampleMod.TestModule
[Example]
Foo: 100
""" % (mod_dir)

        # FFFF Add tests for catching exceptions from buggy modules

    def testDecoding(self):
        'test decoding and test encapsulation.'
        eme = mixminion.server.Modules._escapeMessageForEmail

        message = "Somebody set up us the module!\n\n(What you say?)\n"
        binmessage = hexread("00ADD1EDC0FFEED00DAD")*40
        tag = ".!..!....!........!."

        def FDPFast(type,message,tag="xyzzyxyzzyxyzzyxyzzy"):
            return FakeDeliveryPacket(type,0xFFFE,"addr",message,tag)

        ####
        # Tests escapeMessageForEmail
        self.assert_(stringContains(eme(FDPFast('plain',message)), message))
        expect = "-----\nMessage-type: binary\n\n"+\
                 encodeBase64(binmessage)+"-----"
        self.assert_(stringContains(eme(FDPFast('plain',binmessage)), expect))
        expect = "-----\nMessage-type: encrypted\nDecoding-handle: "+\
                 base64.encodestring(tag)+"\n"+\
                 encodeBase64(binmessage)+"-----"
        self.assert_(stringContains(eme(FDPFast('enc',binmessage,tag)),
                                    expect))

# Sample address file for testing MBOX
MBOX_ADDRESS_SAMPLE = """\
# This is a sample address file
mix-minion: mixminion@thishost

mixdaddy: mixminion@thathost
mixdiddy=mixminion@theotherhost
"""

# The message we expect MBOX to deliver.
MBOX_EXPECTED_MESSAGE = """\
To: mixminion@theotherhost
From: returnaddress@x
Subject: Type III Anonymous Message
X-Anonymous: yes

THIS IS AN ANONYMOUS MESSAGE.  The mixminion server 'nickname' at
<Unknown IP> has been configured to deliver messages to your address.
If you do not want to receive messages in the future, contact removeaddress@x
and you will be removed.

This message is not in plaintext.  It's either 1) a reply; 2) a forward
message encrypted to you; or 3) junk.

-----BEGIN TYPE III ANONYMOUS MESSAGE-----
Message-type: encrypted
Decoding-handle: eHh4eHh4eHh4eHh4eHh4eHh4eHg=

7/rOqx76yt7v+s6rHvrK3u/6zqse+sre7/rOqx76yt7v+s6rHvrK3u/6zqse+sre
7/rOqx76yt7v+s6rHvrK3u/6zqse+sre7/rOqx76yt7v+s6rHvrK3u/6zqse+sre
7/rOqx76yt7v+s6rHvrK3u/6zqse+sre7/rOqx76yt7v+s6rHvrK3u/6zqse+sre
7/rOqx76yt7v+s6rHvrK3g==
-----END TYPE III ANONYMOUS MESSAGE-----
"""

EXAMPLE_ADDRESS_SET = """
deny User freD
Deny User  mr-ed
# Comment
Deny onehost sally
DENY onehost  HOGWARTS.k12
# Another comment, followed by a blank line
dENY allhosts  deathstar.gov
deny allhosts selva-Oscura.it
deny onehost selva-Oscura.it

deny Address  jim@sMith.com
deny pattern    /nyet.*Nyet/

"""

class FakeDeliveryPacket(mixminion.server.PacketHandler.DeliveryPacket):
    """Stub version of DeliveryPacket used for testing modules"""
    def __init__(self, type, exitType, exitAddress, contents, tag=None,
                 headers = {}):
        if tag is None:
            tag = "-="*10
        mixminion.server.PacketHandler.DeliveryPacket.__init__(self,
                        exitType, exitAddress, "Z"*16, tag, "Q"*(28*1024))
        self.type = type
        self.headers = headers
        self.payload = None
        self.contents = contents

class ModuleTests(TestCase):
    def testEmailAddressSet(self):
        EmailAddressSet = mixminion.server.Modules.EmailAddressSet
        def has(set, item, self=self):
            self.assert_(isSMTPMailbox(item), "Invalid address "+item)
            self.failUnless(set.contains(item), "Set should contain "+item)
        def hasNo(set, item, self=self):
            self.assert_(isSMTPMailbox(item), "Invalid address "+item)
            self.failIf(set.contains(item), "Set should not contain "+item)

        # Basic functionality: Match what we're supposed to match
        set = EmailAddressSet(string=EXAMPLE_ADDRESS_SET)
        for _ in 1,2:
            has(set,"jim@smith.com")
            has(set,"freD@fred.com") #(by user....)
            has(set,"fred@x")
            has(set,"fred@boba-fred")
            has(set,"MR-ED@wilburs-barn.com")
            has(set,"Fred@Fred")
            has(set,"Fred@Sally") #(by domains and subdomains...)
            has(set,"joe@SALLY")
            has(set,"h.potter@hogwarts.K12")
            has(set,"nobody@sally")
            has(set,"dante@selva-oscura.it")
            has(set,"dante@camin.selva-oscura.it")
            has(set,"dante@nel.camin.selva-oscura.it")
            has(set,"cushing@deathstar.gov")
            has(set,"cushing@operational.deathstar.gov")
            has(set,"cushing@fully.operational.deathstar.gov")
            has(set,"nyet.jones@nyet.net")
            has(set,"octavio.nyet.jones@nyet.net")
            has(set,"octavio.jones@nyet.nyet.net")

            # Basic functionality: Don't match anything else.
            hasNo(set,"mojo@jojo.com")
            hasNo(set,"mr-fred@wilburs-barn.com") # almost by user
            hasNo(set,"joe@sally.com") # almost by domain...
            hasNo(set,"joe@bob.sally.com")
            hasNo(set,"joe@bob.sally")
            hasNo(set,"dante@other.it")
            hasNo(set,"cushing@gov")
            hasNo(set,"cushing@deathstar.gov.mit.edu")
            hasNo(set,"nyet.jones@net")
            hasNo(set,"jones@nyet.net")

            # Load from file, then try again!
            fn = mix_mktemp()
            writeFile(fn, EXAMPLE_ADDRESS_SET)
            set = EmailAddressSet(fname=fn)

        # Failing cases: invalid addresses needn't give a right answer, but
        # we need to do something reasonable for invalid files.
        def bad(s,self=self):
            self.assertRaises(ConfigError,
                              mixminion.server.Modules.EmailAddressSet,
                              string=s)

        bad("Address foo@bar.baz")
        bad("deny Address foo@bar@baz")
        bad("deny Rumplestiltskin")
        bad("deny bob@bob.com")
        bad("deny user fred@bob")
        bad("deny address foo")
        bad("deny onehost foo@")
        bad("deny onehost @foo")
        bad("deny allhosts foo@bar")
        bad("deny pattern a.*b")
        bad("deny pattern /a.*b")
        bad("deny pattern a.*b/")
        bad("deny onehost")
        bad("deny user")
        bad("deny pattern")
        bad("deny allhosts")

    def testMixmasterSMTP(self):
        """Check out the SMTP-Via-Mixmaster module.  (We temporarily replace
           os.spawnl with a stub function so that we don't actually send
           anything."""
        manager = self.getManager()
        FDP = FakeDeliveryPacket

        # Configure the module.
        module = mixminion.server.Modules.MixmasterSMTPModule()
        module.configure({"Delivery/SMTP-Via-Mixmaster" :
                          {"Enabled":1, "Server": "nonesuch",
                           "Retry": [0,0,0,0],
                           "SubjectLine":'foobar',
                           "FromTag" : '[NotReally]',
                           'MixCommand' : ('ls', ['-z']),
                           "MaximumSize" : 32*1024,
                           }},
                         manager)
        queue = manager.queues['SMTP_MIX2']
        replaceFunction(os, "spawnl")
        try:
            # Send a message...
            queue.queueDeliveryMessage(FDP('plain', SMTP_TYPE, "foo@bar",
                                           "This is the message"))
            queue.sendReadyMessages()
            # And make sure that Mixmaster was invoked correctly.
            calls = getReplacedFunctionCallLog()
            self.assertEquals('spawnl', calls[0][0])
            mixfn, mixargs = calls[0][1][2], calls[0][1][3:]
            self.assertEquals("ls", mixfn)
            self.assertEquals(mixargs[:-1],
                              ('-z', '-l', 'nonesuch'))
            # ...and, if the temporary file it used hasn't been removed yet,
            # that it contains the correct data.
            fn = mixargs[-1]
            fn = os.path.join(os.path.split(fn)[0],
                              "rmv_"+os.path.split(fn)[1][4:])
            m = readFile(fn)
            self.assertStartsWith(m,
                "To: foo@bar\nFrom: nobody\n"
                "Subject: foobar\nX-Anonymous: yes\n\n")
            self.assert_(stringContains(m, "This is the message"))

            ## What about the flush command?
            self.assertEquals("spawnl", calls[-1][0])
            sendfn, sendargs = calls[-1][1][2], calls[-1][1][3:]
            self.assertEquals("ls", sendfn)
            self.assertEquals(sendargs, ('-S',))

            clearReplacedFunctionCallLog()

            # Send another message, with headers.
            queue.queueDeliveryMessage(
                FDP('plain', SMTP_TYPE, "foo@bar",
                    "This is the message",
                    headers={"FROM":"Mal", "SUBJECT":"Fnord"}))
            queue.sendReadyMessages()
            calls = getReplacedFunctionCallLog()
            mixfn, mixargs = calls[0][1][2], calls[0][1][3:]
            fn = mixargs[-1]
            fn = os.path.join(os.path.split(fn)[0],
                              "rmv_"+os.path.split(fn)[1][4:])
            m = readFile(fn)
            self.assertEquals(m, '''\
To: foo@bar
From: "[NotReally] Mal" <nobody>
Subject: Fnord
X-Anonymous: yes

-----BEGIN TYPE III ANONYMOUS MESSAGE-----
Message-type: plaintext

This is the message
-----END TYPE III ANONYMOUS MESSAGE-----
''')

        finally:
            undoReplacedAttributes()
            clearReplacedFunctionCallLog()

    def testDirectSMTP(self):
        """Check out the SMTP module.  (We temporarily replace sendSMTPMessage
           with a stub function so that we don't actually send anything.)"""
        FDP = FakeDeliveryPacket

        blacklistFile = mix_mktemp()
        writeFile(blacklistFile, "Deny onehost wangafu.net\nDeny user fred\n")

        manager = self.getManager("""[Delivery/SMTP]
Enabled: yes
SMTPServer: nowhere
BlacklistFile: %s
Message: Avast ye mateys!  Prepare to be anonymized!
ReturnAddress: yo.ho.ho@bottle.of.rum
SubjectLine: Arr! This be a Type III Anonymous Message
        """ % blacklistFile)

        module = manager.nameToModule["SMTP"]
        queue = manager.queues["SMTP"]
        queueMessage = queue.queueDeliveryMessage

        # Make sure blacklist got read.
        self.assert_(module.blacklist.contains("nobody@wangafu.net"))

        # Stub out sendSMTPMessage.
        replaceFunction(mixminion.server.Modules, 'sendSMTPMessage',
                        lambda *args: mixminion.server.Modules.DELIVER_OK)

        try:
            haiku = ("Hidden, we are free\n"+
                     "Free to speak, to free ourselves\n"+
                     "Free to hide no more.")

            # Try queueing a valid message and sending it.
            queueMessage(FDP('plain', SMTP_TYPE, "users@everywhere", haiku))
            self.assertEquals(getReplacedFunctionCallLog(), [])
            queue.sendReadyMessages()
            # Was sendSMTPMessage invoked correctly?
            calls = getReplacedFunctionCallLog()
            self.assertEquals(1, len(calls))
            fn, args, _ = calls[0]
            self.assertEquals("sendSMTPMessage", fn)
            #server, toList, fromAddr, message
            self.assertEquals(('nowhere',
                               ['users@everywhere'],
                               'yo.ho.ho@bottle.of.rum'),
                              args[:3])
            EXPECTED_SMTP_PACKET = """\
To: users@everywhere
From: yo.ho.ho@bottle.of.rum
Subject: Arr! This be a Type III Anonymous Message
X-Anonymous: yes

Avast ye mateys!  Prepare to be anonymized!

-----BEGIN TYPE III ANONYMOUS MESSAGE-----
Message-type: plaintext

Hidden, we are free
Free to speak, to free ourselves
Free to hide no more.
-----END TYPE III ANONYMOUS MESSAGE-----\n"""
            self.assertLongStringEq(EXPECTED_SMTP_PACKET, args[3])
            clearReplacedFunctionCallLog()

            # Now, with headers.
            queueMessage(FDP('plain', SMTP_TYPE, "users@everywhere", haiku,
                             headers={"FROM":"Captain Nick",
                                      "SUBJECT":"Gold Doubloons",
                                      "IN-REPLY-TO":"aaaaa@b.com",
                                      "REFERENCES":"cccccc@d.com"}))
            queue.sendReadyMessages()
            # Was sendSMTPMessage invoked correctly?
            calls = getReplacedFunctionCallLog()
            self.assertEquals(1, len(calls))
            fn, args, _ = calls[0]
            self.assertEquals("sendSMTPMessage", fn)
            #server, toList, fromAddr, message
            self.assertEquals(('nowhere',
                               ['users@everywhere'],
                               'yo.ho.ho@bottle.of.rum'),
                              args[:3])
            EXPECTED_SMTP_PACKET = '''\
To: users@everywhere
From: "[Anon] Captain Nick" <yo.ho.ho@bottle.of.rum>
Subject: Gold Doubloons
In-Reply-To: aaaaa@b.com
References: cccccc@d.com
X-Anonymous: yes

Avast ye mateys!  Prepare to be anonymized!

-----BEGIN TYPE III ANONYMOUS MESSAGE-----
Message-type: plaintext

Hidden, we are free
Free to speak, to free ourselves
Free to hide no more.
-----END TYPE III ANONYMOUS MESSAGE-----\n'''
            self.assertLongStringEq(EXPECTED_SMTP_PACKET, args[3])
            clearReplacedFunctionCallLog()

            # Now, try a bunch of messages that won't be delivered: one with
            # an invalid address, and one with a blocked address.
            try:
                suspendLog()
                queueMessage(FDP('plain',SMTP_TYPE, "not.an.addr", haiku))
                queueMessage(FDP('plain',SMTP_TYPE,
                                 "blocked@wangafu.net",haiku))
                queue.sendReadyMessages()
            finally:
                s = resumeLog()
            self.assertEquals(1,s.count(
              "Dropping message to blacklisted address 'blocked@wangafu.net'"))
            self.assertEquals(1,s.count(
                "Dropping SMTP message to invalid address 'not.an.addr'"))
            self.assertEquals([], getReplacedFunctionCallLog())
        finally:
            undoReplacedAttributes()
            clearReplacedFunctionCallLog()

    def testMBOX(self):
        """Check out the MBOX module. (We temporarily replace sendSMTPMessage
           with a stub function so that we don't actually send anything.)"""
        FDP = FakeDeliveryPacket
        # Configure the module
        manager = self.getManager()
        module = mixminion.server.Modules.MBoxModule()
        addrfile = mix_mktemp()
        writeFile(addrfile, MBOX_ADDRESS_SAMPLE)
        module.configure({'Server':{'Nickname': "nickname"},
                          'Incoming/MMTP':{},
                          "Delivery/MBOX" :
                          {"Enabled": 1,
                           "AddressFile": addrfile,
                           "ReturnAddress": "returnaddress@x",
                           "RemoveContact": "removeaddress@x",
                           "Retry": [0,0,0,3],
                           "SMTPServer" : "foo.bar.baz",
                           "MaximumSize" : 32*1024,
                           }}, manager)
        # Check that the address file was read correctly.
        self.assertEquals({'mix-minion': 'mixminion@thishost',
                           'mixdaddy':   'mixminion@thathost',
                           'mixdiddy':   'mixminion@theotherhost'},
                           module.addresses)
        queue = manager.queues['MBOX']
        # Stub out sendSMTPMessage.
        replaceFunction(mixminion.server.Modules, 'sendSMTPMessage',
                 lambda *args: mixminion.server.Modules.DELIVER_OK)
        self.assertEquals(queue.retrySchedule, [0,0,0,3])
        try:
            # Try queueing a message...
            queue.queueDeliveryMessage(FDP('enc', MBOX_TYPE, 'mixdiddy',
                                   hexread("EFFACEAB1EFACADE")*20, "x"*20))
            self.assertEquals(getReplacedFunctionCallLog(), [])
            # ...and sending it.
            queue.sendReadyMessages()
            try:
                # Also, try sending a message to an unknown address
                suspendLog()
                queue.queueDeliveryMessage(
                    FDP('env', MBOX_TYPE, 'mixmuffin',
                        hexread("EFFACEAB1EFACADE")*20,
                            'x'*20))
                queue.sendReadyMessages()
            finally:
                m = resumeLog()
            self.assert_(stringContains(m,"Unknown MBOX user 'mixmuffin'"))
            self.assert_(stringContains(m,"Unable to deliver message"))

            # Check that sendSMTPMessage was called correctly.
            self.assertEquals(1, len(getReplacedFunctionCallLog()))
            fn, args, _ = getReplacedFunctionCallLog()[0]
            self.assertEquals('sendSMTPMessage', fn)
            self.assertEquals(('foo.bar.baz',
                               ['mixminion@theotherhost'],
                               'returnaddress@x'),
                              args[:3])
            self.assertLongStringEq(MBOX_EXPECTED_MESSAGE, args[3])
        finally:
            undoReplacedAttributes()
            clearReplacedFunctionCallLog()

    def testDirectoryDump(self):
        """Check out the DirectoryStoreModule that we use for testing on
           machines with unreliable/nonexistent SMTP."""
        FDP = FakeDeliveryPacket
        eme = mixminion.server.Modules._escapeMessageForEmail
        dir = mix_mktemp()
        manager = self.getManager()
        # Configure the module: disabled and enabled (queueless mode)
        module = mixminion.testSupport.DirectoryStoreModule()
        module.configure({'Testing/DirectoryDump' : {}}, manager)
        self.assert_(not manager.queues.has_key('Testing_DirectoryDump'))
        module.configure({'Testing/DirectoryDump' :
                          {'Location': dir, 'UseQueue' : 0,
                           'Retry': [60]}}, manager)
        # Try sending a couple of messages.
        queue = manager.queues['Testing_DirectoryDump']
        p1 = FDP('plain',0xFFFE, "addr1","this is the message","t"*20)
        queue.queueDeliveryMessage(p1)
        self.assert_(os.path.exists(os.path.join(dir, "0")))
        p2 = FDP('plain',0xFFFE, "addr2", "This is message 2", "x"*20)
        queue.queueDeliveryMessage(p2)
        self.assert_(os.path.exists(os.path.join(dir, "1")))
        self.assertEquals(eme(p2),
                          readFile(os.path.join(dir, "1")))
        # test failure.
        try:
            suspendLog()
            queue.queueDeliveryMessage(
               FDP('plain', 0xFFFE, "FAIL!",
                   "This is message X which won't be delivered", "x"*20))
            self.assert_(not os.path.exists(os.path.join(dir, "2")))
        finally:
            m = resumeLog()
        self.assertEndsWith(m, "Unable to deliver message\n")

        try:
            suspendLog()
            queue.queueDeliveryMessage(
                FDP('plain', 0xFFFE, "fail",
                    "This is message X which won't be delivered", "z"*20))
            self.assert_(not os.path.exists(os.path.join(dir, "2")))
        finally:
            m = resumeLog()
        self.assertEndsWith(m, "Unable to retry delivery for message\n")

        queue.sendReadyMessages()

        # Check sane behavior on missing files, and on restart.
        writeFile(os.path.join(dir, "90"), 'zed')
        module = mixminion.testSupport.DirectoryStoreModule()
        # This time, use a queue.
        module.configure({'Testing/DirectoryDump' :
                          {'Location': dir, 'UseQueue' : 1,
                           'Retry': [60]}}, manager)
        # Do we skip over the missing messages?
        self.assertEquals(module.next, 91)
        self.assertEquals(len(os.listdir(dir)), 3)
        queue = manager.queues['Testing_DirectoryDump']
        queue.queueDeliveryMessage(
                FDP('plain',0xFFFE, "addr91", "This is message 91"))
        queue.queueDeliveryMessage(
                FDP('plain',0xFFFE, "addr92", "This is message 92"))
        _ = queue.queueDeliveryMessage(
                FDP('plain',0xFFFE, "fail", "This is message 93"))
        queue.queueDeliveryMessage(
                FDP('plain',0xFFFE, "FAIL!", "This is message 94"))

        # All 4 messages go into the queue...
        self.assertEquals(4, queue.count())
        self.assertEquals(3, len(os.listdir(dir)))
        try:
            suspendLog()
            queue.sendReadyMessages()
        finally:
            m = resumeLog()
        self.assert_(stringContains(m,"[ERROR] Unable to deliver message"))
        # After delivery: 91 and 92 go through, 93 stays, and 94 gets dropped.
        self.assertEquals(1, queue.count())
        self.assertEquals(5, len(os.listdir(dir)))

    def getManager(self, extraConfig=None):
        d = mix_mktemp()
        c = SERVER_CONFIG_SHORT % d
        if extraConfig:
            c += extraConfig
        try:
            suspendLog()
            conf = mixminion.server.ServerConfig.ServerConfig(string=c)
            m = conf.getModuleManager()
            m.configure(conf)
            return m
        finally:
            resumeLog()

#----------------------------------------------------------------------

# Sample server configuration to test ServerKeys
SERVERCFG = """
[Server]
Homedir: %(home)s
Mode: local
EncryptIdentityKey: No
PublicKeyLifetime: 10 days
IdentityKeyBits: 2048
EncryptPrivateKey: no
Nickname: mac-the-knife
[Incoming/MMTP]
Enabled: yes
IP: 10.0.0.1
"""

_FAKE_HOME = None
def _getServerKeyring():
    global _FAKE_HOME
    _FAKE_HOME = mix_mktemp()
    cfg = SERVERCFG % { 'home' : _FAKE_HOME }
    try:
        suspendLog()
        conf = mixminion.server.ServerConfig.ServerConfig(string=cfg)
    finally:
        resumeLog()
    return mixminion.server.ServerKeys.ServerKeyring(conf)

class ServerKeysTests(TestCase):
    def testServerKeyring(self):
        keyring = _getServerKeyring()
        home = _FAKE_HOME

        # Test creating identity key
        #identity = getRSAKey(0,2048)
        identity = keyring.getIdentityKey()
        fn = os.path.join(home, "keys", "identity.key")
        identity2 = Crypto.pk_PEM_load(fn)
        self.assertEquals(Crypto.pk_get_modulus(identity),
                          Crypto.pk_get_modulus(identity2))
        # (Make sure warning case can occur.)
        pk = getRSAKey(0,128)
        Crypto.pk_PEM_save(pk, fn)
        suspendLog()
        keyring.getIdentityKey()
        msg = resumeLog()
        self.failUnless(len(msg))
        Crypto.pk_PEM_save(identity, fn)
        if not ON_WINDOWS:
            self.assertEquals(os.stat(fn)[stat.ST_MODE] & 0777, 0600)

        # Now create a keyset
        now = time.time()
        keyring.createKeys(1, now)
        # check internal state
        ivals = keyring.keySets
        start = mixminion.Common.previousMidnight(now)
        finish = mixminion.Common.previousMidnight(start+(10*24*60*60)+30)
        self.assertEquals(1, len(ivals))
        self.assertEquals((start,finish), ivals[0][0:2])

        keyring.createKeys(2)

        # Check the first key we created
        va, vu, _ = keyring._getLiveKeys()[0]
        self.assertEquals(va, start)
        self.assertEquals(vu, finish)
        keyset = keyring.getServerKeysets()[0]
        self.assertEquals(keyset.getHashLogFileName(),
                          os.path.join(home, "work", "hashlogs", "hash_0001"))
        self.assertEquals(vu, keyring.getNextKeyRotation())

        # Check the second key we created.
        key2time = vu+3600*48
        live = keyring._getLiveKeys(key2time)
        self.assertEquals(len(live),1)
        va, vu, curKey = live[0]
        self.assertEquals(va, finish)
        self.assertEquals(vu, mixminion.Common.previousMidnight(
            finish+10*24*60*60+60))

        # Does published-marking work right?
        self.assert_(not curKey.isPublished())
        curKey.markAsPublished()
        self.assert_(curKey.isPublished())
        keyring.checkKeys()
        va, vu, curKey = keyring._getLiveKeys(key2time)[0]
        self.assert_(curKey.isPublished())
        curKey.markAsUnpublished()
        self.assert_(not curKey.isPublished())
        keyring.checkKeys()
        va, vu, curKey = keyring._getLiveKeys(key2time)[0]
        self.assert_(not curKey.isPublished())
        curKey.markAsPublished()

        # Does 'regenerate' work?
        cfg2 = SERVERCFG%{'home':_FAKE_HOME}
        cfg2 = cfg2.replace("10.0.0.1", "10.0.0.2")
        config2 = mixminion.server.ServerConfig.ServerConfig(string=cfg2)

        self.assert_(curKey.isPublished())
        curKey.load()
        key0 = curKey.getPacketKeyID()
        curKey.regenerateServerDescriptor(config2, keyring.getIdentityKey())
        self.assert_(not curKey.isPublished())
        inf = curKey.getServerDescriptor()
        self.assertEquals(inf['Incoming/MMTP']['IP'], "10.0.0.2")
        curKey.load()
        self.assertEquals(key0, curKey.getPacketKeyID())

        # Make a key in the past, to see if it gets scrubbed.
        keyring.createKeys(1, mixminion.Common.previousMidnight(
            start - 10*24*60*60 + 1))
        self.assertEquals(4, len(keyring.keySets))
        waitForChildren() # make sure keys are really gone before we remove

        # In case we started very close to midnight, remove keys as if it
        # were a little in the future; otherwise, we won't remove the
        # just-expired keys.
        keyring.removeDeadKeys(now+24*60*60)
        self.assertEquals(3, len(keyring.keySets))

        if USE_SLOW_MODE:
            # These are slow, since they regenerate the DH params.
            # Test getDHFile
            f = keyring._getDHFile()
            f2 = keyring._getDHFile()
            self.assertEquals(f, f2)

            # Test getTLSContext
            keyring._getTLSContext()




#----------------------------------------------------------------------

class ServerMainTests(TestCase):
    def testScheduler(self):
        _Scheduler = mixminion.server.ServerMain._Scheduler
        lst=[]
        def a(lst=lst): lst.append('a')
        def b(lst=lst): lst.append('b')
        def c(lst=lst): lst.append('c')
        def d(lst=lst): lst.append('d')
        s = _Scheduler()
        self.assertEquals(s.firstEventTime(), -1)
        tm = time.time()

        s.scheduleOnce(tm+1, "A", a)
        s.scheduleOnce(tm+2, "B", b)
        self.assertEquals(s.firstEventTime(), tm+1)
        s.processEvents(tm+1)
        self.assertEquals(['a'],lst)
        del lst[:]

        s.scheduleRecurring(tm+1.5, 1, "C", c)
        s.scheduleOnce(tm+1.9, "D", d)
        self.assertEquals(s.firstEventTime(), tm+1.5)
        s.processEvents(tm+1.5)
        self.assertEquals(["c"], lst)
        diff = abs(s.firstEventTime()-(tm+1))
        self.assert_(diff < 0.01)

        s.processEvents(tm+5)
        self.assertEquals(["c", "c", "d", "b"], lst)

    def testMixPool(self):
        ServerConfig = mixminion.server.ServerConfig.ServerConfig
        MixPool = mixminion.server.ServerMain.MixPool
        baseDir = mix_mktemp()
        mixDir = mix_mktemp()
        cfg = SERVER_CONFIG_SHORT % baseDir

        configTimed = ServerConfig(string=(cfg+
               "MixAlgorithm: timed\nMixInterval: 2 hours\n"))
        configCottrell = ServerConfig(string=(cfg+
               "MixAlgorithm: Mixmaster\nMixInterval: .5 days\n"+
               "MixPoolMinSize: 10\nMixPoolRate: 40%\n"))
        configBCottrell = ServerConfig(string=(cfg+
               "MixAlgorithm: BinomialCottrell\nMixInterval: .25 days\n"+
               "MixPoolMinSize: 10\nMixPoolRate: 40%\n"))

        # Test pool configuration
        pool = MixPool(configTimed, mixDir)
        self.assert_(isinstance(pool.queue,
                                TimedMixPool))
        self.assertEquals(pool.getNextMixTime(100), 100+2*60*60)

        pool = MixPool(configCottrell, mixDir)
        self.assert_(isinstance(pool.queue,
                                CottrellMixPool))
        self.assertEquals(pool.getNextMixTime(100), 100+12*60*60)
        self.assertEquals(pool.queue.minPool, 10)
        self.assertEquals(pool.queue.minSend, 1)
        self.assertFloatEq(pool.queue.sendRate, .4)

        pool = MixPool(configBCottrell, mixDir)
        self.assert_(isinstance(pool.queue,
                                BinomialCottrellMixPool))
        self.assertEquals(pool.getNextMixTime(100), 100+6*60*60)
        self.assertEquals(pool.queue.minPool, 10)
        self.assertEquals(pool.queue.minSend, 1)
        self.assertFloatEq(pool.queue.sendRate, .4)

        # FFFF test other mix pool behavior

#----------------------------------------------------------------------

_EXAMPLE_DESCRIPTORS = {} # name->list of str
EX_SERVER_CONF_TEMPLATE = """
[Server]
Mode: relay
Homedir: %(homedir)s
EncryptIdentityKey: No
PublicKeyLifetime: %(lifetime)s
IdentityKeyBits: 2048
EncryptPrivateKey: no
Nickname: %(nickname)s
[Incoming/MMTP]
Enabled: yes
IP: %(ip)s
[Outgoing/MMTP]
Enabled: yes
"""

_EXAMPLE_DESCRIPTORS_INP = [
    # name        days         ip?        validAt
    [ "Fred",     "10 days", "10.0.0.6", (-19,-9,1,11), () ],
    [ "Lola",     "5 days",  "10.0.0.7", (-2,0,5),      (MBOX_TYPE,) ],
    [ "Joe",      "20 days", "10.0.0.8", (-15,5,25),    (SMTP_TYPE,) ],
    [ "Alice",    "8 days",  "10.0.0.9", (-3,5,13),     () ],
    [ "Bob",      "4 days",  "10.0.0.10", (-2, 2, 6, 'X', 0, 4, -3), () ],
    [ "Lisa",     "3 days",  "10.0.0.11", (-10,-1,5),   () ],
]

def getExampleServerDescriptors():
    """Helper function: generate a map of list of ServerInfo objects based
       on the values of _EXAMPLE_DESCRIPTORS_INP"""
    if _EXAMPLE_DESCRIPTORS:
        return _EXAMPLE_DESCRIPTORS

    gen = generateServerDescriptorAndKeys
    tmpkeydir = mix_mktemp()
    now = time.time()

    sys.stdout.flush()

    # For each server...
    serveridx = 0
    for (nickname, lifetime, ip, starting, types) in _EXAMPLE_DESCRIPTORS_INP:
        # Generate a config file
        homedir = mix_mktemp()
        conf = EX_SERVER_CONF_TEMPLATE % locals()
        identity = getRSAKey(serveridx%3,2048)
        serveridx += 1
        for t in types:
            if t == MBOX_TYPE:
                addrf = mix_mktemp()
                writeFile(addrf,"")
                conf += ("[Delivery/MBOX]\nEnabled: yes\nAddressFile: %s\n"+
                         "ReturnAddress: a@b.c\nRemoveContact: b@c.d\n"+
                         "Retry: every 2 hours for 1 week\n") %(
                    addrf)
            elif t == SMTP_TYPE:
                conf += ("[Delivery/SMTP]\nEnabled: yes\n"+
                         "ReturnAddress: a@b.c\n"+
                         "Retry: every 2 hours for 1 week\n")
            else:
                raise MixFatalError("Unrecognized type: %04x"%t)
        try:
            suspendLog()
            conf = mixminion.server.ServerConfig.ServerConfig(string=conf)
            conf.getModuleManager().configure(conf)
        finally:
            resumeLog()

        # Now, for each starting time, generate a server descriptor.
        _EXAMPLE_DESCRIPTORS[nickname] = []
        publishing = now
        for n in xrange(len(starting)):
            if starting[n] == 'X':
                publishing += 60
                continue
            k = "tst%d"%n
            validAt = previousMidnight(now + 24*60*60*starting[n])
            gen(config=conf, identityKey=identity, keyname=k,
                keydir=tmpkeydir, hashdir=tmpkeydir, validAt=validAt,
                now=publishing)

            sd = os.path.join(tmpkeydir,"key_"+k,"ServerDesc")
            _EXAMPLE_DESCRIPTORS[nickname].append(readFile(sd))

            # (print some dots here; this step can take a while)
            sys.stdout.write('.')
            sys.stdout.flush()
    sys.stdout.flush()
    return _EXAMPLE_DESCRIPTORS

def getDirectory(servers, identity):
    """Return the filename of a newly created server directory, containing
       the server descriptors provided as literal strings in <servers>,
       signed with the RSA key <identity>"""
    SL = mixminion.directory.ServerList.ServerList(mix_mktemp())
    active = IntervalSet()
    for s in servers:
        SL.importServerInfo(s)
        s = mixminion.ServerInfo.ServerInfo(fname=s, assumeValid=1)
        active += s.getIntervalSet()
    start, end = active.start(), active.end()
    SL.generateDirectory(start, end, 0, identity)
    return SL.getDirectoryFilename()

# variable to hold the latest instance of FakeBCC.
BCC_INSTANCE = None

class ClientMainTests(TestCase):
    def testClientDirectory(self):
        """Check out ClientMain's directory implementation"""
        eq = self.assertEquals
        neq = self.assertNotEquals
        ServerInfo = mixminion.ServerInfo.ServerInfo

        dirname = mix_mktemp()
        ks = mixminion.ClientMain.ClientDirectory(dirname)

        ## Write the descriptors to disk.
        edesc = getExampleServerDescriptors()
        impdirname = mix_mktemp()
        createPrivateDir(impdirname)
        for server, descriptors in edesc.items():
            for idx in xrange(len(descriptors)):
                fname = os.path.join(impdirname, "%s%s" % (server,idx))
                writeFile(fname, descriptors[idx])
                f = gzip.GzipFile(fname+".gz", 'wb')
                f.write(descriptors[idx])
                f.close()

        ## Test empty keystore
        eq(None, ks.getServerInfo("Fred"))
        self.assertRaises(MixError, ks.getServerInfo, "Fred", strict=1)
        fred = ks.getServerInfo(os.path.join(impdirname, "Fred2"))
        self.assertEquals("Fred", fred.getNickname())
        self.assertSameSD(edesc["Fred"][2],fred)

        ## Test importing.
        ks.importFromFile(os.path.join(impdirname, "Joe0"))
        ks.importFromFile(os.path.join(impdirname, "Joe1.gz"))
        ks.importFromFile(os.path.join(impdirname, "Lola1"))

        now = time.time()
        oneDay=24*60*60
        for i in 0,1,2,3:
            self.assertSameSD(edesc["Joe"][0], ks.getServerInfo("Joe"))
            self.assertSameSD(edesc["Lola"][1], ks.getServerInfo("Lola"))
            self.assertSameSD(edesc["Joe"][1],
                              ks.getServerInfo("Joe", startAt=now+10*oneDay))
            self.assertRaises(MixError, ks.getServerInfo, "Joe",
                              startAt=now+30*oneDay)
            self.assertRaises(MixError, ks.getServerInfo, "Joe", startAt=now,
                              endAt=now+6*oneDay)
            if i in (0,1,2):
                ks = mixminion.ClientMain.ClientDirectory(dirname)
            if i == 1:
                ks.rescan()
            if i == 2:
                ks.rescan(force=1)

        # Refuse to import a server with a modified identity
        writeFile(os.path.join(impdirname, "Notjoe"),
                  edesc["Lola"][0].replace("Nickname: Lola", "Nickname: Joe"))
        self.assertRaises(MixError,
                          ks.importFromFile,
                          os.path.join(impdirname, "Notjoe"))

        # Try getServerInfo(ServerInfo)
        si = ServerInfo(string=edesc['Lisa'][1],assumeValid=1)
        self.assert_(ks.getServerInfo(si) is si)
        try:
            suspendLog()
            si = ServerInfo(string=edesc['Lisa'][0],assumeValid=1)
            self.assert_(ks.getServerInfo(si) is None)
        finally:
            s = resumeLog()
        self.assert_(stringContains(s, "Server is not currently"))

        ##
        # Now try out the directory.  This is tricky; we add the other
        # descriptors here.
        identity = getRSAKey(0,2048)
        fingerprint = Crypto.pk_fingerprint(identity)
        fname = getDirectory(
            [os.path.join(impdirname, s) for s in
             ("Fred1", "Fred2", "Lola2", "Alice0", "Alice1",
              "Bob3", "Bob4", "Lisa1") ], identity)

        # Replace the real URL and fingerprint with the ones we have; for
        # unit testing purposes, we can't rely on an http server.
        mixminion.ClientMain.MIXMINION_DIRECTORY_URL = fileURL(fname)
        mixminion.ClientMain.MIXMINION_DIRECTORY_FINGERPRINT = fingerprint

        # Reload the directory.
        ks.updateDirectory(now=now)

        for i in 0,1,2,3:
            self.assertSameSD(ks.getServerInfo("Alice"), edesc["Alice"][0])
            self.assertSameSD(ks.getServerInfo("Bob"), edesc["Bob"][3])
            self.assertSameSD(ks.getServerInfo("Bob", startAt=now+oneDay*5),
                              edesc["Bob"][4])

            if i in (0,1,2):
                ks = mixminion.ClientMain.ClientDirectory(dirname)
            if i == 1:
                ks.rescan()
            if i == 2:
                ks.rescan(force=1)

        replaceFunction(ks, 'downloadDirectory')

        # Now make sure that update is properly zealous.
        ks.updateDirectory(now=now)
        self.assertEquals([], getReplacedFunctionCallLog())
        ks.updateDirectory(now=now, forceDownload=1)
        self.assertEquals(1, len(getReplacedFunctionCallLog()))
        ks.updateDirectory(now=now+oneDay+60)
        self.assertEquals(2, len(getReplacedFunctionCallLog()))
        undoReplacedAttributes()
        clearReplacedFunctionCallLog()

        ## Now make sure we can really update the directory.
        # (this is the same as before, but with 'Lisa2'.)
        fname = getDirectory(
            [os.path.join(impdirname, s) for s in
             ("Fred1", "Fred2", "Lola2", "Alice0", "Alice1",
              "Bob3", "Bob4", "Lisa1", "Lisa2") ], identity)
        mixminion.ClientMain.MIXMINION_DIRECTORY_URL = fileURL(fname)
        ks.updateDirectory(forceDownload=1)
        # Previous entries.
        self.assertSameSD(ks.getServerInfo("Alice"), edesc["Alice"][0])
        self.assertSameSD(ks.getServerInfo("Bob"), edesc["Bob"][3])
        # New entry
        self.assertSameSD(ks.getServerInfo("Lisa",startAt=now+6*oneDay),
                          edesc["Lisa"][2])
        # Entry from server info
        self.assertSameSD(edesc["Joe"][0], ks.getServerInfo("Joe"))

        def nRuns(lst):
            n = 0
            for idx in xrange(len(lst)-1):
                if lst[idx] == lst[idx+1]:
                    n += 1
            return n

        # Override ks.DEFAULT_REQUIRED_LIFETIME so we don't need to
        # explicitly specify a really early endAt all the time.
        ks.DEFAULT_REQUIRED_LIFETIME = 1

        suspendLog()
        joe = edesc["Joe"]
        alice = edesc["Alice"]
        lola = edesc["Lola"]
        fred = edesc["Fred"]
        bob = edesc["Bob"]
        try:
            ### Try out getPath.
            # 1. Fully-specified paths.
            p = ks.getPath(None, ['Joe', 'Lisa', 'Alice', 'Joe'])

            # 2. Partly-specified paths...
            # 2a. With plenty of servers
            p = ks.getPath(None, [None, None])
            eq(2, len(p))
            neq(p[0].getNickname(), p[1].getNickname())

            p = ks.getPath(None, ["Joe", None, None])
            eq(3, len(p))
            self.assertSameSD(p[0], joe[0])
            neq(p[1].getNickname(), "Joe")
            neq(p[2].getNickname(), "Joe")
            neq(p[1].getNickname(), p[2].getNickname())

            p = ks.getPath(None, [None, None, "Joe"])
            eq(3, len(p))
            self.assertSameSD(joe[0], p[2])

            p = ks.getPath(None, ["Alice", None, None, "Joe"])
            eq(4, len(p))
            self.assertSameSD(alice[0], p[0])
            self.assertSameSD(joe[0], p[3])
            nicks = [ s.getNickname() for s in p ]
            self.assert_(nicks.count("Alice")>=1)
            self.assert_(nicks.count("Joe")>=1)
            neq(nicks[1],nicks[2])

            p = ks.getPath(None, ["Joe", None, "Alice", "Joe"])
            eq(4, len(p))
            self.assertSameSD(alice[0], p[2])
            self.assertSameSD(joe[0], p[0])
            self.assertSameSD(joe[0], p[3])
            neq(p[1].getNickname(), "Alice")
            neq(p[1].getNickname(), "Joe")
            # 2b. With 3 <= servers < length
            ks2 = mixminion.ClientMain.ClientDirectory(mix_mktemp())
            ks2.importFromFile(os.path.join(impdirname, "Joe0"))
            ks2.importFromFile(os.path.join(impdirname, "Alice0"))
            ks2.importFromFile(os.path.join(impdirname, "Lisa1"))
            ks2.importFromFile(os.path.join(impdirname, "Bob0"))

            p = ks2.getPath(None, [None]*9)
            eq(9, len(p))
            self.failIf(nRuns([s.getNickname() for s in p]))

            p = ks2.getPath(None, ["Joe"]+[None]*6+["Joe"])
            self.failIf(nRuns([s.getNickname() for s in p]))
            eq(8, len(p))
            self.assertSameSD(joe[0], p[0])
            self.assertSameSD(joe[0], p[-1])

            p = ks2.getPath(None, ["Joe"]+[None]*6)
            self.failIf(nRuns([s.getNickname() for s in p]))
            eq(7, len(p))
            self.assertSameSD(joe[0], p[0])

            p = ks2.getPath(None, [None]*6+["Joe"])
            self.failIf(nRuns([s.getNickname() for s in p]))
            eq(7, len(p))
            self.assertSameSD(joe[0], p[-1])

            # 2c. With 2 servers
            ks2.expungeByNickname("Alice")
            ks2.expungeByNickname("Bob")
            p = ks2.getPath(None, [None]*4)
            self.failIf(nRuns([s.getNickname() for s in p]) > 1)

            p = ks2.getPath(None, ["Joe",None,None,None])

            self.failIf(nRuns([s.getNickname() for s in p]) > 2)
            p = ks2.getPath(None, [None, None, None, "Joe"])
            self.failIf(nRuns([s.getNickname() for s in p]) > 1)

            p = ks2.getPath(None, [None,None,None,None,None, "Joe"])
            self.failIf(nRuns([s.getNickname() for s in p]) > 1)

            # 2d. With only 1.
            ks2.expungeByNickname("Lisa")
            p = ks2.getPath(None,[None]*4)
            eq(len(p), 4)
            p = ks2.getPath(None,["Joe",None,None,None])
            eq(len(p), 4)
            p = ks2.getPath(None,[None,None,None,"Joe"])
            eq(len(p), 4)

            # 2e. With 0
            self.assertRaises(MixError, ks.getPath,
                              None, [None]*4, startAt=now+100*oneDay)
        finally:
            s = resumeLog()
        self.assertEquals(4, s.count("to avoid same-server hops"))
        self.assertEquals(3, s.count("Only one relay known"))

        # 3. With capabilities.
        p = ks.getPath("smtp", [None]*5)
        eq(5, len(p))
        self.assertSameSD(p[-1], joe[0]) # Only Joe has SMTP

        p = ks.getPath("mbox", [None]*4)
        eq(4, len(p))
        self.assertSameSD(p[-1], lola[1]) # Only Lola has MBOX

        p = ks.getPath("mbox", ["Alice", None, None, None, None])
        eq(5, len(p))
        self.assertSameSD(p[-1], lola[1]) # Only Lola has MBOX
        self.assertSameSD(p[0], alice[0])

        p = ks.getPath("mbox", [None,None,None,None, "Alice"])
        eq(5, len(p))
        self.assertSameSD(p[-1], alice[0]) # We ignore endCap with endServers

        ### Now try parsePath.  This should exercise resolvePath as well.
        ppath = mixminion.ClientMain.parsePath
        paddr = mixminion.ClientMain.parseAddress
        email = paddr("smtp:lloyd@dobler.com")
        mboxWithServer = paddr("mbox:Granola@Lola")
        mboxWithoutServer = paddr("mbox:Granola")

        alice = ks.getServerInfo("Alice")
        fred = ks.getServerInfo("Fred")
        bob = ks.getServerInfo("Bob")
        joe = ks.getServerInfo("Joe")
        lola = ks.getServerInfo("Lola")

        def pathIs(p, exp, self=self):
            if isinstance(p[0],mixminion.ServerInfo.ServerInfo):
                p1, p2 = p, ()
                exp1, exp2 = exp, ()
            else:
                p1, p2 = p
                exp1, exp2 = exp
            try:
                self.assertEquals(len(p1),len(exp1))
                self.assertEquals(len(p2),len(exp2))
                for a, b in zip(p1, exp1):
                    self.assertSameSD(a,b)
                for a, b in zip(p2, exp2):
                    self.assertSameSD(a,b)
            except:
                print [s.getNickname() for s in p1], \
                      [s.getNickname() for s in p2]
                raise

        # 1. Successful cases
        # 1a. No colon, no star
        fredfile = os.path.join(impdirname, "Fred1")
        p1,p2 = ppath(ks, None, "Alice,Fred,Bob,Joe", email)
        pathIs((p1,p2), ((alice,fred),(bob,joe)))
        fredfile = os.path.join(impdirname, "Fred1")
        p1,p2 = ppath(ks, None, "Alice,%r,Bob,Joe"%fredfile, email)
        pathIs((p1,p2), ((alice,fred),(bob,joe)))
        p1,p2 = ppath(ks, None, "Alice,Fred,Bob,Lola,Joe", email, nHops=5)
        pathIs((p1,p2), ((alice,fred,bob),(lola,joe)))
        p1,p2 = ppath(ks, None, "Alice,Fred,Bob", mboxWithServer)
        pathIs((p1,p2), ((alice,fred),(bob,lola)))
        p1,p2 = ppath(ks, None, "Alice,Fred,Bob,Lola", mboxWithoutServer)
        pathIs((p1,p2), ((alice,fred),(bob,lola)))
        p1,p2 = ppath(ks, None, "Alice,?,?,Bob", mboxWithServer)
        eq((len(p1),len(p2)), (2,3))
        pathIs((p1[:1],p2[-2:]), ((alice,),(bob,lola)))

        # 1b. Colon, no star
        p1,p2 = ppath(ks, None, "Alice:Fred,Joe", email)
        pathIs((p1,p2), ((alice,),(fred,joe)))
        p1,p2 = ppath(ks, None, "Alice:Bob,Fred,Joe", email)
        pathIs((p1,p2), ((alice,),(bob,fred,joe)))
        p1,p2 = ppath(ks, None, "Alice,Bob,Fred:Joe", email)
        pathIs((p1,p2), ((alice,bob,fred),(joe,)))
        p1,p2 = ppath(ks, None, "Alice,Bob,?:Joe", email)
        eq((len(p1),len(p2)), (3,1))
        pathIs((p1[:-1],p2), ((alice,bob),(joe,)))
        p1,p2 = ppath(ks, None, "Alice,Bob,Fred:Joe", email, nHops=4)
        pathIs((p1,p2), ((alice,bob,fred),(joe,)))
        p1,p2 = ppath(ks, None, "Alice,Bob,Fred:Joe", mboxWithServer)
        pathIs((p1,p2), ((alice,bob,fred),(joe,lola)))
        p1,p2 = ppath(ks, None, "Alice,Bob,Fred:Lola", mboxWithoutServer)
        pathIs((p1,p2), ((alice,bob,fred),(lola,)))

        # 1c. Star, no colon
        p1,p2 = ppath(ks, None, 'Alice,*,Joe', email, nHops=5)
        pathIs((p1[0],p2[-1]), (alice, joe))
        eq((len(p1),len(p2)), (3,2))

        p1,p2 = ppath(ks, None, 'Alice,Bob,*,Joe', email, nHops=6)
        pathIs((p1[0],p1[1],p2[-1]), (alice, bob, joe))
        eq((len(p1),len(p2)), (3,3))

        p1,p2 = ppath(ks, None, 'Alice,Bob,*', email, nHops=6)
        pathIs((p1[0],p1[1],p2[-1]), (alice, bob, joe))
        eq((len(p1),len(p2)), (3,3))

        p1,p2 = ppath(ks, None, '*,Bob,Joe', email) #default nHops=6
        pathIs((p2[-2],p2[-1]), (bob, joe))
        eq((len(p1),len(p2)), (3,3))

        p1,p2 = ppath(ks, None, 'Bob,*,Alice', mboxWithServer, nHops=5)
        pathIs((p1[0],p2[-2],p2[-1]), (bob, alice, lola))
        eq((len(p1),len(p2)), (3,3))

        p1,p2 = ppath(ks, None, 'Bob,*,Alice,Lola', mboxWithoutServer)
        pathIs((p1[0],p2[-2],p2[-1]), (bob, alice, lola))
        eq((len(p1),len(p2)), (3,3))

        # 1d. Star and colon
        p1,p2 = ppath(ks, None, 'Bob:*,Alice', mboxWithServer, nHops=5)
        pathIs((p1[0],p2[-2],p2[-1]), (bob, alice, lola))
        eq((len(p1),len(p2)), (1,5))

        p1,p2 = ppath(ks, None, 'Bob,*:Alice', mboxWithServer, nHops=5)
        pathIs((p1[0],p2[-2],p2[-1]), (bob, alice, lola))
        eq((len(p1),len(p2)), (4,2))

        p1,p2 = ppath(ks, None, 'Bob,*,Joe:Alice', mboxWithServer, nHops=5)
        pathIs((p1[0],p1[-1],p2[-2],p2[-1]), (bob, joe, alice, lola))
        eq((len(p1),len(p2)), (4,2))

        p1,p2 = ppath(ks, None, 'Bob,*,Lola:Alice,Joe', email)
        pathIs((p1[0],p1[-1],p2[-2],p2[-1]), (bob, lola, alice, joe))
        eq((len(p1),len(p2)), (4,2))

        p1,p2 = ppath(ks, None, '*,Lola:Alice,Joe', email)
        pathIs((p1[-1],p2[-2],p2[-1]), (lola, alice, joe))
        eq((len(p1),len(p2)), (4,2))

        p1,p2 = ppath(ks, None, 'Lola:Alice,*', email)
        pathIs((p1[0],p2[0],p2[-1]), (lola, alice, joe))
        eq((len(p1),len(p2)), (1,5))

        p1,p2 = ppath(ks, None, 'Bob:Alice,*', mboxWithServer, nHops=5)
        pathIs((p1[0],p2[0],p2[-1]), (bob, alice, lola))
        eq((len(p1),len(p2)), (1,5))

        # 1d'. Tilde
        p1,p2 = ppath(ks, None, '?,~4,Bob,Joe', email) #default nHops=6
        p = p1+p2
        pathIs((p2[-1], p2[-2],), (joe, bob))

        # 1e. Complex.
        try:
            suspendLog()
            p1,p2 = ppath(ks, None, '?,Bob,*:Joe,*2,Joe', email, nHops=9)
        finally:
            resumeLog()
        pathIs((p1[1],p2[0],p2[-1]), (bob, joe, joe))
        eq((len(p1),len(p2)), (5,4))

        # 1f. Half-path
        p1,p2 = ppath(ks, None, "*3", email, halfPath=1)
        eq((len(p1),len(p2)), (0,3))

        # 2. Failing cases
        raises = self.assertRaises
        # Nonexistent server
        raises(MixError, ppath, ks, None, "Pierre:Alice,*", email)
        # Two swap points
        raises(MixError, ppath, ks, None, "Alice:Bob:Joe", email)
        # Last hop doesn't support exit type
        raises(MixError, ppath, ks, None, "Alice:Bob,Fred", email)
        raises(MixError, ppath, ks, None, "Alice:Bob,Fred", mboxWithoutServer)
        # Two stars.
        raises(MixError, ppath, ks, None, "Alice,*,Bob,*,Joe", email)
        # NHops mismatch
        raises(MixError, ppath, ks, None, "Alice:Bob,Joe", email, nHops=2)
        raises(MixError, ppath, ks, None, "Alice:Bob,Joe", email, nHops=4)
        # Nonexistent file
        raises(MixError, ppath, ks, None, "./Pierre:Alice,*", email)

        ## Try 'expungeByNickname'.
        # Zapping 'Lisa' does nothing, since she's in the directory...
        ks.expungeByNickname("Lisa")
        self.assertSameSD(ks.getServerInfo("Lisa",startAt=now+6*oneDay),
                          edesc["Lisa"][2])
        # But Joe can be removed.
        ks.expungeByNickname("Joe")
        eq(None, ks.getServerInfo("Joe"))

        ## Now try clean()
        ks.clean() # Should do nothing.
        ks = mixminion.ClientMain.ClientDirectory(dirname)
        ks.clean(now=now+oneDay*500) # Should zap all of imported servers.
        raises(MixError, ks.getServerInfo, "Lola")

    def testAddress(self):
        def parseEq(s, tp, addr, server, eq=self.assertEquals):
            "Helper: return true iff parseAddress(s).getRouting() == t,s,a."
            t, a, s = mixminion.ClientMain.parseAddress(s).getRouting()
            eq(t, tp)
            eq(s, server)
            eq(a, addr)

        ##
        # Check valid mbox and smtp addresses
        parseEq("mbox:foo", MBOX_TYPE, "foo", None)
        parseEq("mbox:foo@bar", MBOX_TYPE, "foo", "bar")
        parseEq("mbox:foo@bar@baz", MBOX_TYPE, "foo", "bar@baz")
        parseEq("smtp:foo@bar", SMTP_TYPE, "foo@bar", None)
        parseEq("smtp:foo@bar.com", SMTP_TYPE, "foo@bar.com", None)
        parseEq("foo@bar.com", SMTP_TYPE, "foo@bar.com", None)
        ##
        # Check other address formats.
        parseEq("drop", DROP_TYPE, "", None)
        parseEq("test:foobar", 0xFFFE, "foobar", None)
        parseEq("test", 0xFFFE, "", None)
        parseEq("0x999:zymurgy", 0x999, "zymurgy", None)
        parseEq("0x999:", 0x999, "", None)

        def parseFails(s, f=self.failUnlessRaises):
            f(ParseError, mixminion.ClientMain.parseAddress, s)

        # Check failing cases
        parseFails("sxtp:foo@bar.com") # unknown module
        parseFails("mbox") # missing mbox address
        parseFails("mbox:") # missing mbox address
        parseFails("smtp:Foo") # Invalid mailbox
        parseFails("smtp:foo@bar@baz") # Invalid mailbox
        parseFails("hello-friends") # Invalid mailbox
        parseFails("@bar.baz") # Invalid mailbox
        parseFails("moo:") # Unknown module; no text
        parseFails("moo") # Unknown module; no text
        parseFails(":oom") # Missing module
        parseFails("0xZZ:zymurgy") # Bad hex literal
        parseFails("0xZZ") # Bad hex literal, no data.
        parseFails("0x9999") # No data
        parseFails("0xFEEEF:zymurgy") # Hex literal out of range

    def testSURBLog(self):
        SURBLog = mixminion.ClientMain.SURBLog
        dirname = mix_mktemp()
        fname = os.path.join(dirname, "surblog")
        s = SURBLog(fname)
        try:
            #XXXX005 writeme
            pass
        finally:
            s.close()

    def testClientKeyring(self):
        keydir = mix_mktemp()
        keyring = mixminion.ClientMain.ClientKeyring(keydir)
        # Check for some nonexistent keys.
        self.assertEquals({}, keyring.getSURBKeys(password="pwd"))

        self.assertEquals(None, keyring.getSURBKey(create=0))
        # Reload, try again:
        kfirst = None
        for _ in 1, 2:
            keyring = mixminion.ClientMain.ClientKeyring(keydir)
            self.assertEquals(kfirst, keyring.getSURBKey(
                create=0,password="pwd"))
            try:
                suspendLog()
                k1 = keyring.getSURBKey(create=1,password="pwd")
            finally:
                s = resumeLog()
            if kfirst:
                self.assertEquals(s, "")
                self.assertEquals(k1, kfirst)
            else:
                self.assert_(stringContains(s, "No keyring found"))
                kfirst = k1
            self.assertEquals(20, len(k1))
            k2 = keyring.getSURBKey(name="Bob",create=1)
            self.assertEquals(20, len(k2))
            self.assertNotEquals(k1,k2)
            self.assertEquals({"":k1,"Bob":k2}, keyring.getSURBKeys())

        # Incorrect password
        keyring = mixminion.ClientMain.ClientKeyring(keydir)
        try:
            suspendLog()
            self.assertEquals(None,keyring.getSURBKey(password="incorrect"))
        finally:
            s = resumeLog()
        self.assert_(stringContains(s, "Incorrect password"))

    def testMixminionClient(self):
        # Create and configure a MixminionClient object...
        parseAddress = mixminion.ClientMain.parseAddress
        userdir = mix_mktemp()
        usercfgstr = "[User]\nUserDir: %s\n[DirectoryServers]\n"%userdir
        usercfg = mixminion.Config.ClientConfig(string=usercfgstr)
        client = mixminion.ClientMain.MixminionClient(usercfg)

        # Now try with some servers...
        edesc = getExampleServerDescriptors()
        ServerInfo = mixminion.ServerInfo.ServerInfo
        Lola = ServerInfo(string=edesc["Lola"][1], assumeValid=1)
        Joe = ServerInfo(string=edesc["Joe"][0], assumeValid=1)
        Alice = ServerInfo(string=edesc["Alice"][1], assumeValid=1)

        # ... and for now, we need to restart the client.
        client = mixminion.ClientMain.MixminionClient(usercfg)

        ##  Test generateForwardMessage.
        # We replace 'buildForwardMessage' to make this easier to test.
        replaceFunction(mixminion.BuildMessage, "buildForwardMessage",
                        lambda *a, **k:"X")
        try:
            getCalls = getReplacedFunctionCallLog
            clearCalls = clearReplacedFunctionCallLog
            # First, two forward messages that end with 'joe' and go via
            # SMTP
            payload = "Hey Joe, where you goin' with that gun in your hand?"
            client.generateForwardMessage(
                parseAddress("joe@cledonism.net"),
                payload,
                servers1=[Lola, Joe], servers2=[Alice, Joe])
            client.generateForwardMessage(
                parseAddress("smtp:joe@cledonism.net"),
                "Hey Joe, where you goin' with that gun in your hand?",
                servers1=[Lola, Joe], servers2=[Alice, Joe])

            for fn, args, kwargs in getCalls():
                self.assertEquals(fn, "buildForwardMessage")
                self.assertEquals(args[1:3],
                                  (SMTP_TYPE, "joe@cledonism.net"))
                self.assert_(len(args[3]) == len(args[4]) == 2)
                self.assertEquals(["Lola", "Joe", "Alice", "Joe"],
                     [x['Server']['Nickname'] for x in args[3]+args[4]])
            clearCalls()

            # Now try an mbox message, with an explicit last hop.
            payload = "Hey, Lo', where you goin' with that pun in your hand?"
            client.generateForwardMessage(
                parseAddress("mbox:granola"),
                payload,
                servers1=[Lola, Joe], servers2=[Alice, Lola])
            # And an mbox message with a last hop implicit in the address
            client.generateForwardMessage(
                parseAddress("mbox:granola@Lola"),
                payload,
                servers1=[Lola, Joe], servers2=[Alice, Lola])

            for fn, args, kwargs in getCalls():
                self.assertEquals(fn, "buildForwardMessage")
                self.assertEquals(args[0:3],
                                  (payload, MBOX_TYPE, "granola"))
                self.assert_(len(args[3]) == len(args[4]) == 2)
                self.assertEquals(["Lola", "Joe", "Alice", "Lola"],
                     [x.getNickname() for x in args[3]+args[4]])
            clearCalls()
        finally:
            undoReplacedAttributes()
            clearCalls()

        ### Now try some failing cases for generateForwardMessage:
        # Empty path...
        self.assertRaises(MixError,
                          client.generateForwardMessage,
                          parseAddress("0xFFFE:zed"),
                          "Z", [], [Alice])

        # Temporarily replace BlockingClientConnection so we can try the client
        # without hitting the network.
        class FakeBCC:
            def __init__(self, addr, port, keyid):
                global BCC_INSTANCE
                BCC_INSTANCE = self
                self.addr = addr
                self.port = port
                self.keyid = keyid
                self.packets = []
                self.connected = 0
            def connect(self, connectTimeout):
                self.connected = 1
                self.timeout = connectTimeout
            def sendPacket(self, msg):
                assert self.connected
                self.packets.append(msg)
            def shutdown(self):
                self.connected = 0

        replaceAttribute(mixminion.MMTPClient, "BlockingClientConnection",
                         FakeBCC)
        try:
            client.sendForwardMessage(
                parseAddress("mbox:granola@Lola"),
                "You only give me your information.",
                [Alice, Lola, Joe, Alice], [Joe, Alice])
            bcc = BCC_INSTANCE
            # first hop is alice
            self.assertEquals(bcc.addr, "10.0.0.9")
            self.assertEquals(bcc.port, 48099)
            self.assertEquals(0, bcc.connected)
            self.assertEquals(1, len(bcc.packets))
            self.assertEquals(32*1024, len(bcc.packets[0]))

        finally:
            undoReplacedAttributes()
            clearCalls()

    def assertSameSD(self, s1, s2):
        self.assert_(self.isSameServerDesc(s1,s2))

    def isSameServerDesc(self, s1, s2):
        """s1 and s2 are either ServerInfo objects or strings containing server
           descriptors. Returns 1 iff their digest fields match"""
        ds = []
        for s in s1, s2:
            if type(s) == types.StringType:
                m = re.search(r"^Digest: (\S+)\n", s, re.M)
                assert m
                ds.append(base64.decodestring(m.group(1)))
            elif isinstance(s, mixminion.ServerInfo.ServerInfo):
                ds.append(s.getDigest())
            else:
                return 0
        return ds[0] == ds[1]

#----------------------------------------------------------------------
class FragmentTests(TestCase):
    def testFragmentParams(self):
        K28 = 28*1024
        FP = mixminion.Fragments.FragmentationParams
        # 1 chunk, small
        fp1 = FP(K28 + 1, 0)
        self.assertEquals((fp1.length, fp1.fragCapacity, fp1.k, fp1.n,
                           fp1.nChunks, fp1.chunkSize, fp1.paddedLen,
                           fp1.paddingLen),
                          (K28+1, K28 - 47, 2, 3,
                           1, 2*(K28-47), 2*(K28-47),
                           fp1.paddedLen-(K28+1)))
        # 1 chunk, a bit larger, with enc-fwd overhead
        fp1 = FP(150*1024, 38)
        self.assertEquals((fp1.length, fp1.fragCapacity, fp1.k, fp1.n,
                           fp1.nChunks, fp1.chunkSize, fp1.paddedLen,
                           fp1.paddingLen),
                          (150*1024, K28 - 47 - 38, 8, 11,
                           1, 8*(K28-47-38), 8*(K28-47-38),
                           fp1.paddedLen-(150*1024)))
        # 2 chunks.
        fp1 = FP(K28 * 20, 0)
        self.assertEquals((fp1.length, fp1.fragCapacity, fp1.k, fp1.n,
                           fp1.nChunks, fp1.chunkSize, fp1.paddedLen,
                           fp1.paddingLen),
                          (K28*20, K28 - 47, 16, 22,
                           2, 16*(K28-47), 32*(K28-47),
                           fp1.paddedLen-(K28*20)))
        

        # 3 chunks.
        fp1 = FP(K28 * 32 + 101, 0)
        self.assertEquals((fp1.length, fp1.fragCapacity, fp1.k, fp1.n,
                           fp1.nChunks, fp1.chunkSize, fp1.paddedLen,
                           fp1.paddingLen),
                          (K28*32+101, K28 - 47, 16, 22,
                           3, 16*(K28-47), 48*(K28-47),
                           fp1.paddedLen-(K28*32+101)))
        

    def testFragmentation(self):
        FP = mixminion.Fragments.FragmentationParams
        
        # One chunk.
        msg = Crypto.getCommonPRNG().getBytes(150*1024)
        fp1 = FP(len(msg), 38)
        fec = mixminion.Fragments._getFEC(8, 11)
        blocks = fp1.getFragments(msg)
        self.assertEquals(len(blocks), 11)
        for b in blocks:
            self.assertEquals(len(b), 28*1024 - 47 - 38)
        m2 = "".join(fec.decode(zip(range(3,11),blocks[3:])))
        self.assertLongStringEq(msg, unwhiten(m2[:150*1024]))
        
        # Three chunks.
        msg = Crypto.getCommonPRNG().getBytes(28*32*1024 + 101)
        fp1 = FP(len(msg), 0)
        fec = mixminion.Fragments._getFEC(16, 22)
        blocks = fp1.getFragments(msg)
        self.assertEquals(len(blocks), 66)
        for b in blocks: self.assertEquals(len(b), 28*1024 - 47)
        chunks = []
        for chunkno in 0,1,2:
            blocksInChunk = zip(range(22), blocks[chunkno*22:(chunkno+1)*22])
            receivedBlocks = Crypto.getCommonPRNG().shuffle(blocksInChunk, 16)
            self.assertEquals(16, len(receivedBlocks))
            chunks.append("".join(fec.decode(receivedBlocks)))
        self.assertLongStringEq(msg, unwhiten(("".join(chunks))[:len(msg)]))
        
    def testFragmentPool(self):
        em = mixminion.BuildMessage.encodeMessage
        pp = mixminion.Packet.parsePayload
        M1 = Crypto.getCommonPRNG().getBytes(1024*30)
        M2 = Crypto.getCommonPRNG().getBytes(1024*900)
        pkts1 = [ pp(x) for x in em(M1,0) ]
        pkts2 = [ pp(x) for x in em(M2,0) ]
        self.assertEquals(map(len, [pkts1,pkts2]),
                          [3, 66])
        
        loc = mix_mktemp()
        pool = mixminion.Fragments.FragmentPool(loc)
        self.assertEquals([], pool.listReadyMessages())
        pool.unchunkMessages()

        ####
        # Reconstruct: simple case.
        ####
        pool.addFragment(pkts1[2]) # Add a single packet.
        self.assertEquals(1, pool.store.count()) # Is it there?
        self.assertEquals([], pool.listReadyMessages()) # Message isn't ready.
        pool.addFragment(pkts1[0]) # Add another packet.
        self.assertEquals(2, pool.store.count()) # Two packets waiting.
        pool.addFragment(pkts1[1]) # duplicate; should be 'unnneeded'
        self.assertEquals(2, pool.store.count()) # Still two waiting.
        self.assertEquals([], pool.listReadyMessages()) # Still not ready.
        pool.unchunkMessages() # Now try to unchunk the message.
        self.assertEquals([pkts1[0].msgID], pool.listReadyMessages()) # Ready!
        mid = pool.listReadyMessages()[0] # Get the message; is it right?
        self.assertLongStringEq(M1, uncompressData(pool.getReadyMessage(mid)))
        pool.markMessageCompleted(mid) # Mark it as done.
        self.assertEquals([], pool.listReadyMessages()) # Not there any more.
        pool.addFragment(pkts1[1]) # Adding more fragments to it doesn't work.
        self.assertEquals([], pool.store.getAllMessages())

        ####
        # Reconstruct: large message, stop half-way, reload, finish.
        ####
        # enough for chunk1 -- 17 messages
        for p in pkts2[5:22]: pool.addFragment(p)
        # enough for half of chunk2: 8 messages
        for p in pkts2[22:30]: pool.addFragment(p)
        pool.unchunkMessages()
        # close and re-open messages
        pool.close()
        pool = mixminion.Fragments.FragmentPool(loc)
        # Enough for the rest of message 4...  8 from 2, 17 from 3.
        for p in pkts2[36:44]+pkts2[49:66]:
            pool.addFragment(p)
            pool.unchunkMessages()
        self.assertEquals(len(pool.listReadyMessages()), 1)
        mid = pool.listReadyMessages()[0]
        self.assertLongStringEq(M2, uncompressData(pool.getReadyMessage(mid)))
        pool.markMessageCompleted(mid)
        pool.close()
        pool = mixminion.Fragments.FragmentPool(loc)
        pool.addFragment(pkts2[48])
        self.assertEquals([], pool.store.getAllMessages())

        # free some RAM
        M1 = M2 = None
        pkts1 = pkts2 = None

        ####
        # Try an interleaved case with two smallish msgs and one big one.
        # Provoke an error in the big one part way through.
        ####
        M1 = Crypto.getCommonPRNG().getBytes(1024*150)
        M2 = Crypto.getCommonPRNG().getBytes(1024*200) 
        M3 = Crypto.getCommonPRNG().getBytes(1024*900)
        pkts1 = [ pp(x) for x in em(M1,38) ]
        pkts2 = [ pp(x) for x in em(M2,0) ]
        pkts3 = [ pp(x) for x in em(M3,0) ]
        self.assertEquals(map(len,[pkts1,pkts2,pkts3]),
                          [11,11,66])
        for i in xrange(7,11):
            pool.addFragment(pkts1[i])
            pool.addFragment(pkts2[11-i])
        for i in xrange(26):
            pool.addFragment(pkts3[i])
        pool.unchunkMessages()
        self.assertEquals(pool.store.count(), 4+4+1+4)
        # Change index of message to impossible value, make sure m3 gets
        # dropped.
        pkts3[60].index = 66
        pool.addFragment(pkts3[60])
        self.assertEquals(pool.store.count(), 4+4)
        for i in xrange(40,55):
            pool.addFragment(pkts3[i])
        self.assertEquals(pool.store.count(), 4+4)

        for i in xrange(1,5):
            pool.addFragment(pkts1[i])
            pool.addFragment(pkts2[11-i])
        pool.unchunkMessages()
        msgids = pool.listReadyMessages()
        self.assertUnorderedEq([pkts1[0].msgID, pkts2[0].msgID],
                               msgids)
        self.assertLongStringEq(M1,
                 uncompressData(pool.getReadyMessage(pkts1[0].msgID)))
        pool.markMessageCompleted(pkts1[0].msgID)

        # Force pkts2 to rejected by expiring it.
        pool.expireMessages(time.time()+48*60*60)
        self.assertEquals(pool.listReadyMessages(), [])
        
#----------------------------------------------------------------------
def testSuite():
    """Return a PyUnit test suite containing all the unit test cases."""
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    tc = loader.loadTestsFromTestCase

    if 0:
        suite.addTest(tc(FragmentTests))
        return suite
    testClasses = [MiscTests,
                   MinionlibCryptoTests,
                   MinionlibFECTests,
                   CryptoTests,
                   PacketTests,
                   LogTests,
                   FileParanoiaTests,
                   ConfigFileTests,
                   HashLogTests,
                   BuildMessageTests,
                   PacketHandlerTests,
                   FilestoreTests,
                   FragmentTests,
                   QueueTests,
                   EventStatsTests,
                   ModuleTests,

                   ClientMainTests,
                   ServerKeysTests,
                   ServerMainTests,

                   # These tests are slowest, so we do them last.
                   ModuleManagerTests,
                   ServerInfoTests,
                   MMTPTests]

    for cl in testClasses:
        suite.addTest(tc(cl))

    return suite

def testAll(name, args):
    init_crypto()
    mixminion.ClientMain.configureClientLock(mix_mktemp())

    # Suppress 'files-can't-be-securely-deleted' message while testing
    LOG.setMinSeverity("FATAL")
    mixminion.Common.secureDelete([],1)

    # Don't complain about owner on /tmp, no matter who it is.
    mixminion.Common._VALID_DIRECTORIES["/tmp"] = 1
    mixminion.Common._VALID_DIRECTORIES["/var/tmp"] = 1

    # Disable TRACE and DEBUG log messages, unless somebody overrides from
    # the environment.
    LOG.setMinSeverity(os.environ.get('MM_TEST_LOGLEVEL', "WARN"))
    #LOG.setMinSeverity(os.environ.get('MM_TEST_LOGLEVEL', "TRACE"))

    unittest.TextTestRunner(verbosity=1).run(testSuite())
