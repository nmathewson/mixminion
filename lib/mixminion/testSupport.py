# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: testSupport.py,v 1.14 2003/02/09 22:30:58 nickm Exp $

"""mixminion.testSupport

   Shared support code for unit tests, benchmark tests, and integration tests.
   """

import base64
import cStringIO
import os
import stat
import sys

import mixminion.Crypto
import mixminion.Common
from mixminion.Common import waitForChildren, createPrivateDir, LOG
from mixminion.Config import _parseBoolean, ConfigError

from mixminion.server.Modules import DELIVER_FAIL_NORETRY, DELIVER_FAIL_RETRY,\
     DELIVER_OK, DeliveryModule, ImmediateDeliveryQueue, \
     SimpleModuleDeliveryQueue, _escapeMessageForEmail

#----------------------------------------------------------------------
# DirectoryStoreModule

class DirectoryStoreModule(DeliveryModule):
    """Delivery module for testing: puts messages in files in a given
       directory.  Can be configured to use a delivery queue or not.

       When this module delivers a message:
       If the routing info is 'FAIL!', the message is treated as undeliverable.
       If the routing info is 'fail', the message is treated as temporarily
         undeliverable (and so will eventually time out).
       Otherwise, creates a file in the specified directory, containing
          the routing info, a newline, and the message contents.
    """
    ## Fields:
    # loc -- The directory to store files in.  All filenames are numbers;
    #    we always put new messages in the smallest number greater than
    #    all existing numbers.
    # next -- the number of the next file.
    def getConfigSyntax(self):
        return { 'Testing/DirectoryDump':
                 { 'Location' : ('REQUIRE', None, None),
                   'UseQueue': ('REQUIRE', _parseBoolean, None) } }

    def validateConfig(self, sections, entries, lines, contents):
        # loc = sections['Testing/DirectoryDump'].get('Location')
        pass

    def configure(self, config, manager):
        self.loc = config['Testing/DirectoryDump'].get('Location')
        if not self.loc:
            return
        self.useQueue = config['Testing/DirectoryDump']['UseQueue']
        manager.enableModule(self)

        if not os.path.exists(self.loc):
            createPrivateDir(self.loc)

        max = -1
        for f in os.listdir(self.loc):
            if int(f) > max:
                max = int(f)
        self.next = max+1

    def getServerInfoBlock(self):
        return ""

    def getName(self):
        return "Testing_DirectoryDump"

    def getExitTypes(self):
        return [ 0xFFFE ]

    def createDeliveryQueue(self, queueDir):
        if self.useQueue:
            return SimpleModuleDeliveryQueue(self, queueDir)
        else:
            return ImmediateDeliveryQueue(self)

    def processMessage(self, packet):
        assert packet.getExitType() == 0xFFFE
        exitInfo = packet.getAddress()

        if exitInfo == 'fail':
            return DELIVER_FAIL_RETRY
        elif exitInfo == 'FAIL!':
            return DELIVER_FAIL_NORETRY

        LOG.debug("Delivering test message")

        m = _escapeMessageForEmail(packet)
        if m is None:
            # Ordinarily, we'd drop corrupt messages, but this module is
            # meant for debugging.
            m = """\
==========CORRUPT OR UNDECODABLE MESSAGE
Decoding handle: %s%s==========MESSAGE ENDS""" % (
                      base64.encodestring(packet.getTag()),
                      base64.encodestring(packet.getContents()))

        f = open(os.path.join(self.loc, str(self.next)), 'w')
        self.next += 1
        f.write(m)
        f.close()
        return DELIVER_OK

#----------------------------------------------------------------------
# mix_mktemp: A secure, paranoid mktemp replacement.  (May be overkill
# for testing, but better safe than sorry.)

# Constant flag: are we paranoid about permissions and uid on our tmpdir?
_MM_TESTING_TEMPDIR_PARANOIA = 1
# Name of our temporary directory: all temporary files go under this
# directory.  If None, it hasn't been created yet.  If it exists,
# it must be owned by us, mode 700, and have no parents that an adversary
# (other than root) could write to.
_MM_TESTING_TEMPDIR = None
# How many temporary files have we created so far?
_MM_TESTING_TEMPDIR_COUNTER = 0
# Do we nuke the contents of _MM_TESTING_TEMPDIR on exit?
_MM_TESTING_TEMPDIR_REMOVE_ON_EXIT = 1
def mix_mktemp(extra=""):
    '''mktemp wrapper. puts all files under a securely mktemped
       directory.'''
    global _MM_TESTING_TEMPDIR
    global _MM_TESTING_TEMPDIR_COUNTER
    if _MM_TESTING_TEMPDIR is None:
        # We haven't configured our temporary directory yet.
        import tempfile
        paranoia = _MM_TESTING_TEMPDIR_PARANOIA

        # If tempfile.mkdtemp exists, use it.  This avoids warnings, and
        # is harder for people to exploit.
        if hasattr(tempfile, 'mkdtemp'):
            try:
                temp = tempfile.mkdtemp()
            except OSError, e:
                print "mkdtemp failure: %s" % e
                sys.exit(1)
        else:
        # Otherwise, pick a dirname, make sure it doesn't exist, and try to
        # create it.
            temp = tempfile.mktemp()
            if paranoia and os.path.exists(temp):
                print "I think somebody's trying to exploit mktemp."
                sys.exit(1)
            try:
                os.mkdir(temp, 0700)
            except OSError, e:
                print "Something's up with mktemp: %s" % e
                sys.exit(1)

        # The directory must exist....
        if not os.path.exists(temp):
            print "Couldn't create temp dir %r" %temp
            sys.exit(1)
        st = os.stat(temp)
        if paranoia:
            # And be writeable only by us...
            if st[stat.ST_MODE] & 077:
                print "Couldn't make temp dir %r with secure permissions" %temp
                sys.exit(1)
            # And be owned by us...
            if st[stat.ST_UID] != os.getuid():
                print "The wrong user owns temp dir %r"%temp
                sys.exit(1)
            parent = temp
            # And if, and all of its parents, must not be group-writeable
            # unless their sticky bit is set, and must not be owned by
            # anybody except us and root.
            while 1:
                p = os.path.split(parent)[0]
                if parent == p:
                    break
                parent = p
                st = os.stat(parent)
                m = st[stat.ST_MODE]
                if m & 02 and not (m & stat.S_ISVTX):
                    print "Directory %s has fishy permissions %o" %(parent,m)
                    sys.exit(1)
                if st[stat.ST_UID] not in (0, os.getuid()):
                    print "Directory %s has bad owner %s" % (parent,
                                                             st[stat.ST_UID])
                    sys.exit(1)

        _MM_TESTING_TEMPDIR = temp
        if _MM_TESTING_TEMPDIR_REMOVE_ON_EXIT:
            import atexit
            atexit.register(deltree, temp)

    # So now we have a temporary directory; return the name of a new
    # file there.
    _MM_TESTING_TEMPDIR_COUNTER += 1
    return os.path.join(_MM_TESTING_TEMPDIR,
                        "tmp%05d%s" % (_MM_TESTING_TEMPDIR_COUNTER,extra))

_WAIT_FOR_KIDS = 1
def deltree(*dirs):
    """Delete each one of a list of directories, along with all of its
       contents."""
    global _WAIT_FOR_KIDS
    if _WAIT_FOR_KIDS:
        print "Waiting for shred processes to finish."
        waitForChildren()
        _WAIT_FOR_KIDS = 0
    for d in dirs:
        if os.path.isdir(d):
            for fn in os.listdir(d):
                loc = os.path.join(d,fn)
                if os.path.isdir(loc):
                    deltree(loc)
                else:
                    os.unlink(loc)
            os.rmdir(d)
        elif os.path.exists(d):
            os.unlink(d)

#----------------------------------------------------------------------
# suspendLog

def suspendLog(severity=None):
    """Temporarily suppress logging output"""
    log = LOG
    if hasattr(log, '_storedHandlers'):
        resumeLog()
    buf = cStringIO.StringIO()
    h = mixminion.Common._ConsoleLogHandler(buf)
    log._storedHandlers = log.handlers
    log._storedSeverity = log.severity
    log._testBuf = buf
    log.handlers = []
    if severity is not None:
        log.setMinSeverity(severity)
    log.addHandler(h)

def resumeLog():
    """Resume logging output.  Return all new log messages since the last
       suspend."""
    log = LOG
    if not hasattr(log, '_storedHandlers'):
        return None
    buf = log._testBuf
    del log._testBuf
    log.handlers = log._storedHandlers
    del log._storedHandlers
    log.setMinSeverity(log._storedSeverity)
    del log._storedSeverity
    return buf.getvalue()

#----------------------------------------------------------------------
# Facilities to temporarily replace attributes and functions for testing

# List of object, attribute, old-value for all replaced attributes.
_REPLACED_OBJECT_STACK = []

def replaceAttribute(object, attribute, value):
    """Temporarily replace <object.attribute> with value.  When
       undoReplacedAttributes() is called, the old value is restored."""
    if hasattr(object, attribute):
        tup = (object, attribute, getattr(object, attribute))
    else:
        tup = (object, attribute)
    _REPLACED_OBJECT_STACK.append(tup)
    setattr(object, attribute, value)

# List of (fnname, args, kwargs) for all the replaced functions that
# have been called.
_CALL_LOG = []

class _ReplacementFunc:
    """Helper object: callable stub that logs its invocations to _CALL_LOG
       and delegates to an internal function."""
    def __init__(self, name, fn=None):
        self.name = name
        self.fn = fn
    def __call__(self, *args, **kwargs):
        _CALL_LOG.append((self.name, args, kwargs))
        if self.fn:
            return self.fn(*args, **kwargs)
        else:
            return None

def replaceFunction(object, attribute, fn=None):
    """Temporarily replace the function or method <object.attribute>.
       If <fn> is provided, replace it with fn; otherwise, the new
       function will just return None.  All invocations of the new
       function will logged, and retrievable by getReplacedFunctionCallLog()"""
    replaceAttribute(object, attribute, _ReplacementFunc(attribute, fn))

def getReplacedFunctionCallLog():
    """Return a list of (functionname, args, kwargs)"""
    return _CALL_LOG

def clearReplacedFunctionCallLog():
    """Clear all entries from the replaced function call log"""
    del _CALL_LOG[:]

def undoReplacedAttributes():
    """Undo all replaceAttribute and replaceFunction calls in effect."""
    # Remember to traverse _REPLACED_OBJECT_STACK in reverse, so that
    # "replace(a,b,c1); replace(a,b,c2)" is properly undone.
    r = _REPLACED_OBJECT_STACK[:]
    r.reverse()
    del _REPLACED_OBJECT_STACK[:]
    for item in r:
        if len(item) == 2:
            o,a = item
            delattr(o,a)
        else:
            o,a,v = item
            setattr(o,a,v)

#----------------------------------------------------------------------
# Long keypairs: stored here to avoid regenerating them every time we need
# to run tests.  (We can't use 1024-bit keys, since they're not long enough
# to use as identity keys.)

TEST_KEYS_2048 = [
"""\
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"""
]

TEST_KEYS_2048 = [
    mixminion.Crypto.pk_decode_private_key(base64.decodestring(s))
    for s in TEST_KEYS_2048 ]
del s
