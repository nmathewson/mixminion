# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Common.py,v 1.109 2003/08/31 19:29:29 nickm Exp $

"""mixminion.Common

   Common functionality and utility code for Mixminion"""

__all__ = [ 'IntervalSet', 'Lockfile', 'LockfileLocked', 'LOG', 'LogStream', 
            'MixError',
            'MixFatalError', 'MixProtocolError', 'UIError', 'UsageError',
            'armorText', 'ceilDiv', 'checkPrivateDir', 'checkPrivateFile',
            'createPrivateDir', 'disp64', 
            'encodeBase64', 'floorDiv', 'formatBase64',
            'formatDate', 'formatFnameTime', 'formatTime',
            'installSIGCHLDHandler', 'isSMTPMailbox', 'openUnique',
            'previousMidnight', 'readFile', 'readPickled',
            'readPossiblyGzippedFile', 'secureDelete', 'stringContains',
            'succeedingMidnight', 'tryUnlink', 'unarmorText',
            'waitForChildren', 'writeFile', 'writePickled' ]

import binascii
import bisect
import calendar
import cPickle
import errno
import gzip
import os
import re
import signal
import stat
import statvfs
import sys
import threading
import time
import traceback
# Imported here so we can get it in mixminion.server without being shadowed
# by the old Queue.py file.
from Queue import Queue, Empty
MessageQueue = Queue
QueueEmpty = Empty
del Queue
del Empty

O_BINARY = getattr(os, 'O_BINARY', 0)

try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import msvcrt
except ImportError:
    mcvcrt = None

try:
    import pwd, grp
except ImportError:
    pwd = grp = None

from types import StringType

class MixError(Exception):
    """Base exception class for all Mixminion errors"""
    pass

class MixFatalError(MixError):
    """Exception class for unrecoverable Mixminion errors."""
    pass

class MixProtocolError(MixError):
    """Exception class for MMTP protocol violations"""
    pass

class MixProtocolReject(MixProtocolError):
    """Exception class for server-rejected packets."""
    pass

class MixProtocolBadAuth(MixProtocolError):
    """Exception class for failed authentication to a server."""
    pass

class MixFilePermissionError(MixFatalError):
    """Exception raised when a file has the wrong owner or permissions."""
    pass

class UIError(MixError):
    """Exception raised for an error that should be reported to the user,
       not dumped as a stack trace."""
    def dump(self):
        if str(self): print >>sys.stderr, "ERROR:", str(self)
    def dumpAndExit(self):
        self.dump()
        sys.exit(1)

class UsageError(UIError):
    """Exception raised for an error that should be reported to the user
       along with a usage message.
    """
    pass

#----------------------------------------------------------------------
# Portability to future Python versions

# In versions of Python before 2.2, a/b performed floor division if a and b
# were integers, and exact division otherwise.  As of 2.2, there is a //
# operator that _always_ does floor division.  As of Python 3, a/b will
# _always_ do exact division.  The most fast, portable way to do floor
# division for nonnegative integers is int(a/b)--but this can give warnings
# if users tell the compiler to gripe when a/b will change.  The most fast,
# portable way that doesn't give warnings is divmod(a,b)[0] -- which is
# not very readable.  Thus, we define these symbolic methods.

# Python 3.0 is off in the distant future, but I like to plan ahead.

def floorDiv(a,b):
    "Compute floor(a / b). See comments for portability notes."
    return divmod(a,b)[0]

def ceilDiv(a,b):
    "Compute ceil(a / b). See comments for portability notes."
    return divmod(a-1,b)[0]+1

#----------------------------------------------------------------------
# String handling

# We create an alias to make the intent of substring-checking code
# more explicit.  It's a bit easier to remember "stringContains(s1,
# s2)" than "s1.find(s2)!=-1".
#
# Note that if s2 is a single character, "s2 in s1" works fine.  Also,
# starting with Python 2.3, the single-caracter restiction is gone.
def stringContains(s1, s2):
    """Return true iff s2 is contained within s1; that is, for some i,
       s1[i:i+len(s2)] == s2"""
    return s1.find(s2) != -1

# String containing characters from "\x00" to "\xFF"; used by 'isPrintingAscii'
_ALLCHARS = "".join(map(chr, range(256)))
# String containing all printing ascii characters; used by 'isPrintingAscii'
_P_ASCII_CHARS = "\t\n\v\r"+"".join(map(chr, range(0x20, 0x7F)))
# String containing all printing ascii characters, and all characters that
# may be used in an extended charset.
_P_ASCII_CHARS_HIGH = "\t\n\v\r"+"".join(map(chr, range(0x20, 0x7F)+
                                                  range(0x80, 0xFF)))

def isPrintingAscii(s,allowISO=0):
    """Return true iff every character in s is a printing ascii character.
       If allowISO is true, also permit characters between 0x80 and 0xFF."""
    if allowISO:
        return len(s.translate(_ALLCHARS, _P_ASCII_CHARS_HIGH)) == 0
    else:
        return len(s.translate(_ALLCHARS, _P_ASCII_CHARS)) == 0

def stripSpace(s, space=" \t\v\n"):
    """Remove all whitespace from s."""
    return s.translate(_ALLCHARS, space)

if sys.version_info[0:3] >= (2,1,0):
    def formatBase64(s):
        """Convert 's' to a one-line base-64 representation."""
        return binascii.b2a_base64(s).strip()
else:
    # Python 2.0 didn't allow a binascii to return more than one line.
    def formatBase64(s):
        """Convert 's' to a one-line base-64 representation."""
        return encodeBase64(s, 64, 1)

def encodeBase64(s, lineWidth=64, oneline=0):
    """Convert 's' to a multiline base-64 representation.  Improves upon
       base64.encodestring by having a variable line width.  Implementation
       is based upon that function.
    """
    pieces = []
    bytesPerLine = floorDiv(lineWidth, 4) * 3
    for i in xrange(0, len(s), bytesPerLine):
        chunk = s[i:i+bytesPerLine]
        pieces.append(binascii.b2a_base64(chunk))
    if oneline:
        return "".join([ s.strip() for s in pieces ])
    else:
        return "".join(pieces)

def disp64(s,n=-1):
    """Return a 'beautified' base64 for use in log messages."""
    s = formatBase64(s)
    if n >= 0:
        s = s[:n]
    while s.endswith('='):
        s = s[:-1]
    return s

def englishSequence(lst, empty="none"):
    """Given a sequence of items, return the sequence formatted
       according to ordinary English conventions of punctuation.

       If the list is empty, the value of 'empty' will be returned."""

    if len(lst) == 0:
        return empty
    elif len(lst) == 1:
        return lst[0]

    punc = ", "
    for item in lst:
        if "," in item or stringContains(item, " and "):
            punc = "; "
            break

    if len(lst) == 2:
        if punc == ", ":
            return "%s and %s" % tuple(lst)
        else:
            return "%s; and %s" % tuple(lst)
    else:
        return "%s%sand %s" % (punc.join(lst[0:-1]), punc, lst[-1])

#----------------------------------------------------------------------
# Functions to generate and parse OpenPGP-style ASCII armor

# Matches a line that needs to be ascii-armored in plaintext mode.
DASH_ARMOR_RE = re.compile('^-', re.M)

def armorText(s, type, headers=(), base64=1):
    """Given a string (s), string holding a message type (type), and a
       list of key-value pairs for headers, generates an OpenPGP-style
       ASCII-armored message of type 'type', with contents 's' and
       headers 'header'.
       
       If base64 is false, uses cleartext armor."""
    result = []
    result.append("-----BEGIN %s-----\n" %type)
    for k,v in headers:
        result.append("%s: %s\n" %(k,v))
    result.append("\n")
    if base64:
        result.append(encodeBase64(s, lineWidth=64))
    else:
        result.append(DASH_ARMOR_RE.sub('- -', s))
    if not result[-1].endswith("\n"):
        result.append("\n")
    result.append("-----END %s-----\n" %type)

    return "".join(result)

# Matches a begin line.
BEGIN_LINE_RE = re.compile(r'^-----BEGIN ([^-]+)-----[ \t]*$',re.M)

# Matches a header line.
ARMOR_KV_RE = re.compile(r'([^:\s]+): ([^\n]+)')
def unarmorText(s, findTypes, base64=1, base64fn=None):
    """Parse a list of OpenPGP-style ASCII-armored messages from 's',
       and return a list of (type, headers, body) tuples, where 'headers'
       is a list of key,val tuples.

       s -- the string to parse.
       findTypes -- a list of types to search for; others are ignored.
       base64 -- if false, we do cleartext armor.
       base64fn -- if provided, called with (type, headers) to tell whether
          we do cleartext armor.
    """
    result = []
    
    while 1:
        tp = None
        fields = []
        value = None

        mBegin = BEGIN_LINE_RE.search(s)
        if not mBegin:
            return result

        tp = mBegin.group(1)
        endPat = r"^-----END %s-----[ \t]*$" % tp

        endRE = re.compile(endPat, re.M)
        mEnd = endRE.search(s, mBegin.start())
        if not mEnd:
            raise ValueError("Couldn't find end line for '%s'"%tp.lower())

        if tp not in findTypes:
            s = s[mEnd.end()+1:]
            continue

        idx = mBegin.end()+1
        endIdx = mEnd.start()

        assert s[idx-1] == s[endIdx-1] == '\n'
        while idx < endIdx:
            nl = s.index("\n", idx, endIdx)
            line = s[idx:nl]
            idx = nl+1
            if ":" in line:
                m = ARMOR_KV_RE.match(line)
                if not m:
                    raise ValueError("Bad header for '%s'"%tp.lower())
                fields.append((m.group(1), m.group(2)))
            elif line.strip() == '':
                break

        if base64fn:
            base64 = base64fn(tp,fields)

        if base64:
            try:
                if stringContains(s[idx:endIdx], "\n[...]\n"):
                    raise ValueError("Value seems to be truncated by a Mixminion-Mixmaster gateway")
                value = binascii.a2b_base64(s[idx:endIdx])
            except (TypeError, binascii.Incomplete, binascii.Error), e:
                raise ValueError(str(e))
        else:
            v = s[idx:endIdx].split("\n")
            for i in xrange(len(v)):
                if v[i].startswith("- "):
                    v[i] = v[i][2:]
            value = "\n".join(v)

        result.append((tp, fields, value))
        
        s = s[mEnd.end()+1:]

    raise MixFatalError("Unreachable code somehow reached.")

#----------------------------------------------------------------------

#----------------------------------------------------------------------

# A set of directories we've issued warnings about -- we won't check
# them again.
_WARNED_DIRECTORIES = {}
# A set of directories that have checked out -- we won't check them again.
_VALID_DIRECTORIES = {}
# A list of user IDs
_TRUSTED_UIDS = [ 0 ]

# Flags: what standard Unix access controls should we check for?
_CHECK_UID = 1
_CHECK_GID = 1
_CHECK_MODE = 1

if sys.platform in ('cygwin', 'win32'):
    # Under windows, we can't do anything sensible with permissions AFAICT.
    _CHECK_UID = _CHECK_GID = _CHECK_MODE = 0
elif os.environ.get("MM_NO_FILE_PARANOIA"):
    _CHECK_UID = _CHECK_GID = _CHECK_MODE = 0

def _uidToName(uid):
    """Helper function: given a uid, return a username or descriptive
       string."""
    try:
        return pwd.getpwuid(uid)[0]
    except (KeyError, AttributeError):
        # KeyError: no such pwent.  AttributeError: pwd module not loaded.
        return "user %s"%uid

def _gidToName(gid):
    """Helper function: given a gid, return a groupname or descriptive string
       """
    try:
        return grp.getgrgid(gid)[0]
    except (KeyError, AttributeError):
        # KeyError: no such grpent.  AttributeError: grp module not loaded.
        return "group %s"%gid
 
def checkPrivateFile(fn, fix=1):
    """Checks whether f is a file owned by this uid, set to mode 0600 or
       0700, and all its parents pass checkPrivateDir.  Raises MixFatalError
       if the assumptions are not met; else return None.  If 'fix' is true,
       repair permissions on the file rather than raising MixFatalError."""
    parent, _ = os.path.split(fn)
    checkPrivateDir(parent)
    try:
        st = os.stat(fn)
    except OSError, e:
        if e.errno == errno.EEXIST:
            raise MixFatalError("Nonexistent file %s" % fn)
        else:
            raise MixFatalError("Couldn't stat file %s: %s" % (fn, e))
    if not st:
        raise MixFatalError("Nonexistent file %s" % fn)
    if not os.path.isfile(fn):
        raise MixFatalError("%s is not a regular file" % fn)
    
    if _CHECK_UID:
        me = os.getuid()
        if st[stat.ST_UID] != me:
            ownerName = _uidToName(st[stat.ST_UID])
            myName = _uidToName(me)
            raise MixFilePermissionError(
                "File %s is owned by %s, but Mixminion is running as %s" 
                % (fn, ownerName, myName))
    mode = st[stat.ST_MODE] & 0777
    if _CHECK_MODE and mode not in (0700, 0600):
        if not fix:
            raise MixFilePermissionError("Bad permissions (mode %o) on file %s"
                                         % (mode & 0777, fn))
        newmode = {0:0600,0100:0700}[(mode & 0100)]
        LOG.warn("Repairing permissions on file %s" % fn)
        os.chmod(fn, newmode)

def createPrivateDir(d, nocreate=0):
    """Create a directory, and all parent directories, checking permissions
       as we go along.  All superdirectories must be owned by root or us."""
    if not os.path.exists(d):
        if nocreate:
            raise MixFatalError("Nonexistent directory %s" % d)
        try:
            os.makedirs(d, 0700)
        except OSError, e:
            raise MixFatalError(
                "Unable to create directory %s: %s" % (d, e))

    checkPrivateDir(d)

def checkPrivateDir(d, recurse=1):
    """Check whether d is a directory owned by this uid, set to mode
       0700. All of d's parents must not be writable or owned by anybody but
       this uid and uid 0.  If any of these conditions are unmet, raise
       MixFatalErrror.  Otherwise, return None."""
    if _CHECK_UID:
        me = os.getuid()
        trusted_uids = _TRUSTED_UIDS + [ me ]

    if not os.path.isabs(d):
        d = os.path.abspath(d)

    if not os.path.exists(d):
        raise MixFatalError("Directory %s does not exist" % d)
    if not os.path.isdir(d):
        raise MixFatalError("%s is not a directory" % d)

    st = os.stat(d)
    # check permissions
    if _CHECK_MODE and st[stat.ST_MODE] & 0777 != 0700:
        raise MixFilePermissionError("Directory %s must be mode 0700" % d)

    if _CHECK_UID and st[stat.ST_UID] != me:
        ownerName = _uidToName( st[stat.ST_UID])
        myName = _uidToName(me)
        raise MixFilePermissionError(
            "Directory %s is owned by %s, but Mixminion is running as %s"
            %(d,ownerName,myName))

    if not recurse:
        return

    # Check permissions on parents.
    while 1:
        parent = os.path.split(d)[0]
        if _VALID_DIRECTORIES.has_key(parent):
            return
        if parent == d:
            return
        d = parent

        st = os.stat(d)
        mode = st[stat.ST_MODE]
        owner = st[stat.ST_UID]
        if _CHECK_UID and owner not in trusted_uids:
            ownerName = _uidToName(owner)
            trustedNames = map(_uidToName,trusted_uids)
            raise MixFilePermissionError(
                "Directory %s is owned by %s, but I only trust %s"
                % (d, ownerName, englishSequence(trustedNames, "(nobody)")))
        if _CHECK_MODE and (mode & 02) and not (mode & stat.S_ISVTX):
            raise MixFilePermissionError(
                "Bad permissions (mode %o) on directory %s" %
                (mode&0777, d))

        if _CHECK_MODE and (mode & 020) and not (mode & stat.S_ISVTX):
            # FFFF We may want to give an even stronger error here.
            if _CHECK_GID and not _WARNED_DIRECTORIES.has_key(d):
                groupName = _gidToName(st[stat.ST_GID])
                LOG.warn("Directory %s is writable by group %s (mode %o)",
                         d, groupName, mode&0777)
                _WARNED_DIRECTORIES[d] = 1

def configureFileParanoia(config):
    global _CHECK_UID
    global _CHECK_GID
    global _CHECK_MODE
    paranoia = config['Host']['FileParanoia']
    if not paranoia:
        _CHECK_UID = _CHECK_GID = _CHECK_MODE = 0

    users = config['Host']['TrustedUser']
    if not users:
        return
    if not _CHECK_UID:
        return

    for uid in users:
        _TRUSTED_UIDS.append(uid)

#----------------------------------------------------------------------
# File helpers


# On windows, rename(f1,f2) fails if f2 already exists.  These wrappers
# handle replacing files.
if sys.platform == 'win32':
    def replaceFile(f1, f2):
        """Move the file named 'f1' to a new name 'f2'.  Replace any file
           already named 'f2'."""
        # WWWW This isn't atomic.  Later versions of the windows API add
        # WWWW functions named MoveFileEx and ReplaceFile that may do the
        # WWWW right thing, but those don't exist in Windows Me/98/95.
        if os.path.exists(f2):
            os.unlink(f2)
        os.rename(f1, f2) 
else:
    def replaceFile(f1, f2):
        """Move the file named 'f1' to a new name 'f2'.  Replace any file
           already named 'f2'."""
        os.rename(f1, f2)

class AtomicFile:
    """Wrapper around open/write/rename to encapsulate writing to a temporary
       file, then moving to the final filename on close.

       NOTE 1: If you don't call 'close' or 'discard' on this object,
       the temporary file it creates will stay around indefinitely.

       NOTE 2: If multiple AtomicFiles are active for the same destination
       file, the last one to close will win, and results for the others will
       not be visible.
       """
    def __init__(self, fname, mode='w'):
        self.fname = fname
        self.tmpname = fname + ".tmp"
        self.f, self.tmpname = openUnique(self.tmpname)

    def write(self, s):
        self.f.write(s)

    def close(self):
        """Close the underlying file and replace the destination file."""
        replaceFile(self.tmpname, self.fname)
        self.f.close()
        self.f = None

    def discard(self):
        """Discard changes to the temporary file."""
        self.f.close()
        os.unlink(self.tmpname)
        self.f = None

    def __del__(self):
        if self.f:
            LOG.error("Atomic file not closed/discarded: %s",self.tmpname)

def readFile(fn, binary=0):
    """Return the contents of the file named <fn>."""
    f = open(fn, ['r', 'rb'][binary])
    try:
        return f.read()
    finally:
        f.close()

def writeFile(fn, contents, mode=0600, binary=0):
    """Atomically write a string <contents> into a file <file> with mode
       <mode>.  If <binary>, binary mode will be used.

       If the file exists, it will be replaced.

       If two processes attempt to writeFile the same file at once,
       the one finishing last wins.
       """
    tmpname = fn+".tmp"
    f, tmpname = openUnique(tmpname, ['w','wb'][binary], mode)
    try:
        try:
            f.write(contents)
        finally:
            f.close()
    except:
        if os.path.exists(tmpname): os.unlink(tmpname)
        raise

    replaceFile(tmpname, fn)

def readPickled(fn):
    """Given the name of a file containing a pickled object, return the pickled
       object."""
    f = open(fn, 'rb')
    try:
        return cPickle.load(f)
    finally:
        f.close()

def writePickled(fn, obj, mode=0600):
    """Given a filename and an object to be pickled, pickles the object into
       a temporary file, then replaces the file with the temporary file.
    """
    tmpname = fn + ".tmp"
    f, tmpname = openUnique(tmpname, 'wb', mode)
    try:
        try:
            cPickle.dump(obj, f, 1)
        finally:
            f.close()
    except:
        if os.path.exists(tmpname): os.unlink(tmpname)
        raise

    replaceFile(tmpname, fn)

def tryUnlink(fname):
    """Try to remove the file named fname.  If the file is erased, return 1.
       If the file didn't exist in the first place, return 0.  Otherwise
       propagate an exception."""
    try:
        os.unlink(fname)
        return 1
    except OSError, e:
        if e.errno == errno.ENOENT:
            return 0
        raise

#----------------------------------------------------------------------
# Secure filesystem operations.

# A 'shred' command to overwrite and unlink files.  It should accept an
# arbitrary number of arguments.  (If "---", we haven't configured the
# shred command.  If None, we're using our internal implementation.)
_SHRED_CMD = "---"
# Tuple of options to be passed to the 'shred' command
_SHRED_OPTS = None

def configureShredCommand(conf):
    """Initialize the secure delete command from a given Config object.
       If no object is provided, try some sane defaults."""
    global _SHRED_CMD
    global _SHRED_OPTS
    cmd, opts = None, None
    if conf is not None:
        val = conf['Host'].get('ShredCommand')
        if val is not None:
            cmd, opts = val

    if cmd is None:
        if os.path.exists("/usr/bin/shred"):
            cmd, opts = "/usr/bin/shred", ["-uz", "-n0"]
        else:
            # Use built-in _overwriteFile
            cmd, opts = None, None

    _SHRED_CMD, _SHRED_OPTS = cmd, opts


# Map from parent directory to blocksize.  We only overwrite files in a few
# locations, so this should be safe.
_BLKSIZEMAP = {}
# A string of max(_BLKSIZEMAP.values()) zeros
_NILSTR = ""
def _overwriteFile(f):
    """Overwrite f with zeros, rounding up to the nearest block.  This is
       used as the default implementation of secureDelete."""
    global _NILSTR
    parent = os.path.split(f)[0]
    try:
        sz = _BLKSIZEMAP[parent]
    except KeyError:
        if hasattr(os, 'statvfs'):
            sz = os.statvfs(f)[statvfs.F_BSIZE]
        else:
            sz = 8192 # Should be a safe guess? (????)
        _BLKSIZEMAP[parent] = sz
        if sz > len(_NILSTR):
            _NILSTR = '\x00' * sz
    nil = _NILSTR[:sz]
    fd = os.open(f, os.O_WRONLY|O_BINARY)
    try:
        size = os.fstat(fd)[stat.ST_SIZE]
        blocks = ceilDiv(size, sz)
        for _ in xrange(blocks):
            os.write(fd, nil)
        if hasattr(os, 'fsync'):
            os.fsync(fd)
    finally:
        os.close(fd)

def secureDelete(fnames, blocking=0):
    """Given a list of filenames, removes the contents of all of those
       files, from the disk, 'securely'.  If blocking=1, does not
       return until the remove is complete.  If blocking=0, returns
       immediately, and continues removing the files in the background.

       Securely deleting files only does so much good.  Metadata on
       the file system, such as atime and dtime, can still be used to
       reconstruct information about message timings.  To be more
       safe, we could use a loopback device and shred _that_ from time
       to time.  But since many filesystems relocate data underneath
       you, you can't trust loopback devices: a separate shreddable
       partition is necessary.  But even then, HD controllers and
       drives sometimes relocate blocks to avoid bad blocks: then
       there's no way to overwrite the old locations!  The only
       heavy-duty solution is to use an encrypted filesystem and swap
       partition from the get-go... or to physically destroy and
       replace your hard drive every so often.)

       So we don't even bother trying to make the data 'physically
       irretrievable.'  We just zero it out, which should be good
       enough to stymie root for most purposes, and totally inadequate
       against a well-funded adversary with access to your hard drive
       and a bunch of sensitive magnetic equipment.

       XXXX Currently, we use shred from GNU fileutils.  Shred's 'unlink'
       XXXX operation has the regrettable property that two shred commands
       XXXX running in the same directory can sometimes get into a race.
       XXXX The source to shred.c seems to imply that this is harmless, but
       XXXX let's try to avoid that, to be on the safe side.
    """
    if _SHRED_CMD == "---":
        configureShredCommand(None)

    if fnames == []:
        return

    if isinstance(fnames, StringType):
        fnames = [fnames]

    if not _SHRED_CMD:
        for f in fnames:
            _overwriteFile(f)
            os.unlink(f)
        return None

    # Some systems are unhappy when you call them with too many options.
    for i in xrange(0, len(fnames), 250-len(_SHRED_OPTS)):
        files = fnames[i:i+250-len(_SHRED_OPTS)]
        pid = os.spawnl(os.P_NOWAIT,
                        _SHRED_CMD, _SHRED_CMD, *(_SHRED_OPTS+files))
        if blocking:
            try:
                os.waitpid(pid, 0)
            except OSError:
                # sigchild handler might get to the pid first.
                pass

#----------------------------------------------------------------------
# Logging
#
# I'm trying to make this interface look like a subset of the one in
# the draft PEP-0282 (http://www.python.org/peps/pep-0282.html).

def _logtime():
    'Helper function.  Returns current local time formatted for log.'
    t = time.time()
    return "%s.%03d"%(time.strftime("%b %d %H:%M:%S", time.localtime(t)),
                      (t*1000)%1000)

class _FileLogHandler:
    """Helper class for logging.  Represents a file on disk, and allows the
       usual close-and-open gimmick for log rotation."""
     ## Fields:
     #     file -- a file object, or None if the file is closed.
     #     fname -- this log's associated filename
    def __init__(self, fname):
        "Create a new FileLogHandler to append messages to fname"
        self.file = None
        self.fname = fname
        self.reset()
    def reset(self):
        """Close and reopen our underlying file.  This behavior is needed
           to implement log rotation."""
        if self.file is not None:
            self.file.close()
        try:
            parent = os.path.split(self.fname)[0]
            if not os.path.exists(parent):
                createPrivateDir(parent)
            self.file = open(self.fname, 'a')
        except OSError, e:
            self.file = None
            raise MixError("Unable to open log file %r: %s"%(self.fname, e))
    def close(self):
        "Close the underlying file"
        self.file.close()
    def write(self, severity, message):
        """(Used by Log: write a message to this log handler.)"""
        if self.file is None:
            return
        print >> self.file, "%s [%s] %s" % (_logtime(), severity, message)
        self.file.flush()

class _ConsoleLogHandler:
    """Helper class for logging: directs all log messages to a stderr-like
       file object"""
    def __init__(self, file):
        "Create a new _ConsoleLogHandler attached to a given file."""
        self.file = file
    def reset(self): pass
    def close(self): pass
    def write(self, severity, message):
        """(Used by Log: write a message to this log handler.)"""
        print >> self.file, "%s [%s] %s" % (_logtime(), severity, message)

# Map from log severity name to numeric values
_SEVERITIES = { 'TRACE' : -2,
                'DEBUG' : -1,
                'INFO' : 0,
                'WARN' : 1,
                'ERROR': 2,
                'FATAL' : 3,
                'NEVER' : 100}

class Log:
    """A Log is a set of destinations for system messages, along with the
       means to filter them to a desired verbosity.

       Log messages have 'severities' as follows:
              TRACE: hyperverbose mode; used for debugging fiddly
                 little details.  This is a security risk.
              DEBUG: very verbose mode; used for tracing connections
                 and messages through the system.  This is a security risk.
              INFO: non-critical events.
              WARN: recoverable errors
              ERROR: nonrecoverable errors that affect only a single
                 message or a connection.
              FATAL: nonrecoverable errors that affect the entire system.

       In practice, we instantiate only a single instance of this class,
       accessed as mixminion.Common.LOG."""
    ## Fields:
    # handlers: a list of logHandler objects.
    # severity: a severity below which log messages are ignored.
    def __init__(self, minSeverity):
        """Create a new Log object that ignores all message less severe than
           minSeverity, and sends its output to stderr."""
        self.configure(None)
        self.setMinSeverity(minSeverity)
        self.__lock = threading.Lock()

    def configure(self, config, keepStderr=0):
        """Set up this Log object based on a ServerConfig or ClientConfig
           object

           If keepStderr is true, do not silence the console log, regardless
           of the value of 'Daemon' or 'EchoMessages'.
           """
        self.handlers = []
        if config == None or not config.has_section("Server"):
            self.setMinSeverity("WARN")
            self.addHandler(_ConsoleLogHandler(sys.stderr))
        else:
            self.setMinSeverity(config['Server'].get('LogLevel', "WARN"))
            logfile = config['Server'].get('LogFile')
            if logfile is None:
                homedir = config['Server'].get('Homedir')
                if homedir:
                    logfile = os.path.join(homedir, "log")
            self.addHandler(_ConsoleLogHandler(sys.stderr))
            if logfile:
                try:
                    self.addHandler(_FileLogHandler(logfile))
                except MixError, e:
                    self.error(str(e))
                if keepStderr:
                    return
                if (config['Server'].get('Daemon',0) or
                    not config['Server'].get('EchoMessages',0)):
                    print "Silencing the console log; look in %s instead"%(
                        logfile)
                    del self.handlers[0]

    def setMinSeverity(self, minSeverity):
        """Sets the minimum severity of messages to be logged.
              minSeverity -- the string representation of a severity level."""
        self.severity = _SEVERITIES.get(minSeverity, 1)

    def getMinSeverity(self):
        """Return a string representation of this log's minimum severity
           level."""
        for k,v in _SEVERITIES.items():
            if v == self.severity:
                return k
        return "INFO"

    def addHandler(self, handler):
        """Add a LogHandler object to the list of objects that receive
           messages from this log."""
        self.handlers.append(handler)

    def reset(self):
        """Flush and re-open all logs."""
        for h in self.handlers:
            try:
                h.reset()
            except MixError, e:
                if len(self.handlers) > 1:
                    self.error(str(e))
                else:
                    print >>sys.stderr, "Unable to reset log system"

    def close(self):
        """Close all logs"""
        for h in self.handlers:
            h.close()

    def log(self, severity, message, *args):
        """Send a message of a given severity to the log.  If additional
           arguments are provided, write 'message % args'. """
        self._log(severity, message, args)

    def _log(self, severity, message, args):
        """Helper method: If we aren't ignoring messages of level 'severity',
           then send message%args to all the underlying log handlers."""

        # Enable this block to bail early in production versions
        #if _SEVERITIES.get(severity, 100) < self.severity:
        #    return
        if args is None:
            m = message
        else:
            m = message % args

        # Enable this block to debug message formats.
        if _SEVERITIES.get(severity, 100) < self.severity:
            return

        self.__lock.acquire()
        try:
            for h in self.handlers:
                h.write(severity, m)
        finally:
            self.__lock.release()

    def trace(self, message, *args):
        "Write a trace (hyperverbose) message to the log"
        self.log("TRACE", message, *args)
    def debug(self, message, *args):
        "Write a debug (verbose) message to the log"
        self.log("DEBUG", message, *args)
    def info(self, message, *args):
        "Write an info (non-error) message to the log"
        self.log("INFO", message, *args)
    def warn(self, message, *args):
        "Write a warn (recoverable error) message to the log"
        self.log("WARN", message, *args)
    def error(self, message, *args):
        "Write an error (message loss error) message to the log"
        self.log("ERROR", message, *args)
    def fatal(self, message, *args):
        "Write a fatal (unrecoverable system error) message to the log"
        self.log("FATAL", message, *args)
    def log_exc(self, severity, (exclass, ex, tb), message=None, *args):
        """Write an exception and stack trace to the log.  If message and
           args are provided, use them as an explanatory message; otherwise,
           introduce the message as "Unexpected exception".

           This should usually be called as
               LOG.log_exc('ERROR', sys.exc_info(), message, args...)
           """
        if message is not None:
            self.log(severity, message, *args)
        elif tb is not None:
            filename = tb.tb_frame.f_code.co_filename
            self.log(severity, "Unexpected exception in %s", filename)
        else:
            self.log(severity, "Unexpected exception")

        formatted = traceback.format_exception(exclass, ex, tb)
        formatted[1:] = [ "  %s" % line for line in formatted[1:] ]
        indented = "".join(formatted)
        if indented.endswith('\n'):
            indented = indented[:-1]
        self._log(severity, indented, None)

    def error_exc(self, (exclass, ex, tb), message=None, *args):
        "Same as log_exc, but logs an error message."
        self.log_exc("ERROR", (exclass, ex, tb), message, *args)

    def fatal_exc(self, (exclass, ex, tb), message=None, *args):
        "Same as log_exc, but logs a fatal message."
        self.log_exc("FATAL", (exclass, ex, tb), message, *args)

# The global 'Log' instance for the mixminion client or server.
LOG = Log('WARN')

class LogStream:
    """Replacement for stdout or stderr when running in daemon mode;
       sends all output to log.

       We don't actually want to use these; but they keep us from dropping
       prints on the floor.
       """
    # Fields:
    #    name -- The name of this stream
    #    severity -- The severity of log messages to generate.
    #    buf -- A list of strings that have been written to this stream since
    #        we most recently flushed the buffer to the log.
    def __init__(self, name, severity):
        self.name = name
        self.severity = severity
        self.buf = []
    def write(self, s):
        # This is inefficient, but we don't actually use this class if we can
        # avoid it.  The basic idea is to generate a call to Log.log for every
        # newline.  (This buffering is particularly necessary because typical
        # uses of sys.stdout/stderr generate multiple calls to file.write per
        # line.)
        if "\n" not in s:
            self.buf.append(s)
            return

        while "\n" in s:
            idx = s.index("\n")
            line = "%s%s" %("".join(self.buf), s[:idx])
            LOG.log(self.severity, "->%s: %s", self.name, line)
            del self.buf[:]
            s = s[idx+1:]

        if s:
            self.buf.append(s)

    def flush(self): pass
    def close(self): pass

#----------------------------------------------------------------------
# Time processing

def previousMidnight(when):
    """Given a time_t 'when', return the greatest time_t <= when that falls
       on midnight, GMT."""
    yyyy,MM,dd = time.gmtime(when)[0:3]
    return calendar.timegm((yyyy,MM,dd,0,0,0,0,0,0))

def succeedingMidnight(when):
    """Given a time_t 'when', return the smallest time_t > when that falls
       on midnight, GMT."""
    yyyy,MM,dd = time.gmtime(when)[0:3]
    try:
        return calendar.timegm((yyyy,MM,dd+1,0,0,0,0,0,0))
    except ValueError:
        # Python 2.3 seems to raise ValueError when dd is the last day of the
        # month.
        pass
    if MM < 12:
        return calendar.timegm((yyyy,MM+1,1,0,0,0,0,0,0))
    else:
        return calendar.timegm((yyyy+1,1,1,0,0,0,0,0,0))

def formatTime(when,localtime=0):
    """Given a time in seconds since the epoch, returns a time value in the
       format used by server descriptors (YYYY/MM/DD HH:MM:SS) in GMT"""
    if localtime:
        gmt = time.localtime(when)
    else:
        gmt = time.gmtime(when)
    return "%04d/%02d/%02d %02d:%02d:%02d" % (
        gmt[0],gmt[1],gmt[2],  gmt[3],gmt[4],gmt[5])

def formatDate(when):
    """Given a time in seconds since the epoch, returns a date value in the
       format used by server descriptors (YYYY/MM/DD) in GMT"""
    gmt = time.gmtime(when+1) # Add 1 to make sure we round down.
    return "%04d/%02d/%02d" % (gmt[0],gmt[1],gmt[2])

def formatFnameTime(when=None):
    """Given a time in seconds since the epoch, returns a date value suitable
       for use as part of a filename.  Defaults to the current time."""
    if when is None:
        when = time.time()
    return time.strftime("%Y%m%d%H%M%S", time.localtime(when))

#----------------------------------------------------------------------
class Duration:
    """A Duration is a number of time units, such as '1.5 seconds' or
       '2 weeks'.  Durations are stored internally as a number of seconds.
    """
    ## Fields:
    # seconds: the number of seconds in this duration
    # unitName: the name of the units comprising this duration.
    # nUnits: the number of units in this duration
    def __init__(self, seconds, unitName=None, nUnits=None):
        """Initialize a new Duration with a given number of seconds."""
        self.seconds = seconds
        if unitName:
            self.unitName = unitName
            self.nUnits = nUnits
        else:
            self.unitName = "second"
            self.nUnits = seconds

    def __str__(self):
        s = ""
        if self.nUnits != 1:
            s = "s"
        return "%s %s%s" % (self.nUnits, self.unitName, s)

    def __repr__(self):
        return "Duration(%r, %r, %r)" % (self.seconds, self.unitName,
                                         self.nUnits)

    def __float__(self):
        """Return the number of seconds in this duration"""
        return self.seconds

    def __int__(self):
        """Return the number of seconds in this duration"""
        return int(self.seconds)

    def getSeconds(self):
        """Return the number of seconds in this duration"""
        return self.seconds

    def reduce(self):
        """Change the representation of this object to its clearest form"""
        s = self.seconds
        for n,u in [(60*60*24*365,'year'),
                    (60*60*24*30, 'month'),
                    (60*60*24*7,  'week'),
                    (60*60*24,    'day'),
                    (60*60,       'hour'),
                    (60,          'minute')]:
            if s % n == 0:
                self.nUnits = floorDiv(s,n)
                self.unitName = u
                return
        self.nUnits = s
        self.unitName = 'second'
        return self

#----------------------------------------------------------------------
# IntervalSet

class IntervalSet:
    """An IntervalSet is a mutable set of numeric intervals, closed below and
       open above.  Not very optimized for now.  Supports "+" for union, "-"
       for disjunction, and "*" for intersection."""
    ## Fields:
    # edges: an ordered list of boundary points between interior and
    #     exterior points, of the form (x, '+') for an 'entry' and
    #     (x, '-') for an 'exit' boundary.
    #
    # FFFF There must be a more efficient algorithm for this, but we're so
    # FFFF far from the critical path here that I'm not going to look for it
    # FFFF for quite a while.
    def __init__(self, intervals=None):
        """Given a list of (start,end) tuples, construct a new IntervalSet.
           Tuples are ignored if start>=end."""
        self.edges = []
        if intervals:
            for start, end in intervals:
                if start < end:
                    self.edges.append((start, '+'))
                    self.edges.append((end, '-'))
    def copy(self):
        """Create a new IntervalSet with the same intervals as this one."""
        r = IntervalSet()
        r.edges = self.edges[:]
        return r
    def __iadd__(self, other):
        """self += b : Causes this set to contain all points in itself but not
           in b."""
        self.edges += other.edges
        self._cleanEdges()
        return self
    def __isub__(self, other):
        """self -= b : Causes this set to contain all points in itself but not
           in b"""
        for t, e in other.edges:
            if e == '+':
                self.edges.append((t, '-'))
            else:
                self.edges.append((t, '+'))
        self._cleanEdges()
        return self
    def __imul__(self, other):
        """self *= b : Causes this set to contain all points in both itself and
           b."""
        self.edges += other.edges
        self._cleanEdges(2)
        return self

    def _cleanEdges(self, nMin=1):
        """Internal helper method: to be called when 'edges' is in a dirty
           state, containing entry and exit points that don't create a
           well-defined set of intervals.  Only those points that are 'entered'
           nMin times or more are retained.
           """
        edges = self.edges
        edges.sort()
        depth = 0
        newEdges = [ ('X', 'X') ] #marker value; will be removed.
        for t, e in edges:
            # Traverse the edges in order; keep track of how many more
            # +'s we have seen than -'s.  Whenever that number increases
            # above nMin, add a +.  Whenever that number drops below nMin,
            # add a - ... but if the new edge would cancel out the most
            # recently added one, then delete the most recently added one.
            if e == '+':
                depth += 1
                if depth == nMin:
                    if newEdges[-1] == (t, '-'):
                        del newEdges[-1]
                    else:
                        newEdges.append((t, '+'))
            if e == '-':
                if depth == nMin:
                    if newEdges[-1] == (t, '+'):
                        del newEdges[-1]
                    else:
                        newEdges.append((t, '-'))
                depth -= 1
        assert depth == 0
        del newEdges[0]
        self.edges = newEdges

    def __add__(self, other):
        r = self.copy()
        r += other
        return r

    def __sub__(self, other):
        r = self.copy()
        r -= other
        return r

    def __mul__(self, other):
        r = self.copy()
        r *= other
        return r

    def __contains__(self, other):
        """'a in self' is true when 'a' is a number contained in some interval
            in this set, or when 'a' is an IntervalSet that is a subset of
            this set."""
        if isinstance(other, IntervalSet):
            return self*other == other
        idx = bisect.bisect(self.edges, (other, '-'))
        return idx < len(self.edges) and self.edges[idx][1] == '-'

    def isEmpty(self):
        """Return true iff this set contains no points"""
        return len(self.edges) == 0

    def __nonzero__(self):
        """Return true iff this set contains some points"""
        return len(self.edges) != 0

    def __repr__(self):
        s = [ "(%s,%s)"%(start,end) for start, end in self.getIntervals() ]
        return "IntervalSet([%s])"%",".join(s)

    def getIntervals(self):
        """Returns a list of (start,end) tuples for a the intervals in this
           set."""
        s = []
        for i in range(0, len(self.edges), 2):
            s.append((self.edges[i][0], self.edges[i+1][0]))
        return s

    def _checkRep(self):
        """Helper function: raises AssertionError if this set's data is
           corrupted."""
        assert (len(self.edges) % 2) == 0
        for i in range(0, len(self.edges), 2):
            assert self.edges[i][0] < self.edges[i+1][0]
            assert self.edges[i][1] == '+'
            assert self.edges[i+1][1] == '-'
            assert i == 0 or self.edges[i-1][0] < self.edges[i][0]

    def __cmp__(self, other):
        """A == B iff A and B contain exactly the same intervals."""
        return cmp(self.edges, other.edges)

    def start(self):
        """Return the first point contained in this interval."""
        return self.edges[0][0]

    def end(self):
        """Return the last point contained in this interval."""
        return self.edges[-1][0]

#----------------------------------------------------------------------
# SMTP address functionality

# Regular expressions to validate RFC822 addresses.
# (This is more strict than RFC822, actually.  RFC822 allows tricky stuff to
#   quote special characters, and I don't trust every MTA or delivery command
#   to support addresses like <bob@bob."; rm -rf /; echo".com>
# (Also, allowing trickier syntax like president@[198.137.241.45] or
#  w@"whitehouse".gov, or makes it far harder to implement exit-address
#  blacklisting.)

# An 'Atom' is a non-escape, non-null, non-space, non-punctuation character.
_ATOM_PAT = r'[^\x00-\x20()\[\]()<>@,;:\\".\x7f-\xff]+'
# The 'Local part' (and, for us, the domain portion too) is a sequence of
# dot-separated atoms.
_LOCAL_PART_PAT = r"(?:%s)(?:\.(?:%s))*" % (_ATOM_PAT, _ATOM_PAT)
# A mailbox is two 'local parts' separated by an @ sign.
_RFC822_PAT = r"\A%s@%s\Z" % (_LOCAL_PART_PAT, _LOCAL_PART_PAT)
RFC822_RE = re.compile(_RFC822_PAT)
# We explicitly check for IPs in the domain part, and block them, for reasons
# described above.  (Enough MTA's deliver x@127.0.0.1 as if it were
# x@[127.0.0.1] that we need to be careful.)
_EMAIL_BY_IP_PAT = r"\A.*@\d+(?:\.\d+)*\Z"
EMAIL_BY_IP_RE = re.compile(_EMAIL_BY_IP_PAT)

def isSMTPMailbox(s):
    """Return true iff s is a valid SMTP address"""
    m = RFC822_RE.match(s)
    if m is None:
        return 0
    m = EMAIL_BY_IP_RE.match(s)
    return m is None

#----------------------------------------------------------------------
# Signal handling

def waitForChildren(onceOnly=0, blocking=1):
    """Wait until all subprocesses have finished.  Useful for testing."""
    if blocking:
        options = 0
    else:
        options = os.WNOHANG
    if sys.platform == 'win32':
        LOG.warn("Skipping waitForChildren")
        return
    while 1:
        try:
            # WWWW This won't work on Windows.  What to do?
            pid, status = os.waitpid(-1, options)
        except OSError, e:
            return
        except e:
            print e, repr(e), e.__class__
        if onceOnly:
            return

def _sigChldHandler(signal_num, _):
    '''(Signal handler for SIGCHLD)'''
    # Because of the peculiarities of Python's signal handling logic, I
    # believe we need to re-register ourself.
    signal.signal(signal.SIGCHLD, _sigChldHandler)

    while 1:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
        except OSError:
            break

    #outcome, core, sig = status & 0xff00, status & 0x0080, status & 0x7f
    # FFFF Log if outcome wasn't as expected.

def installSIGCHLDHandler():
    '''Register sigchld handler for this process.'''
    #WWWWW
    if sys.platform == 'win32':
        LOG.warn("Skipping installSIGCHLDHandler")
        return
    signal.signal(signal.SIGCHLD, _sigChldHandler)

#----------------------------------------------------------------------
# File helpers.

def readPossiblyGzippedFile(fname, mode='r'):
    """Read the contents of the file <fname>.  If <fname> ends with ".gz",
       treat it as a gzipped file."""
    f = None
    try:
        if fname.endswith(".gz"):
            f = gzip.GzipFile(fname, 'rb')
        else:
            f = open(fname, 'r')
        return f.read()
    finally:
        if f is not None:
            f.close()

def openUnique(fname, mode='w', perms=0600):
    """Helper function. Returns a file open for writing into the file named
       'fname'.  If fname already exists, opens 'fname.1' or 'fname.2' or
       'fname.3' or so on."""
    if 'b' in mode: 
        bin = O_BINARY
    else:
        bin = 0
    base, rest = os.path.split(fname)
    idx = 0
    while 1:
        try:
            fd = os.open(fname, os.O_WRONLY|os.O_CREAT|os.O_EXCL|bin, perms)
            return os.fdopen(fd, mode), fname
        except OSError, e:
            if e.errno != errno.EEXIST:
                raise
        idx += 1
        fname = os.path.join(base, "%s.%s"%(rest,idx))

    raise MixFatalError("unreachable code")

#----------------------------------------------------------------------
class LockfileLocked(Exception):
    """Exception raised when trying to get a nonblocking lock on a locked
       lockfile"""
    pass

class Lockfile:
    """Class to implement a recursive advisory lock, using flock on a
       'well-known' filename."""
    ## Fields:
    # filename--the name of the file to lock
    # count--the recursion depth of the lock; 0 is unlocked.
    # fd--If fd>1, a file descriptor open to 'filename'.  Otherwise, None.
    def __init__(self, filename):
        """Create a new Lockfile object to acquire and release a lock on
           'filename'"""
        self.filename = filename
        self.count = 0
        self.fd = None

    def getContents(self):
        """Return the contents of the lock file."""
        return readFile(self.filename)

    def acquire(self, contents="", blocking=0):
        """Acquire this lock.  If we're acquiring the lock for the first time,
           write 'contents' to the lockfile.  If 'blocking' is true, wait
           until we can acquire the lock.  If 'blocking' is false, raise
           LockfileLocked if we can't acquire the lock."""

        if self.count > 0:
            self.count += 1
            return

        assert self.fd is None
        self.fd = os.open(self.filename, os.O_RDWR|os.O_CREAT, 0600)
        try:
            self._lock(self.fd, blocking)
            self.count += 1
            os.write(self.fd, contents)
            os.fsync(self.fd)
        except:
            os.close(self.fd)
            self.fd = None
            raise

    def release(self):
        """Release the lock."""
        assert self.fd is not None
        self.count -= 1
        if self.count > 0:
            return
        try:
            os.unlink(self.filename)
        except OSError:
            pass
        try:
            self._unlock(self.fd)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass

        self.fd = None

    def _lock(self, fd, blocking):
        """Compatibility wrapper to implement file locking for posix and win32
           systems.  If 'blocking' is false, and the lock cannot be obtained,
           raises LockfileLocked."""
        if fcntl:
            # Posixy systems have a friendly neighborhood flock clone.
            flags = fcntl.LOCK_EX
            if not blocking: flags |= fcntl.LOCK_NB
            try:
                fcntl.flock(fd, flags)
            except IOError, e:
                if e.errno in (errno.EAGAIN, errno.EACCES) and not blocking:
                    raise LockfileLocked()
                else:
                    raise
        elif msvcrt:
            # Windows has decided that System V's perennially unstandardized
            # "locking" is a cool idea.
            os.lseek(fd, 0, 0)
            # The msvcrt.locking() function never gives you a blocking lock.
            # If you ask for one, it just retries once per second for ten
            # seconds.  This must be some genius's idea of a 'feature'.
            while 1:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 0)
                    return
                except IOError, e:
                    if e.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                    elif not blocking:
                        raise LockfileLocked()
                    else:
                        time.sleep(0.5)
        else:
            # There is no locking implementation.
            _warn_no_locks()
        
    def _unlock(self, fd):
        """Compatibility wrapper: unlock a file for unix and windows systems.
        """
        if fcntl:
            fcntl.flock(fd, fcntl.LOCK_UN)
        elif msvcrt:
            os.lseek(fd, 0, 0)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 0)
        else:
            _warn_no_locks()

_warned_no_locks = 0
def _warn_no_locks():
    global _warned_no_locks
    if not _warned_no_locks:
        _warned_no_locks = 1
        LOG.warn("Mixminion couldn't find a file locking implementation.")
        LOG.warn("  (Simultaneous accesses may lead to data corruption.")

#----------------------------------------------------------------------
# Threading operations

class ClearableQueue(MessageQueue):
    """Extended version of python's Queue class that supports removing
       all the items from the queue."""
    def clear(self):
        """Remove all the items from this queue."""
        # If the queue is empty, return.
        if not self.esema.acquire(0):
            return
        self.mutex.acquire()
        was_full = self._full()
        self._clear()
        assert self._empty()
        # If the queue used to be full, it isn't anymore.
        if was_full:
            self.fsema.release()
        self.mutex.release()

    def _clear(self):
        """Backend for _clear"""
        del self.queue[:]
