# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Common.py,v 1.56 2003/02/07 17:23:11 nickm Exp $

"""mixminion.Common

   Common functionality and utility code for Mixminion"""

__all__ = [ 'IntervalSet', 'LOG', 'LogStream', 'MixError', 'MixFatalError',
            'MixProtocolError', 'ceilDiv', 'checkPrivateDir',
            'createPrivateDir', 'floorDiv', 'formatBase64', 'formatDate',
            'formatFnameTime', 'formatTime', 'installSIGCHLDHandler',
            'isSMTPMailbox', 'openUnique', 'previousMidnight',
            'readPossiblyGzippedFile', 'secureDelete', 'stringContains',
            'waitForChildren' ]

import base64
import bisect
import calendar
import fcntl
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
from Queue import Queue
MessageQueue = Queue
del Queue

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

def formatBase64(s):
    """Convert 's' to a one-line base-64 representation."""
    return base64.encodestring(s).replace("\n", "")

#----------------------------------------------------------------------
def createPrivateDir(d, nocreate=0):
    """Create a directory, and all parent directories, checking permissions
       as we go along.  All superdirectories must be owned by root or us."""
    if not os.path.exists(d):
        if nocreate:
            raise MixFatalError("Nonexistent directory %s" % d)
        try:
            os.makedirs(d, 0700)
        except OSError:
            raise MixFatalError("Unable to create directory %s" % d)

    checkPrivateDir(d)

_WARNED_DIRECTORIES = {} # ???? Threading danger?

def checkPrivateDir(d, recurse=1):
    """Return true iff d is a directory owned by this uid, set to mode
       0700. All of d's parents must not be writable or owned by anybody but
       this uid and uid 0.  If any of these conditions are unmet, raise
       MixFatalErrror.  Otherwise, return None."""
    me = os.getuid()

    if not os.path.isabs(d):
        d = os.path.abspath(d)

    if not os.path.exists(d):
        raise MixFatalError("Directory %s does not exist" % d)
    if not os.path.isdir(d):
        raise MixFatalError("%s is not a directory" % d)

    st = os.stat(d)
    # check permissions
    if st[stat.ST_MODE] & 0777 != 0700:
        raise MixFatalError("Directory %s must be mode 0700" % d)

    if st[stat.ST_UID] != me:
        raise MixFatalError("Directory %s has must have owner %s" %(d, me))

    if not recurse:
        return

    # Check permissions on parents.
    while 1:
        parent = os.path.split(d)[0]
        if parent == d:
            return
        d = parent

        st = os.stat(d)
        mode = st[stat.ST_MODE]
        owner = st[stat.ST_UID]
        if owner not in (0, me):
            raise MixFatalError("Bad owner (uid=%s) on directory %s"
                                % (owner, d))
        if (mode & 02) and not (mode & stat.S_ISVTX):
            raise MixFatalError("Bad mode (%o) on directory %s" %(mode, d))

        if (mode & 020) and not (mode & stat.S_ISVTX):
            # FFFF We may want to give an even stronger error here.
            if not _WARNED_DIRECTORIES.has_key(d):
                LOG.warn("Iffy mode %o on directory %s (Writable by gid %s)",
                         mode, d, st[stat.ST_GID])
            _WARNED_DIRECTORIES[d] = 1

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
        val = conf['Host'].get('ShredCommand', None)
        if val is not None:
            cmd, opts = val

    if cmd is None:
        if os.path.exists("/usr/bin/shred"):
            cmd, opts = "/usr/bin/shred", ["-uz", "-n0"]
        else:
            # Use built-in _overwriteFile
            cmd, opts = None, None

    _SHRED_CMD, _SHRED_OPTS = cmd, opts


# Size of a block on the filesystem we're overwriting on; If zero, we need
# to determine it.
_BLKSIZE = 0
# A string of _BLKSIZE zeros
_NILSTR = None
def _overwriteFile(f):
    """Overwrite f with zeros, rounding up to the nearest block.  This is
       used as the default implementation of secureDelete."""
    global _BLKSIZE
    global _NILSTR
    if not _BLKSIZE:
        #???? this assumes that all filesystems we are using have the same
        #???? block size.
        if hasattr(os, 'statvfs'):
            _BLKSIZE = os.statvfs(f)[statvfs.F_BSIZE]
        else:
            _BLKSIZE = 8192 # ???? Safe guess?
        _NILSTR = '\x00' * _BLKSIZE
    fd = os.open(f, os.O_WRONLY)
    try:
        size = os.fstat(fd)[stat.ST_SIZE]
        blocks = ceilDiv(size, _BLKSIZE)
        for _ in xrange(blocks):
            os.write(fd, _NILSTR)
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

       So we don't even bother trying to make the data 'physcially
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
                      # ???? There is probably a faster way to do this.
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
        except OSError:
            self.file = None
            raise MixError("Unable to open log file %r"%self.fname)
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

       In practise, we instantiate only a single instance of this class,
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

    def configure(self, config):
        """Set up this Log object based on a ServerConfig or ClientConfig
           object"""

        self.handlers = []
        if config == None or not config.has_section("Server"):
            self.setMinSeverity("WARN")
            self.addHandler(_ConsoleLogHandler(sys.stderr))
        else:
            self.setMinSeverity(config['Server'].get('LogLevel', "WARN"))
            logfile = config['Server'].get('LogFile',None)
            if logfile is None:
                homedir = config['Server']['Homedir']
                if homedir:
                    logfile = os.path.join(homedir, "log")
            self.addHandler(_ConsoleLogHandler(sys.stderr))
            if logfile:
                try:
                    self.addHandler(_FileLogHandler(logfile))
                except MixError, e:
                    self.error(str(e))
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
           args are provided, use them as an explanitory message; otherwise,
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
    "DOCDOC"
    #XXXX003 test me
    yyyy,MM,dd = time.gmtime(when)[0:3]
    return calendar.timegm((yyyy,MM,dd+1,0,0,0,0,0,0))

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
       for use as part of a fileame.  Defaults to the current time."""
    if when is None:
        when = time.time()
    return time.strftime("%Y%m%d%H%M%S", time.localtime(when))

#----------------------------------------------------------------------
# InteralSet

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
        """Return the first point contained in this inverval."""
        return self.edges[0][0]

    def end(self):
        """Return the last point contained in this interval."""
        return self.edges[-1][0]

#----------------------------------------------------------------------
# SMTP address functionality

# Regular expressions to valide RFC822 addresses.
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
    while 1:
        try:
            # WIN32 This won't work on Windows.  What to do?
            pid, status = os.waitpid(0, options)
        except OSError, e:
            break
        except e:
            print e, repr(e), e.__class__
        if onceOnly:
            return

def _sigChldHandler(signal_num, _):
    '''(Signal handler for SIGCHLD)'''
    # Because of the peculiarities of Python's signal handling logic, I
    # believe we need to re-register ourself.
    signal.signal(signal_num, _sigChldHandler)

    while 1:
        try:
            # WIN32 This waitpid call won't work on Windows.  What to do?
            pid, status = os.waitpid(0, os.WNOHANG)
            if pid == 0:
                break
        except OSError:
            break

    #outcome, core, sig = status & 0xff00, status & 0x0080, status & 0x7f
    # FFFF Log if outcome wasn't as expected.

def installSIGCHLDHandler():
    '''Register sigchld handler for this process.'''
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

def openUnique(fname, mode='w'):
    """Helper function. Returns a file open for writing into the file named
       'fname'.  If fname already exists, opens 'fname.1' or 'fname.2' or
       'fname.3' or so on."""
    base, rest = os.path.split(fname)
    idx = 0
    while 1:
        try:
            fd = os.open(fname, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0600)
            return os.fdopen(fd, mode), fname
        except OSError:
            pass
        idx += 1
        fname = os.path.join(base, "%s.%s"%(rest,idx))

#----------------------------------------------------------------------
class Lockfile:
    "DOCDOC"
    def __init__(self, filename):
        self.filename = filename
        self.count = 0
        self.fd = None

    def acquire(self, contents="", blocking=0):
        "Raises IOError DOCDOC"
        if self.count > 0:
            self.count += 1
            return

        assert self.fd is None
        self.fd = os.open(self.filename, os.O_RDWR|os.O_CREAT, 0600)
        try:
            if blocking:
                fcntl.flock(self.fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            else:
                fcntl.flock(self.fd, fcntl.LOCK_EX)
            self.count += 1
        except:
            os.close(self.fd)
            self.fd = None
            raise

    def release(self):
        assert self.fd is not None
        self.count -= 1
        if self.count > 0:
            return
        try:
            os.unlink(self.filename)
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None
        except OSError:
            pass
    
                
        
