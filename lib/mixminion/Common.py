# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Common.py,v 1.36 2002/12/16 02:40:11 nickm Exp $

"""mixminion.Common

   Common functionality and utility code for Mixminion"""

__all__ = [ 'LOG', 'LogStream', 'MixError', 'MixFatalError',
            'MixProtocolError', 'ceilDiv', 'checkPrivateDir',
            'createPrivateDir', 'floorDiv', 'formatBase64', 'formatDate',
            'formatTime', 'installSignalHandlers', 'isSMTPMailbox', 'mkgmtime',
            'onReset', 'onTerminate', 'previousMidnight', 'secureDelete',
            'stringContains', 'waitForChildren' ]

import base64
import calendar
import os
import re
import signal
import stat
import statvfs
import sys
import time
import traceback

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

def checkPrivateDir(d, recurse=1):
    """Return true iff d is a directory owned by this uid, set to mode
       0700. All of d's parents must not be writable or owned by anybody but
       this uid and uid 0.  If any of these conditions are unmet, raise
       MixFatalErrror.  Otherwise, return None."""
    me = os.getuid()

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
            LOG.warn("Iffy mode %o on directory %s (Writable by gid %s)",
                     mode, d, st[stat.ST_GID])

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

    if blocking:
        mode = os.P_WAIT
    else:
        mode = os.P_NOWAIT

    # Some systems are unhappy when you call them with too many options.
    for i in xrange(0, len(fnames), 250-len(_SHRED_OPTS)):
        files = fnames[i:i+250-len(_SHRED_OPTS)]
        os.spawnl(mode, _SHRED_CMD, _SHRED_CMD, *(_SHRED_OPTS+files))

#----------------------------------------------------------------------
# Logging
#
# I'm trying to make this interface look like a subset of the one in
# the draft PEP-0282 (http://www.python.org/peps/pep-0282.html).

def _logtime():
    'Helper function.  Returns current local time formatted for log.'
    return time.strftime("%b %d %H:%M:%S", time.localtime(time.time()))

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

    def configure(self, config):
        """Set up this Log object based on a ServerConfig or ClientConfig
           object"""
        # XXXX001 Don't EchoLogMessages when NoDaemon==0.
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
            if logfile and not (config['Server'].get('EchoMessages',0) and
                                config['Server'].get('NoDaemon',0)):
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

        for h in self.handlers:
            h.write(severity, m)

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
    def __init__(self, name, severity):
        self.name = name
        self.severity = severity
    def write(self, s):
        LOG.log(self.severity, "->%s: %s", self.name, s)
    def flush(self): pass
    def close(self): pass

#----------------------------------------------------------------------
# Time processing

def mkgmtime(yyyy,MM,dd,hh,mm,ss):
    """Analogously to time.mktime, return a number of seconds since the
       epoch when GMT is yyyy/MM/dd hh:mm:ss"""

    # we set the DST flag to zero so that subtracting time.timezone always
    # gives us gmt.
    return calendar.timegm((yyyy,MM,dd,hh,mm,ss,0,0,0))

def previousMidnight(when):
    """Given a time_t 'when', return the greatest time_t <= when that falls
       on midnight, GMT."""
    yyyy,MM,dd = time.gmtime(when)[0:3]
    return calendar.timegm((yyyy,MM,dd,0,0,0,0,0,0))

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

#----------------------------------------------------------------------
# SMTP address functionality

# Regular expressions to valide RFC822 addresses.
# (This is more strict than RFC822, actually.  RFC822 allows tricky stuff to
#  quote special characters, and I don't trust every MTA or delivery command
#  to support addresses like <bob@bob."; rm -rf /; echo".com>)

# An 'Atom' is a non-escape, non-null, non-space, non-punctuation character.
_ATOM_PAT = r'[^\x00-\x20()\[\]()<>@,;:\\".\x7f-\xff]+'
# The 'Local part' (and, for us, the domain portion too) is a sequence of
# dot-separated atoms.
_LOCAL_PART_PAT = r"(?:%s)(?:\.(?:%s))*" % (_ATOM_PAT, _ATOM_PAT)
# A mailbox is two 'local parts' separated by an @ sign.
_RFC822_PAT = r"\A%s@%s\Z" % (_LOCAL_PART_PAT, _LOCAL_PART_PAT)
RFC822_RE = re.compile(_RFC822_PAT)

def isSMTPMailbox(s):
    """Return true iff s is a valid SMTP address"""
    m = RFC822_RE.match(s)
    return m is not None

#----------------------------------------------------------------------
# Signal handling

# List of 0-argument functions to call on SIGHUP
resetHooks = []

# List of 0-argument functions to call on SIGTERM
terminateHooks = []

def onReset(fn):
    """Given a 0-argument function fn, cause fn to be invoked when
       this process next receives a SIGHUP."""
    resetHooks.append(fn)

def onTerminate(fn):
    """Given a 0-argument function fn, cause fn to be invoked when
       this process next receives a SIGTERM."""
    terminateHooks.append(fn)

def waitForChildren(onceOnly=0):
    """Wait until all subprocesses have finished.  Useful for testing."""
    while 1:
        try:
            # FFFF This won't work on Windows.  What to do?
            pid, status = os.waitpid(0, 0)
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
            # This waitpid call won't work on Windows.  What to do?
            pid, status = os.waitpid(0, os.WNOHANG)
            if pid == 0:
                break
        except OSError:
            break

    #outcome, core, sig = status & 0xff00, status & 0x0080, status & 0x7f
    # FFFF Log if outcome wasn't as expected.

def _sigHandler(signal_num, _):
    '''(Signal handler for SIGTERM and SIGHUP)'''
    signal.signal(signal_num, _sigHandler)
    if signal_num == signal.SIGTERM:
        for hook in terminateHooks:
            hook()
        sys.exit(1)
    else:
        for hook in resetHooks:
            hook()

def installSignalHandlers(child=1,hup=1,term=1):
    '''Register signal handlers for this process.  If 'child', registers
       a handler for SIGCHLD.  If 'hup', registers a handler for SIGHUP.
       If 'term', registes a handler for SIGTERM.'''
    if child:
        signal.signal(signal.SIGCHLD, _sigChldHandler)
    if hup:
        signal.signal(signal.SIGHUP, _sigHandler)
    if term:
        signal.signal(signal.SIGTERM, _sigHandler)
