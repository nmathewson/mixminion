# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Common.py,v 1.25 2002/11/22 00:15:07 nickm Exp $

"""mixminion.Common

   Common functionality and utility code for Mixminion"""

__all__ = [ 'MixError', 'MixFatalError', 'onReset', 'onTerminate',
            'installSignalHandlers', 'secureDelete', 'secureRename',
            'ceilDiv', 'floorDiv', 'getLog' ]

import os
import signal
import sys
import time
import stat
import traceback
import calendar
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
def createPrivateDir(d, nocreate=0):
    """Create a directory, and all parent directories, checking permissions
       as we go along.  All superdirectories must be owned by root or us."""
    if not os.path.exists(d):
	if nocreate:
	    raise MixFatalError("Nonexistent directory %s" % d)
	try:
	    os.makedirs(d, 0700)
	except OSError, _:
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
	    getLog().warn("Iffy mode %o on directory %s (Writable by gid %s)",
			  mode, d, st[stat.ST_GID])

#----------------------------------------------------------------------
# Secure filesystem operations.
#

_SHRED_CMD = "---"
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
            cmd, opts = "/usr/bin/shred", ["-uz"]
        else:
            getLog().warn("Files will not be securely deleted.")
            cmd, opts = None, None

    _SHRED_CMD, _SHRED_OPTS = cmd, opts

def secureDelete(fnames, blocking=0):
    """Given a list of filenames, removes the contents of all of those
       files, from the disk, 'securely'.  If blocking=1, does not
       return until the remove is complete.  If blocking=0, returns
       immediately, and returns the PID of the process removing the
       files.  (Returns None if this process unlinked the files
       itself.) 

       XXXX Securely deleting files only does so much good.  Metadata on
       XXXX the file system, such as atime and dtime, can still be used
       XXXX to reconstruct information about message timings.  To be
       XXXX really safe, we should use a loopback device and shred _that_
       XXXX from time to time.

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
    if blocking:
        mode = os.P_WAIT
    else:
        mode = os.P_NOWAIT

    if _SHRED_CMD:
        code = os.spawnl(mode, _SHRED_CMD, _SHRED_CMD, *(_SHRED_OPTS+fnames))
	return code
    else:
        for f in fnames:
            os.unlink(f)
        return None

#----------------------------------------------------------------------
# Logging
#
# I'm trying to make this interface look like a subset of the one in
# the draft PEP-0282 (http://www.python.org/peps/pep-0282.html).

if sys.version_info[:2] >= (2,1):
    def _logtime():
        'Helper function.  Returns current local time formatted for log.'
        
        # Note: Python strftime is implemented using that platform libc's
        # strftime, so in theory, this might barf.  All of the format
        # elements below are (I think) standard, so we should be ok.
        return time.strftime("%b %d %H:%M:%S")
else:
    def _logtime():
        'Helper function.  Returns current local time formatted for log.'
        return time.strftime("%b %d %H:%M:%S", time.localtime(time.time()))

class _FileLogHandler:
    """Helper class for logging.  Represents a file on disk, and allows the
       usual close-and-open gimmick for log rotation."""
    def __init__(self, fname):
	"Create a new FileLogHandler to append messages to fname"
        self.file = None
        self.fname = fname
        self.reset()
    def reset(self):
	"Close and reopen our underlying file"
        if self.file is not None:
            self.file.close()
	try: 
	    parent = os.path.split(self.fname)[0]
	    if not os.path.exists(parent):
		createPrivateDir(parent)
	    self.file = open(self.fname, 'a')
	except OSError, _:
	    self.file = None
	    raise MixError("Unable to open log file %r"%self.fname)
    def close(self):
	"Close the underlying file"
        self.file.close()
    def write(self, severity, message):
	if self.file is None:
	    return
        print >> self.file, "%s [%s] %s" % (_logtime(), severity, message)
        
class _ConsoleLogHandler: 
    def __init__(self, file):
        self.file = file 
    def reset(self): pass
    def close(self): pass
    def write(self, severity, message):
        print >> self.file, "%s [%s] %s" % (_logtime(), severity, message)

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
	      FATAL: nonrecoverable errors that affect the entire system"""
    def __init__(self, minSeverity):
	self.configure(None)
	self.setMinSeverity(minSeverity)

    def configure(self, config):
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
            if logfile and not config['Server'].get('EchoMessages',0):
		del self.handlers[0]
            
    def setMinSeverity(self, minSeverity):
        self.severity = _SEVERITIES.get(minSeverity, 1)

    def getMinSeverity(self):
        for k,v in _SEVERITIES.items():
            if v == self.severity:
                return k
	return _SEVERITIES['INFO']
        
    def addHandler(self, handler):
        self.handlers.append(handler)

    def reset(self):
        for h in self.handlers:
	    try:
		h.reset()
	    except MixError, e:
		if len(self.handlers) > 1:
		    self.error(str(e))
		else:
		    print >>sys.stderr, "Unable to reset log system"

    def close(self):
        for h in self.handlers:
            h.close()
        
    def log(self, severity, message, *args):
	self._log(severity, message, args)

    def _log(self, severity, message, args):
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
        self.log("TRACE", message, *args)
    def debug(self, message, *args):
        self.log("DEBUG", message, *args)
    def info(self, message, *args):
        self.log("INFO", message, *args)
    def warn(self, message, *args):
        self.log("WARN", message, *args)
    def error(self, message, *args):
        self.log("ERROR", message, *args)
    def fatal(self, message, *args):
        self.log("FATAL", message, *args)
    def log_exc(self, severity, (exclass, ex, tb), message=None, *args):
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
	self.log_exc("ERROR", (exclass, ex, tb), message, *args)

    def fatal_exc(self, (exclass, ex, tb), message=None, *args):
	self.log_exc("FATAL", (exclass, ex, tb), message, *args)

_THE_LOG = None
def getLog():
    """Return the MixMinion log object."""
    global _THE_LOG
    if _THE_LOG is None:
        _THE_LOG = Log('WARN')

    return _THE_LOG

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

def waitForChildren():
    """Wait until all subprocesses have finished.  Useful for testing.""" 
    while 1:
        try:
            # FFFF This won't work on Windows.  What to do?
            pid, status = os.waitpid(0, 0)
        except OSError, e:
            break
        except e:
            print e, repr(e), e.__class__

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
