# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Common.py,v 1.4 2002/06/24 20:28:19 nickm Exp $

"""mixminion.Common

   Common functionality and utility code for Mixminion"""

__all__ = [ 'MixError', 'MixFatalError', 'onReset', 'onTerminate',
            'installSignalHandlers', 'secureDelete', 'secureRename',
            'ceilDiv', 'floorDiv', 'log', 'debug' ]

import os, signal, sys

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
    "Computes floor(a / b). See comments for portability notes."
    return divmod(a,b)[0]

def ceilDiv(a,b):
    "Computes ceil(a / b). See comments for portability notes."
    return divmod(a-1,b)[0]+1

#----------------------------------------------------------------------
# Secure filesystem operations.
#
# FFFF This needs to be made portable.
_SHRED_CMD = "/usr/bin/shred"

def secureDelete(fnames, blocking=0):
    """ Given a list of filenames, removes the contents of all of those files,
        from the disk, 'securely'.  If blocking=1, does not return until the
        remove is complete.  If blocking=0, returns immediately, and returns
        the PID of the process removing the files.  (Returns None if this
        process unlinked the files itself) XXXX Clarify this."""
    if type(fnames) == type(""):
        fnames = [fnames]
    if blocking:
        mode = os.P_WAIT
    else:
        mode = os.P_NOWAIT

    if _SHRED_CMD:
        return os.spawnl(mode, _SHRED_CMD, _SHRED_CMD, "-uz", *fnames)
    else:
        for f in fnames:
            os.unlink(f)
        return None

#----------------------------------------------------------------------
# Logging

# XXXX Placeholder for a real logging mechanism
def log(s):
    print s
def debug(s):
    print s

#----------------------------------------------------------------------
# Signal handling

# List of 0-argument functions to call on SIGHUP
resetHooks = []

# List of 0-argument functions to call on SIGTERM
terminateHooks = []

def onReset(fn):
    """Given a 0-argument function fn, causes fn to be invoked when
       this process next receives a SIGHUP."""
    resetHooks.append(fn)

def onTerminate(fn):
    """Given a 0-argument function fn, causes fn to be invoked when
       this process next receives a SIGTERM."""
    terminateHooks.append(fn)

def waitForChildren():
    """Waits until all subprocesses have finished.  Useful for testing.""" 
    while 1:
        try:
            # FFFF This won't work on Windows.  What to do?
            pid, status = os.waitpid(-1, 0)
        except:
            break

def _sigChldHandler(signal_num, _):
    '''(Signal handler for SIGCHLD)'''
    # Because of the peculiarities of Python's signal handling logic, I
    # believe we need to re-register ourself.
    signal.signal(signal.SIGCHLD, _sigChldHandler)

    while 1:
        try:
            # This waitpid call won't work on Windows.  What to do?
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
        except OSError:
            break
    
    #outcome, core, sig = status & 0xff00, status & 0x0080, status & 0x7f
    # FFFF Log if outcome wasn't as expected.

def _sigHandler(signal_num, frame):
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
    '''Registers signal handlers for this process.  If 'child', registers
       a handler for SIGCHLD.  If 'hup', registers a handler for SIGHUP.
       If 'term', registes a handler for SIGTERM.'''
    if child:
        signal.signal(signal.SIGCHLD, _sigChldHandler)
    if hup:
        signal.signal(signal.SIGHUP, _sigHandler)
    if term:
        signal.signal(signal.SIGTERM, _sigHandler)
