#!/usr/bin/python2
# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Main.py,v 1.38 2003/04/04 20:28:55 nickm Exp $

#"""Code to correct the python path, and multiplex between the various
#   Mixminion CLIs.
#
#   This is the command-line entry point for all of mixminion.
#   """

# NOTE: We're up to funny business here.  This file can't import any other
#       mixminion modules until we've run correctPath() below.  Also, it
#       needs to be _syntactically_ backwards compatible with all Python
#       versions back to 1.0, so that we can exit gracefully when run
#       with the wrong python version.  Thus: no multiline strings, no
#       print>>, no automatic string concatenation and no import foo.bar.

import sys

# Check: are we running a version earlier than 2.0?  If so, die.
if not hasattr(sys,'version_info') or sys.version_info[0] < 2:
    import string
    _ver = sys.version[:string.find(sys.version,' ')]
    sys.stderr.write((
        "ERROR: Mixminion requires Python version 2.0 or higher.\n"+
        "       You seem to be running version %s.\n")%_ver)
    sys.exit(1)

import getopt
import os
import stat
import types

def filesAreSame(f1, f2):
    "Return true if f1 and f2 are exactly the same file."
    if os.path.normpath(f1) == os.path.normpath(f2):
        return 1
    try:
        # FFFF what happens on systems that (shudder) lack inodes?
        ino1 = os.stat(f1)[stat.ST_INO]
        ino2 = os.stat(f2)[stat.ST_INO]
        return ino1 and ino1 > 0 and ino1 == ino2
    except OSError:
        return 0

def correctPath(myself):
    "Given a command (sys.argv[0]), fix sys.path so 'import mixminion' works"
    # (If the admin uses distutils to install Mixminion, the code will
    # wind up somewhere appropriate on pythonpath.  This isn't good enough,
    # however: we want to run even when sysadmins don't understand distutils.)

    # If we can import mixminion.Main, we bail out early: let's not mess
    # with anything.
    try:
        __import__('mixminion.Main')
        return
    except ImportError:
        pass

    orig_cmd = myself
    # First, resolve all links.
    while os.path.islink(myself):
        myself = os.readlink(myself)

    # Now, the module ought to be living in x/y/z/mixminion/Foo.py.
    # The "x/y/z" is the part we're interested in.
    mydir = os.path.split(myself)[0]
    parentdir, miniondir = os.path.split(mydir)
    if not miniondir == 'mixminion':
        sys.stderr.write(("Bad mixminion installation:\n"+
        " I resolved %s to %s, but expected to find ../mixminion/Main.py\n")%(
            orig_cmd, myself))

    # Now we check whether there's already an entry in sys.path.  If not,
    # we add the directory we found.
    parentdir = os.path.normpath(parentdir)
    foundEntry = 0
    for pathEntry in sys.path:
        # There are intimations on Python-dev that sys.path may eventually
        # contain non-strings.
        if not isinstance(pathEntry, types.StringType):
            continue
        if os.path.normpath(pathEntry) == parentdir:
            foundEntry = 1; break

        ent = os.path.join(pathEntry, 'mixminion', 'Main.py')
        if os.path.exists(ent) and filesAreSame(pathEntry, myself):
            foundEntry = 1; break

    if not foundEntry:
        #sys.stderr.write("Adding %s to PYTHONPATH\n" % parentdir)
        sys.path[0:0] = [ parentdir ]

    # Finally, we make sure it all works.
    try:
        # We use __import__ here instead of 'import' so that we can stay
        #   parseable by Python 1.1.  You're welcome.
        __import__('mixminion.Main')
    except ImportError, e:
        sys.stderr.write(str(e)+"\n")
        sys.stderr.write("Unable to find correct path for mixminion.\n")
        sys.exit(1)

#   Global map from command name to 2-tuples of (module_name, function_name).
#   The function 'main' below uses this map to pick which module to import,
#   and which function to invoke.
#
#  'Main.py <cmd> arg1 arg2 arg3' will result in a call to <function_name>
#   in <module_name>.  The function should take two arguments: a string to
#   be used as command name in error messages, and a list of [arg1,arg2,arg3].'
#
#   By convention, all commands must print a usage message and exit when
#   invoked with a single argument, "--help"
_COMMANDS = {
    "version" :        ( 'mixminion.Main',       'printVersion' ),
    "unittests" :      ( 'mixminion.test',       'testAll' ),
    "benchmarks" :     ( 'mixminion.benchmark',  'timeAll' ),
    "send" :           ( 'mixminion.ClientMain', 'runClient' ),
    "client" :         ( 'mixminion.ClientMain', 'runClient' ),
    "pool" :           ( 'mixminion.ClientMain', 'runClient' ),
    "import-server" :  ( 'mixminion.ClientMain', 'importServer' ),
    "list-servers" :   ( 'mixminion.ClientMain', 'listServers' ),
    "update-servers" : ( 'mixminion.ClientMain', 'updateServers' ),
    "decode" :         ( 'mixminion.ClientMain', 'clientDecode' ),
    "generate-surb" :  ( 'mixminion.ClientMain', 'generateSURB' ),
    "generate-surbs" : ( 'mixminion.ClientMain', 'generateSURB' ),
    "inspect-surb" :   ( 'mixminion.ClientMain', 'inspectSURBs' ),
    "inspect-surbs" :  ( 'mixminion.ClientMain', 'inspectSURBs' ),
    "flush" :          ( 'mixminion.ClientMain', 'flushQueue' ),
    "inspect-queue" :   ( 'mixminion.ClientMain', 'listQueue' ),
    # XXXX Obsolete; use "inspect-queue"; remove in 0.0.5
    "inspect-pool" :   ( 'mixminion.ClientMain', 'listQueue' ),    
    # XXXX Obsolete; use "server-start"; remove in 0.0.5
    "server" :         ( 'mixminion.server.ServerMain', 'runServer' ),
    "server-start" :   ( 'mixminion.server.ServerMain', 'runServer' ),
    "server-stop" :    ( 'mixminion.server.ServerMain', 'signalServer' ),
    "server-reload" :  ( 'mixminion.server.ServerMain', 'signalServer' ),
    "server-keygen" :  ( 'mixminion.server.ServerMain', 'runKeygen'),
    "server-DELKEYS" : ( 'mixminion.server.ServerMain', 'removeKeys'),
    "server-stats" :   ( 'mixminion.server.ServerMain', 'printServerStats' ),
    "dir":             ( 'mixminion.directory.DirMain', 'main'),
}

_USAGE = (
  "Usage: mixminion <command> [arguments]\n"+
  "where <command> is one of:\n"+
  "                              (For Everyone)\n"+
  "       version        [Print the version of Mixminion and exit]\n"+
  "       send           [Send an anonymous message]\n"+
  "       pool           [Schedule an anonymous message to be sent later]\n"+
  "       flush          [Send all messages waiting in the pool]\n"+
  "       inspect-pool   [Describe all messages waiting in the pool]\n"+
  "       import-server  [Tell the client about a new server]\n"+
  "       list-servers   [Print a list of currently known servers]\n"+
  "       update-servers [Download a fresh server directory]\n"+
  "       decode         [Decode or decrypt a received message]\n"+
  "       generate-surb  [Generate a single-use reply block]\n"+
  "       inspect-surbs  [Describe a single-use reply block]\n"+
  "                               (For Servers)\n"+
  "       server-start   [Begin running a Mixminion server]\n"+
  "       server-stop    [Halt a running Mixminion server]\n"+
  "       server-reload  [Make running Mixminion server reload its config\n"+
  "                        (Not implemented yet; only restarts logging.)]\n"+
  "       server-keygen  [Generate keys for a Mixminion server]\n"+
  "       server-DELKEYS [Remove generated keys for a Mixminion server]\n"+
  "       server-stats   [XXXX]\n"+
  "                             (For Developers)\n"+
  "       dir            [Administration for server directories]\n"+
  "       unittests      [Run the mixminion unit tests]\n"+
  "       benchmarks     [Time underlying cryptographic operations]\n"+
  "\n"+
  "For help on sending a message, run 'mixminion send --help'"
)

def printVersion(cmd,args):
    import mixminion
    print "Mixminion version %s" % mixminion.__version__
    print ("Copyright 2002-2003 Nick Mathewson.  "+
           "See LICENSE for licensing information.")
    print "NOTE: This software is for testing only.  The user set is too small"
    print "      to be anonymous, and the code is too alpha to be reliable."

def printUsage():
    import mixminion
    print "Mixminion version %s" % mixminion.__version__
    print _USAGE
    print "NOTE: This software is for testing only.  The user set is too small"
    print "      to be anonymous, and the code is too alpha to be reliable."

def main(args):
    "Use <args> to fix path, pick a command and pass it arguments."
    # Specifically, args[0] is used to fix sys.path so we can import
    # mixminion.*; args[1] is used to select a command name from _COMMANDS,
    # and args[2:] are passed to the command we select.

    correctPath(args[0])

    # Check whether we have a recognized command.
    if len(args) == 1 or not _COMMANDS.has_key(args[1]):
        printUsage()
        sys.exit(1)

    # Read the 'common' module to get the UIError class.  To simplify
    # command implementation code, we catch all UIError exceptions here.
    commonModule = __import__('mixminion.Common', {}, {}, ['UIError'])
    uiErrorClass = getattr(commonModule, 'UIError')

    # Read the module and function.
    command_module, command_fn = _COMMANDS[args[1]]
    mod = __import__(command_module, {}, {}, [command_fn])
    func = getattr(mod, command_fn)

    # Invoke the command.
    try:
        cmdFile = os.path.split(args[0])[1]
        cmdName = args[1]
        commandStr = "%s %s" % (cmdFile, cmdName)
        func(commandStr, args[2:])
    except getopt.GetoptError, e:
        sys.stderr.write(str(e)+"\n")
        func(commandStr, ["--help"])
    except uiErrorClass, e:
        e.dumpAndExit()
    except KeyboardInterrupt:
        print "Interrupted."

if __name__ == '__main__':
    main(sys.argv)
