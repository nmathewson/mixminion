#!/usr/bin/python2
"""Code to correct the python path, and multiplex between the various 
   Mixminion CLIs.

   This is the command-line entry point for all of mixminion.
   """

import sys
import stat
import os

def filesAreSame(f1, f2):
    """Return true if f1 and f2 are exactly the same file."""
    if os.path.normpath(f1) == os.path.normpath(f2):
	return 1
    try:
	ino1 = os.stat(f1)[stat.ST_INO]
	ino2 = os.stat(f2)[stat.ST_INO]
	return ino1 and ino1 > 0 and ino1 == ino2
    except OSError, _:
	return 0

def correctPath(myself):
    """Given a command file (taken from sys.argv[0]), try to adjust sys.path
       so that 'import mixminion' will work.

       (If the admin uses distutils to install Mixminion, the code will 
       wind up somewhere appropriate on pythonpath.  This isn't good enough,
       however: we want to run even when sysadmins don't understand distutils.)
       """
    import os

    orig_cmd = myself
    # First, resolve all links.
    while os.path.islink(myself):
	myself = os.readlink(myself)

    # Now, the module ought to be living in x/y/z/mixminon/Foo.py.
    # The "x/y/z" is the part we're interested in.
    mydir = os.path.split(myself)[0]
    parentdir, miniondir = os.path.split(mydir)
    if not miniondir == 'mixminion':
	print >>sys.stderr, ("Bad mixminion installation:\n"+
	 " I resolved %s to %s, but expected to find ../mixminion/Main.py")%(
	     orig_cmd, myself)

    # Now we check whether there's already an entry in sys.path.  If not,
    # we add the directory we found.
    parentdir = os.path.normpath(parentdir)
    foundEntry = 0
    for pathEntry in sys.path:
	if os.path.normpath(pathEntry) == parentdir:
	    foundEntry = 1; break
		
	ent = os.path.join(pathEntry, 'mixminion', 'Main.py')
	if os.path.exists(ent) and filesAreSame(pathEntry, myself):
	    foundEntry = 1; break

    if not foundEntry:
	print >>sys.stderr, "Adding %s to PYTHONPATH" % parentdir
	sys.path[0:0] = [ parentdir ]

    # Finally, we make sure it all works.
    try:
	import mixminion.Main as _
    except ImportError, _:
	print >>sys.stderr,"Unable to find correct path for mixminion."
	sys.exit(1)

# Global map from command name to 2-tuples of (module_name, function_name).
# 
#   'Main.py <cmd> arg1 arg2 arg3' will result in a call to function_name
#   in module_name.  The function should take two arguments: a string to
#   be used as command name in error messages, and a list of [arg1,arg2,arg3].
_COMMANDS = {
    "unittests" : ( 'mixminion.test', 'testAll' ),
    "benchmarks" : ( 'mixminion.benchmark', 'timeAll' ),
    "server" : ( 'mixminion.ServerMain', 'runServer' ),
    "server-keygen" : ( 'mixminion.ServerMain', 'runKeygen')
}

def main(args):
    """Given a list of strings in the same format as sys.argv, use args[0]
       to correct sys.path; use args[1] to pick a command from _COMMANDS, and
       use args[2:] as arguments.
    """
    correctPath(args[0])

    # Check whether we have a recognized command.
    if len(args) == 1 or not _COMMANDS.has_key(args[1]):
	# FFFF we could do better in generating a usage message here.
	cmds = _COMMANDS.keys()
	cmds.sort()
	print >>sys.stderr, "Usage: %s {%s} [arguments]" %(
	    args[0], "|".join(cmds))
	sys.exit(1)

    # Read the module and function.
    command_module, command_fn = _COMMANDS[args[1]]
    mod = __import__(command_module, {}, {}, [command_fn])
    func = getattr(mod, command_fn)

    # Invoke the command.
    func(" ".join(args[0:2]), args[2:])

if __name__ == '__main__':
    main(sys.argv)




