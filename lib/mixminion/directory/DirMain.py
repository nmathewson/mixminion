# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DirMain.py,v 1.8 2003/01/07 04:49:11 nickm Exp $

"""mixminion.directory.DirMain

   CLI for mixminion directory generation.
"""

__all__ = [ ]

import gzip
import os
import shutil
import stat
import sys
import time
from mixminion.Common import createPrivateDir, formatTime, LOG
from mixminion.Crypto import init_crypto, pk_fingerprint, pk_generate, \
     pk_PEM_load, pk_PEM_save
from mixminion.directory.ServerList import ServerList

USAGE = """\
Usage: %s -d <directory> command
   Where 'command' is one of:
      import <serverinfo>      [Import a descriptor for a known server]
      import-new <serverinfo>  [Import a descriptor for a new server]
      generate                 [Generate and sign a new directory]
      export <filename>        [Export the most recently generated directory]
      remove <nickname>        [Remove a server from storage]
      fingerprint              [Return the fingerprint of this directory's pk]
""".strip()

def getIdentity(baseDir):
    """Load the identity key stored under the base directory, creating it
       if necessary."""
    createPrivateDir(baseDir)
    fname = os.path.join(baseDir, "identity")
    if not os.path.exists(fname):
        print "No public key found; generating new key..."
        key = pk_generate(2048)
        pk_PEM_save(key, fname)
        return key
    else:
        return pk_PEM_load(fname)

def usageAndExit(cmd):
    """Print a usage message and exit"""
    print USAGE%cmd
    sys.exit(1)

def cmd_import(cmd, base, rest):
    if len(rest) != 1: usageAndExit(cmd)
    lst = ServerList(base)
    lst.importServerInfo(rest[0], knownOnly=1)
    print "Imported."

def cmd_import_new(cmd, base, rest):
    if len(rest) != 1: usageAndExit(cmd)
    lst = ServerList(base)
    lst.importServerInfo(rest[0], knownOnly=0)
    print "Imported."

def cmd_generate(cmd, base, rest):
    if len(rest) != 0: usageAndExit(cmd)
    lst = ServerList(base)
    key = getIdentity(base)
    # XXXX Until we have support for automatic directory generation, we
    # XXXX set the validity time to be pretty long: 2 months.
    now = time.time()
    twoMonthsLater = now + 60*60*24*30*2
    lst.generateDirectory(startAt=now, endAt=twoMonthsLater, extraTime=0,
                          identityKey=key)
    print >>sys.stderr, "Directory generated."

def cmd_export(cmd, base, rest):
    if len(rest) != 1: usageAndExit(cmd)
    lst = ServerList(base)
    fname = lst.getDirectoryFilename()
    if not os.path.exists(fname):
        print >>sys.stderr, "No directory has been generated"
    st = os.stat(fname)
    print >>sys.stderr, "Exporting directory from %s"%(
        formatTime(st[stat.ST_MTIME]))
    if rest[0] == '-':
        f = open(fname)
        d = f.read()
        f.close()
        sys.stdout.write(d)
    elif rest[0].endswith(".gz"):
        fIn = open(fname)
        fOut = gzip.GzipFile(rest[0], 'wb')
        fOut.write(fIn.read())
        fIn.close()
        fOut.close()
    else:
        shutil.copy(fname, rest[0])
        print >>sys.stderr, "Exported."

def cmd_remove(cmd, base, rest):
    if len(rest) != 1: usageAndExit(cmd)
    lst = ServerList(base)
    lst.expungeServersByNickname(rest[0])

def cmd_fingerprint(cmd, base, rest):
    if len(rest) != 0: usageAndExit(cmd)
    key = getIdentity(base)
    print pk_fingerprint(key)

SUBCOMMANDS = { 'import' : cmd_import,
                'import-new' : cmd_import_new,
                'generate' : cmd_generate,
                'export' : cmd_export,
                'remove' : cmd_remove,
                'fingerprint' : cmd_fingerprint }

def main(cmd, args):
    if len(args) < 3 or args[0] != "-d" or args[0] in ('-h', '--help'):
        usageAndExit(cmd)
    baseDir = args[1]
    command = args[2]
    if not SUBCOMMANDS.has_key(command):
        print >>sys.stderr, "Unknown command", command
        usageAndExit(cmd)
    init_crypto()
    LOG.setMinSeverity("INFO")
    SUBCOMMANDS[command](cmd, baseDir, args[3:])
