# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DirMain.py,v 1.10 2003/05/26 21:08:13 nickm Exp $

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
from mixminion.directory.Directory import Directory, DirectoryConfig

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

def getDirectory():
    fn = os.environ.get('MINION_DIR_CONF')
    if not fn:
        fn = os.expanduser("~/.mixminion_dir.cf")
        if not os.path.exists(fn):
            fn = None
    if not fn:
        fn = "/etc/mixion_dir.cf"
        if not os.path.exists(fn):
            fn = None
    if not fn:
        raise UIError("No configuration file found")

    try:
        config = DirectoryConfig(filename=fn)
    except ConfigError, e:
        raise UIError("Error in %s: %s", fn, e)

    return Directory(config)

def usageAndExit(cmd):
    """Print a usage message and exit"""
    print USAGE%cmd
    sys.exit

def cmd_init():
    d = getDirectory()
    d.setupDirectories()
    d.getServerList()
    d.getServerInbox()

def cmd_update(args):
    if args:
        raise UIError("mixminion dir update takes no arguments")
    
    d = getDirectory()
    serverList = d.getServerList()
    inbox = d.getInbox()
    inbox.acceptUpdates(serverList)

def cmd_list(args):
    if args:
        raise UIError("mixminion dir list takes no arguments")

    d = getDirectory()
    inbox = d.getInbox()
    inbox.listPendingServers(sys.stdout)

def cmd_import(args):
    d = getDirectory()
    inbox = d.getInbox()
    serverLsit = d.getServerList()

    if not args:
        print "(No server names given)"

    bad, good = 0,0
    for name in args:
        print "Importing server %r..."%name
        try:
            inbox.acceptNewServer(serverList, name)
            good += 1
            print "Imported."
        except UIError, e:
            bad += 1
            print "Error importing %r: %s"%(name, e)

    print "\n%s servers imported, %s rejected." %(good,bad)

def cmd_generate(args):
    if args:
        raise UIError("mixminion dir generate takes no arguments")

    d = getDirectory()
    serverList = d.getServerList()
    key = d.getIdentity()
    serverList.clean()

    config = d.getConfig()

    badServers = config['Directory'].get('BadServer', [])
    location = config['Publishing']['Location']
    print >>sys.stderr, "(Bad servers==%r)"%badServers

    now = time.time()
    tomorrow = now+60*60*24
    twoWeeks = 60*60*24*14
    
    serverList.generateDirectory(startAt=now, endAt=tomorrow,
                                 extraTime=twoWeeks,
                                 identityKey=key,
                                 badServers=badServers)
    print >>sys.stderr, "Directory generated; publishing."

    fname = serverList.getDirectoryFilename()

    if location.endswith(".gz"):
        fIn = open(fname)
        fOut = gzip.GzipFile(location, 'wb')
        fOut.write(fIn.read())
        fIn.close()
        fOut.close()
    else:
        shutil.copy(fname, location)

    print >>sys.stderr, "Published."

def cmd_fingerprint(args):
    if args:
        raise UIError("mixminion dir fingerprint takes no arguments")
    d = getDirectory()
    key = d.getIdentity()
    print pk_fingerprint(key)

SUBCOMMANDS = { 'initialize' : cmd_init,
                'update' : cmd_update,
                'list' : cmd_list,
                'import-new' : cmd_import,
                'generate' : cmd_generate,
                'fingerprint' : cmd_fingerprint
                }

def main(cmd, args):
    if len(args)<1 or ('-h', '--help') in args:
        usageAndExit()
    command = args[0]
    args = args[1:]
    if not SUBCOMMANDS.has_key(command):
        print >>sys.stderr, "Unknown command", command
        usageAndExit()
    init_crypto()
    LOG.setMinSeverity("INFO")
    SUBCOMMANDS[command](args)
