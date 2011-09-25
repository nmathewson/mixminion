# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.

"""mixminion.directory.DirMain

   CLI for mixminion directory generation.
"""

__all__ = [ ]

import gzip
import os
import shutil
import sys
import time
from mixminion.Common import createPrivateDir, formatTime, iterFileLines, LOG, \
     UIError
from mixminion.Config import ConfigError
from mixminion.Crypto import init_crypto, pk_fingerprint, pk_generate, \
     pk_PEM_load, pk_PEM_save
from mixminion.directory.Directory import Directory, DirectoryConfig

USAGE = """\
Usage: mixminion dir <command>
   Where 'command' is one of:
      initialize               [Set up a new set of directory files]
      import-new <nickname>    [Import a descriptor for a new server]
      list                     [List descriptors waiting to be imported]
      update                   [Process updates for currently known servers]
      generate                 [Generate and sign a new directory]
      fingerprint              [Return the fingerprint of this directory's pk]
      rebuildcache             [Rebuild a corrupted or removed identity cache]
""".strip()

def getDirectory():
    """Return the Directory object for this directory.  Looks for a
       configuration file first in $MINION_DIR_CONF, then in
       ~/.mixminion_dir.cf, then in /etc/mixminion_dir.cf.
    """
    fn = os.environ.get('MINION_DIR_CONF')
    if not fn:
        fn = os.path.expanduser("~/.mixminion_dir.cf")
        if not os.path.exists(fn):
            fn = None
    if not fn:
        fn = "/etc/mixminion_dir.cf"
        if not os.path.exists(fn):
            fn = None
    if not fn:
        raise UIError("No configuration file found")

    try:
        config = DirectoryConfig(filename=fn)
    except ConfigError, e:
        raise UIError("Error in %s: %s"%(fn, e))

    return Directory(config)

def usageAndExit():
    """Print a usage message and exit"""
    print USAGE
    sys.exit(0)

def cmd_init(args):
    """[Entry point] Set up a new set of directory files."""
    if args:
        raise UIError("mixminion dir initialize takes no arguments")

    d = getDirectory()
    d.setupDirectories()
    d.getServerList()
    d.getInbox()

def cmd_update(args):
    """[Entry point] Process updates for currently known servers: copies
       descriptors from the Inbox to ServerList.  This can be run automatically
       as part of a cron job."""
    if args:
        raise UIError("mixminion dir update takes no arguments")

    d = getDirectory()
    serverList = d.getServerList()
    inbox = d.getInbox()
    inbox.acceptUpdates(serverList)

def cmd_list(args):
    """[Entry point] List descriptors waiting to be imported."""
    if args:
        raise UIError("mixminion dir list takes no arguments")

    d = getDirectory()
    inbox = d.getInbox()
    inbox.listNewPendingServers(sys.stdout)

def cmd_rebuildcache(args):
    """[Entry point] Reconstruct the ID cache from the contents of the
       'servers' directory.
    """
    if args:
        raise UIError("mixminion dir rebuildcache takes no arguments")
    d = getDirectory()
    serverList = d.getServerList()
    serverList.rebuildIDCache()
    d.getIDCache().save()

def cmd_import(args):
    """[Entry point] Import descriptors for new servers, by nickname."""
    d = getDirectory()
    inbox = d.getInbox()
    serverList = d.getServerList()

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
    """[Entry point] generate a fresh directory.  Can be run from a cron
       job."""
    if args:
        raise UIError("mixminion dir generate takes no arguments")

    d = getDirectory()
    serverList = d.getServerList()
    key = d.getIdentity()
    serverList.clean()

    config = d.getConfig()

    badServers = config['Directory'].get('BadServer', [])[:]
    badServerFiles = config['Directory'].get('BadServerFile', [])
    for fn in badServerFiles:
        if not os.path.exists(fn):
            print "No such file %r; skipping" %fn
            continue
        f = open(fn, 'r')
        for ln in iterFileLines(f):
            ln = ln.strip()
            if ln and ln[0] != '#':
                badServers.append(ln)
        f.close()

    excludeServers = config['Directory'].get("ExcludeServer",[])[:]
    excludeServers = [ nn.strip().lower() for nn in excludeServers ]

    location = config['Publishing']['Location']
    print "(Bad servers==%r)"%badServers

    now = time.time()
    tomorrow = now+60*60*24
    twoWeeks = 60*60*24*14

    serverList.generateDirectory(startAt=now, endAt=tomorrow,
                                 extraTime=twoWeeks,
                                 identityKey=key,
                                 badServers=badServers,
                                 excludeServers=excludeServers)
    print "Directory generated; publishing."

    fname = serverList.getDirectoryFilename()

    if location.endswith(".gz"):
        fIn = open(fname)
        fOut = gzip.GzipFile(location, 'wb')
        fOut.write(fIn.read())
        fIn.close()
        fOut.close()
    else:
        shutil.copy(fname, location)

    print "Published."

def cmd_fingerprint(args):
    """[Entry point] Print the fingerprint for this directory's key."""

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
                'fingerprint' : cmd_fingerprint,
                'rebuildcache' : cmd_rebuildcache
                }

def main(cmd, args):
    """[Entry point] Multiplex among subcommands."""
    if len(args)<1 or ('-h', '--help') in args:
        usageAndExit()
    command = args[0]
    args = args[1:]
    if not SUBCOMMANDS.has_key(command):
        print "Unknown command", command
        usageAndExit()
    init_crypto()
    LOG.setMinSeverity("INFO")
    SUBCOMMANDS[command](args)
