# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.2 2002/09/10 14:45:30 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.

   XXXX THIS ISN'T IMPLEMENTED YET!  This file is just a placeholder that
   XXXX routes a testing message through a few servers so I can make sure that
   XXXX at least one configuration works.
   """


# The client needs to store:
#      - config
#      - keys for pending SURBs
#      - server directory
#          (Have dir of files from which to reconstruct a shelf of cached
#           info.)
#          (Don't *name* files in dir; or at least, don't make their names
#           magic.  Files can be: ServerInfos, ServerDirectories, or 'fake'
#           directories.  Each server can have any number of virtual or 
#           official tags.  Users should use the CLI to add/remove entries from
#           dir.)
#      - Per-systemm directory location is a neat idea, but individual users
#        must check signature.  That's a way better idea for later.

import os
import getopt
import sys
import time
import bisect

import mixminion.Crypto
from mixminion.Common import getLog, floorDiv, createPrivateDir
import mixminion.Config
import mixminion.BuildMessage
import mixminion.MMTPClient
import mixminion.Modules

class DirectoryCache:
    """Holds a set of directories and serverinfo objects persistently.

       FFFF This should actually cache the nickname and liveness information 
       FFFF rather than parsing and reparsing it each time.  Of course, we'll
       FFFF want to re-do it entirely once we have directory support, so it
       FFFF doesn't matter so much right now.
       """
    def __init__(self, dirname):
	createPrivateDir(dirname)
	self.dirname = dirname
	self.servers = None

    def load(self, forceReload=0):
	if not (self.servers is None or forceReload):
	    return
	now = time.time()
	self.servers = {}
	self.allServers = []
	self.highest_num = -1
	for fn in os.listdir(self.dirname):
	    if not fn.startswith("si"):
		continue
	    n = int(fn[2:])
	    if n > self.highest_num:
		self.highest_num = n
	    info = ServerInfo(fname=os.path.join(self.dirname, fn),
			      assumeValid=1)
	    nickname = info['Server']['Nickname']
	    if info['Server']['Valid-Until'] < now:
		getLog().info("Removing expired descriptor for %s",
			      nickname)
		os.unlink(os.path.join(dirname, fn))
		continue
	    self.allServers.append(info)
	    if self.servers.has_key(nickname):
		self.servers[nickname].append(info)
	    else:
		self.servers[nickname] = info

    def getCurrentServer(nickname, when=None):
	if when is None:
	    when = time.time()
	for info in self.servers[nickname]:
	    #XXXX fail on DNE
	    server = info['Server']
	    if server['Valid-After'] <= now <= server['Valid-Until']:
		return info
	#XXXX fail on DNE
	return None

    def importServerInfo(self, fname, force=1):
	self.load()
	f = open(fname)
	contents = f.read()
	f.close()
	info = ServerInfo(string=contents, assumeValid=0)
	now = time.time()
	if info['Server']['Valid-Until'] < now:
	    getLog().error("Not importing descriptor %s: already expired", 
			   fname)
	    return 0
	nickname = info['Server']['Nickname']
	identity_pk = info['Server']['Identity'].get_public_key()
	if self.servers.has_key(nickname):
	    other = self.servers[nickname][0]
	    if other['Server']['Identity'].get_public_key() != identity_pk:
		getLog().error("Possible spoofing: that's not the public key I remember for %s", nickname)
		if not force:
		    getLog().error("I'm not going to import it.")
		    return 0
		else:
		    getLog().error("... importing anyway.")
	
	    self.servers[nickname].append(info)
	else:
	    self.servers[nickname] = info

	self.allServers.append(info)

	self.highest_num += 1
	fname_new = "si%d" % self.highest_num
	f = os.fdopen(os.open(os.path.join(self.dirname, fname_name),
			      os.O_CREAT|os.O_EXCL, 0600),
		      'w')
	f.write(contents)
	f.close()



def sendTestMessage(servers1, servers2):
    assert len(servers1)
    assert len(servers2)
    payload = """ 
           Insert
	   Example
	   Message
	   Here.
	   """
    rt, ri = 0xFFFE, "deliver"
    m = mixminion.BuildMessage.buildForwardMessage(payload,
						   rt, ri,
						   servers1, servers2)
    firstHop = servers1[0]
    b = mixminion.MMTPClient.BlockingClientConnection(firstHop.getAddr(),
						      firstHop.getPort(),
						      firstHop.getKeyID())
    b.connect()
    b.sendPacket(m)
    b.shutdown()


def readConfigFile(configFile):
    try:
	return mixminion.Config.ClientConfig(fname=configFile)
    except (IOError, OSError), e:
	print >>sys.stderr, "Error reading configuration file %r:"%configFile
	print >>sys.stderr, "   ", str(e)
	sys.exit(1)
    except mixminion.Config.ConfigError, e:
	print >>sys.stderr, "Error in configuration file %r"%configFile
	print >>sys.stderr, str(e)
	sys.exit(1)

# XXXX This isn't anything LIKE the final client interface: for now, I'm
# XXXX just testing the server.
def runClient(cmd, args):
    options, args = getopt.getopt(args, "hf:", ["help", "config="])
    configFile = '~/.mixminion/mixminion.conf'
    usage = 0
    for opt,val in options:
	if opt in ('-h', '--help'):
	    usage=1
	elif opt in ('-f', '--config'):
	    configFile = val
    if usage:
	print >>sys.stderr, "Usage: %s [-h] [-f configfile] server1 server2..."%cmd
	sys.exit(1)
    config = readConfigFile(os.path.expanduser(configFile))

    getLog().setMinSeverity("INFO")
    mixminion.Crypto.init_crypto(config)
    if len(args) < 2:
	print >> sys.stderr, "I need at least 2 servers"
    servers = [ mixminion.ServerInfo.ServerInfo(fn) for fn in args ]
    idx = floorDiv(len(servers),2)

    sendTestMessage(servers[:idx], servers[idx:])


