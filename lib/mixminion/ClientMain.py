# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.7 2002/11/22 21:05:22 nickm Exp $

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
#      - Per-system directory location is a neat idea, but individual users
#        must check signature.  That's a way better idea for later.

import os
import getopt
import sys
import time

from mixminion.Common import getLog, floorDiv, createPrivateDir, MixError, \
     MixFatalError
import mixminion.Crypto
from mixminion.BuildMessage import buildForwardMessage
import mixminion.MMTPClient
import mixminion.Modules
from mixminion.ServerInfo import ServerInfo
from mixminion.Config import ClientConfig

class TrivialDirectoryCache:
    def __init__(self, directory):
	self.directory = directory
	createPrivateDir(directory)
	self.byNickname = {}
	self.byFilename = {}

	for f in os.listdir(self.directory):
	    p = os.path.join(self.directory, f)
	    try:
		info = ServerInfo(fname=p, assumeValid=0)
	    except ConfigError, e:
		getLog().warn("Invalid server descriptor %s", p)
		continue

	    serverSection = info['Server']
	    nickname = serverSection['Nickname']
	    
	    if '.' in f:
		f = f[:f.rindex('.')]
	    
	    now = time.time()

	    if now < serverSec['Valid-After']:
		getLog().warn("Ignoring future decriptor %s", p)
		continue
	    if now >= serverSec['Valid-Until']:
		getLog().warn("Ignoring expired decriptor %s", p)
		continue
	    if now + 3*60*60 >= serverSec['Valid-Until']:
		getLog().warn("Ignoring soon-to-expire decriptor %s", p)
		continue
	    if self.byNickname.has_key(nickname):
		getLog().warn(
		    "Ignoring descriptor %s with duplicate nickname %s",
		    p, nickname)
		continue
	    if self.byFilename.has_key(fname):
		getLog().warn(
		    "Ignoring descriptor %s with duplicate prefix %s",
		    p, f)
		continue
	    self.byNickname[nickname] = info
	    self.byFilename[f] = info

    def getServerInfo(self, name):
	if isinstance(name, ServerInfo):
	    return name
	if self.byNickname.has_key(name):
	    return self.byNickname(name)
	if self.byFilename.has_key(name):
	    return self.byFilename(name)
	return None

    def getPath(self, minLength, serverList):
	path = []
	for s in serverList:
	    if isinstance(s, ServerInfo):
		path.append(s)
	    elif isinstance(s, types.StringType):
		server = self.dirCache.getServer(s)
		if server is not None:
		    path.append(server)
		elif os.path.exists(s):
		    try:
			server = ServerInfo(fname=s, assumeValid=0)
			path.append(server)
		    except OSError, e:
			getLog().error("Couldn't read descriptor %s: %s", 
				       s, e)
			sys.exit(1)
		    except ConfigError, e:
			getLog().error("Couldn't parse descriptor %s: %s", 
				       s, e)
			sys.exit(1)
		else:
		    getLog().error("Couldn't find descriptor %s")
		    sys.exit(1)
	return path

    def getRandomServers(self, prng, n):
	vals = self.byNickname.values()
	if len(vals) < n:
	    raise MixFatalError("Not enough servers (%s requested)", n)
	return prng.shuffle(vals, n)
	
def installDefaultConfig(fname):
    """Create a default, 'fail-safe' configuration in a given file"""
    getLog().warn("No configuration file found. Installing default file in %s",
		  fname)
    f = open(os.path.expanduser(fname), 'w')
    f.write("""\ 
# This file contains your options for the mixminion client.
[Host]
## Use this option to specify a 'secure remove' command.
#ShredCommand: rm -f
## Use this option to specify a nonstandard entropy source.
#EntropySource: /dev/urandom

[DirectoryServers]
# Not yet implemented

[User]
## By default, mixminion puts your files in ~/.mixminion.  You can override
## this directory here.
#UserDir: ~/.mixminion

[Security]
PathLength: 4

## Not yet implemented:
# SURBAddress: mbox:quux
# SURBPathLength: 8

""")
    f.close()

class MixminionClient:
    def __init__(self, conf=None):
	if conf is None:
	    conf = os.environ.get("MINIONRC", None)
	    if conf is None: 
		conf = "~/.minionrc"
		if not os.path.exists(conf):
		    installDefaultConfig(conf)
	conf = os.path.expanduser(conf)
	self.config = ClientConfig(fname=conf)

	getLog().configure(self.config)
	getLog().debug("Configuring client")
	mixminion.Common.configureShredCommand(self.config)
	mixminion.Crypto.init_crypto(self.config)

	# Make directories
	userdir = self.config['User']['UserDir']
	createPrivateDir(userdir)
	createPrivateDir(os.path.join(userdir, 'surbs'))
	createPrivateDir(os.path.join(userdir, 'servers'))

	# Get directory cache
	self.dirCache = TrivialDirectoryCache(
	    os.path.join(userdir,"servers"))

	# Initialize PRNG
	self.prng = mixminion.Crypto.AESCounterPRNG()

    def sendForwardMessage(self, address, payload, path1, path2):
	message, firstHop = \
		 self.generateForwardMessage(address, payload, path1, path2)

	self.sendMessages([message], firstHop)

    def generateForwardMessage(self, address, payload, path1, path2):
	servers1 = self.dirCache.getPath(path1)
	servers2 = self.dirCache.getPath(path2)
	# XXXXencode payloadXXXX
	
	routingType, routingInfo, lastHop = address.getRouting()
	if lastHop != None:
	    servers2.append(self.dirCache.getServerInfo(lastHop))
	msg = buildForwardMessage(payload,
				  routingType, routingInfo,
				  servers1, servers2)
	return msg, servers1[0]

    def sendMessages(self, msgList, server):
	con = mixminion.MMTPClient.BlockingClientConnection(server.getAddr(),
							    server.getPort(),
							    server.getKeyID())
	try:
	    con.connect()
	    for msg in msgList:
		con.sendPacket(msg)
	finally:
	    con.shutdown()

def parseAddress():

class Address:
    def __init__(self, exitType, exitAddress, lastHop=None):
	self.exitType = exitType
	self.exitAddress = exitAddress
	self.lastHop = lastHop
    def getRouting(self):
	return self.exitType, self.exitAddress, self.lastHop

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
    m = buildForwardMessage(payload, rt, ri, servers1, servers2)
			    
    firstHop = servers1[0]
    b = mixminion.MMTPClient.BlockingClientConnection(firstHop.getAddr(),
						      firstHop.getPort(),
						      firstHop.getKeyID())
    b.connect()
    b.sendPacket(m)
    b.shutdown()

def readConfigFile(configFile):
    try:
	return ClientConfig(fname=configFile)
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

    mixminion.Crypto.init_crypto(config)
    if len(args) < 2:
	print >> sys.stderr, "I need at least 2 servers"
    servers = [ ServerInfo(fn) for fn in args ]
    idx = floorDiv(len(servers),2)

    sendTestMessage(servers[:idx], servers[idx:])
