# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.5 2002/10/30 02:19:39 nickm Exp $

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
import bisect

from mixminion.Common import getLog, floorDiv, createPrivateDir, MixError
import mixminion.Crypto
import mixminion.BuildMessage
import mixminion.MMTPClient
import mixminion.Modules
from mixminion.ServerInfo import ServerInfo
from mixminion.Config import ClientConfig

class DirectoryCache:
    """Holds a set of directories and serverinfo objects persistently.

       FFFF This should actually cache the nickname and liveness information 
       FFFF rather than parsing and reparsing it each time.  Of course, we'll
       FFFF want to re-do it entirely once we have directory support, so it
       FFFF doesn't matter so much right now.
       """
    ## Fields
    # dirname: the name of the storage directory.  All files in the directory
    #     should be of the form 'si_XXXX...X', and contain validated server
    #     descriptors.
    # servers: a map from nickname to [list of serverinfo objects], or None
    #     if no servers have been loaded
    # allServers: a list of serverinfo objects
    def __init__(self, dirname):
	dirname = os.path.join(dirname, 'servers')
	createPrivateDir(dirname)
	self.dirname = dirname
	self.servers = None

    def load(self, forceReload=0):
	"""Retrieve a list of servers from disk.  If 'forceReload' is false,
           only load the servers if we have not already done so."""
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
		self.servers[nickname] = [ info ]

    def getCurrentServer(self,nickname, when=None, until=None):
        """Return a server descriptor valid during the interval
           when...until.  If 'nickname' is a string, return only a
           server with the appropriate nickname.  If 'nickname' is a
           server descriptor, return that same server descriptor.

           Raise 'MixError' if no appropriate descriptor is found. """
        self.load()
	if when is None:
	    when = time.time()
	if until is None:
	    until = when+1
	if isinstance(nickname, ServerInfo):
	    serverList = [ nickname ]
	else:
	    try:
		serverList = self.servers[nickname]
	    except KeyError, e:
		raise MixError("Nothing known about server %s"%nickname)
	for info in serverList:
	    #XXXX fail on DNE
	    server = info['Server']
	    if server['Valid-After'] <= when <= until <= server['Valid-Until']:
		return info
	raise MixError("No time-valid information for server %s"%nickname)

    def getAllCurrentServers(self, when=None, until=None):
	"""Return all ServerInfo objects valid during a given interval."""
        self.load()
	if when is None:
	    when = time.time()
	if until is None:
	    until = when+1
	result = []
	for nickname, infos in self.servers.items():
	    for info in infos:
		server = info['Server']
		if server['Valid-After'] <= when <= until <= server['Valid-Until']:
		    result.append(info)
	return result

    def importServerInfo(self, fname, force=1, string=None):
	"""Import a server descriptor from an external file into the internal
	   cache.  Return 1 on import; 0 on failure."""
	self.load()
	if string is None:
	    f = open(fname)
	    contents = f.read()
	    f.close()
	else:
	    assert fname is None
	    contents = string
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
	
	    for other in self.servers[nickname]:
		if other['Server']['Digest'] == info['Server']['Digest']:
		    getLog().warn("Duplicate server info; skipping")
		    return 0

	    self.servers[nickname].append(info)
	else:
	    self.servers[nickname] = [ info ]

	self.allServers.append(info)

	self.highest_num += 1
	fname_new = "si%d" % self.highest_num
	fd = os.open(os.path.join(self.dirname, fname_new), 
		     os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0600)
	f = os.fdopen(fd, 'w')
	f.write(contents)
	f.close()

	return 1

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

	# Get directory cache
	self.dirCache = DirectoryCache(os.path.join(userdir, 
						    'directory', 'servers'))
	self.dirCache.load()

	# Initialize PRNG
	self.prng = mixminion.Crypto.AESCounterPRNG()

    def getDirectoryCache(self):
	return self.dirCache

    def _getRandomPath(self, length=None):
	# FFFF Base-list functionality
	if not length:
	    length = self.config['Security'].get('PathLength',8)

	# XXXX We only pick servers that will be good for 24 hours.  That's
	# XXXX bad!  It allows a delaying/partitioning attack.
	servers = self.dirCache.getAllCurrentServers(when=time.time(),
					     until=time.time()+24*60*60)

	# XXXX Pick only servers that relay to all other servers!
	# XXXX Watch out for many servers with the same IP or nickname or...

	if length > len(servers):
	    getLog().warn("I only know about %s servers; That's not enough to use distinct servers on your path.", len(servers))
	    result = []
	    while len(result) < length:
		result.extend(prng.shuffle(servers))
	    return result[:length]
	else:
	    return self.prng.shuffle(servers, length)

    def _getPath(self, minLength, startAt, endAt, serverList=None):
	if serverList is not None:
	    if len(serverList) < minLength:
		raise MixError("Path must have at least %s hops", minLength)
	    
	    serverList = [ self.dirCache.getCurrentServer(s,startAt,endAt) 
			            for s in serverList ]
	else:
	    serverList = self._getRandomPath()
	
	if len(serverList) < minLength:
	    serverList += self._getRandomPath(minLength-len(serverList))
	    
	return serverList

    def sendForwardMessage(self, routingType, routingInfo, payload, 
			   serverList=None):
	message, firstHop = self.generateForwardMessage(address,
							payload,
							serverList)
	self.sendMessages([message], firstHop)

    def sendReplyMessage(self, payload, replyBlock, serverList=None):
	message, firstHop = self.generateReplyMessage(payload, 
						      replyBlock,
						      serverList)
	self.sendMessages([message], firstHop)

    def generateForwardMessage(self, address, payload, serverList=None):
	serverList = self._getPath(2, 
				   #XXXX This is bogus; see above
				   time.time(), time.time()+24*60*60,
				   serverList)
	    
	firstPathlen = floorDiv(len(serverList), 2)
	servers1,servers2 = serverList[:firstPathLen],serverList[firstPathLen:]
	
	routingType, routingInfo, lastHop = address.getRouting()
	if lastHop != None:
	    servers2.append(self.dirCache.getCurrentServer(lastHop))
	msg = mixminion.BuildMessage.buildForwardMessage(payload,
							 routingType, 
							 routingInfo,
							 servers1, servers2)
	return msg, servers1[0]

    def generateReplyBlock(self, address, startAt=None, endAt=None,
			   password=None, serverList=None):
	if startAt is None:
	    startAt = time.time()
	if endAt is None:
	    lifetime = self.config['Security'].get('SURBLifetime')
	    if lifetime:
		endAt = startAt + lifetime[2]
	    else:
		endAt = startAt + 24*60*60*7
	    
	path  = self._getPath(2, 
			      #XXXX This is bogus; see above
			      startAt, endAt,
			      serverList)

	if password:
	    # XXXX Out of sync with spec.
	    raise MixFatalError("Not implemented")

	handle = Crypto.getBytes(16)
	rt, ri, lastHop = address.getRouting("RTRN"+handle)
	if lastHop is not None:
	    path.append(lastHop)
	block, secrets = mixminion.BuildMesssage.buildReplyBlock(path, rt, ri,
								 endAt,
								 self.prng)

	# XXXX Store secrets and expiry time
	return block

    def generateReplyMessage(self, payload, replyBlock, serverList=None):
	# XXXX Not in sync with spec
	path = self._getPath(1, time.time(), replyBlock.timestamp,
			     serverList)

	msg = mixminion.BuildMessage.buildReplyMessage(payload,
						       path,
						       replyBlock)
	return msg, path[0]

    def decodeReplyMessage(self, tag, payload):
	pass

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

class Address:
    def getRouting(self, tag=None):
	# Return rt, ri, lasthop
	raise NotImplemented("Address.getRouting()")

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

    getLog().setMinSeverity("INFO")
    mixminion.Crypto.init_crypto(config)
    if len(args) < 2:
	print >> sys.stderr, "I need at least 2 servers"
    servers = [ ServerInfo(fn) for fn in args ]
    idx = floorDiv(len(servers),2)

    sendTestMessage(servers[:idx], servers[idx:])


