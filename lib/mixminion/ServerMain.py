# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerMain.py,v 1.6 2002/08/25 05:58:02 nickm Exp $

"""mixminion.ServerMain

   The main loop and related functionality for a Mixminion server

   BUG: No support for encrypting private keys."""

import os
import getopt
import sys
import time
import bisect

import mixminion._minionlib
import mixminion.Queue
import mixminion.MMTPServer
from mixminion.ServerInfo import ServerKeyset, ServerInfo
from mixminion.Common import getLog, MixFatalError, MixError, secureDelete, \
     createPrivateDir

# Directory layout:
#     MINION_HOME/work/queues/incoming/
#                             mix/
#                             outgoing/
#                             deliver/mbox/
#                      tls/dhparam
#                      hashlogs/hash_1 ...
#                 log
#                 keys/key_1/ServerDesc
#                            mix.key
#                            mmtp.key
#                            mmtp.cert
#                      key_2/...
#                 conf/miniond.conf 
#                       ....

class ServerKeyring:
    # homeDir: ----
    # keyDir: ----
    # keySloppiness: ----
    # keyIntervals: list of (start, end, ServerKeyset Name)
    def __init__(self, config):
	self.configure(config)

    def configure(self, config):
	self.homeDir = config['Server']['Homedir']
	self.keyDir = os.path.join(self.homeDir, 'keys')
	self.keySloppiness = config['Server']['PublicKeySloppiness']
	self.checkKeys()

    def checkKeys(self):
        self.keyIntervals = [] 
        for dirname in os.listdir(self.keyDir):
            if not dirname.startswith('key_'):
		getLog().warn("Unexpected directory %s under %s",
			      dirname, self.keyDir)
                continue
            keysetname = dirname[4:]
            
            d = os.path.join(self.keyDir, dirname)
            si = os.path.join(d, "ServerDesc")
            if os.path.exists(si):
                inf = ServerInfo(fname=si, assumeValid=1)
                t1 = inf['Server']['Valid-After']
                t2 = inf['Server']['Valid-Until']
                self.keyIntervals.append( (t1, t2, keysetname) ) 

        self.keyIntervals.sort()
    
    def removeDeadKeys(self):
        now = time.time()
        cutoff = now - self.keySloppiness
	dirs = [ os.path.join(self.keyDir,"key_"+name)
                  for va, vu, name in self.keyIntervals if vu < cutoff ]

	for dirname in dirs:
	    files = [ os.path.join(dirname,f) 
		                 for f in os.listdir(dirname) ]
	    secureDelete(files, blocking=1)
	    os.rmdir(dirname)
	    
	self.checkKeys()

    def _getLiveKey(self):
	# returns valid-after, valid-until, name
        now = time.time()
        idx = bisect.bisect_left(self.keyIntervals, (now, None, None))
        return self.keyIntervals[idx]

    def getNextKeyRotation(self):
        return self._getLiveKey()[1]

    def getServerKeyset(self):
	# FFFF Support passwords on keys
	_, _, name = self._getLiveKey()
	hashroot = os.path.join(self.homeDir, 'work', 'hashlogs')
	keyset = ServerKeyset(self.keyDir, name, hashroot)
	keyset.load()
	return self.keyset
	
    def getDHFile(self):
	dhdir = os.path.join(self.homeDir, 'work', 'tls')
	createPrivateDir(dhdir)
	dhfile = os.path.join(dhdir, 'dhparam')
        if not os.path.exists(dhfile):
            getLog().info("Generating Diffie-Helman parameters for TLS...")
            mixminion._minionlib.generate_dh_parameters(dhfile, verbose=0)
            getLog().info("...done")

        return dhfile
			    
    def getTLSContext(self):
        keys = self.getServerKeyset()
        return mixminion._minionlib.TLSContext_new(keys.getCertFileName(),
						   keys.GetMMTPKey(),
						   self.getDHFile())

    def getPacketHandler(self):
        keys = self.getServerKeyset()
        return mixminion.PacketHandler.PacketHandler(keys.getPacketKey(),
                                                     keys.getHashLogFile())

class IncomingQueue(mixminion.Queue.DeliveryQueue):
    def __init__(self, location, packetHandler):
	mixminion.Queue.DeliveryQueue.__init__(self, location)
	self.packetHandler = packetHandler
	self.mixQueue = None

    def connectQueues(self, mixQueue):
	self.mixQueue = mixQueue

    def queueMessage(self, msg):
	mixminion.Queue.queueMessage(None, msg)
    
    def deliverMessages(self, msgList):
	ph = self.packetHandler
	for handle, _, message, n_retries in msgList:
	    try:
		res = ph.packetHandler(message)
		if res is None:
		    getLog().info("Padding message dropped")
		else:
		    self.mixQueue.queueObject(res)
		    self.deliverySucceeded(handle)
	    except mixminion.Crypto.CryptoError, e:
		getLog().warn("Invalid PK or misencrypted packet header:"+str(e))
		self.deliveryFailed(handle)
	    except mixminion.Packet.ParseError, e:
		getLog().warn("Malformed message dropped:"+str(e))
		self.deliveryFailed(handle)
	    except mixminion.PacketHandler.ContentError, e:
		getLog().warn("Discarding bad packet:"+str(e))
		self.deliveryFailed(handle)

class MixQueue:
    def __init__(self, queue):
	self.queue = queue
	self.outgoingQueue = None
	self.moduleManager = None

    def connectQueues(self, outgoing, manager):
	self.outgoingQueue = outgoing
	self.moduleManager = manager

    def mix(self):
	handles = self.queue.getBatch()
	for h in handles:
	    tp, info = self.queue.getObject(h)
	    if tp == 'EXIT':
		rt, ri, app_key, payload = info
		self.moduleManager.queueMessage((rt, ri), payload)
	    else:
		assert tp == 'QUEUE'
		ipv4, msg = info
		self.outgoingQueue.queueMessage(ipv4, msg)

class OutgoingQueue(mixminion.Queue.DeliveryQueue):
    def __init__(self, location):
	OutgoingQueue.__init__(self, location)
	self.server = None

    def connectQueues(self, server):
	self.server = server

    def deliverMessages(self, msgList):
	# Map from addr -> [ (handle, msg) ... ]
	msgs = {}
	for handle, addr, message, n_retries in msgList:
	    msgs.setdefault(addr, []).append( (handle, message) )
	for addr, messages in msgs.items():
	    messages, handles = zip(*messages)
	    self.server.sendMessages(addr.ip, addr.port, addr.keyinfo,
				     messages, handles)

class _MMTPConnection(mixminion.MMTPServer):
    def __init__(self, config):
        MMTPServer.__init__(self, config)

    def connectQueues(self, incoming, outgoing):
        self.incomingQueue = incoming
        self.outgoingQueue = outgoing

    def onMessageReceived(self, msg):
        self.incomingQueue.queueMessage(msg)

    def onMessageSent(self, msg, handle):
        self.outgoingQueue.deliverySucceeded(handle)

    def onMessageUndeliverable(self, msg, handle, retriable):
	self.outgoingQueue.deliveryFailed(handle, retriable)


class MixminionServer:
    def __init__(self, config):
	self.config = config
	self.keyring = ServerKeyring(config)
	
	self.packetHandler = self.keyring.getPacketHandler()
	self.mmtpConnection = _MMTPConnection(config)

	# FFFF Modulemanager should know about async so it can patch in if it
	# FFFF needs to.
	self.moduleManager = config.getModuleManager()

	homeDir = config['Server']['Homedir']
	queueDir = os.path.join(homeDir, 'work', 'queues')

	incomingDir = os.path.join(queueDir, "incoming")
	self.incomingQueue = IncomingQueue(incomingDir, self.packetHandler)

	mixDir = os.path.join(queueDir, "mix")
	# FFFF The choice of mix algorithm should be configurable
	self.mixQueue = MixQueue(mixminion.Queue.TimedMixQueue(mixDir, 60))

	outgoingDir = os.path.join(queueDir, "outgoing")
	self.outgoingQueue = OutgoingQueue(outgoingDir)

	self.incomingQueue.connectQueues(mixQueue=self.mixQueue)
	self.mixQueue.connectQueues(outgoing=self.outgoingQueue,
				    manager=self.moduleManager)
	self.outgoingQueue.connectQueues(server=self.mmtpConnection)
	self.mmtpConnection.connectQueues(incoming=self.incomingQueue,
					  outgoing=self.outgoingQueue)
	
    def run(self):
	now = time.time()
	nextMix = now + 60 # FFFF Configurable!
	nextShred = now + 6000
	
	while 1:
	    while time.time() < nextMix:
		self.mmtpConnection.process(1)
		self.incomingQueue.sendReadyMessages()
	    
	    self.mixQueue.mix()
	    self.outgoingQueue.sendReadyMessages()
	    self.moduleManager.sendReadyMessages()

	    now = time.time()
	    nextMix = now + 60
	    if now > nextShred:
		# Configurable shred interval
		self.incomingQueue.cleanQueue()
		self.mixQueue.queue.cleanQueue()
		self.outgoingQueue.cleanQueue()
		self.moduleManager.cleanQueues()
		nextShred = now + 6000

#----------------------------------------------------------------------

def usageAndExit(cmd):
    executable = sys.argv[0]
    # XXXX show versioning info
    print >>sys.stderr, "Usage: %s [-h] [-f configfile]" % cmd
    sys.exit(0)

def configFromArgs(cmd, args):
    options, args = getopt.getopt(args, "hf:", ["help", "config="])
    if args:
	usageAndExit(cmd)
    configFile = "/etc/miniond.conf"
    for o,v in options:
	if o in ('-h', '--help'):
	    usageAndExit()
	if o in ('-f', '--config'):
	    configFile = v
    try:
	config = mixminion.Config.ServerConfig(fname=configFile)
    except (IOError, OSError), e:
	print >>sys.stderr, "Error reading configuration file %r"%configFile
	sys.exit(1)
    except mixminion.Config.ConfigError, e:
	print >>sys.stderr, "Error in configuration file %r"%configFile
	print >>sys.stderr, str(e)
	sys.exit(1)

    return config

def runServer(cmd, args):
    config = configFromArgs(cmd, args)
    try:
	mixminion.Common.getLog().configure(config)
	getLog().debug("Configuring server")
	mixminion.Common.configureShredCommand(config)
	mixminion.Crypto.init_crypto(config)
	config.getModuleManager().configure(config)

	server = MixminionServer(config)
    except:
	getLog().fatal_exc("Exception while configuring server")
	print >>sys.stderr, "Shutting down because of exception"
	sys.exit(1)

    getLog().info("Starting server")
    try:
	server.run()
    except KeyboardInterrupt:
	pass
    except:
	getLog().fatal_exc("Exception while running server")
    getLog().info("Server shutting down")
    
    sys.exit(0)
