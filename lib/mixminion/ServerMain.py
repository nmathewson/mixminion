# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerMain.py,v 1.2 2002/08/11 07:50:34 nickm Exp $

"""mixminion.ServerMain

   The main loop and related functionality for a Mixminion server

   BUG: No support for encrypting private keys.n"""

import cPickle

from mixminion.Common import getLog, MixFatalError, MixError

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

def createDir(d):
    if not os.path.exists(d):
        try:
            os.mkdir(d, 0700)
        except OSError, e:
            getLog().fatal("Unable to create directory %s"%d)
            raise MixFatalError()
    elif not os.path.isdir(d):
        getLog().fatal("%s is not a directory"%d)
        raise MixFatalError()
    else:
        m = os.stat(d)[stat.ST_MODE]
        # check permissions
        if m & 0077:
            getLog().fatal("Directory %s must be mode 0700" %d)
            raise MixFatalError()

class ServerState:
    # XXXX This should be refactored.  keys should be separated from queues.
    # config
    # log
    # homedir
    def __init__(self, config):
        self.config = config

        #XXXX DOCDOC
        # set up directory structure.
        c = self.config
        self.homedir = c['Server']['Homedir']
        createDir(self.homedir)
        getLog()._configure() # ????
        
        w = os.path.join(self.homeDir, "work")
        q = os.path.join(w, "queues")
        self.incomingDir = os.path.join(q, "incoming")
        self.mixDir = os.path.join(q, "mix")
        self.outgoingDir = os.path.join(q, "outgoing")
        self.deliverDir = os.path.join(q, "deliver")
        self.deliverMBOXDir = os.path.join(self.deliverDir, "mbox")

        tlsDir = os.path.join(w, "tls")
        self.hashlogsDir = os.path.join(w, "hashlogs")
        self.keysDir = os.path.join(self.homeDir, "keys")
        self.confDir = os.path.join(self.homeDir, "conf")
        
        for d in [self.homeDir, w, q, self.incomingDir, self.mixDir,
                  self.outgoingDir, self.deliverDir, tlsDir,
                  self.hashlogsDir, self.keysDir, self.confDir]:
            createDir(d)

        for name in ("incoming", "mix", "outgoing", "deliverMBOX"):
            loc = getattr(self, name+"Dir")
            queue = mixminion.Queue.Queue(loc, create=1, scrub=1)
            setattr(self, name+"Queue", queue)

        self.dhFile = os.path.join(tlsDir, "dhparam")

        self.checkKeys()

    def getDHFile(self):
        if not os.path.exists(self.dhFile):
            getLog().info("Generating Diffie-Helman parameters for TLS...")
            mixminion._minionlib.generate_dh_parameters(self.dhFile, verbose=0)
            getLog().info("...done")

        return self.dhFile

    def checkKeys(self):
        self.keyIntervals = [] # list of start, end, keysetname
        for dirname in os.listdir(self.keysDir):
            if not dirname.startswith('key_'):
                continue
            keysetname = dirname[4:]
            
            d = os.path.join(self.keysDir, dirname)
            si = os.path.join(self.keysDir, "ServerDesc")
            if os.path.exists(si):
                inf = mixminion.ServerInfo.ServerInfo(fname=si, assumeValid=1)
                t1 = inf['Server']['Valid-After']
                t2 = inf['Server']['Valid-Until']
                self.keyIntervals.append( (t1, t2, keysetname) ) 

        self.keyIntervals.sort()

    def removeDeadKeys(self):
        now = time.time()
        cutoff = now - config['Server']['PublicKeySloppiness']
        names = [ os.path.join(self.keyDir,"key_"+name)
                  for va, vu, name in self.keyIntervals if vu < cutoff ]
        # XXXX DELETE KEYS
        
    def _getLiveKey(self):
        now = time.time()
        idx = bisect.bisect_left(self.keyIntervals, (now, None, None))
        return self.keyIntervals[idx]

    def getNextKeyRotation(self):
        return self._getLiveKey()[1]

    def getServerKeys(self):
        keyset = self._getLiveKey()[2]
        sk = mixminion.ServerInfo.ServerKeys(self.keyDir, keyset,
                                             self.hashlogsDir)
        sk.load()
        return sk

    def getTLSContext(self):
        # XXXX NO SUPPORT FOR ROTATION
        keys = self.getServerKeys()
        return mixminion._minionlib.TLSContext_new(keys.certFile,
                                                   keys.mmtpKey,
                                                   self.dhFile)
    
    def getPacketHandler(self):
        keys = self.getServerKeys()
        return mixminion.PacketHandler.PacketHandler(keys.packetKey,
                                                     keys.hashlogFile)

    def getIncomingQueues(self):
        return self.incomingQueue

    def getOutgoingQueue(self):
        return self.outgoingQueue

    def getMixQueue(self):
        return self.mixQueue

    def getDeliverMBOXQueue(self, which):
        return self.deliverMBOXQueue

class _Server(MMTPServer):
    def __init__(self, config, serverState):
        self.incomingQueue = serverState.getIncomingQueue()
        self.outgoingQueue = serverState.getOutgoingQueue()
        MMTPServer.__init__(self, config)
        
    def onMessageReceived(self, msg):
        self.incomingQueue.queueMessage(msg)

    def onMessageSent(self, msg, handle):
        self.outgoingQueue.remove(handle)

def runServer(config):
    s = ServerState(config)
    log = getLog()
    packetHandler = s.getPacketHandler()
    context = s.getTLSContext()

    # XXXX Make these configurable; make mixing OO.
    mixInterval = 60
    mixPoolMinSize = 5
    mixPoolMaxRate = 0.5 

    nextMixTime = time.time() + mixInterval

    server = _Server(config, s)

    incomingQueue = s.getIncomingQueue()
    outgoingQueue = s.getOutgoingQueue()
    mixQueue = s.getMixQueue()
    deliverMBOXQueue = s.getDeliverMBOXQueue()
    while 1:  # Add shutdown mechanism XXXX
        server.process(1)

	# Possible timing attack here????? XXXXX ????
	if incomingQueue.count():
	    for h in incomingQueue.getAllMessages():
		msg = incomingQueue.messageContents(h)
		res = None
		try:
		    res = packetHandler.processHandler(msg)
		    if res is None: log.info("Padding message dropped")
		except miximinion.Packet.ParseError, e:
		    log.warn("Malformed message dropped:"+str(e))
		except miximinion.Crypto.CryptoError, e:
		    log.warn("Invalid PK or misencrypted packet header:"+str(e))
		except mixminion.PacketHandler.ContentError, e:
		    log.warn("Discarding bad packet:"+str(e))

		if res is not None:
		    f, newHandle = mixQueue.openNewMessage()
		    cPickle.dump(res, f, 1)
		    mixQueue.finishMessage(f, newHandle)
		    log.info("Message added to mix queue")
		
		incomingQueue.removeMessage(h)
	
	if time.time() > nextMixTime:
	    nextMixTime = time.time() + mixInterval
	    
	    poolSize = mixQueue.count()
	    if poolSize > mixPoolMinSize:
		beginSending = {}
		n = min(poolSize-mixPoolMinSize, int(poolSize*mixPoolMaxRate))
		handles = mixQueue.pickRandom(n)
		for h in handles:
		    f = mixQueue.openMessage(h)
		    type, data = cPickle.load(f)
		    f.close()
		    if type == 'QUEUE':
			newHandle = mixQueue.moveMessage(h, outgoingQueue)
			ipv4info, payload = data
			beginSending.setdefault(ipv4info,[]).append(
			    (newHandle, payload))
		    else:
			assert type == 'EXIT'
			# XXXX Use modulemanager for this.
			rt, ri, appKey, payload = data
			if rt == Modules.DROP_TYPE:
			    mixQueue.removeMessage(h)
			elif rt == Moddules.MBOX_TYPE:
			    mixQueue.moveMessage(h, deliverMBOXQueue)
			else:
			    # XXXX Shouldn't we drop stuff as early as possible,
			    # XXXX so that we don't wind up with only a single
			    # XXXX message sent out of the server?
			    log.warn("Dropping unhandled type 0x%04x",rt)
			    mixQueue.removeMessage(h)

		if beginSending:
		    # XXXX Handle timeouts; handle if we're already sending
		    # XXXX to a server.
		    for addr, messages in beginSending.items():
			handles, payloads = zip(*messages)
			server.sendMessages(addr.ip, addr.port, addr.keyinfo,
					    payloads, handles)
		    
	    # XXXX Retry and resend after failure.
	    # XXXX Scan for messages we should begin sending after restart.
	    # XXXX Remove long-undeliverable messages
	    # XXXX Deliver MBOX messages.

