# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerMain.py,v 1.1 2002/08/06 16:09:21 nickm Exp $

"""mixminion.ServerMain

   The main loop and related functionality for a Mixminion server

   BUG: No support for public key encryption"""

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

    def onMessageSent(self, msg):
        self.outgoingQueue.remove
    

def runServer(config):
    s = ServerState(config)
    packetHandler = s.getPacketHandler()
    context = s.getTLSContext()

    shouldProcess = len(os.listdir(s.incomingDir))
    shouldSend = len(os.listdir(s.outgoingDir))
    shouldMBox = len(os.listdir(s.deliverMBOXDir))
    # XXXX Make these configurable; make mixing OO.
    mixInterval = 60
    mixPoolMinSize = 5
    mixPoolMaxRate = 5 

    nextMixTime = time.time() + mixInterval

    server = mixminion.MMTPServer.MMTPServer(config)

    while 1:
        
        
