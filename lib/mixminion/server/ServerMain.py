# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerMain.py,v 1.52 2003/05/17 00:08:45 nickm Exp $

"""mixminion.ServerMain

   The main loop and related functionality for a Mixminion server.

   See the "MixminionServer" class for more information about how it
   all works. """

__all__ = [ 'MixminonServer' ]

import getopt
import os
import sys
import signal
import string
import time
import threading
from types import *
# We pull this from mixminion.Common, just in case somebody still has
# a copy of the old "mixminion/server/Queue.py" (since renamed to
# ServerQueue.py)
from mixminion.Common import MessageQueue

import mixminion.Config
import mixminion.Crypto
import mixminion.server.MMTPServer
import mixminion.server.Modules
import mixminion.server.PacketHandler
import mixminion.server.ServerQueue
import mixminion.server.ServerConfig
import mixminion.server.ServerKeys
import mixminion.server.EventStats as EventStats

from bisect import insort
from mixminion.Common import LOG, LogStream, MixError, MixFatalError,\
     UIError, ceilDiv, createPrivateDir, formatBase64, formatTime, \
     installSIGCHLDHandler, Lockfile, secureDelete, waitForChildren

class IncomingQueue(mixminion.server.ServerQueue.Queue):
    """A Queue to accept packets from incoming MMTP connections,
       and hold them until they can be processed.  As packets arrive, and
       are stored to disk, we notify a message queue so that another thread
       can read them."""
    ## Fields:
    # packetHandler -- an instance of PacketHandler.
    # mixPool -- an instance of MixPool
    # processingThread -- an instance of ProcessingThread
    def __init__(self, location, packetHandler):
        """Create an IncomingQueue that stores its messages in <location>
           and processes them through <packetHandler>."""
        mixminion.server.ServerQueue.Queue.__init__(self, location, create=1)
        self.packetHandler = packetHandler
        self.mixPool = None

    def connectQueues(self, mixPool, processingThread):
        """Sets the target mix queue"""
        self.mixPool = mixPool
        self.processingThread = processingThread
        for h in self.getAllMessages():
            assert h is not None
            self.processingThread.addJob(
                lambda self=self, h=h: self.__deliverMessage(h))

    def queueMessage(self, msg):
        """Add a message for delivery"""
        LOG.trace("Inserted message %s into incoming queue",
                  formatBase64(msg[:8]))
        h = mixminion.server.ServerQueue.Queue.queueMessage(self, msg)
        assert h is not None
        self.processingThread.addJob(
            lambda self=self, h=h: self.__deliverMessage(h))

    def __deliverMessage(self, handle):
        """Process a single message with a given handle, and insert it into
           the Mix pool.  This function is called from within the processing
           thread."""
        ph = self.packetHandler
        message = self.messageContents(handle)
        try:
            res = ph.processMessage(message)
            if res is None:
                # Drop padding before it gets to the mix.
                LOG.debug("Padding message %s dropped",
                          formatBase64(message[:8]))
                self.removeMessage(handle)
            else:
                if res.isDelivery():
                    res.decode()
                LOG.debug("Processed message %s; inserting into pool",
                          formatBase64(message[:8]))
                self.mixPool.queueObject(res)
                self.removeMessage(handle)
        except mixminion.Crypto.CryptoError, e:
            LOG.warn("Invalid PK or misencrypted header in message %s: %s",
                     formatBase64(message[:8]), e)
            self.removeMessage(handle)
        except mixminion.Packet.ParseError, e:
            LOG.warn("Malformed message %s dropped: %s",
                     formatBase64(message[:8]), e)
            self.removeMessage(handle)
        except mixminion.server.PacketHandler.ContentError, e:
            LOG.warn("Discarding bad packet %s: %s",
                     formatBase64(message[:8]), e)
            self.removeMessage(handle)
        except:
            LOG.error_exc(sys.exc_info(),
                    "Unexpected error when processing message %s (handle %s)",
                          formatBase64(message[:8]), handle)
            self.removeMessage(handle) # ???? Really dump this message?

class MixPool:
    """Wraps a mixminion.server.Queue.*MixPool to send messages to an exit
       queue and a delivery queue.  The files in the MixPool are instances
       of RelayedPacket or DeliveryPacket from PacketHandler.

       All methods on this class are invoked from the main thread.
    """
    ## Fields:
    # queue -- underlying *MixPool
    # outgoingQueue -- instance of OutgoingQueue
    # moduleManager -- instance of ModuleManager.
    def __init__(self, config, queueDir):
        """Create a new MixPool, based on this server's configuration and
           queue location."""

        server = config['Server']
        interval = server['MixInterval'].getSeconds()
        if server['MixAlgorithm'] == 'TimedMixPool':
            self.queue = mixminion.server.ServerQueue.TimedMixPool(
                location=queueDir, interval=interval)
        elif server['MixAlgorithm'] == 'CottrellMixPool':
            self.queue = mixminion.server.ServerQueue.CottrellMixPool(
                location=queueDir, interval=interval,
                minPool=server.get("MixPoolMinSize", 5),
                sendRate=server.get("MixPoolRate", 0.6))
        elif server['MixAlgorithm'] == 'BinomialCottrellMixPool':
            self.queue = mixminion.server.ServerQueue.BinomialCottrellMixPool(
                location=queueDir, interval=interval,
                minPool=server.get("MixPoolMinSize", 5),
                sendRate=server.get("MixPoolRate", 0.6))
        else:
            raise MixFatalError("Got impossible mix pool type from config")

        self.outgoingPool = None
        self.moduleManager = None

    def lock(self):
        """Acquire the lock on the underlying pool"""
        self.queue.lock()

    def unlock(self):
        """Release the lock on the underlying pool"""
        self.queue.unlock()

    def queueObject(self, obj):
        """Insert an object into the pool."""
        self.queue.queueObject(obj)

    def count(self):
        "Return the number of messages in the pool"
        return self.queue.count()

    def connectQueues(self, outgoing, manager):
        """Sets the queue for outgoing mixminion packets, and the
           module manager for deliverable messages."""
        self.outgoingQueue = outgoing
        self.moduleManager = manager

    def mix(self):
        """Get a batch of messages, and queue them for delivery as
           appropriate."""
        if self.queue.count() == 0:
            LOG.trace("No messages in the mix pool")
            return
        handles = self.queue.getBatch()
        LOG.debug("%s messages in the mix pool; delivering %s.",
                  self.queue.count(), len(handles))

        for h in handles:
            packet = self.queue.getObject(h)
            if type(packet) == type(()):
                #XXXX005 remove this case.
                LOG.error("  (skipping message %s in obsolete format)", h)
            elif packet.isDelivery():
                LOG.debug("  (sending message %s to exit modules)",
                          formatBase64(packet.getContents()[:8]))
                self.moduleManager.queueDecodedMessage(packet)
            else:
                LOG.debug("  (sending message %s to MMTP server)",
                          formatBase64(packet.getPacket()[:8]))
                self.outgoingQueue.queueDeliveryMessage(packet)
            # In any case, we're through with this message now.
            self.queue.removeMessage(h)

    def getNextMixTime(self, now):
        """Given the current time, return the time at which we should next
           mix."""
        return now + self.queue.getInterval()

class OutgoingQueue(mixminion.server.ServerQueue.DeliveryQueue):
    """DeliveryQueue to send messages via outgoing MMTP connections.  All
       methods on this class are called from the main thread.  The underlying
       objects in this queue are instances of RelayedPacket.

       All methods in this class are run from the main thread.
    """
    ## Fields:
    # server -- an instance of _MMTPServer
    # addr -- (publishedIP, publishedPort, publishedKeyID)
    # incomingQueue -- pointer to IncomingQueue object to be used for
    #        self->self communication.
    def __init__(self, location, (ip,port,keyid)):
        """Create a new OutgoingQueue that stores its messages in a given
           location."""
        mixminion.server.ServerQueue.DeliveryQueue.__init__(self, location)
        self.server = None
        self.incomingQueue = None
        self.addr = (ip,port,keyid)

    def configure(self, config):
        """Set up this queue according to a ServerConfig object."""
        retry = config['Outgoing/MMTP']['Retry']
        self.setRetrySchedule(retry)

    def connectQueues(self, server, incoming):
        """Set the MMTPServer and IncomingQueue that this
           OutgoingQueue informs of its deliverable messages."""

        self.server = server
        self.incomingQueue = incoming

    def _deliverMessages(self, msgList):
        "Implementation of abstract method from DeliveryQueue."
        # Map from addr -> [ (handle, msg) ... ]
        msgs = {}
        for handle, packet in msgList:
            if not isinstance(packet,
                              mixminion.server.PacketHandler.RelayedPacket):
                LOG.warn("Skipping packet in obsolete format")
                self.deliverySucceeded(handle)
                continue
            addr = packet.getAddress()
            message = packet.getPacket()
            msgs.setdefault(addr, []).append( (handle, message) )
        for addr, messages in msgs.items():
            if self.addr[:2] == (addr.ip, addr.port):
                if self.addr[2] != addr.keyinfo:
                    LOG.warn("Delivering messages to myself with bad KeyID")
                for h,m in messages:
                    LOG.trace("Delivering message %s to myself.",
                              formatBase64(m[:8]))
                    self.incomingQueue.queueMessage(m)
                    self.deliverySucceeded(h)
                continue

            handles, messages = zip(*messages)
            self.server.sendMessages(addr.ip, addr.port, addr.keyinfo,
                                     list(messages), list(handles))

class _MMTPServer(mixminion.server.MMTPServer.MMTPAsyncServer):
    """Implementation of mixminion.server.MMTPServer that knows about
       delivery queues.

       All methods in this class are run from the main thread.
       """
    ## Fields:
    # incomingQueue -- a Queue to hold messages we receive
    # outgoingQueue -- a DeliveryQueue to hold messages to be sent.
    def __init__(self, config, tls):
        mixminion.server.MMTPServer.MMTPAsyncServer.__init__(self, config, tls)

    def connectQueues(self, incoming, outgoing):
        self.incomingQueue = incoming
        self.outgoingQueue = outgoing

    def onMessageReceived(self, msg):
        self.incomingQueue.queueMessage(msg)
        # XXXX Replace with server.
        EventStats.log.receivedPacket()

    def onMessageSent(self, msg, handle):
        self.outgoingQueue.deliverySucceeded(handle)
        EventStats.log.attemptedRelay() # XXXX replace with addr
        EventStats.log.successfulRelay() # XXXX replace with addr

    def onMessageUndeliverable(self, msg, handle, retriable):
        self.outgoingQueue.deliveryFailed(handle, retriable)
        EventStats.log.attemptedRelay() # XXXX replace with addr
        if retriable:
            EventStats.log.failedRelay() # XXXX replace with addr
        else:
            EventStats.log.unretriableRelay() # XXXX replace with addr

#----------------------------------------------------------------------
class CleaningThread(threading.Thread):
    """Thread that handles file deletion.  Some methods of secure deletion
       are slow enough that they'd block the server if we did them in the
       main thread.
    """
    # Fields:
    #   mqueue: A MessageQueue holding filenames to delete, or None to indicate
    #     a shutdown.
    def __init__(self):
        threading.Thread.__init__(self)
        self.mqueue = MessageQueue()

    def deleteFile(self, fname):
        """Schedule the file named 'fname' for deletion"""
        LOG.trace("Scheduling %s for deletion", fname)
        assert fname is not None
        self.mqueue.put(fname)

    def deleteFiles(self, fnames):
        """Schedule all the files in the list 'fnames' for deletion"""
        for f in fnames:
            self.deleteFile(f)

    def shutdown(self):
        """Tell this thread to shut down once it has deleted all pending
           files."""
        LOG.info("Telling cleanup thread to shut down.")
        self.mqueue.put(None)

    def run(self):
        """implementation of the cleaning thread's main loop: waits for
           a filename to delete or an indication to shutdown, then
           acts accordingly."""
        try:
            while 1:
                fn = self.mqueue.get()
                if fn is None:
                    LOG.info("Cleanup thread shutting down.")
                    return
                if os.path.exists(fn):
                    LOG.trace("Deleting %s", fn)
                    secureDelete(fn, blocking=1)
                else:
                    LOG.warn("Delete thread didn't find file %s",fn)
        except:
            LOG.error_exc(sys.exc_info(),
                          "Exception while cleaning; shutting down thread.")

class ProcessingThread(threading.Thread):
    """Background thread to handle CPU-intensive functions.

       Currently used to process packets in the background."""
    # Fields:
    #   mqueue: a MessageQueue of callable objects.
    class _Shutdown:
        """Callable that raises itself when called.  Inserted into the
           queue when it's time to shut down."""
        def __call__(self):
            raise self

    def __init__(self):
        """Given a MessageQueue object, create a new processing thread."""
        threading.Thread.__init__(self)
        self.mqueue = MessageQueue()

    def shutdown(self):
        LOG.info("Telling processing thread to shut down.")
        self.mqueue.put(ProcessingThread._Shutdown())

    def addJob(self, job):
        """Adds a job to the message queue.  A job is a callable object
           to be invoked by the processing thread.  If the job raises
           ProcessingThread._Shutdown, the processing thread stops running."""
        self.mqueue.put(job)

    def run(self):
        try:
            while 1:
                job = self.mqueue.get()
                job()
        except ProcessingThread._Shutdown:
            LOG.info("Processing thread shutting down.")
            return
        except:
            LOG.error_exc(sys.exc_info(),
                          "Exception while processing; shutting down thread.")

#----------------------------------------------------------------------
STOPPING = 0 # Set to one if we get SIGTERM
def _sigTermHandler(signal_num, _):
    '''(Signal handler for SIGTERM)'''
    signal.signal(signal_num, _sigTermHandler)
    global STOPPING
    STOPPING = 1

GOT_HUP = 0 # Set to one if we get SIGHUP.
def _sigHupHandler(signal_num, _):
    '''(Signal handler for SIGTERM)'''
    signal.signal(signal_num, _sigHupHandler)
    global GOT_HUP
    GOT_HUP = 1

def installSignalHandlers():
    """Install signal handlers for sigterm and sighup."""
    signal.signal(signal.SIGHUP, _sigHupHandler)
    signal.signal(signal.SIGTERM, _sigTermHandler)

#----------------------------------------------------------------------

class _Scheduler:
    """Mixin class for server.  Implements a priority queue of ongoing,
       scheduled tasks with a loose (few seconds) granularity.
    """
    # Fields:
    #   scheduledEvents: list of (time, identifying-string, callable)
    #       Sorted by time.  We could use a heap here instead, but
    #       that doesn't turn into a net benefit until we have a hundred
    #       events or so.
    def __init__(self):
        """Create a new _Scheduler"""
        self.scheduledEvents = []

    def firstEventTime(self):
        """Return the time at which the earliest-scheduled event is
           supposed to occur.  Returns -1 if no events.
        """
        if self.scheduledEvents:
            return self.scheduledEvents[0][0]
        else:
            return -1

    def scheduleOnce(self, when, name, cb):
        """Schedule a callback function, 'cb', to be invoked at time 'when.'
        """
        assert type(name) is StringType
        assert type(when) in (IntType, LongType, FloatType)
        insort(self.scheduledEvents, (when, name, cb))

    def scheduleRecurring(self, first, interval, name, cb):
        """Schedule a callback function 'cb' to be invoked at time 'first,'
           and every 'interval' seconds thereafter.
        """
        assert type(name) is StringType
        assert type(first) in (IntType, LongType, FloatType)
        assert type(interval) in (IntType, LongType, FloatType)
        next = lambda t=time.time,i=interval: t()+i
        insort(self.scheduledEvents, (first, name,
                                      _RecurringEvent(name, cb, self, next)))

    def scheduleRecurringComplex(self, first, name, cb, nextFn):
        """Schedule a callback function 'cb' to be invoked at time 'first,'
           and thereafter at times returned by 'nextFn'.

           (nextFn is called immediately after the callback is invoked,
           every time it is invoked, and should return a time at which.)
        """
        assert type(name) is StringType
        assert type(first) in (IntType, LongType, FloatType)
        insort(self.scheduledEvents, (first, name,
                                      _RecurringEvent(name, cb, self, nextFn)))

    def processEvents(self, now=None):
        """Run all events that are scheduled to occur before 'now'.

           Note: if an event reschedules itself for a time _before_ now,
           it will only be run once per invocation of processEvents.

           The right way to run this class is something like:
               while 1:
                   interval = time.time() - scheduler.firstEventTime()
                   if interval > 0:
                       time.sleep(interval)
                       # or maybe, select.select(...,...,...,interval)
                   scheduler.processEvents()
        """
        if now is None: now = time.time()
        se = self.scheduledEvents
        cbs = []
        while se and se[0][0] <= now:
            cbs.append(se[0][2])
            del se[0]
        for cb in cbs:
            cb()

class _RecurringEvent:
    """helper for _Scheduler. Calls a callback, then reschedules it."""
    def __init__(self, name, cb, scheduler, nextFn):
        self.name = name
        self.cb = cb
        self.scheduler = scheduler
        self.nextFn = nextFn
    def __call__(self):
        self.cb()
        self.scheduler.scheduleOnce(self.nextFn(), self.name, self)

class MixminionServer(_Scheduler):
    """Wraps and drives all the queues, and the async net server.  Handles
       all timed events."""
    ## Fields:
    # config: The ServerConfig object for this server
    # keyring: The mixminion.server.ServerKeys.ServerKeyring
    #
    # mmtpServer: Instance of mixminion.ServerMain._MMTPServer.  Receives
    #    and transmits packets from the network.  Places the packets it
    #    receives in self.incomingQueue.
    # incomingQueue: Instance of IncomingQueue.  Holds received packets
    #    before they are decoded.  Decodes packets with PacketHandler,
    #    and places them in mixPool.
    # packetHandler: Instance of PacketHandler.  Used by incomingQueue to
    #    decrypt, check, and re-pad received packets.
    # mixPool: Instance of MixPool.  Holds processed messages, and
    #    periodically decides which ones to deliver, according to some
    #    batching algorithm.
    # moduleManager: Instance of ModuleManager.  Map routing types to
    #    outging queues, and processes non-MMTP exit messages.
    # outgoingQueue: Holds messages waiting to be send via MMTP.
    # cleaningThread: Thread used to remove packets in the background
    # processingThread: Thread to handle CPU-intensive activity without
    #    slowing down network interactivity.
    # lockFile: An instance of Lockfile to prevent multiple servers from
    #    running in the same directory
    # pidFile: Filename in which we store the pid of the running server.
    def __init__(self, config):
        """Create a new server from a ServerConfig."""
        _Scheduler.__init__(self)
        LOG.debug("Initializing server")

        self.config = config
        homeDir = config['Server']['Homedir']
        createPrivateDir(homeDir)

        # Lock file.
        self.lockFile = Lockfile(os.path.join(homeDir, "lock"))
        try:
            self.lockFile.acquire()
        except IOError:
            raise MixFatalError("Another server seems to be running.")

        # The pid file.
        self.pidFile = os.path.join(homeDir, "pid")

        #XXXX004 Catch ConfigError for bad serverinfo.
        #XXXX004 Check whether config matches serverinfo
        self.keyring = mixminion.server.ServerKeys.ServerKeyring(config)
        if not self.keyring.getLiveKeys():
            LOG.info("Generating a month's worth of keys.")
            LOG.info("(Don't count on this feature in future versions.)")
            # We might not be able to do this, if we password-encrypt keys
            keylife = config['Server']['PublicKeyLifetime'].getSeconds()
            nKeys = ceilDiv(30*24*60*60, keylife)
            self.keyring.createKeys(nKeys)

        LOG.debug("Initializing packet handler")
        self.packetHandler = mixminion.server.PacketHandler.PacketHandler()
        LOG.debug("Initializing MMTP server")
        self.mmtpServer = _MMTPServer(config, None)
        LOG.debug("Initializing keys")
        self.keyring.updateKeys(self.packetHandler, self.mmtpServer)

        publishedIP, publishedPort, publishedKeyID = self.keyring.getAddress()

        # FFFF Modulemanager should know about async so it can patch in if it
        # FFFF needs to.
        LOG.debug("Initializing delivery module")
        self.moduleManager = config.getModuleManager()
        self.moduleManager.configure(config)

        queueDir = os.path.join(homeDir, 'work', 'queues')

        incomingDir = os.path.join(queueDir, "incoming")
        LOG.debug("Initializing incoming queue")
        self.incomingQueue = IncomingQueue(incomingDir, self.packetHandler)
        LOG.debug("Found %d pending messages in incoming queue",
                  self.incomingQueue.count())

        mixDir = os.path.join(queueDir, "mix")

        LOG.trace("Initializing Mix pool")
        self.mixPool = MixPool(config, mixDir)
        LOG.debug("Found %d pending messages in Mix pool",
                       self.mixPool.count())

        outgoingDir = os.path.join(queueDir, "outgoing")
        LOG.debug("Initializing outgoing queue")
        self.outgoingQueue = OutgoingQueue(outgoingDir,
                               (publishedIP, publishedPort, publishedKeyID))
        self.outgoingQueue.configure(config)
        LOG.debug("Found %d pending messages in outgoing queue",
                       self.outgoingQueue.count())

        self.cleaningThread = CleaningThread()
        self.processingThread = ProcessingThread()

        LOG.debug("Connecting queues")
        self.incomingQueue.connectQueues(mixPool=self.mixPool,
                                       processingThread=self.processingThread)
        self.mixPool.connectQueues(outgoing=self.outgoingQueue,
                                   manager=self.moduleManager)
        self.outgoingQueue.connectQueues(server=self.mmtpServer,
                                         incoming=self.incomingQueue)
        self.mmtpServer.connectQueues(incoming=self.incomingQueue,
                                      outgoing=self.outgoingQueue)

        self.cleaningThread.start()
        self.processingThread.start()
        self.moduleManager.startThreading()

    def updateKeys(self):
        """DOCDOC"""
        self.keyring.updateKeys(self.packetHandler, self.mmtpServer)

    def run(self):
        """Run the server; don't return unless we hit an exception."""
        global GOT_HUP
        f = open(self.pidFile, 'wt')
        f.write("%s\n" % os.getpid())
        f.close()

        self.cleanQueues()

        now = time.time()
        self.scheduleRecurring(now+600, 600, "SHRED", self.cleanQueues)
        self.scheduleRecurring(now+180, 180, "WAIT",
                               lambda: waitForChildren(blocking=0))
        if EventStats.log.getNextRotation():
            self.scheduleRecurring(now+300, 300, "ES_SAVE",
                                   lambda: EventStats.log.save)
            self.scheduleRecurringComplex(EventStats.log.getNextRotation(),
                                        "ES_ROTATE",
                                        lambda: EventStats.log.rotate,
                                        lambda: EventStats.log.getNextRotation)

        self.scheduleRecurringComplex(self.mmtpServer.getNextTimeoutTime(now),
                                      "TIMEOUT",
                                      self.mmtpServer.tryTimeout,
                                      self.mmtpServer.getNextTimeoutTime)

        self.scheduleRecurringComplex(self.keyring.getNextKeyRotation(),
                                      self.updateKeys,
                                      "KEY_ROTATE",
                                      self.keyring.getKeyRotation)

        nextMix = self.mixPool.getNextMixTime(now)
        LOG.debug("First mix at %s", formatTime(nextMix,1))
        self.scheduleOnce(self.mixPool.getNextMixTime(now),
                          "MIX", self.doMix)

        LOG.info("Entering main loop: Mixminion %s", mixminion.__version__)

        # This is the last possible moment to shut down the console log, so
        # we have to do it now.
        mixminion.Common.LOG.configure(self.config, keepStderr=0)
        if self.config['Server'].get("Daemon",1):
            closeUnusedFDs()

        # FFFF Support for automatic key rotation.
        while 1:
            nextEventTime = self.firstEventTime()
            now = time.time()
            timeLeft = nextEventTime - now
            while timeLeft > 0:
                # Handle pending network events
                self.mmtpServer.process(2)
                # Check for signals
                if STOPPING:
                    LOG.info("Caught sigterm; shutting down.")
                    return
                elif GOT_HUP:
                    LOG.info("Caught sighup")
                    self.reset()
                    GOT_HUP = 0
                # Make sure that our worker threads are still running.
                if not (self.cleaningThread.isAlive() and
                        self.processingThread.isAlive() and
                        self.moduleManager.thread.isAlive()):
                    LOG.fatal("One of our threads has halted; shutting down.")
                    return

                # Calculate remaining time until the next event.
                now = time.time()
                timeLeft = nextEventTime - now

            # An event has fired.
            self.processEvents()

    def doReset(self):
        LOG.info("Resetting logs")
        LOG.reset()
        EventStats.log.save()
        LOG.info("Checking for key rotation")
        self.keyring.checkKeys()
        self.updateKeys()

    def doMix(self):
        now = time.time()
        # Before we mix, we need to log the hashes to avoid replays.
        try:
            # There's a potential threading problem here... in
            # between this sync and the 'mix' below, nobody should
            # insert into the mix pool.
            self.mixPool.lock()
            self.packetHandler.syncLogs()

            LOG.trace("Mix interval elapsed")
            # Choose a set of outgoing messages; put them in
            # outgoingqueue and modulemanager
            self.mixPool.mix()
        finally:
            self.mixPool.unlock()

        # Send outgoing messages
        self.outgoingQueue.sendReadyMessages()
        # Send exit messages
        self.moduleManager.sendReadyMessages()

        # Choose next mix interval
        nextMix = self.mixPool.getNextMixTime(now)
        self.scheduleOnce(nextMix, "MIX", self.doMix)
        LOG.trace("Next mix at %s", formatTime(nextMix,1))

    def cleanQueues(self):
        """Remove all deleted messages from queues"""
        LOG.trace("Expunging deleted messages from queues")
        # We use the 'deleteFiles' method from 'cleaningThread' so that
        # we schedule old files to get deleted in the background, rather than
        # blocking while they're deleted.
        df = self.cleaningThread.deleteFiles
        self.incomingQueue.cleanQueue(df)
        self.mixPool.queue.cleanQueue(df)
        self.outgoingQueue.cleanQueue(df)
        self.moduleManager.cleanQueues(df)

    def close(self):
        """Release all resources; close all files."""
        self.cleaningThread.shutdown()
        self.processingThread.shutdown()
        self.moduleManager.shutdown()

        self.cleaningThread.join()
        self.processingThread.join()
        self.moduleManager.join()

        self.packetHandler.close()

        EventStats.log.save()

        try:
            self.lockFile.release()
            os.unlink(self.pidFile)
        except OSError:
            pass

#----------------------------------------------------------------------
def daemonize():
    """Put the server into daemon mode with the standard trickery."""

    # This logic is more-or-less verbatim from Stevens's _Advanced
    # Programming in the Unix Environment_:

    # Fork, to run in the background.
    pid = os.fork()
    if pid != 0:
        os._exit(0)

    # Call 'setsid' to make ourselves a new session.
    if hasattr(os, 'setsid'):
        # Setsid is not available everywhere.
        os.setsid()
        # Fork again so the parent, (the session group leader), can exit. This
        # means that we, as a non-session group leader, can never regain a
        # controlling terminal.
        pid = os.fork()
        if pid != 0:
            os._exit(0)
    # Chdir to / so that we don't hold the CWD unnecessarily.
    os.chdir(os.path.normpath("/")) # WIN32 Is this right on Windows?
    # Set umask to 000 so that we drop any (possibly nutty) umasks that
    # our users had before.
    os.umask(0000)

def closeUnusedFDs():
    """Close stdin, stdout, and stderr."""
    # (We could try to do this via sys.stdin.close() etc., but then we
    #  would miss the magic copies in sys.__stdin__, sys.__stdout__, etc.
    #  Using os.close instead just nukes the FD for us.)
    os.close(sys.stdin.fileno())
    os.close(sys.stdout.fileno())
    os.close(sys.stderr.fileno())
    # Override stdout and stderr in case some code tries to use them
    sys.stdout = sys.__stdout__ = LogStream("STDOUT", "WARN")
    sys.stderr = sys.__stderr__ = LogStream("STDERR", "WARN")

_SERVER_USAGE = """\
Usage: %s [options]
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than the default.
""".strip()

def usageAndExit(cmd):
    print _SERVER_USAGE %cmd
    sys.exit(0)

def configFromServerArgs(cmd, args):
    #XXXX
    options, args = getopt.getopt(args, "hf:", ["help", "config="])
    if args:
        usageAndExit(cmd)
    configFile = None
    for o,v in options:
        if o in ('-h', '--help'):
            usageAndExit(cmd)
        if o in ('-f', '--config'):
            configFile = v

    return readConfigFile(configFile)

def readConfigFile(configFile):
    #XXXX
    if configFile is None:
        if os.path.exists(os.path.expanduser("~/.mixminiond.conf")):
            configFile = os.path.expanduser("~/.mixminiond.conf")
        elif os.path.exists(os.path.expanduser("~/etc/mixminiond.conf")):
            configFile = os.path.expanduser("~/etc/mixminiond.conf")
        elif os.path.exists("/etc/mixminiond.conf"):
            configFile = "/etc/mixminiond.conf"
        else:
            print >>sys.stderr, "No config file found or specified."
            sys.exit(1)

    try:
        print "Reading configuration from %s"%configFile
        return mixminion.server.ServerConfig.ServerConfig(fname=configFile)
    except (IOError, OSError), e:
        print >>sys.stderr, "Error reading configuration file %r:"%configFile
        print >>sys.stderr, "   ", str(e)
        sys.exit(1)
    except mixminion.Config.ConfigError, e:
        print >>sys.stderr, "Error in configuration file %r"%configFile
        print >>sys.stderr, str(e)
        sys.exit(1)
    return None #suppress pychecker warning

#----------------------------------------------------------------------
def runServer(cmd, args):
    if cmd.endswith(" server"):
        print "Obsolete command. Use 'mixminion server-start' instead."

    config = configFromServerArgs(cmd, args)
    try:
        # Configure the log, but delay disabling stderr until the last
        # possible minute; we want to keep echoing to the terminal until
        # the main loop starts.
        mixminion.Common.LOG.configure(config, keepStderr=1)
        LOG.debug("Configuring server")
    except:
        info = sys.exc_info()
        LOG.fatal_exc(info,"Exception while configuring server")
        LOG.fatal("Shutting down because of exception: %s", info[0])
        sys.exit(1)

    daemonMode = config['Server'].get("Daemon",1)
    if daemonMode:
        LOG.info("Starting server in the background")
        try:
            daemonize()
        except:
            LOG.fatal_exc(sys.exc_info(),
                          "Exception while starting server in the background")
            os._exit(0)
    else:
        os.umask(0000)

    # Configure event log
    try:
        EventStats.configureLog(config)
    except:
        LOG.fatal_exc(sys.exc_info(), "")
        os._exit(0)

    installSIGCHLDHandler()
    installSignalHandlers()

    try:
        mixminion.Common.configureShredCommand(config)
        mixminion.Crypto.init_crypto(config)

        server = MixminionServer(config)
    except:
        info = sys.exc_info()
        LOG.fatal_exc(info,"Exception while configuring server")
        LOG.fatal("Shutting down because of exception: %s", info[0])
        sys.exit(1)

    LOG.info("Starting server: Mixminion %s", mixminion.__version__)
    try:
        # We keep the console log open as long as possible so we can catch
        # more errors.
        server.run()
    except KeyboardInterrupt:
        pass
    except:
        info = sys.exc_info()
        LOG.fatal_exc(info,"Exception while running server")
        LOG.fatal("Shutting down because of exception: %s", info[0])

    LOG.info("Server shutting down")
    server.close()
    LOG.info("Server is shut down")

    LOG.close()
    sys.exit(0)

#----------------------------------------------------------------------
_PRINT_STATS_USAGE = """\
Usage: mixminion server-stats [options]
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than the default.
""".strip()

def printServerStats(cmd, args):
    #XXXX
    config = configFromServerArgs(cmd, args)
    _signalServer(config, 1)
    EventStats.configureLog(config)
    EventStats.log.dump(sys.stdout)

#----------------------------------------------------------------------
_SIGNAL_SERVER_USAGE = """\
Usage: %s [options]
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than the default.
""".strip()

def signalServer(cmd, args):
    options, args = getopt.getopt(args, "hf:", ["help", "config="])
    usage = 0
    # XXXX Refactor this and configFromServerArgs to raise UsageError
    if args:
        usage = 1
    configFile = None
    for o,v in options:
        if o in ('-h', '--help'):
            usageAndExit(cmd)
        elif o in ('-f', '--config'):
            configFile = v

    LOG.setMinSeverity("ERROR")
    config = readConfigFile(configFile)
    if cmd.endswith("stop-server") or cmd.endswith("server-stop"):
        reload = 0
    else:
        assert cmd.endswith("reload-server") or cmd.endswith("server-reload")
        reload = 1

    if usage:
        print _SIGNAL_SERVER_USAGE % { 'cmd' : cmd }
        return

    _signalServer(config, reload)

def _signalServer(config, reload):
    """Given a configuration file, sends a signal to the corresponding
       server if it's running.  If 'reload', the signal is HUP.  Else,
       the signal is TERM.
    """
    homeDir = config['Server']['Homedir']
    pidFile = os.path.join(homeDir, "pid")
    if not os.path.exists(pidFile):
        raise UIError("No server seems to be running.")

    try:
        f = open(pidFile, 'r')
        s = f.read()
        f.close()
        pid = string.atoi(s)
    except (IOError, ValueError), e:
        raise UIError("Couldn't read pid file: %s"%e)

    if reload:
        signal_num = signal.SIGHUP
        signal_name = "SIGHUP"
    else:
        signal_num = signal.SIGTERM
        signal_name = "SIGTERM"

    try:
        print "Sending %s to server (pid=%s)"%(signal_name, pid)
        os.kill(pid, signal_num)
        print "Done."
    except OSError, e:
        print UIError("Couldn't send signal: %s"%e)

#----------------------------------------------------------------------
_KEYGEN_USAGE = """\
Usage: %s [options]
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than
                                /etc/mixminiond.conf
  -n <n>, --keys=<n>         Generate <n> new keys. (Defaults to 1.)
""".strip()

def runKeygen(cmd, args):
    options, args = getopt.getopt(args, "hf:n:",
                                  ["help", "config=", "keys="])
    # FFFF password-encrypted keys
    # FFFF Ability to fill gaps
    # FFFF Ability to generate keys with particular start/end intervals
    keys=1
    usage=0
    configFile = None
    for opt,val in options:
        if opt in ('-h', '--help'):
            usage=1
        elif opt in ('-f', '--config'):
            configFile = val
        elif opt in ('-n', '--keys'):
            try:
                keys = int(val)
            except ValueError:
                print >>sys.stderr,("%s requires an integer" %opt)
                usage = 1
    if usage:
        print _KEYGEN_USAGE % cmd
        sys.exit(1)

    config = readConfigFile(configFile)

    LOG.setMinSeverity("INFO")
    mixminion.Crypto.init_crypto(config)
    keyring = mixminion.server.ServerKeys.ServerKeyring(config)
    print "Creating %s keys..." % keys
    for i in xrange(keys):
        keyring.createKeys(1)
        print ".... (%s/%s done)" % (i+1,keys)

#----------------------------------------------------------------------
_REMOVEKEYS_USAGE = """\
Usage: %s [options]
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than
                                /etc/mixminiond.conf
  --remove-identity          Remove the identity key as well.  (DANGEROUS!)
""".strip()

def removeKeys(cmd, args):
    # FFFF Resist removing keys that have been published.
    # FFFF Generate 'suicide note' for removing identity key.
    options, args = getopt.getopt(args, "hf:", ["help", "config=",
                                                "remove-identity"])
    if args:
        print >>sys.stderr, "%s takes no arguments"%cmd
        usage = 1
        args = options = ()
    usage = 0
    removeIdentity = 0
    configFile = None
    for opt,val in options:
        if opt in ('-h', '--help'):
            usage=1
        elif opt in ('-f', '--config'):
            configFile = val
        elif opt == '--remove-identity':
            removeIdentity = 1
    if usage:
        print _REMOVEKEYS_USAGE % cmd
        sys.exit(0)

    config = readConfigFile(configFile)
    mixminion.Common.configureShredCommand(config)
    LOG.setMinSeverity("INFO")
    keyring = mixminion.server.ServerKeys.ServerKeyring(config)
    keyring.checkKeys()
    # This is impossibly far in the future.
    keyring.removeDeadKeys(now=(1L << 36))
    if removeIdentity:
        keyring.removeIdentityKey()
    LOG.info("Done removing keys")
