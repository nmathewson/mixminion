# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerMain.py,v 1.124.2.1 2004/04/26 16:57:18 nickm Exp $

"""mixminion.ServerMain

   The main loop and related functionality for a Mixminion server.

   See the "MixminionServer" class for more information about how it
   all works. """

#XXXX make usage messages have the same format.

## Directory layout:
#    ${BASEDIR}/current-desc [Filename of current server descriptor.]
#               version      [Version of homedir format.]
#
#    WORKDIR defaults to ${BASEDIR}/work
#    ${WORKDIR}/tls/dhparam       [Diffie-Hellman parameters]
#               hashlogs/hash_1*  [HashLogs of packet hashes
#                        hash_2*     corresponding to key sets]
#                          ...
#               stats.tmp         [Cache of stats from latest period]
#               dir/...           [Directory dowloaded from directory server.]
#
#    QUEUEDIR defaults to ${WORKDIR}/queues
#    ${QUEUEDIR}/incoming/        [Queue of received,unprocessed pkts]
#                mix/             [Mix pool]
#                outgoing/        [Packets for mmtp delivery]
#                deliver/*/       [Messages for delivery via modules]
#
#    KEYDIR defaults to ${BASEDIR}/keys
#    ${KEYDIR}/identity.key [Long-lived identity private key]
#              key_0001/ServerDesc [Server descriptor]
#                       mix.key [packet key]
#                       mmtp.key [mmtp key]
#                       mmtp.cert [mmtp key's x509 cert chain]
#                       published [present if this desc is published]
#              key_0002/...
#
#   LOGFILE defaults to ${BASEDIR}/log
#   PIDFILE defaults to ${BASEDIR}/pid
#   STATSFILE defaults to ${BASEDIR}/stats

__all__ = [ 'MixminionServer' ]

import errno
import getopt
import os
import sys
import signal
import time
import threading
from types import *
# We pull this from mixminion.ThreadUtils just in case somebody still has
# a copy of the old "mixminion/server/Queue.py" (since renamed to
# ServerQueue.py)
from mixminion.ThreadUtils import MessageQueue, ClearableQueue, QueueEmpty

import mixminion.ClientDirectory
import mixminion.Config
import mixminion.Crypto
import mixminion.Filestore
import mixminion.server.DNSFarm
import mixminion.server.MMTPServer
import mixminion.server.Modules
import mixminion.server.PacketHandler
import mixminion.server.ServerQueue
import mixminion.server.ServerConfig
import mixminion.server.ServerKeys
import mixminion.server.EventStats as EventStats

from bisect import insort
from mixminion.Common import LOG, LogStream, MixError, MixFatalError,\
     UIError, ceilDiv, createPrivateDir, disp64, formatTime, \
     installSIGCHLDHandler, Lockfile, LockfileLocked, readFile, secureDelete, \
     succeedingMidnight, tryUnlink, waitForChildren, writeFile

# Version number for server home-directory.
#
# For backward-incompatible changes only.
SERVER_HOMEDIR_VERSION = "1001"

def getHomedirVersion(config):
    """Return the version of the server's homedir.  If no version is found,
       the version must be '1000'.  If no directory structure is found,
       returns None."""
    homeDir = config.getBaseDir()
    versionFile = os.path.join(homeDir, "version")
    # Note: we actually don't want to use config.getWorkDir() or
    # config.getKeyDir() here: we're testing for pre-0.0.5 versions of
    # Mixminion.  Those versions didn't have a $HOMEDIR/version file, but
    # always had a $HOMEDIR/work directory and a $HOMEDIR/keys directory.
    wDir = os.path.join(homeDir, "work")
    kDir = os.path.join(homeDir, "keys")
    if not os.path.exists(homeDir):
        return None
    else:
        try:
            dirVersion = readFile(versionFile).strip()
        except (OSError, IOError), e:
            if e.errno == errno.ENOENT:
                if os.path.exists(wDir) and os.path.exists(kDir):
                    # The file doesn't exist, but the 'work' and 'keys'
                    # subdirectories do: the version must be '1000'.
                    dirVersion = "1000"
                else:
                    # The version file doesn't exist, and neither do the 'work'
                    # and 'keys' subdirectories: There is no preexisting
                    # installation.
                    dirVersion = None
            elif e.errno == errno.EACCES:
                raise UIError("You don't have permission to read %s"%
                              versionFile)
            else:
                raise UIError("Unexpected error while reading %s: %s"%(
                              versionFile, e))

    return dirVersion

def checkHomedirVersion(config):
    """Check the version of the server's homedir.  If it's too old, tell
       the user to upgrade and raise UIError.  If it's too new, tell the
       user we're confused and raise UIError.  Otherwise, return silently.
    """
    dirVersion = getHomedirVersion(config)

    if dirVersion is None:
        return None
    elif dirVersion != SERVER_HOMEDIR_VERSION:
        if float(dirVersion) < float(SERVER_HOMEDIR_VERSION):
            print >>sys.stderr, """\
This server's files are stored in an older format, and are not compatible
with this version of the mixminion server.  To upgrade, run:
     'mixminiond upgrade'."""
            raise UIError
        else:
            print >>sys.stderr, """\
This server's file are stored in format which this version of mixminion
is too old to recognize."""
            raise UIError

    return 1

class IncomingQueue(mixminion.Filestore.StringStore):
    """A Queue to accept packets from incoming MMTP connections,
       and hold them until they can be processed.  As packets arrive, and
       are stored to disk, we notify a MessageQueue so that another thread
       can read them."""
    ## Fields:
    # packetHandler -- an instance of PacketHandler.
    # mixPool -- an instance of MixPool
    # processingThread -- an instance of ProcessingThread
    def __init__(self, location, packetHandler):
        """Create an IncomingQueue that stores its packets in <location>
           and processes them through <packetHandler>."""
        mixminion.Filestore.StringStore.__init__(self, location, create=1)
        self.packetHandler = packetHandler
        self.mixPool = None

    def connectQueues(self, mixPool, processingThread):
        """Sets the target mix queue"""
        self.mixPool = mixPool
        self.processingThread = processingThread
        for h in self.getAllMessages():
            assert h is not None
            self.processingThread.addJob(
                lambda self=self, h=h: self.__deliverPacket(h))

    def queuePacket(self, pkt):
        """Add a packet for delivery"""
        h = mixminion.Filestore.StringStore.queueMessage(self, pkt)
        LOG.trace("Inserting packet IN:%s into incoming queue", h)
        assert h is not None
        self.processingThread.addJob(
            lambda self=self, h=h: self.__deliverPacket(h))

    def queueMessage(self, m):
        # Never call this directly.
        assert 0

    def __deliverPacket(self, handle):
        """Process a single packet with a given handle, and insert it into
           the Mix pool.  This function is called from within the processing
           thread."""
        ph = self.packetHandler
        packet = self.messageContents(handle)
        try:
            res = ph.processPacket(packet)
            if res is None:
                # Drop padding before it gets to the mix.
                LOG.debug("Padding packet IN:%s dropped", handle)
                self.removeMessage(handle)
            else:
                if res.isDelivery():
                    res.decode()

                self.mixPool.queueObject(res)
                self.removeMessage(handle)
                LOG.debug("Processed packet IN:%s; inserting into mix pool",
                          handle)
        except mixminion.Crypto.CryptoError, e:
            LOG.warn("Invalid PK or misencrypted header in packet IN:%s: %s",
                     handle, e)
            self.removeMessage(handle)
        except mixminion.Packet.ParseError, e:
            LOG.warn("Malformed packet IN:%s dropped: %s", handle, e)
            self.removeMessage(handle)
        except mixminion.server.PacketHandler.ContentError, e:
            LOG.warn("Discarding bad packet IN:%s: %s", handle, e)
            self.removeMessage(handle)
        except:
            LOG.error_exc(sys.exc_info(),
                    "Unexpected error when processing IN:%s", handle)
            self.removeMessage(handle)

class MixPool:
    """Wraps a mixminion.server.ServerQueue.*MixPool to send packets
       to an exit queue and a delivery queue.  The files in the
       MixPool are instances of RelayedPacket or DeliveryPacket from
       PacketHandler.

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
        return self.queue.queueObject(obj)

    def count(self):
        "Return the number of packets in the pool"
        return self.queue.count()

    def connectQueues(self, outgoing, manager):
        """Sets the queue for outgoing mixminion packets, and the
           module manager for deliverable packets."""
        self.outgoingQueue = outgoing
        self.moduleManager = manager

    def mix(self):
        """Get a batch of packets, and queue them for delivery as
           appropriate."""
        if self.queue.count() == 0:
            LOG.trace("No packets in the mix pool")
            return
        handles = self.queue.getBatch()
        LOG.debug("%s packets in the mix pool; delivering %s.",
                  self.queue.count(), len(handles))

        for h in handles:
            try:
                packet = self.queue.getObject(h)
            except mixminion.Filestore.CorruptedFile:
                continue
            if packet.isDelivery():
                h2 = self.moduleManager.queueDecodedMessage(packet)
                if h2:
                    LOG.debug("  (sending packet MIX:%s to exit modules as MOD:%s)"
                              , h, h2)
                else:
                    LOG.debug("  (exit modules received packet MIX:%s without queueing.)", h)
            else:
                address = packet.getAddress()
                h2 = self.outgoingQueue.queueDeliveryMessage(packet, address)
                LOG.debug("  (sending packet MIX:%s to MMTP server as OUT:%s)"
                          , h, h2)
            # In any case, we're through with this packet now.
            self.queue.removeMessage(h)

    def getNextMixTime(self, now):
        """Given the current time, return the time at which we should next
           mix."""
        return now + self.queue.getInterval()

class OutgoingQueue(mixminion.server.ServerQueue.DeliveryQueue):
    """DeliveryQueue to send packets via outgoing MMTP connections.  All
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
        """Create a new OutgoingQueue that stores its packets in a given
           location."""
        mixminion.server.ServerQueue.DeliveryQueue.__init__(self, location)
        self.server = None
        self.incomingQueue = None
        self.keyID = keyid

    def configure(self, config):
        """Set up this queue according to a ServerConfig object."""
        retry = config['Outgoing/MMTP']['Retry']
        self.setRetrySchedule(retry)

    def connectQueues(self, server, incoming):
        """Set the MMTPServer and IncomingQueue that this
           OutgoingQueue informs of its deliverable packets."""

        self.server = server
        self.incomingQueue = incoming

    def _deliverMessages(self, msgList):
        "Implementation of abstract method from DeliveryQueue."
        # Map from addr -> [ (handle, msg) ... ]
        pkts = {}
        for pending in msgList:
            try:
                addr = pending.getAddress()
                if addr is None:
                    addr = pending.getMessage().getAddress()
            except mixminion.Filestore.CorruptedFile:
                continue
            pkts.setdefault(addr, []).append(pending)
        for routing, packets in pkts.items():
            if self.keyID == routing.keyinfo:
                for pending in packets:
                    LOG.trace("Delivering packet OUT:%s to myself.",
                              pending.getHandle())
                    self.incomingQueue.queuePacket(
                        pending.getMessage().getPacket())
                    pending.succeeded()
                continue

            deliverable = [
                mixminion.server.MMTPServer.DeliverablePacket(pending)
                for pending in packets ]
            LOG.trace("Delivering packets OUT:[%s] to %s",
                      " ".join([p.getHandle() for p in packets]),
                      mixminion.ServerInfo.displayServerByRouting(routing))
            self.server.sendPacketsByRouting(routing, deliverable)

class _MMTPServer(mixminion.server.MMTPServer.MMTPAsyncServer):
    """Implementation of mixminion.server.MMTPServer that knows about
       delivery queues.

       All methods in this class are run from the main thread.
       """
    ## Fields:
    # incomingQueue -- a Queue to hold packetts we receive
    # outgoingQueue -- a DeliveryQueue to hold packets to be sent.
    def __init__(self, config, servercontext):
        mixminion.server.MMTPServer.MMTPAsyncServer.__init__(
            self, config, servercontext)

    def connectQueues(self, incoming, outgoing):
        self.incomingQueue = incoming
        self.outgoingQueue = outgoing

    def onPacketReceived(self, pkt):
        self.incomingQueue.queuePacket(pkt)
        # FFFF Replace with server.
        EventStats.log.receivedPacket()

#----------------------------------------------------------------------
class CleaningThread(threading.Thread):
    """Thread that handles file deletion.  Some methods of secure deletion
       are slow enough that they'd block the server if we did them in the
       main thread.
    """
    # Fields:
    #   mqueue: A ClearableQueue holding lists of filenames to delete,
    #     or None to indicate a shutdown.
    def __init__(self):
        threading.Thread.__init__(self)
        self.mqueue = ClearableQueue()

    def deleteFile(self, fname):
        """Schedule the file named 'fname' for deletion"""
        #LOG.trace("Scheduling %s for deletion", fname)
        assert fname is not None
        self.mqueue.put([fname])

    def deleteFiles(self, fnames):
        """Schedule all the files in the list 'fnames' for deletion"""
        self.mqueue.put(fnames)

    def shutdown(self):
        """Tell this thread to shut down once it has deleted all pending
           files."""
        LOG.info("Telling cleanup thread to shut down.")
        self.mqueue.clear()
        self.mqueue.put(None)

    def run(self):
        """implementation of the cleaning thread's main loop: waits for
           a filename to delete or an indication to shutdown, then
           acts accordingly."""
        try:
            running = 1
            while running:
                fnames = self.mqueue.get()
                if fnames is None:
                    fnames = []
                    running = 0

                try:
                    while 1:
                        more = self.mqueue.get(0)
                        if more is None:
                            running=0
                        fnames.extend(more)
                except QueueEmpty:
                    pass

                delNames = []
                for fn in fnames:
                    if os.path.exists(fn):
                        delNames.append(fn)
                    else:
                        LOG.warn("Delete thread didn't find file %s",fn)

                secureDelete(delNames, blocking=1)

            LOG.info("Cleanup thread shutting down.")
        except:
            LOG.error_exc(sys.exc_info(),
                          "Exception while cleaning; shutting down thread.")

class ProcessingThread(threading.Thread):
    """Background thread to handle CPU-intensive functions.

       Currently used to process packets in the background."""
    # Fields:
    #   mqueue: a ClearableQueue of callable objects.
    class _Shutdown:
        """Callable that raises itself when called.  Inserted into the
           queue when it's time to shut down."""
        def __call__(self):
            raise self

    def __init__(self):
        """Create a new processing thread."""
        threading.Thread.__init__(self)
        self.mqueue = ClearableQueue()

    def shutdown(self):
        LOG.info("Telling processing thread to shut down.")
        self.mqueue.clear()
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
    # Don't suppress subsequent signals!
    # signal.signal(signal_num, _sigTermHandler)
    global STOPPING
    STOPPING = 1

GOT_HUP = 0 # Set to one if we get SIGHUP.
def _sigHupHandler(signal_num, _):
    '''(Signal handler for SIGHUP)'''
    signal.signal(signal_num, _sigHupHandler)
    global GOT_HUP
    GOT_HUP = 1

def installSignalHandlers():
    """Install signal handlers for sigterm and sighup."""
    if hasattr(signal, 'SIGHUP'):
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
        self.schedLock = threading.RLock()

    def firstEventTime(self):
        """Return the time at which the earliest-scheduled event is
           supposed to occur.  Returns -1 if no events.
        """
        self.schedLock.acquire()
        try:
            if self.scheduledEvents:
                return self.scheduledEvents[0][0]
            else:
                return -1
        finally:
            self.schedLock.release()

    def scheduleOnce(self, when, name, cb):
        """Schedule a callback function, 'cb', to be invoked at time 'when.'
        """
        assert type(name) is StringType
        assert type(when) in (IntType, LongType, FloatType)
        try:
            self.schedLock.acquire()
            insort(self.scheduledEvents, (when, name, cb))
        finally:
            self.schedLock.release()

    def scheduleRecurring(self, first, interval, name, cb):
        """Schedule a callback function 'cb' to be invoked at time 'first,'
           and every 'interval' seconds thereafter.
        """
        assert type(name) is StringType
        assert type(first) in (IntType, LongType, FloatType)
        assert type(interval) in (IntType, LongType, FloatType)
        def cbWrapper(cb=cb, interval=interval):
            cb()
            return time.time()+interval
        self.scheduleRecurringComplex(first,name,cbWrapper)

    def scheduleRecurringComplex(self, first, name, cb):
        """Schedule a callback function 'cb' to be invoked at time 'first,'
           and thereafter at times returned by 'cb'.

           (Every time the callback is invoked, if it returns a non-None value,
           the event is rescheduled for the time it returns.)
        """
        assert type(name) is StringType
        assert type(first) in (IntType, LongType, FloatType)
        self.scheduleOnce(first, name, _RecurringEvent(name, cb, self))

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
        self.schedLock.acquire()
        try:
            se = self.scheduledEvents
            cbs = []
            while se and se[0][0] <= now:
                cbs.append(se[0][2])
                del se[0]
        finally:
            self.schedLock.release()
        for cb in cbs:
            cb()

class _RecurringEvent:
    """helper for _Scheduler. Calls a callback, then reschedules it."""
    def __init__(self, name, cb, scheduler):
        self.name = name
        self.cb = cb
        self.scheduler = scheduler

    def __call__(self):
        nextTime = self.cb()
        if nextTime is None:
            LOG.warn("Not rescheduling %s", self.name)
            return
        elif nextTime < time.time():
            raise MixFatalError("Tried to schedule event %s in the past! (%s)"
                                %(self.name, formatTime(nextTime,1)))

        self.scheduler.scheduleOnce(nextTime, self.name, self)

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
    # mixPool: Instance of MixPool.  Holds processed packets, and
    #    periodically decides which ones to deliver, according to some
    #    batching algorithm.
    # moduleManager: Instance of ModuleManager.  Map routing types to
    #    outgoing queues, and processes non-MMTP exit messages.
    # outgoingQueue: Holds packets waiting to be send via MMTP.
    # cleaningThread: Thread used to remove packets in the background
    # processingThread: Thread to handle CPU-intensive activity without
    #    slowing down network interactivity.
    # lockFile: An instance of Lockfile to prevent multiple servers from
    #    running in the same directory.  The filename for this lock is
    #    stored in self.pidFile.
    # pidFile: Filename in which we store the pid of the running server.
    def __init__(self, config):
        """Create a new server from a ServerConfig."""
        _Scheduler.__init__(self)
        LOG.debug("Initializing server")

        self.config = config
        homeDir = config.getBaseDir()

        exists = getHomedirVersion(config)

        createPrivateDir(homeDir)
        if exists != SERVER_HOMEDIR_VERSION:
            # If we reach this point, the homedir is uninitialized.
            writeFile(os.path.join(homeDir, "version"),
                      SERVER_HOMEDIR_VERSION, 0644)

        # The pid/lock file.
        self.pidFile = config.getPidFile()
        if not os.path.exists(os.path.split(self.pidFile)[0]):
            # create parent if needed.
            os.makedirs(os.path.split(self.pidFile)[0], 0700)
        self.lockFile = Lockfile(self.pidFile)
        try:
            self.lockFile.acquire(mode=0644,blocking=0)
        except LockfileLocked:
            raise UIError("Another server seems to be running.")

        # Create directories as needed; homeDir already created.
        createPrivateDir(config.getWorkDir())
        createPrivateDir(config.getKeyDir())
        createPrivateDir(config.getQueueDir())

        # Try to read the keyring.  If we have a pre-0.0.4 version of
        # mixminion, we might have some bad server descriptors lying
        # around.  If so, tell the user to run 'mixminiond upgrade.'
        try:
            self.keyring = mixminion.server.ServerKeys.ServerKeyring(config)
        except mixminion.Config.ConfigError, e:
            if str(e).startswith("Unrecognized descriptor version: 0.1"):
                raise UIError("This server homedir contains keys in an old "
                              "format.\nConsider running 'mixminion server"
                              "-upgrade'")
            elif str(e).startswith("Unrecognized descriptor version"):
                print e
                raise UIError("The server homedir contains keys for an "
                              "unrecognized version of the server.")
            else:
                raise UIError((
"For some reason, your generated server descriptors cannot be parsed.  You\n"
"may want to delete all your keysets with mixminiond DELKEYS and have the\n"
"server generate new ones.  [Messages sent to the old keys will be lost].\n"
"The original error message was '%s'.")%e)

        self.keyring.removeDeadKeys()
        self.keyring.createKeysAsNeeded()
        self.keyring.checkDescriptorConsistency()

        if self.config['DirectoryServers'].get('Publish'):
            self.keyring.publishKeys()

        LOG.debug("Initializing packet handler")
        self.packetHandler = mixminion.server.PacketHandler.PacketHandler()
        LOG.debug("Initializing MMTP server")
        self.mmtpServer = _MMTPServer(config, None)
        LOG.debug("Initializing keys")
        self.descriptorFile = os.path.join(homeDir, "current-desc")
        self.keyring.updateKeys(self.packetHandler, self.mmtpServer,
                                self.descriptorFile)
        LOG.debug("Initializing directory client")
        self.dirClient = mixminion.ClientDirectory.ClientDirectory(
            os.path.join(config.getWorkDir(),"dir"))
        try:
            self.dirClient.updateDirectory()
        except mixminion.ClientDirectory.GotInvalidDirectoryError, e:
            LOG.warn(str(e))
            LOG.warn("   (I'll use the old one until I get one that's good.)")
        except UIError, e:#XXXX008 This should really be a new exception
            LOG.warn(str(e))
            LOG.warn("   (I'll use the old one until a download succeeds.)")

        self.dirClient._installAsKeyIDResolver()

        publishedIP, publishedPort, publishedKeyID = self.keyring.getAddress()

        # FFFF Modulemanager should know about async so it can patch in if it
        # FFFF needs to.
        LOG.debug("Initializing delivery module")
        self.moduleManager = config.getModuleManager()
        self.moduleManager.configure(config)

        queueDir = config.getQueueDir()

        incomingDir = os.path.join(queueDir, "incoming")
        LOG.debug("Initializing incoming queue")
        self.incomingQueue = IncomingQueue(incomingDir, self.packetHandler)
        LOG.debug("Found %d pending packets in incoming queue",
                  self.incomingQueue.count())

        mixDir = os.path.join(queueDir, "mix")

        LOG.trace("Initializing Mix pool")
        self.mixPool = MixPool(config, mixDir)
        LOG.debug("Found %d pending packets in Mix pool",
                       self.mixPool.count())

        outgoingDir = os.path.join(queueDir, "outgoing")
        LOG.debug("Initializing outgoing queue")
        self.outgoingQueue = OutgoingQueue(outgoingDir,
                               (publishedIP, publishedPort, publishedKeyID))
        self.outgoingQueue.configure(config)
        LOG.debug("Found %d pending packets in outgoing queue",
                       self.outgoingQueue.count())

        self.cleaningThread = CleaningThread()
        self.processingThread = ProcessingThread()

        self.dnsCache = mixminion.server.DNSFarm.DNSCache()

        LOG.debug("Connecting queues")
        self.incomingQueue.connectQueues(mixPool=self.mixPool,
                                       processingThread=self.processingThread)
        self.mixPool.connectQueues(outgoing=self.outgoingQueue,
                                   manager=self.moduleManager)
        self.outgoingQueue.connectQueues(server=self.mmtpServer,
                                         incoming=self.incomingQueue)
        self.mmtpServer.connectQueues(incoming=self.incomingQueue,
                                      outgoing=self.outgoingQueue)
        self.mmtpServer.connectDNSCache(self.dnsCache)

        self.cleaningThread.start()
        self.processingThread.start()
        self.moduleManager.startThreading()

    def updateKeys(self, lock=1):
        """Change the keys used by the PacketHandler and MMTPServer objects
           to reflect the currently keys."""
        # We don't want to block here -- If key generation is in process, we
        # could block the main thread for as long as it takes to generate
        # several new RSA keys, which would stomp responsiveness on slow
        # computers.  Instead, we reschedule for 2 minutes later
        # ???? Could there be a more elegant approach to this?
        if lock and not self.keyring.lock(0):
            LOG.warn("generateKeys in progress:"
                     " updateKeys delaying for 2 minutes")
            # This will cause getNextKeyRotation to return 2 minutes later
            # than now.
            return time.time() + 120

        try:
            self.keyring.updateKeys(self.packetHandler, self.mmtpServer,
                                    self.descriptorFile)
            return self.keyring.getNextKeyRotation()
        finally:
            if lock: self.keyring.unlock()

    def generateKeys(self):
        """Callback used to schedule key-generation"""

        # We generate and publish keys in the processing thread, so we don't
        # slow down the server.  We also reschedule from the processing thread,
        # so that we can take the new keyset into account when calculating
        # when keys are next needed.

        def c(self=self):
            try:
                self.keyring.lock()
                self.keyring.createKeysAsNeeded()
                self.updateKeys(lock=0)
                if self.config['DirectoryServers'].get('Publish'):
                    self.keyring.publishKeys()
                self.scheduleOnce(self.keyring.getNextKeygen(),
                                  "KEY_GEN",
                                  self.generateKeys)
            finally:
                self.keyring.unlock()

        self.processingThread.addJob(c)

    def updateDirectoryClient(self):
        def c(self=self):
            try:
                self.dirClient.updateDirectory()
                nextUpdate = succeedingMidnight(time.time()+30)
                prng = mixminion.Crypto.getCommonPRNG()
                # Randomly retrieve the directory within an hour after
                # midnight, to avoid hosing the server.
                nextUpdate += prng.getInt(60)*60
            except mixminion.ClientDirectory.GotInvalidDirectoryError, e:
                LOG.warn(str(e))
                LOG.warn("    I'll try again in an hour.")
                nextUpdate = min(succeedingMidnight(time.time()+30),
                                 time.time()+3600)
            except UIError, e:#XXXX008 This should really be a new exception
                LOG.warn(str(e))
                LOG.warn("    I'll try again in an hour.")
                nextUpdate = min(succeedingMidnight(time.time()+30),
                                 time.time()+3600)
            self.scheduleOnce(nextUpdate, "UPDATE_DIR_CLIENT",
                              self.updateDirectoryClient)
        self.processingThread.addJob(c)

    def run(self):
        """Run the server; don't return unless we hit an exception."""
        global GOT_HUP
        # See the win32 comment in replacecontents to learn why this is
        # left-justified. :P
        self.lockFile.replaceContents("%-10s\n"%os.getpid())

        self.cleanQueues()

        now = time.time()
        self.scheduleRecurring(now+600, 600, "SHRED", self.cleanQueues)
        self.scheduleRecurring(now+180, 180, "WAIT",
                               lambda: waitForChildren(blocking=0))
        if EventStats.log.getNextRotation():
            self.scheduleRecurring(now+300, 300, "ES_SAVE",
                                   lambda: EventStats.log.save)
            def _rotateStats():
                EventStats.log.rotate()
                return EventStats.log.getNextRotation()
            self.scheduleRecurringComplex(EventStats.log.getNextRotation(),
                                          "ES_ROTATE",
                                          _rotateStats)

        def _tryTimeout(self=self):
            self.mmtpServer.tryTimeout()
            self.dnsCache.cleanCache()
            return self.mmtpServer.getNextTimeoutTime()

        self.scheduleRecurringComplex(self.mmtpServer.getNextTimeoutTime(now),
                                      "TIMEOUT",
                                      _tryTimeout)

        self.scheduleRecurringComplex(self.keyring.getNextKeyRotation(),
                                      "KEY_ROTATE",
                                      self.updateKeys)

        self.scheduleOnce(self.keyring.getNextKeygen(),
                          "KEY_GEN",
                          self.generateKeys)

        # Makes next update get scheduled.
        self.updateDirectoryClient()

        nextMix = self.mixPool.getNextMixTime(now)
        LOG.debug("First mix at %s", formatTime(nextMix,1))
        self.scheduleRecurringComplex(self.mixPool.getNextMixTime(now),
                                      "MIX", self.doMix)

        LOG.info("Entering main loop: Mixminion %s", mixminion.__version__)

        # This is the last possible moment to shut down the console log, so
        # we have to do it now.
        mixminion.Common.LOG.configure(self.config, keepStderr=_ECHO_OPT)
        if self.config['Server'].get("Daemon",1):
            closeUnusedFDs()

        while 1:
            nextEventTime = self.firstEventTime()
            now = time.time()
            timeLeft = nextEventTime - now
            tickInterval = self.mmtpServer.TICK_INTERVAL
            nextTick = now+tickInterval
            while timeLeft > 0:
                # Handle pending network events
                self.mmtpServer.process(tickInterval)
                # Check for signals
                if STOPPING:
                    LOG.info("Caught SIGTERM; shutting down.")
                    return
                elif GOT_HUP:
                    LOG.info("Caught SIGHUP")
                    self.doReset()
                    GOT_HUP = 0
                # Make sure that our worker threads are still running.
                if not (self.cleaningThread.isAlive() and
                        self.processingThread.isAlive() and
                        self.moduleManager.thread.isAlive()):
                    LOG.fatal("One of our threads has halted; shutting down.")
                    return

                # Calculate remaining time until the next event.
                now = time.time()
                if now > nextTick:
                    self.mmtpServer.tick()
                    nextTick = now+tickInterval
                timeLeft = nextEventTime - now

            # An event has fired.
            self.processEvents()

    def doReset(self):
        """Called when server receives SIGHUP.  Flushes logs to disk,
           regenerates/republishes descriptors as needed.
        """
        LOG.info("Resetting logs")
        LOG.reset()
        EventStats.log.save()
        self.packetHandler.syncLogs()
        LOG.info("Checking for key rotation")
        self.keyring.checkKeys()
        self.generateKeys()
        self.moduleManager.sync()

    def doMix(self):
        """Called when the server's mix is about to fire.  Picks some
           packets to send, and sends them to the appropriate queues.
        """

        now = time.time()
        # Before we mix, we need to log the hashes to avoid replays.
        try:
            # There's a threading issue here... in between this sync and the
            # 'mix' below, nobody should insert into the mix pool.
            self.mixPool.lock()
            self.packetHandler.syncLogs()

            LOG.trace("Mix interval elapsed")
            # Choose a set of outgoing packets; put them in
            # outgoingqueue and modulemanager
            self.mixPool.mix()
        finally:
            self.mixPool.unlock()

        # Send outgoing packets
        self.outgoingQueue.sendReadyMessages()
        # Send exit messages
        self.moduleManager.sendReadyMessages()

        # Choose next mix interval
        nextMix = self.mixPool.getNextMixTime(now)
        LOG.trace("Next mix at %s", formatTime(nextMix,1))
        return nextMix

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
        self.moduleManager.close()

        EventStats.log.save()

        self.lockFile.release()

#----------------------------------------------------------------------
def daemonize():
    """Put the server into daemon mode with the standard trickery."""
    if sys.platform == 'win32':
        raise UIError("Daemon mode is not supported on win32.")

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
    #  Using os.dup2 instead just nukes the old file for us, and keeps the
    #  fd from getting reused.)
    nullfd = os.open("/dev/null", os.O_RDWR|os.O_APPEND)
    os.dup2(nullfd, sys.stdin.fileno())
    os.dup2(nullfd, sys.stdout.fileno())
    os.dup2(nullfd, sys.stderr.fileno())
    os.close(nullfd)
    # Override stdout and stderr in case some code tries to use them
    sys.stdout = sys.__stdout__ = LogStream("STDOUT", "WARN")
    sys.stderr = sys.__stderr__ = LogStream("STDERR", "WARN")

# Global flag: has the user requested a quiet start?
_QUIET_OPT = 0
# Global flag: has the user requested that the console log be kept?
_ECHO_OPT = 0

def configFromServerArgs(cmd, args, usage):
    """Given cmd and args as passed to one of the entry commands,
       parses the standard '-h/--help' and '-f/--config' options.
       If the user wanted a usage message, print the usage message and exit.
       Otherwise, find and parse the configuration file.
    """
    global _QUIET_OPT
    global _ECHO_OPT
    options, args = getopt.getopt(args, "hQf:",
                                  ["help", "quiet", "config=",
                                   "daemon", "nodaemon", "echo", "severity="])
    if args:
        print >>sys.stderr, "No arguments expected."
        if len(args) == 1:
            print >>sys.stderr, "Did you mean to use the '-f' flag?"
        print usage
        sys.exit(1)
    configFile = None
    forceDaemon = None
    severity = None
    for o,v in options:
        if o in ('-h', '--help'):
            print usage
            sys.exit(0)
        elif o in ('-f', '--config'):
            configFile = v
        elif o in ('-Q', '--quiet'):
            _QUIET_OPT = 1
        elif o == '--nodaemon':
            forceDaemon = 0
        elif o == '--daemon':
            forceDaemon = 1
        elif o == '--echo':
            _ECHO_OPT = 1
        elif o == '--severity':
            try:
                severity = mixminion.Config._parseSeverity(v)
            except mixminion.Config.ConfigError, e:
                raise UIError(str(e))

    config = readConfigFile(configFile)
    if forceDaemon == 0 and not _QUIET_OPT:
        # If we've been forced to use the console, go verbose as well, since
        # people probably want that.
        _ECHO_OPT = 1
    elif _QUIET_OPT:
        # Don't even say we're silencing the log.
        mixminion.Common.LOG.silenceNoted = 1
        config['Server']['EchoMessages'] = 0
    if forceDaemon is not None:
        config['Server']['Daemon'] = forceDaemon
    if severity is not None:
        config['Server']['LogLevel'] = severity

    return config


def readConfigFile(configFile):
    """Given a filename from the command line (or None if the user didn't
       specify a configuration file), find the configuration file, parse it,
       and validate it.  Return the validated configuration file.
    """
    if configFile is None:
        configFile = None
        for p in ["~/.mixminiond.conf", "~/etc/mixminiond.conf",
                  "/etc/mixminiond.conf", "/etc/mixminion/mixminiond.conf" ]:
            p = os.path.expanduser(p)
            if os.path.exists(p):
                configFile = p
                break
        if configFile is None:
            print >>sys.stderr, "No config file found or specified."
            sys.exit(1)

    try:
        if not _QUIET_OPT:
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
    return None #never reached; here to suppress pychecker warning

#----------------------------------------------------------------------
_SERVER_START_USAGE = """\
Usage: mixminiond start [options]
Start a Mixminion server.
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than the default.
  -Q, --quiet                Suppress the verbose server startup.
  --daemon                   Run in daemon mode, overriding the config file.
  --nodaemon                 Run in nondaemon mode, overriding the config file.
  --echo                     Write all log messages to stderr.
  --severity=<level>         Override the configured log severity.
""".strip()

def runServer(cmd, args):
    """[Entry point]  Start a Mixminion server."""
    if cmd.endswith(" server"):
        print "Obsolete command. Use 'mixminiond start' instead."

    config = configFromServerArgs(cmd, args, _SERVER_START_USAGE)
    checkHomedirVersion(config)
    daemonMode = config['Server'].get("Daemon",1)
    quiet = (_QUIET_OPT or daemonMode) and not _ECHO_OPT
    try:
        # Configure the log, but delay disabling stderr until the last
        # possible minute; we want to keep echoing to the terminal until
        # the main loop starts.
        mixminion.Common.LOG.configure(config, keepStderr=(not quiet))
        LOG.debug("Configuring server")
    except UIError:
        raise
    except:
        info = sys.exc_info()
        LOG.fatal_exc(info,"Exception while configuring server")
        LOG.fatal("Shutting down because of exception: %s", info[0])
        sys.exit(1)

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
    except UIError:
        raise
    except:
        LOG.fatal_exc(sys.exc_info(), "")
        os._exit(0)

    installSIGCHLDHandler()
    installSignalHandlers()

    try:
        mixminion.Common.configureShredCommand(config)
        mixminion.Common.configureFileParanoia(config)
        mixminion.Crypto.init_crypto(config)

        server = MixminionServer(config)
    except UIError:
        raise
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
_UPGRADE_USAGE = """\
Usage: mixminiond upgrade [options]
Upgrade the server's home directory from an earlier version.
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than
                                /etc/mixminiond.conf
""".strip()

def runUpgrade(cmd, args):
    """[Entry point] Check the version on this server's homedir.  If it's
       old, remove all the old keys and server descriptors, clean out the
       queues, and mark the directory as up-to-date."""

    config = configFromServerArgs(cmd, args, usage=_UPGRADE_USAGE)
    assert config

    mixminion.Common.configureShredCommand(config)
    mixminion.Common.configureFileParanoia(config)
    mixminion.Crypto.init_crypto(config)

    curVersion = getHomedirVersion(config)
    if curVersion is None:
        print "Server homedir doesn't exist."
        return
    elif curVersion == SERVER_HOMEDIR_VERSION:
        print "Server is current; No need to upgrade."
        return
    elif float(curVersion) > float(SERVER_HOMEDIR_VERSION):
        print "Server homedir uses unrecognized version; I can't downgrade."
        return

    assert curVersion == "1000"

    homeDir = config.getBaseDir()
    keyDir = config.getKeyDir()
    hashDir = os.path.join(config.getWorkDir(), 'hashlogs')
    keysets = []
    if not os.path.exists(keyDir):
        print >>sys.stderr, "No server keys to upgrade."
    else:
        for fn in os.listdir(keyDir):
            if fn.startswith("key_"):
                name = fn[4:]
                keysets.append(mixminion.server.ServerKeys.ServerKeyset(
                    keyDir, name, hashDir))

    errors = 0
    keep = 0
    for keyset in keysets:
        try:
            _ = keyset.getServerDescriptor()
            keep += 1
        except mixminion.Config.ConfigError, e:
            errors += 1
            if str(e).startswith("Unrecognized descriptor version: 0.1"):
                print "Removing old keyset %s"%keyset.keyname
                keyset.delete()
            else:
                print "Unrecognized error from keyset %s: %s" % (
                    keyset.keyname, str(e))

    # Now we need to clean out all the old queues -- the messages in them
    # are incompatible.
    queueDirs = [ os.path.join(config.getQueueDir(), 'incoming'),
                  os.path.join(config.getQueueDir(), 'mix'),
                  os.path.join(config.getQueueDir(), 'outgoing') ]
    deliver = os.path.join(config.getQueueDir(), 'deliver')
    if os.path.exists(deliver):
        for fn in os.listdir(deliver):
            if os.path.isdir(os.path.join(deliver,fn)):
                queueDirs.append(os.path.join(deliver,fn))

    print "Dropping obsolete messages from queues (no upgrade; sorry!)"

    for qd in queueDirs:
        if not os.path.exists(qd): continue
        files = os.listdir(qd)
        print "   (Deleting %s files from %s.)" %(len(files),qd)
        secureDelete([os.path.join(qd,f) for f in files])

    print "Homedir is upgraded"

    writeFile(os.path.join(homeDir, 'version'),
              SERVER_HOMEDIR_VERSION, 0644)


#----------------------------------------------------------------------
_DELKEYS_USAGE = """\
Usage: mixminiond DELKEYS [options]
Delete all keys for this server (except the identity key).
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than
                                /etc/mixminiond.conf
""".strip()

def runDELKEYS(cmd, args):
    """[Entry point.] Remove all keys and server descriptors for this
       server."""
    config = configFromServerArgs(cmd, args, usage=_DELKEYS_USAGE)
    assert config

    mixminion.Common.configureShredCommand(config)
    mixminion.Common.configureFileParanoia(config)
    mixminion.Crypto.init_crypto(config)

    checkHomedirVersion(config)

    keyDir = config.getKeyDir()
    hashDir = os.path.join(config.getWorkDir(), 'hashlogs')
    if not os.path.exists(keyDir):
        print >>sys.stderr, "No server keys to delete"
    else:
        deleted = 0
        for fn in os.listdir(keyDir):
            if fn.startswith("key_"):
                name = fn[4:]
                ks = mixminion.server.ServerKeys.ServerKeyset(
                    keyDir, name, hashDir)
                ks.delete()
                deleted += 1
        print "%s keys deleted"%deleted

#----------------------------------------------------------------------
_PRINT_STATS_USAGE = """\
Usage: mixminiond stats [options]
Print server statistics for the current statistics interval.
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than the default.
""".strip()

def printServerStats(cmd, args):
    """[Entry point]  Print server statistics for the current statistics
       interval."""
    config = configFromServerArgs(cmd, args, _PRINT_STATS_USAGE)
    checkHomedirVersion(config)
    _signalServer(config, 1)
    EventStats.configureLog(config)
    EventStats.log.dump(sys.stdout)

#----------------------------------------------------------------------
_SIGNAL_SERVER_USAGE = """\
Usage: mixminiond %s [options]
Tell a mixminion server to %s.
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than the default.
""".strip()

def signalServer(cmd, args):
    """[Entry point] Send a SIGHUP or a SIGTERM to a running mixminion
       server."""
    if cmd.endswith("stop"):
        sig_reload = 0
        usage = _SIGNAL_SERVER_USAGE % ("stop", "shut down")
    else:
        assert cmd.endswith("reload")
        sig_reload = 1
        usage = _SIGNAL_SERVER_USAGE % ("reload",
                                        "rescan its configuration")

    config = configFromServerArgs(cmd, args, usage=usage)
    LOG.setMinSeverity("ERROR")

    checkHomedirVersion(config)

    _signalServer(config, sig_reload)

def _signalServer(config, reload):
    """Given a configuration file, sends a signal to the corresponding
       server if it's running.  If 'reload', the signal is HUP.  Else,
       the signal is TERM.
    """
    pidFile = config.getPidFile()
    if not os.path.exists(pidFile):
        raise UIError("No server seems to be running.")

    try:
        pid = int(readFile(pidFile))
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
_REPUBLISH_USAGE = """\
Usage: mixminiond republish [options]
Force a mixminion server to republish its keys to the directory.
Options:
  -h, --help:                Print this usage message and exit.
  -f <file>, --config=<file> Use a configuration file other than
                                /etc/mixminiond.conf
""".strip()

def runRepublish(cmd, args):
    """[Entry point] Mark all keys as unpublished, and send a SIGHUP to
       the server."""
    config = configFromServerArgs(cmd, args, usage=_REPUBLISH_USAGE)

    checkHomedirVersion(config)

    LOG.setMinSeverity("INFO")
    mixminion.Crypto.init_crypto(config)

    keydir = config.getKeyDir()
    items = os.listdir(keydir)
    items.sort()
    for fn in items:
        if not fn.startswith("key_"):
            continue
        num = fn[4:]
        publishedFile = os.path.join(keydir, fn, "published")
        try:
            LOG.info("Marking key %s unpublished", num)
            if os.path.exists(publishedFile):
                os.unlink(publishedFile)
        except OSError, e:
            LOG.warn("Couldn't mark key %s unpublished: %s",num,e)

    LOG.info("Telling server to publish descriptors")

    _signalServer(config, reload=1)
