# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Modules.py,v 1.56 2003/09/28 04:12:29 nickm Exp $

"""mixminion.server.Modules

   Code to support pluggable exit module functionality; implementation
   for built-in modules.
   """
# FFFF We may, someday, want to support non-exit modules here.
# FFFF Maybe we should refactor MMTP delivery here too.

__all__ = [ 'ModuleManager', 'DeliveryModule',
            'DELIVER_OK', 'DELIVER_FAIL_RETRY', 'DELIVER_FAIL_NORETRY'
            ]

import os
import re
import sys
import smtplib
import socket
import threading
import time

if sys.version_info[:2] >= (2,3):
    import textwrap
else:
    import mixminion._textwrap as textwrap

import mixminion.BuildMessage
import mixminion.Config
import mixminion.Filestore
import mixminion.Fragments
import mixminion.Packet
import mixminion.server.ServerQueue
import mixminion.server.ServerConfig
import mixminion.server.EventStats as EventStats
import mixminion.server.PacketHandler
from mixminion.Config import ConfigError, _parseBoolean, _parseCommand, \
     _parseInterval, _parseIntervalList, _parseSize
from mixminion.Common import LOG, MixError, ceilDiv, createPrivateDir, \
     encodeBase64, isPrintingAscii, isSMTPMailbox, previousMidnight, \
     readFile, waitForChildren
from mixminion.Packet import ParseError, CompressedDataTooLong, uncompressData

# Return values for processMessage
DELIVER_OK = 1
DELIVER_FAIL_RETRY = 2
DELIVER_FAIL_NORETRY = 3

class DeliveryModule:
    """Abstract base for modules; delivery modules should implement
       the methods in this class.

       A delivery module has the following responsibilities:
           * It must have a 0-argument constructor.
           * If it is configurable, it must be able to specify its options,
             validate its configuration, and configure itself.
           * If it is advertisable, it must provide a server info block.
           * It must know its own name.
           * It must know which types it handles.
           * Of course, it needs to know how to deliver a message."""
    # FFFF DeliveryModules need to know about the AsyncServer object in
    # FFFF case they support asynchronous delivery.
    def __init__(self):
        "Zero-argument constructor, as required by Module protocol."
        pass

    def getRetrySchedule(self):
        """Return a retry schedule for this module's queue, as specified
           in ServerQueue.DeliveryQueue.setRetrySchedule."""
        return None

    def getConfigSyntax(self):
        """Return a map from section names to section syntax, as described
           in Config.py"""
        raise NotImplementedError("getConfigSyntax")

    def validateConfig(self, config, lines, contents):
        """See mixminion.Config.validate"""
        pass

    def configure(self, config, manager):
        """Configure this object using a given Config object, and (if
           required) register it with the module manager."""
        raise NotImplementedError("configure")

    def getServerInfoBlock(self):
        """Return a block for inclusion in a server descriptor."""
        raise NotImplementedError("getServerInfoBlock")

    def getName(self):
        """Return the name of this module.  This name may be used to construct
           directory paths, so it shouldn't contain any funny characters."""
        raise NotImplementedError("getName")

    def getExitTypes(self):
        """Return a sequence of numeric exit types that this module can
           handle."""
        raise NotImplementedError("getExitTypes")

    def createDeliveryQueue(self, queueDir):
        """Return a DeliveryQueue object suitable for delivering messages
           via this module.  The default implementation returns a
           SimpleModuleDeliveryQueue,  which (though adequate) doesn't
           batch messages intended for the same destination.

           For the 'address' component of the delivery queue, modules must
           accept a tuple of: (exitType, address, tag).  If 'tag' is None,
           the message has been decrypted; if 'tag' is 'err', the message is
           corrupt; if 'tag' is 'long', the message has been decrypted, and
           looks like a possible Zlib bomb.

           Otherwise, the message is either a reply or an encrypted
           forward message.
           """
        return SimpleModuleDeliveryQueue(self, queueDir,
                                   retrySchedule=self.getRetrySchedule())

    def processMessage(self, packet):
        """Given a DeliveryPacket object, try to deliver it.  Return one of:
            DELIVER_OK (if the message was successfully delivered),
            DELIVER_FAIL_RETRY (if the message wasn't delivered, but might be
              deliverable later), or
            DELIVER_FAIL_NORETRY (if the message shouldn't be tried later).

           (This method is only used by your delivery queue; if you use
            a nonstandard delivery queue, you don't need to implement this.)"""
        raise NotImplementedError("processMessage")

    def sync(self):
        """Flush all pending data held by this module to disk."""

    def close(self):
        """Release all resources held by this module."""
        pass

class ImmediateDeliveryQueue:
    """Helper class usable as delivery queue for modules that don't
       actually want a queue.  Such modules should have very speedy
       processMessage() methods, and should never have delivery fail."""
    ##Fields:
    #  module: the underlying DeliveryModule object.
    def __init__(self, module):
        self.module = module

    def queueDeliveryMessage(self, packet, retry=0, lastAttempt=0):
        """Instead of queueing our message, pass it directly to the underlying
           DeliveryModule."""
        try:
            EventStats.log.attemptedDelivery() #FFFF
            res = self.module.processMessage(packet)
            if res == DELIVER_OK:
                EventStats.log.successfulDelivery() #FFFF
            elif res == DELIVER_FAIL_RETRY:
                LOG.error("Unable to retry delivery for message")
                EventStats.log.unretriableDelivery() #FFFF
            else:
                LOG.error("Unable to deliver message")
                EventStats.log.unretriableDelivery() #FFFF
        except:
            LOG.error_exc(sys.exc_info(),
                               "Exception delivering message")
            EventStats.log.unretriableDelivery() #FFFF

        return "<nil>"

    def sendReadyMessages(self):
        # We do nothing here; we already delivered the messages
        pass

    def cleanQueue(self, deleteFn=None):
        # There is no underlying queue to worry about here; do nothing.
        pass

    def getPriority(self):
        """Return the order at which this queue should be flushed.  Queues
           are flushed from lowest-valued priority to highest.  Most modules
           should use priority 0.  Modules which insert messages into other
           modules should use priority <0."""
        return 0

class SimpleModuleDeliveryQueue(mixminion.server.ServerQueue.DeliveryQueue):
    """Helper class used as a default delivery queue for modules that
       don't care about batching messages to like addresses."""
    ## Fields:
    # module: the underlying module.
    def __init__(self, module, directory, retrySchedule=None):
        mixminion.server.ServerQueue.DeliveryQueue.__init__(self, directory,
                                                            retrySchedule)
        self.module = module

    def getPriority(self):
        return 0

    def _deliverMessages(self, msgList):
        for handle in msgList:
            try:
                dh = handle.getHandle() # display handle
                EventStats.log.attemptedDelivery() #FFFF
                try:
                    packet = handle.getMessage()
                except mixminion.Filestore.CorruptedFile:
                    continue
                result = self.module.processMessage(packet)
                if result == DELIVER_OK:
                    LOG.debug("Successfully delivered message MOD:%s", dh)
                    handle.succeeded()
                    EventStats.log.successfulDelivery() #FFFF
                elif result == DELIVER_FAIL_RETRY:
                    LOG.debug("Unable to deliver message MOD:%s; will retry",
                              dh)
                    handle.failed(1)
                    EventStats.log.failedDelivery() #FFFF
                else:
                    assert result == DELIVER_FAIL_NORETRY
                    LOG.error("Unable to deliver message MOD:%s; giving up",
                              dh)
                    handle.failed(0)
                    EventStats.log.unretriableDelivery() #FFFF
            except:
                LOG.error_exc(sys.exc_info(),
                                   "Exception delivering message")
                handle.failed(0)
                EventStats.log.unretriableDelivery() #FFFF

class DeliveryThread(threading.Thread):
    """A thread object used by ModuleManager to send messages in the
       background; delegates to ModuleManager._sendReadyMessages."""
    ## Fields:
    # moduleManager -- a ModuleManager object.
    # event -- an Event that is set when we have messages to deliver, or
    #    when we're stopping.
    # __stoppingEvent -- an event that is set when we're shutting down.
    def __init__(self, moduleManager):
        """Create a new DeliveryThread."""
        threading.Thread.__init__(self)
        self.moduleManager = moduleManager
        self.event = threading.Event()
        self.__stoppingevent = threading.Event()

    def beginSending(self):
        """Tell this thread that there are messages ready to be sent."""
        self.event.set()

    def shutdown(self):
        """Tell this thread to shut down after sending further messages."""
        LOG.info("Telling delivery thread to shut down.")
        self.__stoppingevent.set()
        self.event.set()

    def run(self):
        try:
            while 1:
                self.event.wait()
                self.event.clear()
                stop = self.__stoppingevent.isSet()
                if stop:
                    LOG.info("Delivery thread shutting down.")
                    self.moduleManager.close()
                    return
                self.moduleManager._sendReadyMessages()
                waitForChildren(blocking=0)
        except:
            LOG.error_exc(sys.exc_info(),
                          "Exception in delivery; shutting down thread.")

class ModuleManager:
    """A ModuleManager knows about all of the server modules in the system.

       A module may be in one of three states: unloaded, registered, or
       enabled.  An unloaded module is just a class in a python module.
       A registered module has been loaded, configured, and listed with
       the ModuleManager, but will not receive messages until it is
       enabled.

       Because modules need to tell the ServerConfig object about their
       configuration options, initializing the ModuleManager is usually done
       through ServerConfig.  See ServerConfig.getModuleManager().

       To send messages, call 'queueMessage' for each message to send, then
       call 'sendReadyMessages'.
       """
    ##
    # Fields
    #    syntax: extensions to the syntax configuration in Config.py
    #    modules: a list of DeliveryModule objects
    #    enabled: a set of enabled DeliveryModule names.
    #    nameToModule: Map from module name to module
    #    typeToModule: a map from delivery type to enabled deliverymodule.
    #    path: search path for python modules.
    #    queueRoot: directory where all the queues go.
    #    queues: a map from module name to queue (Queue objects must support
    #            queueMessage and sendReadyMessages as in DeliveryQueue.)
    #    _isConfigured: flag: has this modulemanager's configure method been
    #            called?
    #    thread: None, or a DeliveryThread object.

    def __init__(self):
        "Create a new ModuleManager"
        self.syntax = {}
        self.modules = []
        self.enabled = {}

        self.nameToModule = {}
        self.typeToModule = {}
        self.path = []
        self.queueRoot = None
        self.queues = {}

        self.registerModule(MBoxModule())
        self.registerModule(DropModule())
        self.registerModule(DirectSMTPModule())
        self.registerModule(MixmasterSMTPModule())
        self.registerModule(FragmentModule())

        self._isConfigured = 0
        self.thread = None

    def startThreading(self):
        """Begin delivering messages in a separate thread.  Should only
           be called once."""
        self.thread = DeliveryThread(self)
        self.thread.start()

    def isConfigured(self):
        """Return true iff this object's configure method has been called"""
        return self._isConfigured

    def _setQueueRoot(self, queueRoot):
        """Sets a directory under which all modules' queue directories
           should go."""
        self.queueRoot = queueRoot

    def getConfigSyntax(self):
        """Returns a dict to extend the syntax configuration in a Config
           object. Should be called after all modules are registered."""
        return self.syntax

    def registerModule(self, module):
        """Inform this ModuleManager about a delivery module.  This method
           updates the syntax options, but does not enable the module."""
        LOG.info("Loading module %s", module.getName())
        self.modules.append(module)
        syn = module.getConfigSyntax()
        for sec, rules in syn.items():
            if self.syntax.has_key(sec):
                raise ConfigError("Multiple modules want to define [%s]"% sec)
        self.syntax.update(syn)
        self.nameToModule[module.getName()] = module

    def setPath(self, path):
        """Sets the search path for Python modules"""
        if path:
            self.path = [ os.path.expanduser(fn) for fn in path.split(":") ]
        else:
            self.path = []

    def loadExtModule(self, className):
        """Load and register a module from a python file.  Takes a classname
           of the format module.Class or package.module.Class.  Raises
           MixError if the module can't be loaded."""
        ids = className.split(".")
        pyPkg = ".".join(ids[:-1])
        pyClassName = ids[-1]
        orig_path = sys.path[:]
        LOG.info("Loading module %s", className)
        try:
            sys.path[0:0] = self.path
            try:
                m = __import__(pyPkg, {}, {}, [pyClassName])
            except ImportError, e:
                raise MixError("%s while importing %s" %(str(e),className))
        finally:
            sys.path = orig_path
        try:
            pyClass = getattr(m, pyClassName)
        except AttributeError, e:
            raise MixError("No class %s in module %s" %(pyClassName,pyPkg))
        try:
            self.registerModule(pyClass())
        except Exception, e:
            raise MixError("Error initializing module %s" %className)

    def validate(self, config, lines, contents):
        # (As in ServerConfig)
        for m in self.modules:
            m.validateConfig(config, lines, contents)

    def configure(self, config):
        self._setQueueRoot(os.path.join(config['Server']['Homedir'],
                                        'work', 'queues', 'deliver'))
        createPrivateDir(self.queueRoot)
        for m in self.modules:
            m.configure(config, self)
        self._isConfigured = 1

    def enableModule(self, module):
        """Sets up the module manager to deliver all messages whose exitTypes
            are returned by <module>.getExitTypes() to the module."""
        for t in module.getExitTypes():
            if (self.typeToModule.has_key(t) and
                self.typeToModule[t].getName() != module.getName()):
                raise ConfigError("Multiple modules enabled for type %x: %s vs %s:"%(t, self.typeToModule[t].getName(), module.getName()))
            self.typeToModule[t] = module

        LOG.info("Module %s: enabled for types %s",
                      module.getName(),
                      map(hex, module.getExitTypes()))

        queueDir = os.path.join(self.queueRoot, module.getName())
        queue = module.createDeliveryQueue(queueDir)
        self.queues[module.getName()] = queue
        self.enabled[module.getName()] = 1

    def cleanQueues(self, deleteFn=None):
        """Remove trash messages from all internal queues."""
        for queue in self.queues.values():
            queue.cleanQueue(deleteFn)

    def disableModule(self, module):
        """Unmaps all the types for a module object."""
        LOG.debug("Disabling module %s", module.getName())
        for t in module.getExitTypes():
            if (self.typeToModule.has_key(t) and
                self.typeToModule[t].getName() == module.getName()):
                del self.typeToModule[t]
        if self.queues.has_key(module.getName()):
            del self.queues[module.getName()]
        if self.enabled.has_key(module.getName()):
            del self.enabled[module.getName()]

    def queueDecodedMessage(self, packet):
        """Given a packet of type DeliveryPacket, try to find an appropriate
           exit module, and queue the packet for delivery by that exit module.
        """
        exitType = packet.getExitType()

        mod = self.typeToModule.get(exitType)
        if mod is None:
            LOG.error("Unable to handle message with unknown type %s",
                      exitType)
            return "<nil>"
        queue = self.queues[mod.getName()]
        LOG.debug("Delivering message %r (type %04x) via module %s",
                  packet.getContents()[:8], exitType, mod.getName())

        return queue.queueDeliveryMessage(packet)

    def shutdown(self):
        """Tell the delivery thread (if any) to stop."""
        if self.thread is not None:
            self.thread.shutdown()

    def join(self):
        """Wait for the delivery thread (if any) to finish shutting down."""
        if self.thread is not None:
            self.thread.join()

    def sendReadyMessages(self):
        """Begin message delivery, either by telling every module's queue to
           try sending its pending messages, or by telling the delivery
           thread to do so if we're threading."""
        if self.thread is not None:
            self.thread.beginSending()
        else:
            self._sendReadyMessages()

    def _sendReadyMessages(self):
        """Actual implementation of message delivery. Tells every module's
           queue to send pending messages.  This is called directly if
           we aren't threading, and from the delivery thread if we are."""
        queuelist = [ (queue.getPriority(), queue)
                      for queue in self.queues.values() ]
        queuelist.sort()
        for _, queue in queuelist:
            queue.sendReadyMessages()

    def getServerInfoBlocks(self):
        """Return a list of strings that should be appended to the server
           descriptor of this server, based on the configuration of its
           modules.
        """
        return [ m.getServerInfoBlock() for m in self.modules
                       if self.enabled.get(m.getName(),0) ]

    def close(self):
        """Release all resources held by all modules."""
        for module in self.enabled.keys():
            self.nameToModule[module].close()

    def sync(self):
        """Flush all state held by all modules to disk."""
        for module in self.enabled.keys():
            self.nameToModule[module].close()


#----------------------------------------------------------------------
class DropModule(DeliveryModule):
    """Null-object pattern: drops all messages it receives."""
    def getConfigSyntax(self):
        return { }
    def getRetrySchedule(self):
        return [ ]
    def getServerInfoBlock(self):
        return ""
    def configure(self, config, manager):
        manager.enableModule(self)
    def getName(self):
        return "DROP"
    def getExitTypes(self):
        return [ mixminion.Packet.DROP_TYPE ]
    def createDeliveryQueue(self, directory):
        return ImmediateDeliveryQueue(self)
    def processMessage(self, packet):
        LOG.debug("Dropping padding message")
        return DELIVER_OK

#----------------------------------------------------------------------
class FragmentModule(DeliveryModule):
    """Module used to handle server-side reassembly of fragmented payloads.

       When a message is fragmented for reassembly by the exit node, it
       is sent in packets of exit type FRAGMENT.  The actual exit type and
       delivery address are encoded at the start of the reassembled message.
       """
    ## 
    # _queue: An instance of FragmentDeliveryQueue, or None
    # manager: A pointer back to the module manager.  Used to insert
    #   reassembled messages into other modules' queues.
    # maxMessageSize: The largest allowable message size.  (In bytes,
    #   after defragmentation, before uncompression.)
    # maxInterval: The longest we hold onto a fragment of a message before
    #   we give up on receiving the whole message.  (In seconds.)
    # maxFragments: The largest allowable message size, in fragments.
    def __init__(self):
        DeliveryModule.__init__(self)
        self._queue = None
        self.manager = None
        self.maxMessageSize = None
        self.maxInterval = None
        self.maxFragments = None
    def getConfigSyntax(self):
        return { "Delivery/Fragmented" :
                 { 'Enabled' : ('REQUIRE',  _parseBoolean, "no"),
                   'MaximumSize' : ('REQUIRE', _parseSize, None),
                   'MaximumInterval' : ('ALLOW', _parseInterval, "2 days" )
                   } }
    def getRetrySchedule(self):
        return [ ]
    def configure(self, config, manager):
        sec = config['Delivery/Fragmented']
        if not sec.get("Enabled"):
            manager.disableModule(self)
            self.close()
            return
        self.maxMessageSize = sec['MaximumSize']
        self.maxInterval = sec['MaximumInterval'].getSeconds()
        # How many packets could it take to encode a max-size message?
        fp = mixminion.Fragments.FragmentationParams(self.maxMessageSize, 0)
        self.maxFragments = fp.nChunks * fp.n
        self.manager = manager
        manager.enableModule(self)
    def getServerInfoBlock(self):
        return """[Delivery/Fragmented]
                  Version: 0.1
                  Maximum-Fragments: %s
               """ % self.maxFragments
    def getName(self):
        return "FRAGMENT"
    def getExitTypes(self):
        return [ mixminion.Packet.FRAGMENT_TYPE ]
    def createDeliveryQueue(self, queueDir):
        self.close()
        self._queue = FragmentDeliveryQueue(self, queueDir, self.manager)
        return self._queue
    def sync(self):
        self._queue.pool.sync()
    def close(self):
        if self._queue:
            self._queue.pool.close()
            self._queue = None
    
class FragmentDeliveryQueue:
    """Delivery queue for FragmentModule.

       Wraps mixminion.fragments.FragmentPool."""
    ##Fields:
    # module: the FragmentModule.
    # directory: location used for the FragmentPool
    # pool: instance of FragmentPool
    def __init__(self, module, directory, manager):
        self.module = module
        self.directory = directory
        self.manager = manager
        self.pool = mixminion.Fragments.FragmentPool(self.directory)

    def getPriority(self):
        # We want to make sure that fragmented messages get reassembled
        # before any other modules deliver their messages.  This way,
        # reassembled messages get delivered as soon as they're ready.
        return -1

    def queueDeliveryMessage(self, packet, retry=0, lastAttempt=0):
        if packet.isError():
            LOG.warn("Dropping FRAGMENT packet with decoding error: %s",
                     packet.error)
            return
        elif not packet.isFragment():
            LOG.warn("Dropping FRAGMENT packet with non-fragment payload.")
            return
        elif packet.getAddress():
            LOG.warn("Dropping FRAGMENT packet with spurious addressing info.")
            return
        # Should be instance of FragmentPayload.
        payload = packet.getDecodedPayload()
        assert payload is not None
        self.pool.addFragment(payload)

    def cleanQueue(self, deleteFn=None):
        self.pool.cleanQueue(deleteFn)

    def sendReadyMessages(self):
        self.pool.unchunkMessages()
        ready = self.pool.listReadyMessages()
        for msgid in ready:
            msg = self.pool.getReadyMessage(msgid)
            try:
                ssfm = mixminion.Packet.parseServerSideFragmentedMessage(msg)
                del msg
            except ParseError:
                LOG.warn("Dropping malformed server-side fragmented message")
                self.pool.markMessageCompleted(msgid, rejected=1)
                continue
            if len(ssfm.compressedContents) > self.module.maxMessageSize:
                LOG.warn("Dropping over-long fragmented message")
                self.pool.markMessageCompleted(msgid, rejected=1)
                continue

            fm = _FragmentedDeliveryMessage(ssfm)
            self.manager.queueDecodedMessage(fm)
            self.pool.markMessageCompleted(msgid)

        cutoff = previousMidnight(time.time()) - self.module.maxInterval
        self.pool.expireMessages(cutoff)

class _FragmentedDeliveryMessage:
    """Helper class: obeys the interface of mixminion.server.PacketHandler.
       DeliveryMessage, but contains a long message reassembled from
       fragments."""
    ##Fields:
    # m: an instance of ServerSideFragmentedMessage.
    # exitType, address: the routing type and routing info for this message
    # contents: None, or the uncompressed contents off the message if it's
    #    been decoded.
    # headers: None, or a dict of the message's headers.
    # tp: 'plain' or 'err' or 'long'.
    def __init__(self, ssfm):
        """Create a _FragmentedDeliveryMessage object from an instance of
           mixminion.Packet.ServerSideFragmentedMessage."""
        self.m = ssfm
        self.exitType = self.m.routingtype
        self.address = self.m.routinginfo
        self.contents = None
        self.tp = None
        self.headers = None

    def isDelivery(self): return 1
    def getExitType(self): return self.exitType
    def getAddress(self): return self.address
    def getContents(self):
        if self.contents is None: self.decode()
        return self.contents
    def isPlaintext(self): 
        if self.contents is None: self.decode()
        return self.tp == 'plain'
    def isFragment(self): return 0
    def isEncrypted(self): return 0
    def isError(self): 
        if self.contents is None: self.decode()
        return self.tp == 'err'
    def isOvercompressed(self):
        if self.contents is None: self.decode()
        return self.tp == 'long'
    def isPrintingAscii(self):
        if self.contents is None: self.decode()
        return isPrintingAscii(self.contents, allowISO=1)
    def getAsciiContents(self):
        if self.contents is None: self.decode()
        if isPrintingAscii(self.contents, allowISO=1):
            return self.contents
        else:
            return encodeBase64(self.contents)
    def getHeaders(self):
        if self.contents is None:
            self.decode()
        assert self.headers is not None
        return self.headers
    def getTextEncodedMessage(self):
        if self.isOvercompressed():
            tp = 'LONG'
        elif self.isPrintingAscii():
            tp = 'TXT'
        else:
            tp = 'BIN'
        return mixminion.Packet.TextEncodedMessage(self.contents, tp, None)
    def decode(self):
        maxLen = 20*len(self.m.compressedContents)
        try:
            c = uncompressData(self.m.compressedContents, maxLen)
            self.contents, self.headers = \
                           mixminion.Packet.parseMessageAndHeaders(c)
            self.tp = 'plain'
        except CompressedDataTooLong:
            self.contents = self.m.compressedContents
            self.tp = 'long'
            self.headers = {}
            return
        except MixError, e:
            self.contents = str(e)
            self.headers = {}
            self.tp = 'err'
        del self.m
        
#----------------------------------------------------------------------
class EmailAddressSet:
    """A set of email addresses stored on disk, for use in blacklisting email
       addresses.  The file format is line-based.  Lines starting with #
       and empty lines are ignored.  Whitespace is ignored.  All other
       lines take the format 'deny type value', type is one of the
       following...
             address: match an email address, exactly. "Deny address fred@fred"
               matches "fred@fred" and 'FRED@FRED'.
             user: match the part of an email address before the @, exactly.
               "Deny user fred" matches "fred@fred" and "fred@alice", but not
               "bob@fred" or "mr-fred@alice".
             onehost: match the part of an email address after the @, exactly.
               "Deny onehost fred" matches "bob@fred" but not "bob@fred.com" or
               "bob@host.fred".
             allhosts: match the part of an email address after the @,
               or any parent domain thereof.  "Deny allhosts fred.com" matches
               "bob@fred.com" and "bob@host.fred.com", but not "bob@com".
             pattern: match the email address if the provided regex appears
               anywhere in it.  "Deny pattern /./" matches everything;
               "Deny pattern /(..)*/" matches all addresses with an even number
               of characters.
    """
    ## Fields
    # addresses -- A dict whose keys are lowercased email addresses ("foo@bar")
    # domains -- A dict whose keys are lowercased domains ("foo.bar.baz").
    #   If the value for a key is 'SUB', all subdomains are also included.
    # users -- A dict whose keys are lowercased users ("foo")
    # patterns -- A list of regular expression objects.
    # includeStr -- a string the causes items to get included in this set.
    #   defaults to 'deny'
    def __init__(self, fname=None, string=None, includeStr="deny"):
        """Read the address set from a file or a string."""
        if string is None:
            string = readFile(fname)

        self.addresses = {}
        self.domains = {}
        self.users = {}
        self.patterns = []
        self.includeStr = includeStr

        lines = string.split("\n")
        lineno = 0
        for line in lines:
            lineno += 1
            line = line.strip()
            if not line or line[0] == '#':
                # Blank line or comment; skip.
                continue
            line = line.split(" ", 2)
            if len(line) != 3:
                raise ConfigError("Invalid line at %s: %s"%(lineno, line))
            deny = line[0].lower()
            if deny != self.includeStr:
                raise ConfigError("Line on %s doesn't start with 'Deny'"%lineno)
            cmd = line[1].lower()
            arg = line[2].strip()
            if cmd == 'address':
                if not isSMTPMailbox(arg):
                    raise ConfigError("Address %s on %s doesn't look valid"%(
                        arg, lineno))
                self.addresses[arg.lower()] = 1
            elif cmd == 'user':
                if not isSMTPMailbox(arg+"@x"):
                    raise ConfigError("User %s on %s doesn't look valid"%(
                        arg, lineno))
                self.users[arg.lower()] = 1
            elif cmd == 'onehost':
                if not isSMTPMailbox("x@"+arg):
                    raise ConfigError("Domain %s on %s doesn't look valid"%(
                        arg, lineno))
                if not self.domains.has_key(arg.lower()):
                    self.domains[arg.lower()] = 1
            elif cmd == 'allhosts':
                if not isSMTPMailbox("x@"+arg):
                    raise ConfigError("Domain %s on %s doesn't look valid"%(
                        arg, lineno))
                self.domains[arg.lower()] = 'SUB'
            elif cmd == 'pattern':
                if arg[0] != '/' or arg[-1] != '/':
                    raise ConfigError("Pattern %s on %s is missing /s."%(
                                      arg, lineno))
                arg = arg[1:-1]
                # FFFF As an optimization, we may be able to coalesce some
                # FFFF of these patterns.  I doubt this will become part of
                # FFFF the critical path any time soon, though.
                self.patterns.append(re.compile(arg, re.I))
            else:
                if 'host' in cmd:
                    dym = '. Did you mean "OneHost" or "AllHosts"?'
                else:
                    dym = ''
                raise ConfigError("Unrecognized command '%s %s' on line %s%s"%(
                    deny, cmd, lineno, dym))

    def contains(self, address):
        """Return true iff this this address set contains the address
           'address'.

           *REQUIRES* that 'address' is a valid restricted RFC822
           address as checked by isSMTPMailbox.  If not, behavior is
           undefined.
        """
        # Is the address blocked?
        lcaddress = address.lower()
        if self.addresses.has_key(lcaddress):
            return 1

        # What about its user or domain parts?
        user, dom = lcaddress.split("@", 1)
        if self.users.has_key(user) or self.domains.has_key(dom):
            return 1

        # Is it the subdomain of a blocked domain?
        domparts = dom.split(".")
        for idx in range(len(domparts)):
            subdom = ".".join(domparts[idx:])
            if self.domains.get(subdom) == 'SUB':
                return 1

        # Does it match any patterns?
        for pat in self.patterns:
            if pat.search(address):
                return 1

        # Then it must be okay.
        return 0

#----------------------------------------------------------------------
class MailBase:
    """Implementation class: contains code shared by modules that send email
       messages (such as mbox and smtp)."""
    ## Fields: (to be set by subclass)
    # subject: Default subject to use for outgoing mail, if none is given
    #    in the message.
    # fromTag: String to prepend to from name.
    # returnAddress: Return address for mail; should be an rfc822-style 
    #    mailbox.
    # header: Text that should be appended after the headers and before
    #    the message itself.  It must include the empty line that separates
    #    headers from body.
    # maxMessageSize: Largest allowable size (after decompression, before
    #   base64) for outgoing messages.
    # allowFromAddr: Boolean: do we support user-supplied from addresses?
    def _formatEmailMessage(self, address, packet):
        """Given a RFC822 mailbox (delivery address), and an instance of
           DeliveryMessage, return a string containing a message to be sent
           to a recipient, adding headers as needed.
        """

        if len(packet.getContents()) > self.maxMessageSize:
            LOG.warn("Dropping over-long message (message is %sb; max is %sb)",
                     len(packet.getContents()), self.maxMessageSize)
            return None

        headers = packet.getHeaders()
        subject = headers.get("SUBJECT", self.subject)
        fromAddr = headers.get("FROM")
        if fromAddr and self.allowFromAddr:
            fromAddr = '"%s %s" <%s>' % (self.fromTag, fromAddr,
                                         self.returnAddress)
        else:
            fromAddr = self.returnAddress

        morelines = []
        if headers.has_key("IN-REPLY-TO"):
            morelines.append("In-Reply-To: %s\n" % headers['IN-REPLY-TO'])
        if headers.has_key("REFERENCES"):
            morelines.append("References: %s\n" % headers['REFERENCES'])
        #FFFF In the long run, we may want to reject messages with
        #FFFF unrecognized headers.  But while we're in alpha, it'd
        #FFFF be too much of a headache.

        # Decode and escape the message, and get ready to send it.
        msg = _escapeMessageForEmail(packet)
        msg = "To: %s\nFrom: %s\nSubject: %s\n%s%s\n\n%s"%(
            address, fromAddr, subject, "".join(morelines), self.header, msg)

        return msg


#----------------------------------------------------------------------
class MBoxModule(DeliveryModule, MailBase):
    """Implementation for MBOX delivery: sends messages, via SMTP, to
       addresses from a local file.  The file must have the format
          addr: smtpaddr
          addr: smtpaddr
           ...

       When we receive a message send to 'addr', we deliver it to smtpaddr.
       """
    ##
    # Fields:
    #   addresses: a map from address to SMTP address
    #   server: the name of our SMTP server
    #   addressFile: the location of our address file
    #   returnAddress: the address we use in our 'From' line
    #   contact: the contact address we mention in our boilerplate
    #   nickname: our server nickname; for use in our boilerplate
    #   addr: our IP address, or "<Unknown IP>": for use in our boilerplate.
    def __init__(self):
        DeliveryModule.__init__(self)
        self.maxMessageSize = None
        self.addresses = {}

    def getRetrySchedule(self):
        return self.retrySchedule

    def getConfigSyntax(self):
        # FFFF There should be some way to say that fields are required
        # FFFF if the module is enabled.
        return { "Delivery/MBOX" :
                 { 'Enabled' : ('REQUIRE',  _parseBoolean, "no"),
                   'Retry': ('ALLOW', _parseIntervalList,
                             "7 hours for 6 days"),
                   'AddressFile' : ('ALLOW', None, None),
                   'ReturnAddress' : ('ALLOW', None, None),
                   'RemoveContact' : ('ALLOW', None, None),
                   'AllowFromAddress' : ('ALLOW', _parseBoolean, 'yes'),
                   'SMTPServer' : ('ALLOW', None, 'localhost'),
                   'MaximumSize' : ('ALLOW', _parseSize, "100K"),
                   }
                 }

    def validateConfig(self, config, lines, contents):
        sec = config['Delivery/MBOX']
        if not sec.get('Enabled'):
            return
        for field in ['AddressFile', 'ReturnAddress', 'RemoveContact',
                      'SMTPServer']:
            if not sec.get(field):
                raise ConfigError("Missing field %s in [Delivery/MBOX]"%field)
        if not os.path.exists(sec['AddressFile']):
            raise ConfigError("Address file %s seems not to exist."%
                              sec['AddresFile'])
        for field in ['ReturnAddress', 'RemoveContact']:
            if not isSMTPMailbox(sec[field]):
                LOG.warn("Value of %s (%s) doesn't look like an email address",
                         field, sec[field])

        config.validateRetrySchedule("Delivery/MBOX")

    def configure(self, config, moduleManager):
        if not config['Delivery/MBOX'].get("Enabled", 0):
            moduleManager.disableModule(self)
            return

        sec = config['Delivery/MBOX']
        self.server = sec['SMTPServer']
        self.addressFile = sec['AddressFile']
        self.returnAddress = sec['ReturnAddress']
        self.contact = sec['RemoveContact']
        self.retrySchedule = sec['Retry']
        self.allowFromAddr = sec['AllowFromAddress']
        # validate should have caught these.
        assert (self.server and self.addressFile and self.returnAddress
                and self.contact)

        self.nickname = config['Server']['Nickname']
        if not self.nickname:
            self.nickname = socket.gethostname()
        self.addr = config['Incoming/MMTP'].get('IP', "<Unknown IP>")
        self.maxMessageSize = sec['MaximumSize']
        if self.maxMessageSize < 32*1024:
            LOG.warn("Ignoring low maximum message sze")
            self.maxMessageSize = 32*1024

        # These fields are needed by MailBase
        self.subject = "Type III Anonymous Message"
        self.fromTag = "[Anon]"
        self.header = """\
X-Anonymous: yes

THIS IS AN ANONYMOUS MESSAGE.  The mixminion server '%s' at
%s has been configured to deliver messages to your address.
If you do not want to receive messages in the future, contact %s
and you will be removed.""" %(self.nickname, self.addr, self.contact)

        # Parse the address file.
        self.addresses = {}
        f = open(self.addressFile)
        try:
            lines = f.readlines()
        finally:
            f.close()
        
        address_line_re = re.compile(r'([^\s:=]+)\s*[:=]\s*(\S+)')

        lineno = 0
        for line in lines:
            line = line.strip()
            lineno += 1
            if line == '' or line[0] == '#':
                continue
            m = address_line_re.match(line)
            if not m:
                raise ConfigError("Bad address on line %s of %s"%(
                    lineno,self.addressFile))
            self.addresses[m.group(1)] = m.group(2)
            LOG.trace("Mapping MBOX address %s -> %s", m.group(1),
                           m.group(2))

        moduleManager.enableModule(self)

    def getServerInfoBlock(self):
        if self.allowFromAddr: 
            allowFrom = "yes"
        else:
            allowFrom = "no"
        return """\
                  [Delivery/MBOX]
                  Version: 0.1
                  Allow-From: %s
               """ % (allowFrom)

    def getName(self):
        return "MBOX"

    def getExitTypes(self):
        return [ mixminion.Packet.MBOX_TYPE ]

    def processMessage(self, packet): #message, tag, exitType, address):
        # Determine that message's address;
        assert packet.getExitType() == mixminion.Packet.MBOX_TYPE
        LOG.debug("Received MBOX message")
        info = mixminion.Packet.parseMBOXInfo(packet.getAddress())
        try:
            address = self.addresses[info.user]
        except KeyError:
            LOG.error("Unknown MBOX user %r", info.user)
            return DELIVER_FAIL_NORETRY

        # Generate the boilerplate (FFFF Make this more configurable)
        msg = self._formatEmailMessage(address, packet)
        if not msg:
            return DELIVER_FAIL_NORETRY

        # Deliver the message
        return sendSMTPMessage(self.server, [address], self.returnAddress, msg)

#----------------------------------------------------------------------
class SMTPModule(DeliveryModule, MailBase):
    """Common base class for SMTP mail."""
    def __init__(self):
        DeliveryModule.__init__(self)
    def getServerInfoBlock(self):
        if self.allowFromAddr: 
            allowFrom = "yes"
        else:
            allowFrom = "no"
        return ("[Delivery/SMTP]\nVersion: 0.1\n"
                "Maximum-Size: %s\nAllow-From: %s\n") % (
                    ceilDiv(self.maxMessageSize,1024), allowFrom)
    def getName(self):
        return "SMTP"
    def getExitTypes(self):
        return [ mixminion.Packet.SMTP_TYPE ]

class DirectSMTPModule(SMTPModule):
    """Module that delivers SMTP messages via a local MTA."""
    ## Fields
    # server -- Name of the MTA server.
    # subject: The default subject line we use for outgoing messages
    # fromPattern: A printf format string with a field for user-supplied
    #    from addresses.
    # header -- A string, minus "To:"-line, that gets prepended to all
    #    outgoing messages.
    # returnAddress -- The address to use in the "From:" line.
    # blacklist -- An EmailAddressSet of addresses to which we refuse
    #   to deliver messages.
    def __init__(self):
        SMTPModule.__init__(self)

    def getRetrySchedule(self):
        return self.retrySchedule

    def getConfigSyntax(self):
        return { "Delivery/SMTP" :
                 { 'Enabled' : ('REQUIRE', _parseBoolean, "no"),
                   'Retry': ('ALLOW', _parseIntervalList,
                             "7 hours for 6 days"),
                   'BlacklistFile' : ('ALLOW', None, None),
                   'SMTPServer' : ('ALLOW', None, 'localhost'),
                   'AllowFromAddress': ('ALLOW', _parseBoolean, "yes"),
                   'Message' : ('ALLOW', None, ""),
                   'ReturnAddress': ('ALLOW', None, None), #Required on e
                   'FromTag' : ('ALLOW', None, "[Anon]"),
                   'SubjectLine' : ('ALLOW', None,
                                    'Type III Anonymous Message'),
                   'MaximumSize' : ('ALLOW', _parseSize, "100K"),
                   }
                 }

    def validateConfig(self, config, lines, contents):
        sec = config['Delivery/SMTP']
        if not sec.get('Enabled'):
            return
        for field in 'SMTPServer', 'ReturnAddress':
            if not sec.get(field):
                raise ConfigError("Missing field %s in [Delivery/SMTP]"%field)
        fn = sec.get('BlacklistFile')
        if fn and not os.path.exists(fn):
            raise ConfigError("Blacklist file %s seems not to exist"%fn)
        if not isSMTPMailbox(sec['ReturnAddress']):
            LOG.warn("Return address (%s) doesn't look like an email address",
                     sec['ReturnAddress'])

        config.validateRetrySchedule("Delivery/SMTP")

    def configure(self, config, manager):
        sec = config['Delivery/SMTP']
        if not sec.get('Enabled'):
            manager.disableModule(self)
            return

        self.server = sec['SMTPServer']
        self.retrySchedule = sec['Retry']
        if sec['BlacklistFile']:
            self.blacklist = EmailAddressSet(fname=sec['BlacklistFile'])
        else:
            self.blacklist = None
        message = "\n".join(textwrap.wrap(sec.get('Message',""))).strip()
        self.subject = sec['SubjectLine']
        self.returnAddress = sec['ReturnAddress']
        self.fromTag = sec.get('FromTag', "[Anon]")
        self.allowFromAddr = sec['AllowFromAddress']
        if message:
            self.header = "X-Anonymous: yes\n\n%s" %(message)
        else:
            self.header = "X-Anonymous: yes"

        self.maxMessageSize = sec['MaximumSize']
        if self.maxMessageSize < 32*1024:
            LOG.warn("Ignoring low maximum message sze")
            self.maxMessageSize = 32*1024

        manager.enableModule(self)

    def processMessage(self, packet):
        assert packet.getExitType() == mixminion.Packet.SMTP_TYPE
        LOG.debug("Received SMTP message")
        # parseSMTPInfo will raise a parse error if the mailbox is invalid.
        try:
            address = mixminion.Packet.parseSMTPInfo(packet.getAddress()).email
        except ParseError:
            LOG.warn("Dropping SMTP message to invalid address %r",
                     packet.getAddress())
            return DELIVER_FAIL_NORETRY

        # Now, have we blacklisted this address?
        if self.blacklist and self.blacklist.contains(address):
            LOG.warn("Dropping message to blacklisted address %r", address)
            return DELIVER_FAIL_NORETRY

        msg = self._formatEmailMessage(address, packet)
        if not msg:
            return DELIVER_FAIL_NORETRY

        # Send the message.
        return sendSMTPMessage(self.server, [address], self.returnAddress, msg)

class MixmasterSMTPModule(SMTPModule):
    """Implements SMTP by relaying messages via Mixmaster nodes.  This
       is kind of unreliable and kludgey, but it does allow us to
       test mixminion by using Mixmaster nodes as exits."""
    # (Mixmaster has tons of options, but we ignore them, since
    #  this is only a temporary workaround until enough people
    #  are running SMTP exit nodes.)
    ## Fields:
    # server: The path (usually a single server) to use for outgoing messages.
    #    Multiple servers should be separated by commas.
    # subject: The default subject line we use for outgoing messages
    # fromPattern: A printf format string with a field for user-supplied
    #    from addresses.
    # command: The Mixmaster binary.
    # options: Options to pass to the Mixmaster binary when queueing messages
    # tmpQueue: An auxiliary Queue used to hold files so we can pass them to
    #    Mixmaster.  (This should go away; we should use stdin instead.)

    def __init__(self):
        SMTPModule.__init__(self)

    def getRetrySchedule(self):
        return self.retrySchedule

    def getConfigSyntax(self):
        return { "Delivery/SMTP-Via-Mixmaster" :
                 { 'Enabled' : ('REQUIRE', _parseBoolean, "no"),
                   'Retry': ('ALLOW', _parseIntervalList,
                             "7 hours for 6 days"),
                   'MixCommand' : ('REQUIRE', _parseCommand, None),
                   'Server' : ('REQUIRE', None, None),
                   'FromTag' : ('ALLOW', None, "[Anon]"),
                   'SubjectLine' : ('ALLOW', None,
                                    'Type III Anonymous Message'),
                   'MaximumSize' : ('ALLOW', _parseSize, "100K"),
                   'AllowFromAddress' : ('ALLOW', _parseBoolean, "yes"),
                   }
                 }

    def validateConfig(self, config, lines, contents):
        #FFFF write more
        sec = config['Delivery/SMTP-Via-Mixmaster']
        if not sec.get("Enabled"):
            return
        config.validateRetrySchedule("Delivery/SMTP-Via-Mixmaster")

    def configure(self, config, manager):
        sec = config['Delivery/SMTP-Via-Mixmaster']
        if not sec.get("Enabled", 0):
            manager.disableModule(self)
            return
        cmd = sec['MixCommand']
        self.server = sec['Server']
        self.subject = sec['SubjectLine']
        self.retrySchedule = sec['Retry']
        self.fromTag = sec.get('FromTag', "[Anon]")
        self.allowFromAddr = sec['AllowFromAddress']
        self.command = cmd[0]
        self.options = tuple(cmd[1]) + ("-l", self.server)
        self.returnAddress = "nobody"
        self.header = "X-Anonymous: yes"
        self.maxMessageSize = sec['MaximumSize']
        if self.maxMessageSize < 32*1024:
            LOG.warn("Ignoring low maximum message sze")
            self.maxMessageSize = 32*1024
        manager.enableModule(self)

    def getName(self):
        return "SMTP_MIX2"

    def createDeliveryQueue(self, queueDir):
        # We create a temporary queue so we can hold files there for a little
        # while before passing their names to mixmaster.
        self.tmpQueue = mixminion.Filestore.StringStore(queueDir+"_tmp", 1, 1)
        self.tmpQueue.removeAll()
        return _MixmasterSMTPModuleDeliveryQueue(self, queueDir)

    def processMessage(self, packet):
        """Insert a message into the Mixmaster queue"""
        assert packet.getExitType() == mixminion.Packet.SMTP_TYPE
        # parseSMTPInfo will raise a parse error if the mailbox is invalid.
        try:
            info = mixminion.Packet.parseSMTPInfo(packet.getAddress())
        except ParseError:
            LOG.warn("Dropping SMTP message to invalid address %r",
                     packet.getAddress())
            return DELIVER_FAIL_NORETRY

        msg = self._formatEmailMessage(info.email, packet)
        if not msg:
            return DELIVER_FAIL_NORETRY

        handle = self.tmpQueue.queueMessage(msg)

        cmd = self.command
        opts = self.options + (self.tmpQueue.getMessagePath(handle),)
        code = os.spawnl(os.P_WAIT, cmd, cmd, *opts)
        LOG.debug("Queued Mixmaster message: exit code %s", code)
        self.tmpQueue.removeMessage(handle)
        return DELIVER_OK

    def flushMixmasterPool(self):
        """Send all pending messages from the Mixmaster queue.  This
           should be called after invocations of processMessage."""
        cmd = self.command
        LOG.debug("Flushing Mixmaster pool")
        os.spawnl(os.P_WAIT, cmd, cmd, "-S")

class _MixmasterSMTPModuleDeliveryQueue(SimpleModuleDeliveryQueue):
    """Delivery queue for _MixmasterSMTPModule.  Same as
       SimpleModuleDeliveryQueue, except that we must call flushMixmasterPool
       after queueing messages for Mixmaster."""
    def _deliverMessages(self, msgList):
        SimpleModuleDeliveryQueue._deliverMessages(self, msgList)
        self.module.flushMixmasterPool()

#----------------------------------------------------------------------

MAIL_HEADERS = ["SUBJECT", "FROM", "IN-REPLY-TO", "REFERENCES"]
def checkMailHeaders(headers):
    """Check whether the decoded headers in a provided dict are permissible
       for an outgoing email message.  Raise ParseError if they are not."""
    for k in headers.keys():
        if k not in MAIL_HEADERS:
            #XXXX this should raise parse error instead.
            LOG.warn("Skipping unrecognized mail header %s"%k)
        
    fromAddr = headers['FROM']
    if re.search(r'[\[\]:"]', fromAddr):
        raise ParseError("Invalid FROM address: %r", fromAddr)

#----------------------------------------------------------------------

def sendSMTPMessage(server, toList, fromAddr, message):
    """Send a single SMTP message.  The message will be delivered to
       toList, and seem to originate from fromAddr.  We use 'server' as an
       MTA."""
    # FFFF This implementation can stall badly if we don't have a fast
    # FFFF local MTA.

    # FFFF We should leave the connection open if we're going to send many
    # FFFF messages in a row.
    LOG.debug("Sending message via SMTP host %s to %s", server, toList)
    con = smtplib.SMTP(server)
    try:
        con.sendmail(fromAddr, toList, message)
        res = DELIVER_OK
    except (smtplib.SMTPException, socket.error), e:
        LOG.warn("Unsuccessful SMTP connection to %s: %s",
                 server, str(e))
        res = DELIVER_FAIL_RETRY

    con.quit()
    con.close()

    return res

#----------------------------------------------------------------------

def _escapeMessageForEmail(packet):
    """Helper function: Given a DeliveryPacket, escape the message if
       it is not plaintext ascii, and wrap it in some standard
       boilerplate.  Add a disclaimer if the message is not ascii.
       Extracts headers if possible.  Returns a 2-tuple of message/headers.

          packet -- an instance of DeliveryPacket

       Returns None on an invalid message."""
    if packet.isError():
        return None

    if packet.isEncrypted():
        junk_msg = """\
This message is not in plaintext.  It's either 1) a reply; 2) a forward
message encrypted to you; or 3) junk.\n\n"""
    elif packet.isOvercompressed():
        junk_msg = """\
This message is compressed with zlib.  Ordinarily, I would have decompressed
it, but it was compressed by more than a factor of 20, which makes me nervous.
\n"""
    elif not packet.isPrintingAscii():
        assert packet.isPlaintext()
        junk_msg = """\
This message contains nonprinting characters, so I encoded it with Base64
before sending it to you.\n\n"""
    else:
        assert packet.isPlaintext()
        junk_msg = ""

    encMsg = packet.getTextEncodedMessage()
    return "%s%s"%(junk_msg, encMsg.pack())
