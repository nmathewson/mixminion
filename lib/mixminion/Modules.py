# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Modules.py,v 1.13 2002/10/16 23:12:12 nickm Exp $

"""mixminion.Modules

   Type codes and dispatch functions for routing functionality."""

__all__ = [ 'ModuleManager', 'DeliveryModule',
	    'DROP_TYPE', 'FWD_TYPE', 'SWAP_FWD_TYPE',
	    'DELIVER_OK', 'DELIVER_FAIL_RETRY', 'DELIVER_FAIL_NORETRY',
	    'SMTP_TYPE', 'MBOX_TYPE' ]

import os
import sys
import smtplib
import socket
import base64

import mixminion.Config
import mixminion.Packet
import mixminion.Queue
import mixminion.BuildMessage 
from mixminion.Config import ConfigError, _parseBoolean, _parseCommand
from mixminion.Common import getLog, createPrivateDir, MixError

# Return values for processMessage
DELIVER_OK = 1
DELIVER_FAIL_RETRY = 2
DELIVER_FAIL_NORETRY = 3

# Numerically first exit type.
MIN_EXIT_TYPE  = 0x0100

# Mixminion types
DROP_TYPE      = 0x0000  # Drop the current message
FWD_TYPE       = 0x0001  # Forward the msg to an IPV4 addr via MMTP
SWAP_FWD_TYPE  = 0x0002  # SWAP, then forward the msg to an IPV4 addr via MMTP

# Exit types
SMTP_TYPE      = 0x0100  # Mail the message
MBOX_TYPE      = 0x0101  # Send the message to one of a fixed list of addresses

class DeliveryModule:
    """Abstract base for modules; delivery modules should implement
       the methods in this class.

       A delivery module has the following responsibilities:
           * It must have a 0-argument contructor.
           * If it is configurable, it must be able to specify its options,
             validate its configuration, and configure itself.
           * If it is advertisable, it must provide a server info block.
           * It must know its own name.
	   * It must know which types it handles.
	   * Of course, it needs to know how to deliver a message."""
    def __init__(self):
	"Zero-argument constructor, as required by Module protocol."
	pass

    def getConfigSyntax(self):
	"""Return a map from section names to section syntax, as described
	   in Config.py"""
        raise NotImplementedError("getConfigSyntax")

    def validateConfig(self, sections, entries, lines, contents):
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
	   batch messages intended for the same destination."""
        return SimpleModuleDeliveryQueue(self, queueDir)

    def processMessage(self, message, exitType, exitInfo):
	"""Given a message with a given exitType and exitInfo, try to deliver
           it.  Return one of:
            DELIVER_OK (if the message was successfully delivered), 
	    DELIVER_FAIL_RETRY (if the message wasn't delivered, but might be 
              deliverable later), or
	    DELIVER_FAIL_NORETRY (if the message shouldn't be tried later)."""
        raise NotImplementedError("processMessage")


class ImmediateDeliveryQueue:
    """Helper class usable as delivery queue for modules that don't
       actually want a queue.  Such modules should have very speedy
       processMessage() methods, and should never have deliery fail."""
    def __init__(self, module):
	self.module = module

    def queueMessage(self, (exitType, exitInfo), message):
	try:
	    res = self.module.processMessage(message, exitType, exitInfo)
	    if res == DELIVER_OK:
		return
	    elif res == DELIVER_FAIL_RETRY:
		getLog().error("Unable to retry delivery for message")
	    else:
		getLog().error("Unable to deliver message")
	except:
	    getLog().error_exc(sys.exc_info(),
			       "Exception delivering message")

    def sendReadyMessages(self):
	# We do nothing here; we already delivered the messages
	pass

class SimpleModuleDeliveryQueue(mixminion.Queue.DeliveryQueue):
    """Helper class used as a default delivery queue for modules that
       don't care about batching messages to like addresses."""
    def __init__(self, module, directory):
	mixminion.Queue.DeliveryQueue.__init__(self, directory)
	self.module = module
    
    def deliverMessages(self, msgList):
	for handle, addr, message, n_retries in msgList:	  
	    try:
		exitType, exitInfo = addr
		result = self.module.processMessage(message,exitType,exitInfo)
		if result == DELIVER_OK:
		    self.deliverySucceeded(handle)
		elif result == DELIVER_FAIL_RETRY:
		    # XXXX We need to drop undeliverable messages eventually!
		    self.deliveryFailed(handle, 1)
		else:
		    getLog().error("Unable to deliver message")
		    self.deliveryFailed(handle, 0)
	    except:
		getLog().error_exc(sys.exc_info(),
				   "Exception delivering message")
		self.deliveryFailed(handle, 0)

class ModuleManager:
    """A ModuleManager knows about all of the modules in the systems.
   
       A module may be in one of three states: unloaded, registered, or 
       enabled.  An unloaded module is just a class in a python module.
       A registered module has been loaded, configured, and listed with
       the ModuleManager, but will not receive messags until it has been
       enabled."""
    ## 
    # Fields
    #    syntax: extensions to the syntax configuration in Config.py
    #    modules: a list of DeliveryModule objects
    #    nameToModule: Map from module name to module
    #    typeToModule: a map from delivery type to enabled deliverymodule.
    #    path: search path for python modules.
    #    queueRoot: directory where all the queues go.
    #    queues: a map from module name to queue (Queue objects must support
    #            queueMessage and sendReadyMessages as in DeliveryQueue.)
    
    def __init__(self):
        self.syntax = {}
        self.modules = []
	self.nameToModule = {}
        self.typeToModule = {}
	self.path = []
	self.queueRoot = None
	self.queues = {}
        
        self.registerModule(MBoxModule())
        self.registerModule(DropModule())

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
	    self.path = path.split(":")
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
	    
    def validate(self, sections, entries, lines, contents):
        for m in self.modules:
            m.validateConfig(sections, entries, lines, contents)

    def configure(self, config):
	self._setQueueRoot(os.path.join(config['Server']['Homedir'],
					'work', 'queues', 'deliver'))
	createPrivateDir(self.queueRoot)
        for m in self.modules:
            m.configure(config, self)

    def enableModule(self, module):
	"""Maps all the types for a module object."""
        for t in module.getExitTypes():
            self.typeToModule[t] = module

	queueDir = os.path.join(self.queueRoot, module.getName())
	queue = module.createDeliveryQueue(queueDir)
	self.queues[module.getName()] = queue

    def cleanQueues(self):
	for queue in self.queues.values():
	    queue.cleanQueue()
	    
    def disableModule(self, module):
	"""Unmaps all the types for a module object."""
        for t in module.getExitTypes():
            if self.typeToModule.has_key(t):
                del self.typeToModule[t]
	if self.queues.has_key(module.getName()):
	    del self.queues[module.getName()]

    def queueMessage(self, message, exitType, exitInfo):
        mod = self.typeToModule.get(exitType, None)
        if mod is None:
            getLog().error("Unable to handle message with unknown type %s",
                           exitType)
	    return
	queue = self.queues[mod.getName()]
	queue.queueMessage((exitType,exitInfo), message)

    def sendReadyMessages(self):
	for name, queue in self.queues.items():
	    queue.sendReadyMessages()

    def getServerInfoBlocks(self):
        return [ m.getServerInfoBlock() for m in self.modules ]

#----------------------------------------------------------------------
class DropModule(DeliveryModule):
    """Null-object pattern: drops all messages it receives."""
    def getConfigSyntax(self):
        return { }
    def getServerInfoBlock(self):
        return ""
    def configure(self, config, manager):
	manager.enableModule(self)
    def getName(self):
        return "DROP"
    def getExitTypes(self):
        return [ DROP_TYPE ]
    def createDeliveryQueue(self, directory):
	return ImmediateDeliveryQueue(self)
    def processMessage(self, message, exitType, exitInfo):
        getLog().debug("Dropping padding message")
        return DELIVER_OK

#----------------------------------------------------------------------
class MBoxModule(DeliveryModule):
    # FFFF This implementation can stall badly if we don't have a fast
    # FFFF local MTA.
    def __init__(self):
        DeliveryModule.__init__(self)
        self.enabled = 0
        self.addresses = {}

    def getConfigSyntax(self):
        return { "Delivery/MBOX" :
                 { 'Enabled' : ('REQUIRE',  _parseBoolean, "no"),
                   'AddressFile' : ('ALLOW', None, None),
                   'ReturnAddress' : ('ALLOW', None, None),
                   'RemoveContact' : ('ALLOW', None, None),
                   'SMTPServer' : ('ALLOW', None, 'localhost') }
                 }

    def validateConfig(self, sections, entries, lines, contents):
        # XXXX write this.  Parse address file.
        pass

    def configure(self, config, moduleManager):
        # XXXX Check this.  Conside error handling
	
        self.enabled = config['Delivery/MBOX'].get("Enabled", 0)
	if not self.enabled:
	    moduleManager.disableModule(self)
	    return

	self.server = config['Delivery/MBOX']['SMTPServer']
	self.addressFile = config['Delivery/MBOX']['AddressFile']
	self.returnAddress = config['Delivery/MBOX']['ReturnAddress']
	self.contact = config['Delivery/MBOX']['RemoveContact']
	if not self.addressFile:
	    raise ConfigError("Missing AddressFile field in Delivery/MBOX")
	if not self.returnAddress:
	    raise ConfigError("Missing ReturnAddress field in Delivery/MBOX")
	if not self.contact:
	    raise ConfigError("Missing RemoveContact field in Delivery/MBOX")
			      
        
        self.nickname = config['Server']['Nickname']
        if not self.nickname:
            self.nickname = socket.gethostname()
        self.addr = config['Server'].get('IP', "<Unknown host>")

        f = open(self.addressfile)
        addresses = f.read()
        f.close()

        addresses = mixminion.Config._readConfigFile(addresses)
        assert len(addresses) > 1
        assert not addresses.has_key('Addresses')

        self.addresses = {}
        for k, v, line in addresses[0][1]:
            if self.addresses.has_key(k):
                raise ConfigError("Duplicate MBOX user %s"%k)
            self.addresses[k] = v

	moduleManager.enableModule(self)

    def getServerInfoBlock(self):
        return """\
                  [Delivery/MBOX]
                  Version: 0.1
               """
    
    def getName(self):
        return "MBOX"

    def getExitTypes(self):
        return [ MBOX_TYPE ]

    def processMessage(self, message, exitType, exitInfo):
        assert exitType == MBOX_TYPE
        getLog().trace("Received MBOX message")
        info = mixminion.Packet.parseMBOXInfo(exitInfo)
	try:
	    address = self.addresses[info.user]
	except KeyError, _:
            getLog.warn("Unknown MBOX user %r", info.user)

        msg = _escapeMessageForEmail(message, info.tag)

        fields = { 'user': address,
                   'return': self.returnAddress,
                   'nickname': self.nickname,
                   'addr': self.addr,
                   'contact': self.contact,
                   'msg': msg }
        msg = """
To: %(user)s
From: %(return)s
Subject: Anonymous Mixminion message

THIS IS AN ANONYMOUS MESSAGE.  The mixminion server '%(nickname)s' at
%(addr)s has been configured to deliver messages to your address.  If you
do not want to receive messages in the future, contact %(contact)s and you
will be removed.

%(msg)s
""" % fields

        return sendSMTPMessage(self.server, [address], self.returnAddress, msg)

#----------------------------------------------------------------------
def sendSMTPMessage(server, toList, fromAddr, message):
    con = smtplib(server)
    try:
	con.sendmail(fromAddr, toList, message)
	res = DELIVER_OK
    except smtplib.SMTPException, e:
	getLog().warn("Unsuccessful smtp: "+str(e))
	res = DELIVER_FAIL_RETRY

    con.quit()
    con.close()

    return res

#----------------------------------------------------------------------

#XXXX DOCDOC
_allChars = "".join(map(chr, range(256)))
_nonprinting = "".join(map(chr, range(0x00, 0x07)+range(0x0E, 0x20)))
def _escapeMessageForEmail(msg, tag):
    m = decodePayload(tag, msg)
    if m is None:
	junk = 1
	msg = base64.encodestring(msg)
	tag = base64.encodestring(tag)
    else:
	printable = m.translate(_allChars, _nonprinting)
	allChars

    printable = msg.translate(_allChars, _nonprinting)
    if msg[len(printable):] == '\x00'*(len(msg)-len(printable)):
        msg = msg[len(printable)]
        return """\
============ ANONYMOUS MESSAGE BEGINS
%s
============ ANONYMOUS MESSAGE ENDS\n""" %msg
    else:
        msg = base64.encodestring(msg)
        return """\
This message is encoded in Base64 because it contains some nonprintable
characters.  It's possible that this message is a non-text object, that
it was sent to using a reply block, that it was corrupted on its way to
you, or that it's just plain junk.
============ BASE-64 ENCODED ANONYMOUS MESSAGE BEGINS
%s
============ BASE-64 ENCODED ANONYMOUS MESSAGE ENDS\n""" % msg

def _decodeMessage(self, message, exitInfo, text=0):
    """XXXX DOCDOC
	  -> ("TXT"|"BIN"|"ENC", payload, RI, tag|None) or None
    """
    if len(exitInfo) < 20:
	return None
    tag = exitInfo[:20]
    ri = exitInfo[20:]

    try:
	m = mixminion.BuildMessage.decodePayload(message, tag)
    except MixError, e:
	return None

    if m is None:
	code = "ENC"
    else:
	tag = None
	printable = msg.translate(_allChars, _nonprinting)
	if msg[len(printable):] == '\x00'*(len(msg)-len(printable)):
	    code = "TXT"
	else:
	    code = "BIN"

    if text and (code != "TXT") :
	message = base64.encodestring(message)
    if text and tag:
	tag = base64.encodestring(tag)

    return code, message, ri, tag
