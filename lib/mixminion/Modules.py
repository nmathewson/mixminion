# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Modules.py,v 1.3 2002/08/06 16:09:21 nickm Exp $

"""mixminion.Modules

   Type codes and dispatch functions for routing functionality."""

#__all__ = [ 'ModuleManager' ]

import os

import mixminion.Config
import mixminion.Packet
from mixminion.Config import ConfigError, _parseBoolean, _parseCommand
from mixminion.Common import getLog

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
    "XXXX DOCME"
    def __init__(self):
        pass

    def getConfigSyntax(self):
        pass

    def validateConfig(self, sections, entries, lines, contents):
        pass

    def configure(self, config, manager):
        pass

    def getServerInfoBlock(self):
        pass

    def getName(self):
        pass

    def getExitTypes(self):
        pass

    def processMessage(self, message, exitType, exitInfo):
        pass

class ModuleManager:
    def __init__(self):
        self.syntax = {}
        self.modules = []
        self.typeToModule = {}
        
        self.registerModule(MBoxModule())
        self.registerModule(DropModule())

    def getConfigSyntax(self):
        return self.syntax

    def registerModule(self, module):
        self.modules.append(module)
        syn = module.getConfigSyntax()
        for sec, rules in syn.items():
            if self.syntax.has_key(sec):
                raise ConfigError("Multiple modules want to define [%s]"% sec)
        self.syntax.update(syn)

    def setPath(self, path):
        self.path = path

    def loadExtModule(self, className):
        # CHECK! XXXX Handle errors
        ids = className.split(".")
        pyPkg = ".".join(ids[:-1])
        pyClassName = ids[-1]
        try:
            orig_path = sys.path[:]
            sys.path.extend(self.path)
            m = __import__(pyPkg, {}, {}, [])
        finally:
            sys.path = orig_path
        pyClass = getattr(pyPkg, pyClassname)
        self.registerModule(pyClass())

    def validate(self, sections, entries, lines, contents):
        for m in self.modules:
            m.validateConfig(sections, entries, lines, contents)

    def configure(self, config):
        for m in self.modules:
            m.configure(config, self)

    def enableModule(self, module):
        for t in module.getExitTypes():
            self.typeToModule[t] = module

    def disableModule(self, module):
        for t in module.getExitTypes():
            if self.typeToModule.has_key(t):
                del self.typeToModule[t]

    def processMessage(self, message, exitType, exitInfo):
        mod = self.typeToModule.get(exitType, None)
        if mod is not None:
            return mod.processMessage(message, exitType, exitInfo)
        else:
            getLog().error("Unable to deliver message with unknown type %s",
                           exitType)
            return DELIVER_FAIL_NORETRY

    def getServerInfoBlocks(self):
        return [ m.getServerInfoBlock() for m in self.modules ]

class DropModule(DeliveryModule):
    def __init__(self):
        DeliveryModule.__init__(self)

    def getConfigSyntax(self):
        return { }

    def validateConfig(self, sections, entries, lines, contents):
        pass

    def configure(self, config, moduleManager):
        pass

    def getServerInfoBlock(self):
        return ""
    
    def getName(self):
        return "DROP module"

    def getExitTypes(self):
        return [ DROP_TYPE ]

    def processMessage(self, message, exitType, exitInfo):
        getLog().info("Dropping padding message")
        return DELIVER_OK

#----------------------------------------------------------------------
class MBoxModule(DeliveryModule):
    def __init__(self):
        DeliveryModule.__init__(self)
        self.command = None
        self.enabled = 0
        self.addresses = {}

    def getConfigSyntax(self):
        return { "Delivery/MBOX" :
                 { 'Enabled' : ('REQUIRE',  _parseBoolean, "no"),
                   'AddressFile' : ('ALLOW', None, None),
                   'ReturnAddress' : ('ALLOW', None, None),
                   'RemoveContact' : ('ALLOW', None, None),
                   'Command' : ('ALLOW', _parseCommand, "sendmail") }
                 }

    def validateConfig(self, sections, entries, lines, contents):
        # XXXX write this.  Parse address file.
        pass

    def configure(self, config, moduleManager):
        # XXXX Check this.  error handling
        self.enabled = config['Delivery/MBOX'].get("Enabled", 0)
        self.command = config['Delivery/MBOX']['Command']
        self.addressFile = config['Delivery/MBOX']['AddressFile']
        self.returnAddress = config['Delivery/MBOX']['ReturnAddress']
        self.contact = config['Delivery/MBOX']['RemoveContact']
        if self.enabled:
            if not self.addressFile:
                raise ConfigError("Missing AddressFile field in Delivery/MBOX")
            if not self.returnAddress:
                raise ConfigError("Missing ReturnAddress field "+
                                  "in Delivery/MBOX")
            if not self.contact:
                raise ConfigError("Missing RemoveContact field "+
                                  "in Delivery/MBOX")
        
        self.nickname = config['Server']['Nickname']
        if not self.nickname:
            self.nickname = socket.gethostname()
        self.addr = config['Server'].get('IP', "<Unknown host>")

        if self.command != ('sendmail', []):
            getLog().warn("Ignoring mail command in version 0.0.1")

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

        if enabled:
            moduleManager.enableModule(self)
        else:
            moduleManager.disableModule(self)

    def getServerInfoBlock(self):
        return """\
                  [Delivery/MBOX]
                  Version: 1.0
               """
    
    def getName(self):
        return "MBOX module"

    def getExitTypes(self):
        return [ MBOX_TYPE ]

    def processMessage(self, message, exitType, exitInfo):
        assert exitType == MBOX_TYPE
        getLog().trace("Received MBOX message")
        info = mixminion.packet.parseMBOXInfo(exitInfo)
        if not addresses.has_key(info.user):
            getLog.warn("Unknown MBOX user %r", info.user)
            return 
        msg = _escapeMessageForEmail(message)

        fields = { 'user': addresses[info.user],
                   'return': self.returnAddr,
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
will be removed.  (XXXX Need real boilerplate)

%(msg)s
""" % fields

        f = os.popen("sendmail -i -t", 'w')
        f.write(msg)
        status = f.close()
        if status != 0:
            getLog().error("Unsuccessful sendmail")
            return DELIVER_FAIL_RETRY

        return DELIVER_OK

#----------------------------------------------------------------------


_allChars = "".join(map(chr, range(256)))
_nonprinting = "".join(map(chr, range(0x00, 0x07)+range(0x0E, 0x20)))
def _escapeMessageForEmail(msg):
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
