# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.9 2002/12/02 10:13:48 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.

   NOTE: THIS IS NOT THE FINAL VERSION OF THE CODE.  It needs to
         support replies and end-to-end encryption.  It also needs to
         support directories.
   """

# (NOTE: The stuff in the next comment isn't implemented yet.)
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
import types

from mixminion.Common import getLog, floorDiv, createPrivateDir, MixError, \
     MixFatalError
import mixminion.Crypto
from mixminion.BuildMessage import buildForwardMessage
import mixminion.MMTPClient
import mixminion.Modules
from mixminion.ServerInfo import ServerInfo
from mixminion.Config import ClientConfig, ConfigError
from mixminion.Packet import ParseError, parseMBOXInfo, parseSMTPInfo
from mixminion.Modules import MBOX_TYPE, SMTP_TYPE, DROP_TYPE

class TrivialKeystore:
    '''This is a temporary keystore implementation until we get a working
       directory server implementation.'''
    def __init__(self, directory, now=None):
	self.directory = directory
	createPrivateDir(directory)
	self.byNickname = {}
	self.byFilename = {}

	if now is None:
	    now = time.time()

	for f in os.listdir(self.directory):
	    p = os.path.join(self.directory, f)
	    try:
		info = ServerInfo(fname=p, assumeValid=0)
	    except ConfigError, _:
		getLog().warn("Invalid server descriptor %s", p)
		continue

	    serverSection = info['Server']
	    nickname = serverSection['Nickname']

	    if '.' in f:
		f = f[:f.rindex('.')]

	    if now < serverSection['Valid-After']:
		getLog().info("Ignoring future decriptor %s", p)
		continue
	    if now >= serverSection['Valid-Until']:
		getLog().info("Ignoring expired decriptor %s", p)
		continue
	    if now + 3*60*60 >= serverSection['Valid-Until']:
		getLog().info("Ignoring soon-to-expire decriptor %s", p)
		continue
	    if self.byNickname.has_key(nickname):
		getLog().warn(
		    "Ignoring descriptor %s with duplicate nickname %s",
		    p, nickname)
		continue
	    if self.byFilename.has_key(f):
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
	    return self.byNickname[name]
	if self.byFilename.has_key(name):
	    return self.byFilename[name]
	return None

    def getPath(self, serverList):
	path = []
	for s in serverList:
	    if isinstance(s, ServerInfo):
		path.append(s)
	    elif isinstance(s, types.StringType):
		server = self.getServerInfo(s)
		if server is not None:
		    path.append(server)
		elif os.path.exists(s):
		    try:
			server = ServerInfo(fname=s, assumeValid=0)
			path.append(server)
		    except OSError, e:
			raise MixError("Couldn't read descriptor %s: %s" %
				       (s, e))
		    except ConfigError, e:
			raise MixError("Couldn't parse descriptor %s: %s" %
				       (s, e))
		else:
		    raise MixError("Couldn't find descriptor %s" % s)
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
    def __init__(self, conf):
	self.config = conf

	# Make directories
	userdir = os.path.expanduser(self.config['User']['UserDir'])
	createPrivateDir(userdir)
	createPrivateDir(os.path.join(userdir, 'surbs'))
	createPrivateDir(os.path.join(userdir, 'servers'))

	# Get directory cache
	self.keystore = TrivialKeystore(
	    os.path.join(userdir,"servers"))

	# Initialize PRNG
	self.prng = mixminion.Crypto.AESCounterPRNG()

    def sendForwardMessage(self, address, payload, path1, path2):
	message, firstHop = \
		 self.generateForwardMessage(address, payload, path1, path2)

	self.sendMessages([message], firstHop)

    def generateForwardMessage(self, address, payload, path1, path2):
	servers1 = self.keystore.getPath(path1)
	servers2 = self.keystore.getPath(path2)

	routingType, routingInfo, lastHop = address.getRouting()
	if lastHop is None:
            lastServer = servers2[-1]
            print path2[-1], routingType
	    # FFFF This is only a temporary solution.  It needs to get
	    # FFFF rethought, or refactored into ServerInfo, or something.
	    if routingType == SMTP_TYPE:
		ok = lastServer['Delivery/SMTP'].get('Version',None)
		if not ok:
		    raise MixError("Last hop doesn't support SMTP")
	    elif routingType == MBOX_TYPE:
		ok = lastServer['Delivery/MBOX'].get('Version',None)
		if not ok:
		    raise MixError("Last hop doesn't support MBOX")
	else:
	    servers2.append(self.keystore.getServerInfo(lastHop))
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

def parseAddress(s):
    """DOCDOC 
           format is mbox:name@server OR [smtp:]mailbox OR drop OR test:rinfo 
           or 0xABCD:address """
    # DOCDOC
    # ???? Should this should get refactored into clientmodules, or someplace?
    if s.lower() == 'drop':
	return Address(DROP_TYPE, None, None)
    elif s.lower() == 'test':
	return Address(0xFFFE, "", None)
    elif ':' not in s:
	try:
	    return Address(SMTP_TYPE, parseSMTPInfo(s).pack(), None)
	except ParseError, _:
	    raise ParseError("Can't parse address %s"%s)
    tp,val = s.split(':', 1)
    tp = tp.lower()
    if tp.startswith("0x"):
	try:
	    tp = int(tp[2:], 16)
	except ValueError, _:
	    raise ParseError("Invalid hexidecimal value %s"%tp)
	if not (0x0000 <= tp <= 0xFFFF):
	    raise ParseError("Invalid type: 0x%04x"%tp)
	return Address(tp, val, None)
    elif tp == 'mbox':
	if "@" in val:
            mbox, server = val.split("@",1)
            return Address(MBOX_TYPE, parseMBOXInfo(mbox).pack(), server)
        else:
	    return Address(MBOX_TYPE, parseMBOXInfo(val).pack(), None)
    elif tp == 'smtp':
	# May raise ParseError
	return Address(SMTP_TYPE, parseSMTPInfo(val).pack(), None)
    elif tp == 'test':
	return Address(0xFFFE, val, None)
    else:
	raise ParseError("Unrecognized address type: %s"%s)

class Address:
    def __init__(self, exitType, exitAddress, lastHop=None):
	self.exitType = exitType
	self.exitAddress = exitAddress
	self.lastHop = lastHop
    def getRouting(self):
	return self.exitType, self.exitAddress, self.lastHop

def readConfigFile(configFile):
    try:
	return ClientConfig(fname=configFile)
    except (IOError, OSError), e:
	print >>sys.stderr, "Error reading configuration file %r:"%configFile
	print >>sys.stderr, "   ", str(e)
	sys.exit(1)
    except ConfigError, e:
	print >>sys.stderr, "Error in configuration file %r"%configFile
	print >>sys.stderr, str(e)
	sys.exit(1)
    return None #suppress pychecker warning

# NOTE: This isn't anything LIKE the final client interface.  Many or all
#       options will change between now and 1.0.0
def runClient(cmd, args):
    options, args = getopt.getopt(args, "hvf:i:t:",
				  ["help", "verbose", "config=", "input=",
				   "path1=", "path2=", "to="])
    configFile = '~/.mixminionrc'
    usage = 0
    inFile = "-"
    verbose = 0
    path1 = []
    path2 = []
    address = None
    for opt,val in options:
	if opt in ('-h', '--help'):
	    usage=1
	elif opt in ('-f', '--config'):
	    configFile = val
	elif opt in ('-i', '--input'):
	    inFile = val
	elif opt in ('-v', '--verbose'):
	    verbose = 1
	elif opt == '--path1':
	    path1.extend(val.split(","))
	elif opt == '--path2':
	    path2.extend(val.split(","))
	elif opt in ('-t', '--to'):
	    address = parseAddress(val)
    if args:
	print >>sys.stderr, "Unexpected options."
	usage = 1
    if not path1:
	print >>sys.stderr, "First leg of path was not specified"
	usage = 1
    if not path2:
	print >>sys.stderr, "Second leg of path was not specified"
	usage = 1
    if address is None:
	print >>sys.stderr, "No recipient specified"
	usage = 1
    if usage:
	print >>sys.stderr, """\
Usage: %s [-h] [-v] [-f configfile] [-i inputfile]
          [--path1=server1,server2,...]
          [--path2=server1,server2,...] [-t <address>]"""%cmd
	sys.exit(1)

    if configFile is None:
	configFile = os.environ.get("MIXMINIONRC", None)
	if configFile is None:
	    configFile = "~/.mixminionrc"

    configFile = os.path.expanduser(configFile)
    if not os.path.exists(configFile):
	installDefaultConfig(configFile)
    config = readConfigFile(configFile)

    getLog().configure(config)
    if verbose:
	getLog().setMinSeverity("DEBUG")

    getLog().debug("Configuring client")
    mixminion.Common.configureShredCommand(config)
    mixminion.Crypto.init_crypto(config)

    client = MixminionClient(config)

    if inFile == '-':
	f = sys.stdin
    else:
	f = open(inFile, 'r')
    payload = f.read()
    f.close()

    client.sendForwardMessage(address, payload, path1, path2)
