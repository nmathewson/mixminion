# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.16 2002/12/15 03:45:30 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.

   NOTE: THIS IS NOT THE FINAL VERSION OF THE CODE.  It needs to
         support replies and end-to-end encryption.  It also needs to
         support directories.
   """

__all__ = []

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

import getopt
import os
import sys
import time
import types

import mixminion.BuildMessage
import mixminion.Crypto
import mixminion.MMTPClient
from mixminion.Common import LOG, floorDiv, MixError, MixFatalError, \
     createPrivateDir, isSMTPMailbox, formatDate
from mixminion.Config import ClientConfig, ConfigError
from mixminion.ServerInfo import ServerInfo
from mixminion.Packet import ParseError, parseMBOXInfo, parseSMTPInfo, \
     MBOX_TYPE, SMTP_TYPE, DROP_TYPE

class TrivialKeystore:
    """This is a temporary keystore implementation until we get a working
       directory server implementation.

       The idea couldn't be simpler: we just keep a directory of files, each
       containing a single server descriptor.  We cache nothing; we validate
       everything; we have no automatic path generation.  Servers can be
       accessed by nickname, by filename within our directory, or by filename
       from elsewhere on the filesystem.

       We skip all server descriptors that have expired, that will
       soon expire, or which aren't yet in effect.
       """
    ## Fields:
    # directory: path to the directory we scan for server descriptors.
    # byNickname: a map from nickname to valid ServerInfo object.
    # byFilename: a map from filename within self.directory to valid
    #     ServerInfo object.
    def __init__(self, directory, now=None):
	"""Create a new TrivialKeystore to access the descriptors stored in
	   directory.  Selects descriptors that are valid at the time 'now',
	   or at the current time if 'now' is None."""
	self.directory = directory
	createPrivateDir(directory)
	self.byNickname = {}
	self.byFilename = {}

	if now is None:
	    now = time.time()

	for f in os.listdir(self.directory):
	    # Try to read a file: is it a server descriptor?
	    p = os.path.join(self.directory, f)
	    try:
		info = ServerInfo(fname=p, assumeValid=0)
	    except ConfigError:
		LOG.warn("Invalid server descriptor %s", p)
		continue

	    # Find its nickname and normalized filename
	    serverSection = info['Server']
	    nickname = serverSection['Nickname']

	    if '.' in f:
		f = f[:f.rindex('.')]

	    # Skip the descriptor if it isn't valid yet...
	    if now < serverSection['Valid-After']:
		LOG.info("Ignoring future decriptor %s", p)
		continue
	    # ... or if it's expired ...
	    if now >= serverSection['Valid-Until']:
		LOG.info("Ignoring expired decriptor %s", p)
		continue
	    # ... or if it's going to expire within 3 hours (HACK!).
	    if now + 3*60*60 >= serverSection['Valid-Until']:
		LOG.info("Ignoring soon-to-expire decriptor %s", p)
		continue
	    # Only allow one server per nickname ...
	    if self.byNickname.has_key(nickname):
		LOG.warn(
		    "Ignoring descriptor %s with duplicate nickname %s",
		    p, nickname)
		continue
	    # ... and per normalized filename.
	    if self.byFilename.has_key(f):
		LOG.warn(
		    "Ignoring descriptor %s with duplicate prefix %s",
		    p, f)
		continue
	    LOG.info("Loaded server %s from %s", nickname, f)
	    # Okay, it's good. Cache it.
	    self.byNickname[nickname] = info
	    self.byFilename[f] = info

    def getServerInfo(self, name):
	"""Return a ServerInfo object corresponding to 'name'.  If 'name' is
 	   a ServerInfo object, returns 'name'.  Otherwise, checks server by
 	   nickname, then by filename within the keystore, then by filename
 	   on the file system. If no server is found, returns None."""
	if isinstance(name, ServerInfo):
	    return name
	elif self.byNickname.has_key(name):
	    return self.byNickname[name]
	elif self.byFilename.has_key(name):
	    return self.byFilename[name]
	elif os.path.exists(name):
	    try:
		return ServerInfo(fname=name, assumeValid=0)
	    except OSError, e:
		raise MixError("Couldn't read descriptor %s: %s" %
			       (name, e))
	    except ConfigError, e:
		raise MixError("Couldn't parse descriptor %s: %s" %
			       (name, e))
	else:
	    return None

    def getPath(self, serverList):
	"""Given a sequence of strings of ServerInfo objects, resolves each
	   one according to the rule of getServerInfo, and returns a list of
	   ServerInfos.  Raises MixError if any server can't be resolved."""
	path = []
	for s in serverList:
	    if isinstance(s, ServerInfo):
		path.append(s)
	    elif isinstance(s, types.StringType):
		server = self.getServerInfo(s)
		if server is not None:
		    path.append(server)
		else:
		    raise MixError("Couldn't find descriptor %s" % s)
	return path

    def listServers(self):
	"""Returns a linewise listing of the current servers and their caps.
	   stdout.  This will go away or get refactored in future versions
	   once we have real path selection and client-level modules."""
        lines = []
        nicknames = self.byNickname.keys()
	nicknames.sort()
	longestnamelen = max(map(len, nicknames))
	fmtlen = min(longestnamelen, 20)
	format = "%"+str(fmtlen)+"s (expires %s): %s"
	for n in nicknames:
	    caps = []
	    si = self.byNickname[n]
	    if si['Delivery/MBOX'].get('Version',None):
		caps.append("mbox")
	    if si['Delivery/SMTP'].get('Version',None):
		caps.append("smtp")
	    # XXXX This next check is highly bogus.
	    if (si['Incoming/MMTP'].get('Version',None) and 
		si['Outgoing/MMTP'].get('Version',None)):
		caps.append("relay")
	    until = formatDate(si['Server']['Valid-Until'])
	    line = format % (n, until, " ".join(caps))
	    lines.append(line)
	return lines

    def getRandomServers(self, prng, n):
	"""Returns a list of n different servers, in random order, according
	   to prng.  Raises MixError if not enough exist.

	   (This isn't actually used.)"""
	vals = self.byNickname.values()
	if len(vals) < n:
	    raise MixError("Not enough servers (%s requested)", n)
	return prng.shuffle(vals, n)

def installDefaultConfig(fname):
    """Create a default, 'fail-safe' configuration in a given file"""
    LOG.warn("No configuration file found. Installing default file in %s",
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
    """Access point for client functionality.  Currently, this is limited
       to generating and sending forward messages"""
    ## Fields:
    # config: The ClientConfig object with the current configuration
    # keystore: A TrivialKeystore object
    # prng: A pseudo-random number generator for padding and path selection
    def __init__(self, conf):
	"""Create a new MixminionClient with a given configuration"""
	self.config = conf

	# Make directories
	userdir = os.path.expanduser(self.config['User']['UserDir'])
	createPrivateDir(userdir)
	#createPrivateDir(os.path.join(userdir, 'surbs'))
	createPrivateDir(os.path.join(userdir, 'servers'))

	# Get directory cache
	self.keystore = TrivialKeystore(
	    os.path.join(userdir,"servers"))

	# Initialize PRNG
	self.prng = mixminion.Crypto.getCommonPRNG()

    def sendForwardMessage(self, address, payload, path1, path2):
	"""Generate and send a forward message.
	    address -- the results of a parseAddress call
	    payload -- the contents of the message to send
	    path1,path2 -- lists of servers or server names for the first and
	       second legs of the path, respectively.  These are processed
	       as described in TrivialKeystore.getServerInfo"""
	message, firstHop = \
		 self.generateForwardMessage(address, payload, path1, path2)

	self.sendMessages([message], firstHop)

    def generateForwardMessage(self, address, payload, path1, path2):
	"""Generate a forward message, but do not send it.  Returns
	   a tuple of (the message body, a ServerInfo for the first hop.)

	    address -- the results of a parseAddress call
	    payload -- the contents of the message to send
	    path1,path2 -- lists of servers or server names for the first and
	       second legs of the path, respectively.  These are processed
	       as described in TrivialKeystore.getServerInfo"""
        if not path1:
	    raise MixError("No servers in first leg of path")
	if not path2:
	    raise MixError("No servers in second leg of path")

	servers1 = self.keystore.getPath(path1)
	servers2 = self.keystore.getPath(path2)

	routingType, routingInfo, lastHop = address.getRouting()
	if lastHop is None:
            lastServer = servers2[-1]
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
	msg = mixminion.BuildMessage.buildForwardMessage(
	    payload, routingType, routingInfo, servers1, servers2,
	    self.prng)
	return msg, servers1[0]

    def sendMessages(self, msgList, server):
	"""Given a list of packets and a ServerInfo object, sends the
	   packets to the server via MMTP"""
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
    """Parse and validate an address; takes a string, and returns an Address
       object.

       Accepts strings of the format:
              mbox:<mailboxname>@<server>
           OR smtp:<email address>
	   OR <email address> (smtp is implicit)
	   OR drop
	   OR 0x<routing type>:<routing info>
    """
    # ???? Should this should get refactored into clientmodules, or someplace?
    if s.lower() == 'drop':
	return Address(DROP_TYPE, None, None)
    elif s.lower() == 'test':
	return Address(0xFFFE, "", None)
    elif ':' not in s:
	if isSMTPMailbox(s):
	    return Address(SMTP_TYPE, s, None)
	else:
	    raise ParseError("Can't parse address %s"%s)
    tp,val = s.split(':', 1)
    tp = tp.lower()
    if tp.startswith("0x"):
	try:
	    tp = int(tp[2:], 16)
	except ValueError:
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
    """Represents the target address for a Mixminion message.
       Consists of the exitType for the final hop, the routingInfo for
       the last hop, and (optionally) a server to use as the last hop.
       """
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

    LOG.configure(config)
    if verbose:
	LOG.setMinSeverity("DEBUG")

    LOG.debug("Configuring client")
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

def listServers(cmd, args):
    options, args = getopt.getopt(args, "hf:", ['help', 'config='])
    configFile = None
    for o,v in options:
	if o in ('-h', '--help'):
	    print "Usage %s [--help] [--config=configFile]"
	    sys.exit(1)
	elif o in ('-f', '--config'):
	    configFile = v

    # XXXX duplicate code; refactor into separate method.
    if configFile is None:
	configFile = os.environ.get("MIXMINIONRC", None)
	if configFile is None:
	    configFile = "~/.mixminionrc"
    configFile = os.path.expanduser(configFile)
    if not os.path.exists(configFile):
	installDefaultConfig(configFile)
    config = readConfigFile(configFile)

    userdir = os.path.expanduser(config['User']['UserDir'])
    createPrivateDir(os.path.join(userdir, 'servers'))

    keystore = TrivialKeystore(os.path.join(userdir,"servers"))
	
    for line in keystore.listServers():
	print line
