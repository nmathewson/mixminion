# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientMain.py,v 1.1 2002/08/31 04:12:36 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.

   XXXX THIS ISN'T IMPLEMENTED YET!  This file is just a placeholder that
   XXXX routes a testing message through a few servers so I can make sure that
   XXXX at least one configuration works.
   """

import os
import getopt
import sys
import time
import bisect

import mixminion.Crypto
from mixminion.Common import getLog, floorDiv
import mixminion.Config
import mixminion.BuildMessage
import mixminion.MMTPClient
import mixminion.Modules

def sendTestMessage(servers1, servers2):
    assert len(servers1)
    assert len(servers2)
    payload = """ 
           Insert
	   Example
	   Message
	   Here.
	   """
    rt, ri = 0xFFFE, "deliver"
    m = mixminion.BuildMessage.buildForwardMessage(payload,
						   rt, ri,
						   servers1, servers2)
    firstHop = servers1[0]
    b = mixminion.MMTPClient.BlockingClientConnection(firstHop.getAddr(),
						      firstHop.getPort(),
						      firstHop.getKeyID())
    b.connect()
    b.sendPacket(m)
    b.shutdown()


def readConfigFile(configFile):
    try:
	return mixminion.Config.ClientConfig(fname=configFile)
    except (IOError, OSError), e:
	print >>sys.stderr, "Error reading configuration file %r:"%configFile
	print >>sys.stderr, "   ", str(e)
	sys.exit(1)
    except mixminion.Config.ConfigError, e:
	print >>sys.stderr, "Error in configuration file %r"%configFile
	print >>sys.stderr, str(e)
	sys.exit(1)

# XXXX This isn't anything LIKE the final client interface: for now, I'm
# XXXX just testing the server.
def runClient(cmd, args):
    options, args = getopt.getopt(args, "hf:", ["help", "config="])
    configFile = '~/.mixminion/mixminion.conf'
    usage = 0
    for opt,val in options:
	if opt in ('-h', '--help'):
	    usage=1
	elif opt in ('-f', '--config'):
	    configFile = val
    if usage:
	print >>sys.stderr, "Usage: %s [-h] [-f configfile] server1 server2..."%cmd
	sys.exit(1)
    config = readConfigFile(os.path.expanduser(configFile))

    getLog().setMinSeverity("INFO")
    mixminion.Crypto.init_crypto(config)
    if len(args) < 2:
	print >> sys.stderr, "I need at least 2 servers"
    servers = [ mixminion.ServerInfo.ServerInfo(fn) for fn in args ]
    idx = floorDiv(len(servers),2)

    sendTestMessage(servers[:idx], servers[idx:])


