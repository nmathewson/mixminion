# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: testSupport.py,v 1.3 2002/08/29 03:30:21 nickm Exp $

"""mixminion.testSupport

   Shared support code for unit tests, benchmark tests, and integration tests
   """

import os
import sys
import stat

from mixminion.Common import waitForChildren, createPrivateDir
from mixminion.Config import _parseBoolean, ConfigError
from mixminion.Modules import DeliveryModule, ImmediateDeliveryQueue, \
     SimpleModuleDeliveryQueue, DELIVER_OK, DELIVER_FAIL_RETRY, \
     DELIVER_FAIL_NORETRY

class DirectoryStoreModule(DeliveryModule):
    """Delivery module for testing: puts messages in files in a given
       directory.  Can be configured to use a delivery queue or not.

       When this module delivers a message:
       If the routing info is 'FAIL!', the message is treated as undeliverable.
       If the routing info is 'fail', the message is treated as temporarily
         undeliverable (and so will eventually time out).
       Otherwise, creates a file in the specified directory, containing
          the routing info, a newline, and the message contents.
    """
    def getConfigSyntax(self):
	return { 'Testing/DirectoryDump':
		 { 'Location' : ('REQUIRE', None, None),
		   'UseQueue': ('REQUIRE', _parseBoolean, None) } }
    
    def validateConfig(self, sections, entries, lines, contents):
	# loc = sections['Testing/DirectoryDump'].get('Location')
	pass 
    
    
    def configure(self, config, manager):
	self.loc = config['Testing/DirectoryDump'].get('Location')
	if not self.loc:
	    return
	self.useQueue = config['Testing/DirectoryDump']['UseQueue']
	#manager.registerModule(self)
	
	if not os.path.exists(self.loc):
	    createPrivateDir(self.loc)

	max = -1
	for f in os.listdir(self.loc):
	    if int(f) > max: 
		max = int(f)
	self.next = max+1

    def getServerInfoBlock(self):
	return ""

    def getName(self):
	return "Testing_DirectoryDump"
    
    def getExitTypes(self):
	return [ 0xFFFE ]
    
    def createDeliveryQueue(self, queueDir):
	if self.useQueue:
	    return SimpleModuleDeliveryQueue()#XXXX
	else:
	    return ImmediateDeliveryQueue(self)
	
    def processMessage(self, message, exitType, exitInfo):
	assert exitType == 0xFFFE
	if exitInfo == 'fail':
	    return DELIVER_FAIL_RETRY
	elif exitInfo == 'FAIL!':
	    return DELIVER_FAIL_NORETRY

	f = open(os.path.join(self.loc, self.next), 'w')
	self.next += 1
	f.write(exitInfo)
	f.write("\n")
	f.write(message)
	f.close()
	return DELIVER_OK

#----------------------------------------------------------------------

# Test for acceptable permissions and uid on directory?
_MM_TESTING_TEMPDIR_PARANOIA = 1
# Holds 
_MM_TESTING_TEMPDIR = None
_MM_TESTING_TEMPDIR_COUNTER = 0
_MM_TESTING_TEMPDIR_REMOVE_ON_EXIT = 1
def mix_mktemp(extra=""):
    '''mktemp wrapper. puts all files under a securely mktemped
       directory.'''
    global _MM_TESTING_TEMPDIR
    global _MM_TESTING_TEMPDIR_COUNTER
    if _MM_TESTING_TEMPDIR is None:
	import tempfile
	temp = tempfile.mktemp()
	paranoia = _MM_TESTING_TEMPDIR_PARANOIA
	if paranoia and os.path.exists(temp):
	    print "I think somebody's trying to exploit mktemp."
	    sys.exit(1)
	try:
	    os.mkdir(temp, 0700)
	except OSError, e:
	    print "Something's up with mktemp: %s" % e
	    sys.exit(1)
	if not os.path.exists(temp):
	    print "Couldn't create temp dir %r" %temp
	    sys.exit(1)
	st = os.stat(temp)
	if paranoia:
	    if st[stat.ST_MODE] & 077:
		print "Couldn't make temp dir %r with secure permissions" %temp
		sys.exit(1)
	    if st[stat.ST_UID] != os.getuid():
		print "The wrong user owns temp dir %r"%temp
		sys.exit(1)
	    parent = temp
	    while 1:
		p = os.path.split(parent)[0]
		if parent == p:
		    break
		parent = p
		st = os.stat(parent)
		m = st[stat.ST_MODE]
		if m & 02 and not (m & stat.S_ISVTX):
		    print "Directory %s has fishy permissions %o" %(parent,m)
		    sys.exit(1)
		if st[stat.ST_UID] not in (0, os.getuid()):
		    print "Directory %s has bad owner %s" % st[stat.ST_UID]
		    sys.exit(1)
		    
	_MM_TESTING_TEMPDIR = temp
	if _MM_TESTING_TEMPDIR_REMOVE_ON_EXIT:
	    import atexit
	    atexit.register(deltree, temp)
    
    _MM_TESTING_TEMPDIR_COUNTER += 1
    return os.path.join(_MM_TESTING_TEMPDIR,
			"tmp%05d%s" % (_MM_TESTING_TEMPDIR_COUNTER,extra))

_WAIT_FOR_KIDS = 1
def deltree(*dirs):
    """Delete each one of a list of directories, along with all of its
       contents"""
    global _WAIT_FOR_KIDS
    if _WAIT_FOR_KIDS:
	print "Waiting for shred processes to finish."
	waitForChildren()
	_WAIT_FOR_KIDS = 0
    for d in dirs:
        if os.path.isdir(d):
            for fn in os.listdir(d):
		loc = os.path.join(d,fn)
		if os.path.isdir(loc):
		    deltree(loc)
		else:
		    os.unlink(loc)
            os.rmdir(d)
        elif os.path.exists(d):
            os.unlink(d)
