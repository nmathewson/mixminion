# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ClientUtils

   This module holds helper code not included in the Mixminion Client
   API, but useful for more than one user interface.
   """

__all__ = [ 'NoPassword', 'PasswordManager', 'getPassword_term',
            'getNewPassword_term', 'SURBLog', 'ClientQueue' ]

import binascii
import cPickle
import getpass
import os
import sys
import time

import mixminion.Crypto
import mixminion.Filestore

from mixminion.Common import LOG, MixError, UIError, createPrivateDir, \
     floorDiv, previousMidnight, readFile, writeFile

#----------------------------------------------------------------------
class BadPassword(MixError):
    """Exception raised when we try to access a password-protected resource
       and the user doesn't give the right password"""
    pass

class PasswordManager:
    """A PasswordManager keeps track of a set of named passwords, so that
       a user never has to enter any password more than once.  This is an
       abstract class."""
    ## Fields
    # passwords: map from password name to string value of the password.
    def __init__(self):
        """Create a new PasswordManager"""
        self.passwords = {}
    def _getPassword(self, name, prompt):
        """Abstract function; subclasses must override.

           Use the prompt 'prompt' to ask the user for the password
           'name'.  Return what the user enters.
        """   
        raise NotImplemented()
    def _getNewPassword(self, name, prompt):
        """Abstract function; subclasses must override.

           Use the prompt 'prompt' to ask the user for a _new_
           password 'name'.  Ususally, this will involve asking for
           the password twice to confirm that the user hasn't mistyped.
        """   
        raise NotImplemented()
    def setPassword(self, name, password):
        """Change the internally cached value for the password named
           'name' to 'password'."""
        self.passwords[name] = password
    def getPassword(self, name, prompt, confirmFn, maxTries=-1):
        """Return the password named 'name', querying using the prompt
           'prompt' if necessary.  Before returning a prospective
           password, we call 'confirmFn' on it.  If confirmFn returns 1,
           the password is correct.  If confirmFn returns 0, the password
           is incorrect.  Queries the user at most 'maxTries' times before
           giving up.  Raises BadPassword on failure.""" 
        if self.passwords.has_key(name):
            pwd = self.passwords[name]
            if confirmFn(pwd):
                self.passwords[name] = pwd
                return pwd
        for othername, pwd in self.passwords.items():
            if confirmFn(pwd):
                self.passwords[name] = pwd
                return pwd
        pmt = prompt
        while maxTries:
            pwd = self._getPassword(name, pmt)
            if confirmFn(pwd):
                self.passwords[name] = pwd
                return pwd
            maxTries -= 1
            pmt = "Incorrect password. "+prompt

        raise BadPassword()
    def getNewPassword(self, name, prompt):
        """Use 'prompt' to ask the user for a fresh password named 'name'."""
        self.passwords[name] = self._getNewPassword(name, prompt)
        return self.passwords[name]

class CLIPasswordManager(PasswordManager):
    """Impementation of PasswordManager that asks for passwords from the
       command line."""
    def __init__(self):
        PasswordManager.__init__(self)
    def _getPassword(self, name, prompt):
        return getPassword_term(prompt)
    def _getNewPassword(self, name, prompt):
        return getNewPassword_term(prompt)

def getPassword_term(prompt):
    """Read a password from the console, then return it.  Use the string
       'message' as a prompt."""
    # getpass.getpass uses stdout by default .... but stdout may have
    # been redirected.  If stdout is not a terminal, write the message
    # to stderr instead.
    if os.isatty(sys.stdout.fileno()):
        f = sys.stdout
        nl = 0
    else:
        f = sys.stderr
        nl = 1
    f.write(prompt)
    f.flush()
    try:
        p = getpass.getpass("")
    except KeyboardInterrupt:
        if nl: print >>f
        raise UIError("Interrupted")
    if nl: print >>f
    return p

def getNewPassword_term(prompt):
    """Read a new password from the console, then return it."""
    s2 = "Verify password:".rjust(len(prompt))
    if os.isatty(sys.stdout.fileno()):
        f = sys.stdout
    else:
        f = sys.stderr
    while 1:
        p1 = getPassword_term(prompt)
        p2 = getPassword_term(s2)
        if p1 == p2:
            return p1
        f.write("Passwords do not match.\n")
        f.flush()

#----------------------------------------------------------------------
# Functions to save and load data do disk in password-encrypted files.
#
# The file format is:
#     variable      [File-specific magic, used to make sure we have an
#                    encrypted file.]
#     8 bytes       [Random salt.]
#     variable      [AES-CTR Encrypted data:
#                             key is sha1(salt+password+salt),
#                             value is data+sha1(data+salt+magic)]
#
# Note that this format does not conceal the length of the data.

def readEncryptedFile(fname, password, magic):
    """Read encrypted data from the file named 'fname', using the password
       'password' and checking for the filetype 'magic'.  Returns the 
       plaintext file contents on success.  If the 

       If the file is corrupt or the password is wrong, raises BadPassword.
       If the magic is incorrect, raises ValueError.
    """
    s = readFile(fname, 1)
    if not s.startswith(magic):
        raise ValueError("Invalid versioning on %s"%fname)
    s = s[len(magic):]
    if len(s) < 28:
        raise MixError("File %s too short."%fname)
    salt = s[:8]
    s = s[8:]
    key = mixminion.Crypto.sha1(salt+password+salt)[:16]
    s = mixminion.Crypto.ctr_crypt(s, key)
    data = s[:-20]
    hash = s[-20:]
    if hash != mixminion.Crypto.sha1(data+salt+magic):
        raise BadPassword()
    return data

def writeEncryptedFile(fname, password, magic, data):
    """Write 'data' into an encrypted file named 'fname', replacing it
       if necessary.  Encrypts the data with the password 'password',
       and uses the filetype 'magic'."""
    salt = mixminion.Crypto.getCommonPRNG().getBytes(8)
    key = mixminion.Crypto.sha1(salt+password+salt)[:16]
    hash = mixminion.Crypto.sha1("".join([data,salt,magic]))
    encrypted = mixminion.Crypto.ctr_crypt(data+hash, key)
    writeFile(fname, "".join([magic,salt,encrypted]), binary=1)

def readEncryptedPickled(fname, password, magic):
    """Read the pickled object stored in the encrypted file 'fname'. Arguments
       are as for 'readEncryptedFile'."""
    return cPickle.loads(readEncryptedFile(fname, password, magic))

def writeEncryptedPickled(fname, password, magic, obj):
    """Write 'obj' into encrypted file 'fname'. Arguments are as for
       'writeEncryptedFile'."""
    data = cPickle.dumps(obj, 1)
    writeEncryptedFile(fname, password, magic, data)

class LazyEncryptedPickled:
    """Wrapper for a file containing an encrypted pickled object, to
       perform password querying and loading on demand."""
    def __init__(self, fname, pwdManager, pwdName, queryPrompt, newPrompt,
                 magic, initFn):
        """Create a new LazyEncryptedPickled
              fname -- The name of the file to hold the encrypted object.
              pwdManager -- A PasswordManager instance.
              pwdName, queryPrompt, newPrompt -- Arguments used when getting
                  passwords from the PasswordManager.
              magic -- The filetype to use for the encrypted file.
              initFn -- A callable object that returns a fresh value for
                  a newly created encrypted file.
        """
        self.fname = fname
        self.pwdManager = pwdManager
        self.pwdName = pwdName
        self.queryPrompt = queryPrompt
        self.newPrompt = newPrompt
        self.magic = magic
        self.object = None
        self.loaded = 0
        self.password = None
        self.initFn = initFn
    def load(self, create=0,password=None):
        """Try to load the encrypted file from disk.  If 'password' is
           not provided, query it from the password manager.  If the file
           does not exist, and 'create' is true, get a new password and
           create the file."""
        if self.loaded:
            return 
        elif os.path.exists(self.fname):
            if not readFile(self.fname).startswith(self.magic):
                raise MixError("Unrecognized versioning on file %s"%self.fname)
            # ... see if we can load it with no password ...
            if self._loadWithPassword(""):
                return
            if password is not None:
                self._loadWithPassword(password)
                if not self.loaded:
                    raise BadPassword()
            else:
                # sets self.password on successs
                self.pwdManager.getPassword(self.pwdName, self.queryPrompt,
                                            self._loadWithPassword)
        elif create:
            if password is not None:
                self.password = password
            else:
                self.password = self.pwdManager.getNewPassword(
                    self.pwdName, self.newPrompt)
            self.object = self.initFn()
            self.loaded = 1
            self.save()
        else:
            return
    def _loadWithPassword(self, password):
        """Helper function: tries to load the file with a given password.
           If Successful, return 1. Else return 0."""
        try:
            self.object = readEncryptedPickled(self.fname,password,self.magic)
            self.password = password
            self.loaded = 1
            return 1
        except MixError:
            return 0
    def isLoaded(self):
        """Return true iff this file has been successfully loaded."""
        return self.loaded
    def get(self):
        """Returns the contents of this file. The file must first have
           been loaded."""
        assert self.loaded
        return self.object
    def set(self, val):
        """Set the contents of this file.  Does not save the file to
           disk."""
        self.object = val
        self.loaded = 1
    def setPassword(self, pwd):
        """Set the password on this file."""
        self.password = pwd
        self.pwdManager.setPassword(self.pwdName, pwd)
    def save(self):
        """Flush the current contens of this file to disk."""
        assert self.loaded and self.password is not None
        writeEncryptedPickled(self.fname, self.password, self.magic,
                              self.object)
        
# ----------------------------------------------------------------------

class SURBLog(mixminion.Filestore.DBBase):
    """A SURBLog manipulates a database on disk to remember which SURBs we've
       used, so we don't reuse them accidentally.
       """
    #FFFF Using this feature should be optional.
    ## Format:
    # The database holds two kinds of keys:
    #    "LAST_CLEANED" -> an integer of the last time self.clean() was called.
    #    20-byte-hash-of-SURB -> str(expiry-time-of-SURB)
    def __init__(self, filename, forceClean=0):
        """Open a new SURBLog to store data in the file 'filename'.  If
           forceClean is true, remove expired entries on startup.
        """
        mixminion.ClientMain.clientLock() #XXXX
        mixminion.Filestore.DBBase.__init__(self, filename, "SURB log")
        try:
            lastCleaned = int(self.log['LAST_CLEANED'])
        except (KeyError, ValueError):
            lastCleaned = 0

        if lastCleaned < time.time()-24*60*60 or forceClean:
            self.clean()
        self.sync()

    def findUnusedSURBs(self, surbList, nSURBs=1, verbose=0, now=None):
        """Given a list of ReplyBlock objects, find the first that is neither
           expired, about to expire, or used in the past.  Return None if
           no such reply block exists. DOCDOC returns list, nSurbs"""
        if now is None:
            now = time.time()
        nUsed = nExpired = nShortlived = 0
        result = []
        for surb in surbList: 
            expiry = surb.timestamp
            timeLeft = expiry - now
            if self.isSURBUsed(surb):
                nUsed += 1
            elif timeLeft < 60:
                nExpired += 1
            elif timeLeft < 3*60*60:
                nShortlived += 1
            else:
                result.append(surb)
                if len(result) >= nSURBs:
                    break

        if verbose:
            if nUsed:
                LOG.warn("Skipping %s used reply blocks", nUsed)
            if nExpired:
                LOG.warn("Skipping %s expired reply blocks", nExpired)
            if nShortlived:
                LOG.warn("Skipping %s soon-to-expire reply blocks",nShortlived)

        return result

    def close(self):
        """Release resources associated with the surblog."""
        mixminion.Filestore.DBBase.close(self)
        mixminion.ClientMain.clientUnlock()

    def isSURBUsed(self, surb):
        """Return true iff the ReplyBlock object 'surb' is marked as used."""
        return self.has_key(surb)

    def markSURBUsed(self, surb):
        """Mark the ReplyBlock object 'surb' as used."""
        self[surb] = surb.timestamp

    def clean(self, now=None):
        """Remove all entries from this SURBLog the correspond to expired
           SURBs.  This is safe because if a SURB is expired, we'll never be
           able to use it inadvertently."""
        if now is None:
            now = time.time() + 60*60
        allHashes = self.log.keys()
        removed = []
        for hash in allHashes:
            if self._decodeVal(self.log[hash]) < now:
                removed.append(hash)
        del allHashes
        for hash in removed:
            del self.log[hash]
        self.log['LAST_CLEANED'] = str(int(now))
        self.sync()

    def _encodeKey(self, surb):
        return binascii.b2a_hex(mixminion.Crypto.sha1(surb.pack()))
    def _encodeVal(self, timestamp):
        return str(timestamp)
    def _decodeVal(self, timestamp):
        try:
            return int(timestamp)
        except ValueError:
            return 0

# ----------------------------------------------------------------------
class ClientQueue:
    """A ClientQueue holds packets that have been scheduled for delivery
       but not yet delivered.  As a matter of policy, we queue messages if
       the user tells us to, or if deliver has failed and the user didn't
       tell us not to."""
    ## Fields:
    # dir -- a directory to store packets in.
    # store -- an instance of ObjectMetadataStore.  The objects are of the
    #    format:
    #           ("PACKET-0",
    #             a 32K string (the packet),
    #             an instance of IPV4Info or HostInfo (the first hop),
    #             the latest midnight preceding the time when this
    #                 packet was inserted into the queue
    #           )
    #    The metadata is of the format:
    #           ("V0",
    #             an instance of IPV4Info or HostInfo (the first hop),
    #             the latest midnight preceding the time when this
    #                 packet was inserted into the queue
    #           )
    #    [These formats are redundant so that 0.0.6 and 0.0.5 clients
    #     stay backward compatible for now.]
    #
    # XXXX006 write unit tests
    def __init__(self, directory, prng=None):
        """Create a new ClientQueue object, storing packets in 'directory'
           and generating random filenames using 'prng'."""
        self.dir = directory
        createPrivateDir(directory)

        # We used to name entries "pkt_X"; this has changed.
        # XXXX007 remove this when it's no longer needed.
        for fn in os.listdir(directory):
            if fn.startswith("pkt_"):
                handle = fn[4:]
                fname_old = os.path.join(directory, fn)
                fname_new = os.path.join(directory, "msg_"+handle)
                os.rename(fname_old, fname_new)
        
        self.store = mixminion.Filestore.ObjectMetadataStore(
            directory, create=1, scrub=1)

        self.metadataLoaded = 0

    def queuePacket(self, packet, routing, now=None):
        """Insert the 32K packet 'packet' (to be delivered to 'routing')
           into the queue.  Return the handle of the newly inserted packet."""
        if now is None:
            now = time.time()
        mixminion.ClientMain.clientLock()
        try:
            fmt = ("PACKET-0", packet, routing, previousMidnight(now))
            meta = ("V0", routing, previousMidnight(now))
            return self.store.queueObjectAndMetadata(fmt,meta)
        finally:
            mixminion.ClientMain.clientUnlock()

    def getHandles(self):
        """Return a list of the handles of all packets currently in the
           queue."""
        mixminion.ClientMain.clientLock()
        try:
            return self.store.getAllMessages()
        finally:
            mixminion.ClientMain.clientUnlock()

    def getRouting(self, handle):
        """Return the routing information associated with the given handle."""
        self.loadMetadata()
        return self.store.getMetadata(handle)[1]

    def getPacket(self, handle):
        """Given a handle, return a 3-tuple of the corresponding
           32K packet, {IPV4/Host}Info, and time of first queueing.  (The time
           is rounded down to the closest midnight GMT.)  May raise 
           CorruptedFile."""
        obj = self.store.getObject(handle)
        try:
            magic, packet, routing, when = obj
        except (ValueError, TypeError):
            magic = None
        if magic != "PACKET-0":
            LOG.error("Unrecognized packet format for %s",handle)
            return None
        return packet, routing, when

    def packetExists(self, handle):
        """Return true iff the queue contains a packet with the handle
           'handle'."""
        return self.store.messageExists(handle)

    def removePacket(self, handle):
        """Remove the packet named with the handle 'handle'."""
        self.store.removeMessage(handle)

    def inspectQueue(self, now=None):
        """Print a message describing how many packets in the queue are headed
           to which addresses."""
        #XXXX006 refactor
        if now is None:
            now = time.time()
        handles = self.getHandles()
        if not handles:
            print "[Queue is empty.]"
            return
        self.loadMetadata()
        timesByServer = {}
        for h in handles:
            try:
                _, routing, when = self.store.getMetadata(h)
            except mixminion.Filestore.CorruptedFile:
                continue
            timesByServer.setdefault(routing, []).append(when)
        for s in timesByServer.keys():
            count = len(timesByServer[s])
            oldest = min(timesByServer[s])
            days = floorDiv(now - oldest, 24*60*60)
            if days < 1:
                days = "<1"
            print "%2d packets for server at %s:%s (oldest is %s days old)"%(
                count, s.ip, s.port, days)

    def cleanQueue(self, maxAge=None, now=None):
        """Remove all packets older than maxAge seconds from this queue."""
        if now is None:
            now = time.time()
        if maxAge is not None:
            cutoff = now - maxAge
            remove = []
            self.loadMetadata()
            for h in self.getHandles():
                try:
                    when = self.store.getMetadata(h)[2]
                except mixminion.Filestore.CorruptedFile:
                    continue
                if when < cutoff:
                    remove.append(h)
            LOG.info("Removing %s old packets from queue", len(remove))
            for h in remove:
                self.store.removeMessage(h)
        self.store.cleanQueue()

    def loadMetadata(self):
        """Ensure that we've loaded metadata for this queue from disk."""
        if self.metadataLoaded:
            return

        # Helper function: create metadata from a file without it.
        def fixupHandle(h,self=self):
            packet, routing, when = self.getPacket(h)
            return "V0", routing, when

        self.store.loadAllMetadata(fixupHandle)

        self.metadataLoaded = 1
