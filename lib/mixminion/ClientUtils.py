# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ClientUtils

   This module holds helper code not included in the Mixminion Client
   API, but useful for more than one user interface.
   """

__all__ = [ 'NoPassword', 'PasswordManager', 'getPassword_term',
            'getNewPassword_term', 'SURBLog', 'ClientQueue',
            'ClientFragmentPool' ]

import binascii
import cPickle
import getpass
import os
import sys
import time
import types
import struct

import mixminion.Filestore
import mixminion.Packet

from mixminion.Common import LOG, MixError, UIError, ceilDiv, \
     createPrivateDir, floorDiv, previousMidnight, readFile, \
     succeedingMidnight, writeFile, armorText, unarmorText
from mixminion.Crypto import sha1, ctr_crypt, DIGEST_LEN, AES_KEY_LEN, \
     getCommonPRNG, trng

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
    # do_retry: static field: should we keep asking for a password until
    #    one is correct?
    do_retry = 1
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
            if not self.do_retry:
                break
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
    def __init__(self, password_fileno=None):
        PasswordManager.__init__(self)
    def _getPassword(self, name, prompt):
        return getPassword_term(prompt)
    def _getNewPassword(self, name, prompt):
        return getNewPassword_term(prompt)

class FDPasswordManager(PasswordManager):
    """Impementation of PasswordManager that asks for passwords from a
       specified fileno."""
    do_retry = 0
    def __init__(self, password_fileno=None):
        PasswordManager.__init__(self)
        self.password_fileno = password_fileno
    def _getPassword(self, name, prompt):
        return getPassword_fd(self.password_fileno)
    def _getNewPassword(self, name, prompt):
        return getPassword_fd(self.password_fileno)

def getPassword_fd(fileno):
    """Read a password from a specified fileno."""
    pw = ""
    while 1:
        chunk = os.read(fileno, 1024) # read from --password-fd filehandle
        if not chunk:
            break
        pw += chunk
    # Strip trailing endline from password, if any.  
    if pw.endswith("\n"): pw = pw[:-1]
    return pw

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
    if os.isatty(sys.stdin.fileno()):
        # If stdin is a tty, then we use the magic from getpass.getpass to
        # disable echoing and read a line.
        f.write(prompt)
        f.flush()
        try:
            p = getpass.getpass("")
        except KeyboardInterrupt:
            if nl: print >>f
            raise UIError("Interrupted")
        if nl: print >>f
    else:
        # If stdin is _not_ a tty, however, then the getpass magic can
        # raise exceptions.
        print >>f, "Reading password from stdin."
        p = sys.stdin.readline()
        if not p: raise UIError("No password received")
        if p[-1] == '\n': p = p[:-1]
    return p

def getNewPassword_term(prompt):
    """Read a new password from the console, then return it."""
    s2 = "Verify passphrase:".rjust(len(prompt))
    if os.isatty(sys.stdout.fileno()):
        f = sys.stdout
    else:
        f = sys.stderr
    if not os.isatty(sys.stdin.fileno()):
        p1 = getPassword_term("")
        return p1
    while 1:
        p1 = getPassword_term(prompt)
        p2 = getPassword_term(s2)
        if p1 == p2:
            return p1
        f.write("Passphrases do not match.\n")
        f.flush()

    raise AssertionError # unreached; appease pychecker

#----------------------------------------------------------------------
# Functions to save and load data do disk in password-encrypted files.
#
# The file format is documented in E2E-spec.txt.

MAGIC_LEN = 8
SALT_LEN = 8

def _readEncryptedFile(fname, password, magicList):
    """Read encrypted data from the file named 'fname', using the password
       'password' and checking for a magic string contained in 'magicList'.
       Returns the magic string and the plaintext file contents on success.

       If the file is corrupt or the password is wrong, raises BadPassword.
       If the magic is incorrect, raises ValueError.
    """
    assert list(map(len, magicList)) == [8]*len(magicList)

    text = readFile(fname)
    r = unarmorText(text, ["TYPE III KEYRING"])
    if len(r) != 1:
        raise ValueError("Bad ascii armor on keyring")
    tp, headers, s = r[0]
    assert tp == "TYPE III KEYRING"
    vers = [ v for k,v in headers if k == 'Version' ]
    if not vers or vers[0] != '0.1':
        raise ValueError("Unrecognized version on keyring")

    if len(s) < MAGIC_LEN+1 or s[MAGIC_LEN] != '\x00':
        raise ValueError("Unrecognized encryption format on %s"%fname)
    if s[:MAGIC_LEN] not in magicList:
        raise ValueError("Invalid versioning on %s"%fname)
    magic = s[:8]
    s = s[MAGIC_LEN+1:]
    if len(s) < 28:
        raise MixError("File %s is too short."%fname)
    salt = s[:SALT_LEN]
    s = s[SALT_LEN:]
    key = sha1(salt+password+salt)[:AES_KEY_LEN]
    s = ctr_crypt(s, key)
    data = s[:-DIGEST_LEN]
    digest = s[-DIGEST_LEN:]
    if digest != sha1(data+salt+magic):
        raise BadPassword()

    # We've decrypted it; now let's extract the data from the padding.
    if len(data) < 4:
        raise MixError("File %s is too short"%fname)
    length, = struct.unpack("!L", data[:4])
    if len(data) < length+4:
        raise MixError("File %s is too short"%fname)

    return magic, data[4:4+length]

def _writeEncryptedFile(fname, password, magic, data):
    """Write 'data' into an encrypted file named 'fname', replacing it
       if necessary.  Encrypts the data with the password 'password',
       and uses the filetype 'magic'."""
    assert len(magic) == MAGIC_LEN
    prng = getCommonPRNG()
    length = struct.pack("!L", len(data))
    paddingLen = ceilDiv(len(data), 1024)*1024 - len(data)
    padding = prng.getBytes(paddingLen)
    data = "".join([length,data,padding])
    salt = prng.getBytes(SALT_LEN)
    key = sha1(salt+password+salt)[:AES_KEY_LEN]
    digest = sha1("".join([data,salt,magic]))
    encrypted = ctr_crypt(data+digest, key)
    contents = "".join([magic,"\x00",salt,encrypted])
    writeFile(fname, armorText(contents,
                               "TYPE III KEYRING", [("Version","0.1")]))

class _LazyEncryptedStore:
    """Wrapper for a file containing an encrypted object, to
       perform password querying and loading on demand."""
    ## Fields:
    # fname, pwdManager, pwdName, queryPrompt, newPrompt, initFn:
    #    As documented in __init__.
    # okMagic: A list of magic strings we're willing to accept on files
    #    we're reading.
    # bestMagic: The magic string we use on files we're writing.
    # obsoleteMagic: A list of magic strings which we flag as "obsolete"
    #    instead of "unrecongized" when giving error messages to the user.
    # password: The cached password for this object
    # object: The cached contents of this object, or None if this object
    #    hasn't been loaded.
    # loaded: Flag: has this object been loaded?
    def __init__(self, fname, pwdManager, pwdName, queryPrompt, newPrompt,
                 magic, initFn):
        """Create a new LazyEncryptedStore
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
        self.object = None
        self.loaded = 0
        self.password = None
        self.okMagic = [magic]
        self.bestMagic = magic
        assert len(magic) == MAGIC_LEN
        self.initFn = initFn
        self.obsoleteMagic = []

    def load(self, create=0,password=None,now=None):
        """Try to load the encrypted file from disk.  If 'password' is
           not provided, query it from the password manager.  If the file
           does not exist, and 'create' is true, get a new password and
           create the file."""
        if self.loaded:
            # No need to re-load an already-loaded object.
            return
        elif os.path.exists(self.fname):
##             # Okay, the file is there. Snarf it from disk and try to give a
##             # good warning for its magic string.
##             contents = readFile(self.fname)
##             if contents[:8] in self.obsoleteMagic:
##                 raise MixError("Found an obsolete keyring at %r.  Remove this file to use SURBs with this version of Mixminion."%self.fname)
##             if len(contents)<8 or contents[:8] not in self.okMagic:
##                 raise MixError("Unrecognized versioning on file %s"%self.fname)

            # ... see if we can load it with no password ...
            if self._loadWithPassword(""):
                return
            # Nope; see if we can use a password we were given.
            if password is not None:
                self._loadWithPassword(password)
                if not self.loaded:
                    raise BadPassword()
            else:
                # sets self.password on successs
                self.pwdManager.getPassword(self.pwdName, self.queryPrompt,
                                            self._loadWithPassword)
        elif create:
            # It isn't there, but we're allowed to create it.
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
            m, val = _readEncryptedFile(self.fname,password, self.okMagic+self.obsoleteMagic)
            if m in self.obsoleteMagic:
                raise MixError("Found an obsolete keyring at %r.  Remove this file to use SURBs with this version of Mixminion."%self.fname)
            self._decode(val, m)
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
        _writeEncryptedFile(self.fname, self.password, self.bestMagic,
                            self._encode())

    def _encode(self):
        """Helper function for subclasses to override: convert self.object to a
           string for storage, and return the converted object."""
        return cPickle.dumps(self.object, 1)

    def _decode(self,val,magic):
        """Helper function: given a decrypted string and magic string, sets
           self.object to the corresponding decoded value."""
        self.object = cPickle.loads(val)

class _KeyringImpl:
    """Helper class: serves as the value stored by Keyring.  Contains a bunch
       of SURB keys and unrecognized key data, along with functions to
       manipulate those SURB keys.

       Uses the file format documented in appendix A.2 of E2E-spec.txt
    """
    ## Fields
    # recognized: A list of (tp, val) tuples for every item in the keyring
    #    whose type we recognize.
    # unrecognized: A list of (tp, val) tuples for every item in the keyring
    #    whose type we don't recognize.
    # dirty: Boolean: does the state of this object match what we loaded
    #    from disk?
    # surbKeys: A map from lowercase keyid to a list of (expiry-time, secret)
    #    for all of the SURB keys in the keyring.
    SURB_KEY_TYPE = 0x00
    def __init__(self, s="", now=None):
        """Initialize this keyring representation from the encoded string
           's'.  If any keys are set to expire before 'now', delete them.
        """
        if now is None: now = time.time()

        # Build lists of recongized and unrecognized items in 'input'.
        self.unrecognized = []
        rec = []
        self.dirty = 0
        while s:
            if len(s) < 3:
                raise MixError("Corrupt keyring: truncated entry.")
            tp,length = struct.unpack("!BH", s[:3])
            if len(s) < 3+length:
                raise MixError("Corrupt keyring: truncated entry.")
            val = s[3:3+length]
            if tp == self.SURB_KEY_TYPE:
                rec.append((tp,val))
            else:
                self.unrecognized.append((tp,val))
            s = s[3+length:]

        # Now, extract all the SURB keys from the keyring, and remove all
        # expired SURB keys from self.recognized.
        self.surbKeys = {}
        self.recognized = []
        for tp,val in rec:
            if len(val) < 5 or '\0' not in val[4:]:
                raise MixError("Truncated SURB key")
            expiry, = struct.unpack("!L", val[:4])
            if expiry < now:
                self.dirty = 1
            else:
                self.recognized.append((tp,val))
                val = val[4:]
                identity = val[:val.index('\0')].lower()
                secret = val[val.index('\0')+1:]
                self.surbKeys.setdefault(identity,[]).append((expiry,secret))

    def pack(self):
        """Return a string representation of this keyring."""
        items = self.recognized+self.unrecognized
        # Scramble all the items, just to make sure that no broken
        # implementations rely on their oreder.
        getCommonPRNG().shuffle(items)
        encoded = []
        for tp, val in items:
            encoded.append(struct.pack("!BH", tp, len(val)))
            encoded.append(val)
        return "".join(encoded)

    def newSURBKey(self, identity, expiresAt, secretLen):
        """See ClientUtils.Keyring.newSURBKey"""
        assert '\0' not in identity
        identity = identity.lower()
        expires = succeedingMidnight(expiresAt)
        secret = trng(secretLen)
        encoded = "%s%s\0%s" % (struct.pack("!L", expires),identity,secret)
        self.recognized.append((self.SURB_KEY_TYPE, encoded))
        self.surbKeys.setdefault(identity, []).append((expires,secret))
        self.dirty = 1
        return secret

    def getNewestSURBKey(self, identity, minLifetime, now=None):
        """See ClientUtils.Keyring.getNewestSURBKey"""
        identity = identity.lower()
        if now is None:
            now = time.time()
        v = self.surbKeys.get(identity,[])
        if not v:
            return None
        v.sort()
        expires, secret = v[-1]
        if expires < now+minLifetime:
            return None
        return secret

    def getAllSURBKeys(self):
        """See ClientUtils.Keyring.getAllSURBKeys"""
        res = []
        for identity, lst in self.surbKeys.items():
            for _, secret in lst:
                res.append((identity, secret))
        return res

class Keyring(_LazyEncryptedStore):
    """Class to wrap a lazy-loaded file holding a bundle of SURB keys for
       a client.  The format is as described in E2E-spec.txt, appendix A.2."""
    def __init__(self, fname, pwdManager):
        """Create a new LazyEncryptedStore
              fname -- The name of the file to hold the encrypted object.
              pwdManager -- A PasswordManager instance.
        """
        _LazyEncryptedStore.__init__(self,
            fname, pwdManager, pwdName="ClientKeyring",
            queryPrompt = "Enter passphrase for keyring:",
            newPrompt = "Enter new passphrase for client keyring:",
            magic = "KEYRING2",
            initFn = _KeyringImpl)
        self.obsoleteMagic = [ "KEYRING1" ]
    def _encode(self):
        return self.object.pack()
    def _decode(self,val,magic):
        assert magic == 'KEYRING2'
        self.object = _KeyringImpl(val,now=self._now)
    def newSURBKey(self, identity, expiresAt, secretLen=DIGEST_LEN):
        """Generate a fresh SURB key for the identity 'identity',
           set to expire on the time 'expiresAt', and returns the freshly
           generated key.  Old keys are not replaced, and the new key
           will not be saved until you call save() on this object.
        """
        return self.object.newSURBKey(identity,expiresAt,secretLen)
    def getNewestSURBKey(self, identity, minLifetime=2*24*60*60, now=None):
        """Return the SURB key for the identity 'identity' that has
           the latest expiration date.  If no such key exists, or that
           key would expire in less than 'minLifetime' seconds after
           'now', return None.
        """
        return self.object.getNewestSURBKey(identity, minLifetime, now)
    def getAllSURBKeys(self):
        """Return a list of (identity,key) tuples for every SURK key in
           this keyring.
        """
        return self.object.getAllSURBKeys()
    def isDirty(self):
        """Return true iff this keyring contains state the has not been
           written to disk.
        """
        return self.object.dirty
    def save(self):
        _LazyEncryptedStore.save(self)
        self.object.dirty = 0
    def load(self, create=0, password=None, now=None):
        """Try to load the encrypted keyring from disk.  If 'password' is
           not provided, query it from the password manager.  If the file
           does not exist, and 'create' is true, get a new password and
           create the file.

           If the keyring contains any expired keys, remove them.  (They
           will not be removed from disk until this keyring is next
           save()d.)
        """
        self._now = now
        try:
            _LazyEncryptedStore.load(self, create=create, password=password)
        finally:
            del self._now

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
        """Given a list of ReplyBlock objects, return a list of the first
           'nSURBs' of them that neither are expired, are about to expire,
           or have been used in the past.  If less than 'nSURBs' exist,
           return as many as possible. If 'verbose' is true, log the status
           of the SURBs considered.
        """
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
        for h in allHashes:
            if self._decodeVal(self.log[h]) < now:
                removed.append(h)
        del allHashes
        for h in removed:
            del self.log[h]
        self.log['LAST_CLEANED'] = str(int(now))
        self.sync()

    def _encodeKey(self, surb):
        return binascii.b2a_hex(sha1(surb.pack()))
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
    # XXXX write unit tests
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
            directory, create=1)

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

    def getHandlesByAge(self, notAfter):
        self.loadMetadata()
        result = []
        for h in self.store.getAllMessages():
            _,_,when = self.store.getMetadata(h)
            if when <= notAfter: result.append(h)
        return result

    def getHandlesByDestAndAge(self, destList, directory, notAfter=None,
                               warnUnused=1):
        """DOCDOC destset: set of hostnames, ips, or keyids"""
        destSet = {}
        reverse = {}
        for d in destList:
            if directory:
                keyid = directory.getKeyIDByNickname(d)
                if keyid:
                    destSet[keyid] = 1
                    reverse[keyid] = d
                    continue
            destSet[d] = 1

        self.loadMetadata()
        result = []
        foundAny = {}
        foundMatch = {}
        for h in self.store.getAllMessages():
            _, r, when = self.store.getMetadata(h)
            if (destSet.has_key(r.keyinfo) or
                (hasattr(r, 'hostname') and destSet.has_key(r.hostname)) or
                (hasattr(r, 'ip') and destSet.has_key(r.ip))):

                keys = [ getattr(r, 'hostname', None),
                         getattr(r, 'ip', None),
                         reverse.get(r.keyinfo, None),
                         r.keyinfo ]
                for k in keys: foundAny[k]=1
                if notAfter and when > notAfter:
                    continue
                for k in keys: foundMatch[k]=1
                result.append(h)
        if warnUnused:
            for d in destList:
                if foundMatch.get(d):
                    continue
                elif foundAny.get(d):
                    LOG.warn("No expired packets found for %r", d)
                else:
                    LOG.warn("No pending packets found for %r", d)
        return result

    def getRouting(self, handle):
        """Return the routing information associated with the given handle."""
        self.loadMetadata()
        return self.store.getMetadata(handle)[1]

    def getDate(self, handle):
        """Return the date a given handle was inserted."""
        self.loadMetadata()
        return self.store.getMetadata(handle)[2]

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

    def inspectQueue(self):
        """Return a dict from routinginfo to a tuple of: (n,t), where
           n is the number of packets waiting for that routinginfo, and
           t is the insertion-data of the oldest packet waiting for that
           routinginfo.
        """
        handles = self.getHandles()
        if not handles:
            return {}
            return
        self.loadMetadata()
        timesByServer = {}
        for h in handles:
            try:
                _, routing, when = self.store.getMetadata(h)
            except mixminion.Filestore.CorruptedFile:
                continue
            timesByServer.setdefault(routing, []).append(when)
        res = {}
        for s in timesByServer.keys():
            count = len(timesByServer[s])
            oldest = min(timesByServer[s])
            res[s] = (count, oldest)
        return res

    def cleanQueue(self):
        """Remove all packets older than maxAge seconds from this queue."""
        self.store.cleanQueue()
        self.store.cleanMetadata()

    def loadMetadata(self):
        """Ensure that we've loaded metadata for this queue from disk."""
        if self.metadataLoaded:
            return

        # Helper function: create metadata from a file without it.
        def fixupHandle(h,self=self):
            packet, routing, when = self.getPacket(h)
            return "V0", routing, when

        mixminion.ClientMain.clientLock()
        try:
            self.store.loadAllMetadata(fixupHandle)
        finally:
            mixminion.ClientMain.clientUnlock()

        self.metadataLoaded = 1

# ----------------------------------------------------------------------

class ClientFragmentPool:
    """DOCDOC"""
    def __init__(self, directory):
        createPrivateDir(directory)
        self.dir = directory
        self.pool = None

    def __getPool(self):
        if self.pool is None:
            import mixminion.Fragments
            self.pool = mixminion.Fragments.FragmentPool(self.directory)
        return self.pool

    def close(self):
        if self.pool is not None:
            self.pool.close()
            self.pool = None

    def addFragment(self, fragment, nym=None):
        """fragment is instance of fragmentPayload or is a string payload
           DOCDOC"""
        pool = self.__getPool()
        if isinstance(fragment, types.StringType):
            try:
                fragment = mixminion.Packet.parsePayload(fragment)
            except ParseError, s:
                raise UIError("Corrupted fragment payload: %s"%s)
            if not fragment.isFragment():
                raise UIError("Non-fragment payload marked as a fragment.")

        assert isinstance(fragment, mixminion.Packet.FragmentPayload)

        return pool.addFragment(fragment, nym=nym, verbose=1)

    def process(self):
        pool = self.__getPool()
        pool.unchunkMessages()
        pool.cleanQueue()

    def expireMessages(self, cutoff):
        pool = self.__getPool()
        pool.expireMessages(cutoff)
        self.cleanQueue()

    def getMessage(self, msgid):
        pool = self.__getPool()
        msg = pool.getReadyMessage(msgid)
        if msg is not None:
            return msg

        state = pool.getStateByMsgID(msgid)
        if state is None:
            raise UIError("No such message as '%s'" % msgid)
        elif not state.isDone():
            raise UIError("Message '%s' is still missing fragments."%msgid)
        else:
            raise MixFatalError("Can't decode message %s; I don't know why!")

    def removeMessages(self, msgids):
        pool = self.__getPool()
        for i in msgids:
            if pool.getStateByMsgID(m) is None:
                raise UIError("No such message as %s")
        pool._deleteMessageIDs(msgids, "?")
        pool.cleanQueue()

    def listMessages(self):
        pool = self.__getPool()
        return pool.listMessages()

    def formatMessageList(self):
        msgs = self.listMessages()
        result = []
        for msgid in msgs.keys():
            result.append(msgid+(": to <%(nym)s>. %(size)s bytes (%(have)s/%(need)s packets received)"
                                 % msgs[msgid]))
        return result
