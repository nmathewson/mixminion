# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ClientUtils

   This module holds helper code not included in the Mixminion Client
   API, but useful for more than one user interface.
   """

__all__ = [ 'NoPassword', 'PasswordManager', 'getPassword_term',
            'getNewPassword_term', ]

import cPickle
import getpass
import os
import sys

from mixminion.Common import readFile, writeFile, MixError
import mixminion.Crypto

#----------------------------------------------------------------------
class BadPassword(MixError):
    pass

class PasswordManager:
    # passwords: name -> string
    def __init__(self):
        self.passwords = {}
    def _getPassword(self, name, prompt):
        raise NotImplemented()
    def _getNewPassword(self, name, prompt):
        raise NotImplemented()
    def setPassword(self, name, password):
        self.passwords[name] = password
    def getPassword(self, name, prompt, confirmFn, maxTries=-1):
        if self.passwords.has_key(name):
            return self.passwords[name]
        for othername, pwd in self.passwords.items():
            if self._confirm(name, pwd):
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
        self.passwords[name] = self._getNewPassword(name, prompt)

class CLIPasswordManager(PasswordManager):
    def __init__(self):
        PasswordManager.__init__(self)
    def _getPassword(self, name, prompt):
        return getPassword_term(prompt)

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
    s1 = "Enter new password for %s:"%which
    s2 = "Verify password:".rjust(len(s1))
    if os.isatty(sys.stdout.fileno()):
        f = sys.stdout
    else:
        f = sys.stderr
    while 1:
        p1 = self.getPassword_term(s1)
        p2 = self.getPassword_term(s2)
        if p1 == p2:
            return p1
        f.write("Passwords do not match.\n")
        f.flush()

#----------------------------------------------------------------------

def readEncryptedFile(fname, password, magic):
    """DOCDOC
       return None on failure; raise  MixError on corrupt file.
    """
    #  variable         [File specific magic]       "KEYRING1"
    #  8                [8 bytes of salt]
    #  variable         ENCRYPTED DATA:KEY=sha1(salt+password+salt)
    #                                  DATA=data+
    #                                                   sha1(data+salt+magic)
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
    salt = mixminion.Crypto.getCommonPRNG().getBytes(8)
    key = mixminion.Crypto.sha1(salt+password+salt)[:16]
    hash = mixminion.Crypto.sha1("".join([data+salt+magic]))
    encrypted = mixminion.Crypto.ctr_crypt(data+hash, key)
    writeFile(fname, "".join([magic,salt,encrypted]), binary=1)

def readEncryptedPickled(fname, password, magic):
    return cPickle.loads(readEncryptedFile(fname, password, magic))

def writeEncryptedPickled(fname, password, magic, obj):
    data = cPickle.dumps(obj, 1)
    writeEncryptedFile(fname, password, magic, data)

class LazyEncryptedPickled:
    def __init__(self, fname, pwdManager, pwdName, queryPrompt, newPrompt,
                 magic, initFn):
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
        try:
            self.object = readEncryptedPickled(self.fname,password,self.magic)
            self.password = password
            self.loaded = 1
            return 1
        except MixError:
            return 0
    def isLoaded(self):
        return self.loaded
    def get(self):
        assert self.loaded
        return self.object
    def set(self, val):
        self.object = val
        self.loaded = 1
    def setPassword(self, pwd):
        self.password = pwd
    def save(self):
        assert self.loaded and self.password
        writeEncryptedPickled(self.fname, self.password, self.magic,
                              self.object)
        
        
