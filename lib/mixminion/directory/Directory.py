# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Directory.py,v 1.1 2003/05/25 21:57:05 nickm Exp $

"""mixminion.directory.Directory

   DOCDOC

   """

__all__ = [ 'ServerList', 'MismatchedID' ]

import os

import mixminion.Config
import mixminion.Crypto

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     formatBase64, writePickled, readPickled

class MismatchedID(Exception):
    pass

class IDCache:
    """DOCDOC"""
    def __init__(self, location):
        self.location = location
        self.dirty = 0
        self.cache = None

    def containsID(self, nickname, ID):
        nickname = nickname.lower()
        try:
            return self.__containsID(nickname, ID)
        except TypeError:
            self.load()
            return self.__containsID(nickname, ID)

    def __containsID(self, lcnickname, ID):
        try:
            if self.cache[lcnickname] != ID:
                raise MismatchedID()
            return 1
        except KeyError:
            return 0

    def containsServer(self, server):
        nickname = server.getNickname()
        ID = getIDFingerprint(server)
        return self.containsID(nickname, ID)

    def insertID(self, nickname, ID):
        nickname = nickname.lower()
        self.dirty = 1
        try:
            self.__insertID(nickname, ID)
        except AttributeError:
            self.load()
            self.__insertID(nickname, ID)

    def __insertID(self, lcnickname, ID):
        old = self.cache.get(lcnickname)
        if old and old != ID:
            raise MismatchedID()
        self.cache[lcnickname] = ID

    def insertServer(self, server):
        key = server.getIdentity()
        nickname = server.getNickname()
        ID = getIDFingerprint(server)
        self.insertID(nickname, ID)

    def flush(self):
        if self.dirty:
            self.save()

    def load(self):
        if not os.path.exists(self.location):
            LOG.info("No ID cache; will create")
            self.cache = {}
            return
        try:
            obj = readPickled(self.location)
            # Pass pickling error
        except OSError, e:
            raise MixError("Cache exists, but cannot read cache: %s" % e)
        if len(obj) != 2:
            raise MixFatalError("Corrupt ID cache")
        
        typecode, data = obj
        if typecode != 'V0':
            raise MixFatalError("Unrecognized version on ID cache.")

        self.cache = data
        
    def save(self):
        writePickled(self.location,
                     ("V0", self.cache),
                     0644)
        self.dirty = 0
            
def getIDFingerprint(server):
    """DOCDOC"""
    ident = server.getIdentity()
    return formatBase64(
        mixminion.Crypto.sha1(
             mixminion.Crypto.pk_encode_public_key(ident)))
