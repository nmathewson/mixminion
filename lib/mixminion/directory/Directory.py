# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Directory.py,v 1.2 2003/05/25 23:11:43 nickm Exp $

"""mixminion.directory.Directory

   DOCDOC

   """

__all__ = [ 'ServerList', 'MismatchedID', 'DirectoryConfig', 'Directory' ]

import os
import stat

import mixminion.Config as C
import mixminion.Crypto

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     formatBase64, writePickled, readPickled

class Directory:
    def __init__(self, config):
        self.config = config
        self.location = config['Directory-Store']['Homedir']
        self.inboxBase = os.path.join(self.location, "inbox")
        self.directoryBase = os.path.join(self.location, "dir")
        self.cacheFile = os.path.join(self.location, "identity_cache")
        self.cache = None
        self.inbox = None
        self.serverList = None
         
    def setupDirectories(self):
        me = os.getuid()
        roledict = { 0: "root",
                     self.config.dir_uid: "dir",
                     self.config.cgi_uid: "cgi",
                     }
        role = roledict.get(me, "other")
        if role in ("other","cgi"):
            raise MixFatalError("Only the directory user or root can set up"
                                " the directory.")

        ib = self.inboxBase
        join = os.path.join

        dir_uid = self.config.dir_uid
        dir_gid = self.config.dir_gid
        cgi_gid = self.config.cgi_gid
        
        
        for fn, uid, gid, mode, recurse in [
            (self.location,       dir_uid, cgi_gid, 0750, 1),
            (self.directoryBase,  dir_uid, dir_gid, 0700, 0),
            (ib,                  dir_uid, cgi_gid, 0750, 0),
            (join(ib, "new"),     dir_uid, cgi_gid, 0770, 0),
            (join(ib, "reject"),  dir_uid, cgi_gid, 0770, 0),
            (join(ib, "updates"), dir_uid, cgi_gid, 0770, 0), ]:

            if not os.path.exists(fn):
                if recurse:
                    os.makedirs(fn, mode)
                else:
                    os.mkdir(fn, mode)
            _set_uid_gid_mode(fn, dir_uid, cgi_gid, 0640)

        if not os.path.exists(self.cacheFile):
            self.cache = IDCache(self.cacheFile)
            self.cache.emptyCache()
            self.cache.save()

        self._setCacheMode()

    def getIDCache(self):
        if not self.cache:
            self.cache = IDCache(self.cacheFile)
        return self.cache

    def _setCacheMode(self):
        _set_uid_gid_mode(self.cacheFile,
                          self.config.dir_uid,
                          self.config.cgi_gid,
                          0640)

    def getServerList(self):
        if not self.serverList:
            from mixminion.directory.ServerList import ServerList
            self.serverList = ServerList(self.directoryBase, self.getIDCache())
        return self.serverList

    def getInbox(self):
        if not self.inbox:
            from mixminion.directory.ServerInbox import ServerInbox
            self.inbox = ServerInbox(self.inboxBase, self.getIDCache())
        return self.inbox
            
class DirectoryConfig(C._ConfigFile):
    _restrictFormat = 1
    _restrictKeys = 1
    _syntax = {
        'Host' : C.ClientConfig._syntax['Host'],
        "Directory-Store" : {
           "Homedir" : ('REQUIRE', None, None),
           "DirUser" : ('REQUIRE', None, None),
           "CGIUser" : ('REQUIRE', None, None),
           "CGIGroup" : ('REQUIRE', None, None),
        } }
    def __init__(self, filename=None, string=None):
        C._ConfigFile.__init__(self, filename, string)

    def validate(self, lines, contents):
        import pwd
        import grp
        ds_sec = self['Directory-Store']
        diruser = ds_sec['DirUser'].strip()
        cgiuser = ds_sec['CGIUser'].strip()
        cgigrp = ds_sec['CGIGroup'].strip()

        try:
            dir_pwent = pwd.getpwname(diruser)
        except KeyError:
            raise C.ConfigError("No such user: %r"%diruser)
        try:
            cgi_pwent = pwd.getpwname(cgiuser)
        except KeyError:
            raise C.ConfigError("No such user: %r"%cgiuser)
        try:
            cgi_grpent = grp.getgrnam(cgigrp)
        except KeyError:
            raise C.ConfigError("No such group: %r"%cgigrp)

        self.dir_uid = dir_pwent[2]
        self.dir_grp = dir_pwent[3]
        self.cgi_uid = cgi_pwent[2]
        self.cgi_gid = cgi_grpent[2]

        groupMembers = cgi_grpent[3][:]
        for pwent in (dir_pwent, cgi_pwent):
            if pwent[3] == self.cgi_gid:
                groupMembers.append(pwent[0])

        if self.dir_uid not in groupMembers:
            raise C.ConfigError("User %s is not in group %s"
                                %(diruser, cgigrp))
        if self.cgi_uid not in groupMembers:
            raise C.ConfigError("User %s is not in group %s"
                                %(cgiuser, cgigrp))

class MismatchedID(Exception):
    pass

class IDCache:
    """DOCDOC"""
    def __init__(self, location):
        self.location = location
        self.dirty = 0
        self.cache = None

    def emptyCache(self):
        self.dirty = 1
        self.cache = {}

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
                     0640)
        self.dirty = 0
            
def getIDFingerprint(server):
    """DOCDOC"""
    ident = server.getIdentity()
    return mixminion.Crypto.sha1(
        mixminion.Crypto.pk_encode_public_key(ident))

def _set_uid_gid_mode(fn, uid, gid, mode):
    st = os.stat(fn)
    if st[stat.ST_UID] != uid or st[stat.ST_GID] != gid:
        os.chown(fn, uid, gid)
    if (st[stat.ST_MODE] & 0777) != mode:
        os.chmod(fn, mode)
    
