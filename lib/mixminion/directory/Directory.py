# Copyright 2003-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Directory.py,v 1.17 2004/01/03 07:35:24 nickm Exp $

"""mixminion.directory.Directory

   General purpose code for directory servers.
   """

__all__ = [ 'ServerList', 'MismatchedID', 'DirectoryConfig', 'Directory' ]

import os
import stat

import mixminion.Config
import mixminion.Crypto

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     formatBase64, writePickled, readPickled

class Directory:
    """Wrapper class for directory filestores.

       Currently, a directory server keeps two filestores: an 'ServerInbox'
       that contains servers which have been uploaded but not yet inserted
       into the directory, and a 'ServerList' which contains the servers in
       the directory along with the directory's private keys and so on.

       A directory server also keeps an 'IDCache' that's readable by the CGI
       user and read/writable by the directory user.  It maps nicknames to
       identity keys.

       The 'ServerInbox' is readable and (mostly) writable by the CGI user.
       The 'ServerList' is private, and only readable by the directory user.
       (Both of these users must have a group in common.)

       This class uses a DirectoryConfig to initialize a ServerList and
       ServerInbox as appropriate.

       Layout:
          BASEDIR/dir            [Base for ServerList.]
          BASEDIR/inbox          [Base for ServerInbox.]
          BASEDIR/identity_cache [File for IDCache.]
    """
    ##Fields:
    # config: a DirectoryConfig instance
    # location: the base of the directory server's files.
    # inboxBase, directoryBase, cacheFile: filenames for the components
    #     of this directory.
    # cache, inbox, serverList: the actual components of this directory.
    #     None until first initialized.
    def __init__(self, config=None, location=None):
        """Initialize a new Directory object from a given config object."""
        self.config = config
        if config and not location:
            self.location = location = config['Directory-Store']['Homedir']
        else:
            self.location = location
        assert location
        self.inboxBase = os.path.join(self.location, "inbox")
        self.directoryBase = os.path.join(self.location, "dir")
        self.cacheFile = os.path.join(self.location, "identity_cache")
        self.cache = None
        self.inbox = None
        self.serverList = None

    def setupDirectories(self):
        """Create a new tree of dirs with appropriate permissions."""
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
            #Dirname              UID      #GID     mode  recurse
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
            _set_uid_gid_mode(fn, uid, gid, mode)

        if not os.path.exists(self.cacheFile):
            self.cache = IDCache(self.cacheFile)
            self.cache.emptyCache()
            self.cache.save()

        self._setCacheMode()

    def getIDCache(self):
        """Return the IDCache for this directory."""
        if not self.cache:
            self.cache = IDCache(self.cacheFile,self._setCacheMode)
        return self.cache

    def _setCacheMode(self):
        """Make sure that the IDCache is stored with the write uid, gid,
           and permissions."""
        _set_uid_gid_mode(self.cacheFile,
                          self.config.dir_uid,
                          self.config.cgi_gid,
                          0640)

    def getConfig(self):
        """Return the DirectoryConfig for this directory."""
        return self.config

    def getServerList(self):
        """Return the ServerList for this directory"""
        if not self.serverList:
            from mixminion.directory.ServerList import ServerList
            self.serverList = ServerList(self.directoryBase, self.getIDCache())
        return self.serverList

    def getInbox(self):
        """Return the ServerInbox for this directory"""
        if not self.inbox:
            from mixminion.directory.ServerInbox import ServerInbox
            self.inbox = ServerInbox(self.inboxBase, self.getIDCache())
        return self.inbox

    def getIdentity(self):
        """Return the identity key for this directory."""
        _ = self.getServerList()
        fname = os.path.join(self.directoryBase, "identity")
        if not os.path.exists(fname):
            print "No public key found; generating new key..."
            key = mixminion.Crypto.pk_generate(2048)
            mixminion.Crypto.pk_PEM_save(key, fname)
            return key
        else:
            return mixminion.Crypto.pk_PEM_load(fname)

class DirectoryConfig(mixminion.Config._ConfigFile):
    """Configuration file for a directory server."""
    _restrictFormat = 0
    _restrictKeys = _restrictSections = 1
    _syntax = {
        'Host' : mixminion.Config.ClientConfig._syntax['Host'],
        "Directory-Store" : {
           "__SECTION__" : ("REQUIRE", None, None ),
           "Homedir" : ('REQUIRE', "filename", None),
           "DirUser" : ('REQUIRE', None, None),
           "CGIUser" : ('REQUIRE', None, None),
           "CGIGroup" : ('REQUIRE', None, None),
        },
        'Directory' : {
           "BadServer" : ("ALLOW*", None, None),
           "BadServerFile" : ("ALLOW*", "filename", None),
           "ExcludeServer" : ("ALLOW*", None, None),
        },
        'Publishing' : {
           "__SECTION__": ('REQUIRE', None, None),
           "Location" : ('REQUIRE', "filename", None)
        } }
    def __init__(self, filename=None, string=None):
        mixminion.Config._ConfigFile.__init__(self, filename, string)

    def validate(self, lines, contents):
        import pwd
        import grp
        ds_sec = self['Directory-Store']
        diruser = ds_sec['DirUser'].strip().lower()
        cgiuser = ds_sec['CGIUser'].strip().lower()
        cgigrp = ds_sec['CGIGroup'].strip().lower()

        # Make sure that all the users and groups actually exist.
        try:
            dir_pwent = pwd.getpwnam(diruser)
        except KeyError:
            raise mixminion.Config.ConfigError("No such user: %r"%diruser)
        try:
            cgi_pwent = pwd.getpwnam(cgiuser)
        except KeyError:
            raise mixminion.Config.ConfigError("No such user: %r"%cgiuser)
        try:
            cgi_grpent = grp.getgrnam(cgigrp)
        except KeyError:
            raise mixminion.Config.ConfigError("No such group: %r"%cgigrp)

        self.dir_uid = dir_pwent[2]
        self.dir_gid = dir_pwent[3]
        self.cgi_uid = cgi_pwent[2]
        self.cgi_gid = cgi_grpent[2]

        # Find all members in the CGI group.
        groupMembers = cgi_grpent[3][:]
        for pwent in (dir_pwent, cgi_pwent):
            if pwent[3] == self.cgi_gid:
                groupMembers.append(pwent[0])

        groupMembers = [ g.lower().strip() for g in groupMembers ]

        # Make sure that the directory user and the CGI user are both in
        # the CGI group.
        if diruser not in groupMembers:
            raise mixminion.Config.ConfigError("User %s is not in group %s"
                                %(diruser, cgigrp))
        if cgiuser not in groupMembers:
            raise mixminion.Config.ConfigError("User %s is not in group %s"
                                %(cgiuser, cgigrp))

class MismatchedID(Exception):
    """Exception class: raised when the identity key on a new server
       descriptor doesn't match the identity key known for that nickname."""
    pass

class IDCache:
    """Cache to hold a set of nickname->identity key mappings"""
    ##Fields:
    # cache: map from lowercased nickname to ID fingerprint.
    # location: filename to hold pickled cache.
    # dirty: are all the values in 'self.cache' flushed to disk? (boolean)
    # postSave: None, or a function to call after every save.
    ##Pickled Format:
    # ("V0", {lcnickname -> ID Fingerprint} )
    def __init__(self, location, postSave=None):
        """Create an identity cache object.

           location -- name of file to hold pickled cache.
           postSave -- optionally, a function to be called after every
              save."""
        self.location = location
        self.dirty = 0
        self.cache = None
        self.postSave = postSave

    def emptyCache(self):
        """Remove all entries from this cache."""
        self.dirty = 1
        self.cache = {}

    def containsID(self, nickname, ID):
        """Check the identity for the server named 'nickname'.  If the
           server is not known, return false. If the identity matches the
           identity key fingerprint 'ID', return true.  If the server is
           known, but the identity does not match, raise MismatchedID.
        """
        if self.cache is None: self.load()

        lcnickname = nickname.lower()
        try:
            if self.cache[lcnickname] != ID:
                raise MismatchedID()
            return 1
        except KeyError:
            return 0

    def containsServer(self, server):
        """Check the identity key contained in a server descriptor.  Return
           true if the server is known, false if the server unknown, and
           raise MismatchedID if the server is known but its ID is
           incorrect."""
        nickname = server.getNickname()
        ID = getIDFingerprint(server)
        return self.containsID(nickname, ID)

    def insertID(self, nickname, ID):
        """Record the server named 'nickname' as having an identity key
           with fingerprint 'ID'.  If the server already haves a different
           ID, raise MismatchedID."""
        if self.cache is None: self.load()

        lcnickname = nickname.lower()
        self.dirty = 1
        old = self.cache.get(lcnickname)
        if old and old != ID:
            raise MismatchedID()
        self.cache[lcnickname] = ID

    def insertServer(self, server):
        """Record the identity key of ServerInfo 'server'.  If another
           server with the same nickname and a different identity key is
           already known, raise MismatchedID."""
        nickname = server.getNickname()
        ID = getIDFingerprint(server)
        self.insertID(nickname, ID)

    def flush(self):
        """If any entries in the cache are new, write the cache to disk."""
        if self.dirty:
            self.save()

    def load(self):
        """Re-read the cache from disk."""
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
        """Write the cache to disk."""
        if self.cache is None:
            return
        writePickled(self.location,
                     ("V0", self.cache),
                     0640)
        if self.postSave:
            self.postSave()
        self.dirty = 0

def getIDFingerprint(server):
    """Given a ServerInfo, return the fingerprint of its identity key.

       We compute fingerprints by taking the ASN.1 encoding of the key,
       then taking the SHA1 hash of the encoding."""
    ident = server.getIdentity()
    return mixminion.Crypto.sha1(
        mixminion.Crypto.pk_encode_public_key(ident))

def _set_uid_gid_mode(fn, uid, gid, mode):
    """Change the permissions on the file named 'fname', so that fname
       is owned by user 'uid' and group 'gid', and has permissions 'mode'.
    """
    st = os.stat(fn)
    if st[stat.ST_UID] != uid or st[stat.ST_GID] != gid:
        os.chown(fn, uid, gid)
    if (st[stat.ST_MODE] & 0777) != mode:
        os.chmod(fn, mode)
