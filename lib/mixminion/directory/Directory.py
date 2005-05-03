# Copyright 2003-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Directory.py,v 1.19 2005/05/03 03:26:50 nickm Exp $

"""mixminion.directory.Directory

   General purpose code for directory servers.
   """

__all__ = [ 'ServerList', 'MismatchedID', 'DirectoryConfig', 'Directory' ]

import os
import stat
import time

import mixminion.Config
import mixminion.Crypto

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     formatBase64, writePickled, readPickled, formatTime

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
            self.serverList = ServerList(self.directoryBase,
                                         self.config,
                                         self.getIDCache())
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
           "ClientVersions" : ("REQUIRE", "list", None),
           "ServerVersions" : ("REQUIRE", "list", None),
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

class VoteFile:
    """File listing dirserver's current disposition towards various
       nickname/identity comibations.  Each can be voted 'yes', 'no',
       or 'abstain'.
    """
    ## Fields:
    # status: identity fingerprint -> ("yes", "nickname") | ("no", None) |
    #     ("abstain", None) | ("ignore", None)
    # fname
    # dirty, uid, gid
    def __init__(self, fname, uid=None, gid=None):
        self.fname = fname
        self.uid = uid
        self.gid = gig
        if not self._loadFromCache():
            self._load(fname)

    def _load(self, fname):
        pat = re.compile(r'(yes|no|abstain|ignore)\s+(\S+)\s+([a-fA-F0-9 ]+)')
        f = open(fname, 'r')
        try:
            status = {}
            lineof = {}
            byName = {}
            lineno = 0
            for line in open(fname, 'r').readlines():
                lineno += 1
                line = line.strip()
                if not line or line[0] == '#': continue
                m = pat.match(line)
                if not m:
                    LOG.warn("Skipping ill-formed line %s in %s",lineno,fname)
                    continue
                vote, nickname, fingerprint = m.groups()
                try:
                    mixminion.Config._parseNickname(nickname)
                except mixminion.Config.ConfigError, e:
                    LOG.warn("Skipping bad nickname '%s', on line %s of %s: %s",
                             nickname, lineno, fname, e)
                    continue
                try:
                    ident = binascii.a2b_hex(fingerprint.replace(" ", ""))
                    if len(ident) != mixminion.Crypto.DIGEST_LEN:
                        raise TypeError("Wrong length for digest")
                except TypeError, e:
                    LOG.warn("Invalid fingerprint on line %s of %s: %s", lineno,
                             fname, e)
                    continue
                if status.has_key(ident):
                    LOG.warn("Ignoring duplicate entry for fingprint on line %s (first appeared on line %s)", lineno, lineof[ident])
                    continue
                lineof[ident] = lineno
                if vote == 'yes':
                    status[ident] = (vote, nickname)
                    if byName.has_key(nickname.lower()):
                        LOG.warn("Ignoring second yes-vote for a nickname %r",
                                 nickname)
                        continue
                    byName[nickname] = ident
                else:
                    status[ident] = (vote, None)
            self.status = status
            self.dirty = 1
        finally:
            f.close()

    def appendUnknownServers(self, lst):
        # list of [(nickname, fingerprint) ...]
        if not lst:
            return
        f = open(fname, 'a+')
        try:
            f.seek(-1, 2)
            nl = (f.read(1) == '\n')
            if not nl: f.write("\n")
            for name, fp in lst:
                f.write("#   Added %s\n#abstain %s %s\n"%(date, name, fp))
        finally:
            f.close()

    def _loadFromCache(self):
        # raise OSError or return false on can't/shouldn't load.
        cacheFname = self.fname + ".cache"
        try:
            cache_mtime = os.stat(cacheFname)[stat.ST_MTIME]
            file_mtime =  os.stat(self.fname)[stat.ST_MTIME]
        except OSError:
            return 0
        if file_mtime >= cache_mtime:
            return 0
        try:
            p = readPickled(cacheFname)
        except (OSError, cPickle.UnpicklingError), _:
            return 0
        if type(p) != types.TupleType or p[0] != 'VoteCache-0':
            return 0
        self.status = p[1]
        self.dirty = 0
        return 1

    def saveCache(self):
        cacheFname = self.fname + ".cache"
        writePickled(cacheFname, ("VoteCache-0", self.status), 0640)
        if self.uid is not None and self.gid is not None:
            _set_uid_gid_mode(cacheFname, self.uid, self.gid, 0640)
            _set_uid_gid_mode(self.name, self.uid, self.gid, 0640)
        self.dirty = 0

    def getServerStatus(self, server):
        # status + 'unknown' + 'mismatch'
        ident = server.getIdentityDigest()
        try:
            vote, nickname = self.status[ident]
        except KeyError:
            return "unknown"

        if vote == 'yes' and nickname != server.getNickname():
            return "mismatch"

        return vote

def _set_uid_gid_mode(fn, uid, gid, mode):
    """Change the permissions on the file named 'fname', so that fname
       is owned by user 'uid' and group 'gid', and has permissions 'mode'.
    """
    st = os.stat(fn)
    if st[stat.ST_UID] != uid or st[stat.ST_GID] != gid:
        os.chown(fn, uid, gid)
    if (st[stat.ST_MODE] & 0777) != mode:
        os.chmod(fn, mode)
