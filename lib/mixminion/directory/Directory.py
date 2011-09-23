# Copyright 2003-2011 Nick Mathewson.  See LICENSE for licensing information.

"""mixminion.directory.Directory

   General purpose code for directory servers.
   """

__all__ = [ 'ServerList', 'MismatchedID', 'DirectoryConfig', 'Directory' ]

import binascii
import os
import re
import stat
import time

import mixminion.Config
import mixminion.Crypto

from mixminion.Common import LOG, MixError, MixFatalError, UIError, \
     formatBase64, iterFileLines, writePickled, readPickled, formatTime


class Directory:
    """Wrapper class for directory filestores.

       Currently, a directory server keeps two filestores: an 'ServerInbox'
       that contains servers which have been uploaded but not yet inserted
       into the directory, and a 'ServerList' which contains the servers in
       the directory along with the directory's private keys and so on.

       The 'ServerInbox' is readable and (mostly) writable by the CGI user.
       The 'ServerList' is private, and only readable by the directory user.
       (Both of these users must have a group in common.)

       This class uses a DirectoryConfig to initialize a ServerList and
       ServerInbox as appropriate.

       Layout:
          BASEDIR/dir            [Base for ServerList.]
          BASEDIR/inbox          [Base for ServerInbox.]

       DOCDOC
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

class VoteFile(mixminion.Filestore.PickleCache):
    """File listing dirserver's current disposition towards various
       nickname/identity comibations.  Each can be voted 'yes', 'no',
       'abstain', or 'ignore'.
    """
    ## Fields:
    # status: identity fingerprint -> ("yes", "nickname") | ("no", None) |
    #     ("abstain", None) | ("ignore", None)
    # haveComment: fingerprint -> [ nickname ] for servers in comments.
    # uid, gid
    def __init__(self, fname, uid=None, gid=None):
        mixminion.Filestore.PickleCache.__init__(
            self, fname, fname+".cache")
        self.uid = uid
        self.gid = gid
        self.status = None
        self.load()

    def _reload(self,):
        pat = re.compile(r'(\#?)\s*(yes|no|abstain|ignore)\s+(\S+)\s+([a-fA-F0-9 ]+)')
        f = open(self._fname_base, 'r')
        try:
            status = {}
            lineof = {}
            byName = {}
            haveComment = {}
            lineno = 0
            fname = self._fname_base
            for line in iterFileLines(f):
                lineno += 1
                line = line.strip()
                if not line: continue
                m = pat.match(line)
                if not m:
                    if line[0] != '#':
                        LOG.warn("Skipping ill-formed line %s of %s",lineno,fname)
                    continue
                commented, vote, nickname, fingerprint = m.groups()
                try:
                    mixminion.Config._parseNickname(nickname)
                except mixminion.Config.ConfigError, e:
                    if not commented:
                        LOG.warn("Skipping bad nickname '%s', on line %s of %s: %s",
                                 nickname, lineno, fname, e)
                    continue
                fingerprint = _normalizeFingerprint(fingerprint)
                if len(fingerprint) != mixminion.Crypto.DIGEST_LEN * 2:
                    if not commented:
                        LOG.warn("Bad length for digest on line %s of %s",
                                 lineno, fname)
                        continue
                if status.has_key(fingerprint):
                    if not commented:
                        LOG.warn("Ignoring duplicate entry for fingerprint on line %s (first appeared on line %s)", lineno, lineof[fingerprint])
                    continue
                lineof[fingerprint] = lineno
                if commented:
                    haveComment.setdefault(fingerprint, []).append(
                        nickname.lower())
                elif vote == 'yes':
                    status[fingerprint] = (vote, nickname)
                    if byName.has_key(nickname.lower()):
                        if not commented:
                            LOG.warn("Ignoring second yes-vote for a nickname %r",
                                     nickname)
                        continue
                    byName[nickname.lower()] = fingerprint
                else:
                    status[fingerprint] = (vote, None)
            self.status = status
            self.haveComment = haveComment
        finally:
            f.close()

    def _getForPickle(self):
        return ("VoteCache-1", self.status, self.haveComment)

    def _setFromPickle(self, p):
        if not isinstance(p, types.TupleType) or p[0] != 'VoteCache-1':
            return 0
        self.status = p[1]
        self.haveComment = p[2]
        return 1

    def appendUnknownServers(self, lst, now=None):
        # list of [(nickname, fingerprint) ...]
        lst = [ (name, fp) for name, fp in lst if name.lower() not in
                self.haveComment.get(_normalizeFingerprint(fp), ()) ]
        if not lst:
            return
        if now is None:
            now = time.time()
        date = formatTime(now,localtime=1)
        f = open(self._fname_base, 'a+')
        try:
            f.seek(-1, 2)
            nl = (f.read(1) == '\n')
            if not nl: f.write("\n")
            f.write("#   Added %s [GMT]:\n"%formatTime(now))
            for name, fp in lst:
                f.write("#abstain %s %s\n"%(name, fp))
                self.haveComment.setdefault(fp, []).append(
                    binascii.b2a_hex(fp))
        finally:
            f.close()

    def save(self):
        mixminion.Filestore.PickleCache.save(self, 0640)
        if self.uid is not None and self.gid is not None:
            _set_uid_gid_mode(self._fname_cache, self.uid, self.gid, 0640)
            _set_uid_gid_mode(self._fname_base,  self.uid, self.gid, 0640)

    def getStatus(self, fingerprint, nickname):
        try:
            vote, nick = self.status[_normalizeFingerprint(fingerprint)]
        except KeyError:
            return "unknown"

        if vote == 'yes' and nickname.lower() != nick.lower():
            return "mismatch"

        return vote

    def getServerStatus(self, server):
        # status + 'unknown' + 'mismatch'
        return self.getStatus(server.getIdentityFingerprint(),
                              server.getNickname())

def _set_uid_gid_mode(fn, uid, gid, mode):
    """Change the permissions on the file named 'fname', so that fname
       is owned by user 'uid' and group 'gid', and has permissions 'mode'.
    """
    st = os.stat(fn)
    if st[stat.ST_UID] != uid or st[stat.ST_GID] != gid:
        os.chown(fn, uid, gid)
    if (st[stat.ST_MODE] & 0777) != mode:
        os.chmod(fn, mode)

def _normalizeFingerprint(fingerprint):
    return fingerprint.replace(" ", "").upper()
