# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerKeys.py,v 1.39 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ServerKeys

   Classes for servers to generate and store keys and server descriptors.
   """
#FFFF We need support for encrypting private keys.

__all__ = [ "ServerKeyring", "generateServerDescriptorAndKeys",
            "generateCertChain" ]

import os
import errno
import socket
import re
import sys
import time
import threading
import urllib
import urllib2

import mixminion._minionlib
import mixminion.Crypto
import mixminion.Packet
import mixminion.server.HashLog
import mixminion.server.MMTPServer
import mixminion.server.ServerMain

from mixminion.ServerInfo import ServerInfo, PACKET_KEY_BYTES, MMTP_KEY_BYTES,\
     signServerInfo
from mixminion.Common import AtomicFile, LOG, MixError, MixFatalError, \
     ceilDiv, createPrivateDir, checkPrivateFile, formatBase64, formatDate, \
     formatTime, previousMidnight, readFile, secureDelete, tryUnlink, \
     writeFile

#----------------------------------------------------------------------

# Seconds before a key becomes live that we want to generate
# and publish it.
#
#FFFF Make this configurable?  (Set to 2 days, 13 hours)
PUBLICATION_LATENCY = (2*24+13)*60*60

# Number of seconds worth of keys we want to generate in advance.
#
#FFFF Make this configurable?  (Set to 2 weeks).
PREPUBLICATION_INTERVAL = 14*24*60*60

# DOCDOC
#
#FFFF Make this configurable
DIRECTORY_UPLOAD_URL = "http://mixminion.net/minion-cgi/publish"

#----------------------------------------------------------------------
class ServerKeyring:
    """A ServerKeyring remembers current and future keys, descriptors, and
       hash logs for a mixminion server.

       DOCDOC
       """
    ## Fields:
    # homeDir: server home directory
    # keyDir: server key directory
    # keyOverlap: How long after a new key begins do we accept the old one?
    # keySets: sorted list of (start, end, keyset)
    # nextRotation: time_t when this key expires, DOCDOCDOC not so.
    # keyRange: tuple of (firstKey, lastKey) to represent which key names
    #      have keys on disk.
    #
    #DOCDOC currentKeys

    def __init__(self, config):
        "Create a ServerKeyring from a config object"
        self._lock = threading.RLock()
        self.configure(config)

    def configure(self, config):
        "Set up a ServerKeyring from a config object"
        self.config = config
        self.homeDir = config['Server']['Homedir']
        self.keyDir = os.path.join(self.homeDir, 'keys')
        self.hashDir = os.path.join(self.homeDir, 'work', 'hashlogs')
        self.keyOverlap = config['Server']['PublicKeyOverlap'].getSeconds()
        self.nextUpdate = None
        self.currentKeys = None
        self.checkKeys()

    def checkKeys(self):
        """Internal method: read information about all this server's
           currently-prepared keys from disk.

           DOCDOC raises configerror...
           """
        self.keySets = []
        firstKey = sys.maxint
        lastKey = 0

        LOG.debug("Scanning server keystore at %s", self.keyDir)

        if not os.path.exists(self.keyDir):
            LOG.info("Creating server keystore at %s", self.keyDir)
            createPrivateDir(self.keyDir)
        
        # Iterate over the entires in HOME/keys
        for dirname in os.listdir(self.keyDir):
            # Skip any that aren't directories named "key_INT"
            if not os.path.isdir(os.path.join(self.keyDir,dirname)):
                continue
            if not dirname.startswith('key_'):
                LOG.warn("Unexpected directory %s under %s",
                              dirname, self.keyDir)
                continue
            keysetname = dirname[4:]
            try:
                setNum = int(keysetname)
                # keep trace of the first and last used key number
                if setNum < firstKey: firstKey = setNum
                if setNum > lastKey: lastKey = setNum
            except ValueError:
                LOG.warn("Unexpected directory %s under %s",
                              dirname, self.keyDir)
                continue

            # Find the server descriptor...
            keyset = ServerKeyset(self.keyDir, keysetname, self.hashDir)
            t1, t2 = keyset.getLiveness()
            self.keySets.append( (t1, t2, keyset) )
                
            LOG.trace("Found key %s (valid from %s to %s)",
                      dirname, formatDate(t1), formatDate(t2))

        LOG.debug("Found %s keys.", len(self.keySets))

        # Now, sort the key intervals by starting time.
        self.keySets.sort()
        self.keyRange = (firstKey, lastKey)

        # Now we try to see whether we have more or less than 1 key in effect
        # for a given time.
        for idx in xrange(len(self.keySets)-1):
            end = self.keySets[idx][1]
            start = self.keySets[idx+1][0]
            if start < end:
                LOG.warn("Multiple keys for %s.  That's unsupported.",
                              formatDate(end))
            elif start > end:
                LOG.warn("Gap in key schedule: no key from %s to %s",
                              formatDate(end), formatDate(start))

    def checkDescriptorConsistency(self, regen=1):
        """DOCDOC"""
        identity = None
        state = []
        for _,_,ks in self.keySets:
            ok = ks.checkConsistency(self.config, 0)
            if ok == 'good':
                continue
            state.append((ok, ks))

        if not state:
            return
        
        LOG.error("Some generated keysets do not match "
                  "current configuration...")
        
        for ok, ks in state:
            va,vu = ks.getLiveness()
            LOG.error("Keyset %s (%s--%s):",ks.keyname,formatTime(va,1),
                      formatTime(vu,1))
            ks.checkConsistency(self.config, 1)
            if regen and ok == 'bad':
                if not identity: identity = self.getIdentityKey()
                ks.regenerateServerDescriptor(self.config, identity)

    def getIdentityKey(self):
        """Return this server's identity key.  Generate one if it doesn't
           exist."""
        password = None # FFFF Use this, somehow.
        fn = os.path.join(self.keyDir, "identity.key")
        bits = self.config['Server']['IdentityKeyBits']
        if os.path.exists(fn):
            checkPrivateFile(fn)
            key = mixminion.Crypto.pk_PEM_load(fn, password)
            keylen = key.get_modulus_bytes()*8
            if keylen != bits:
                LOG.warn(
                    "Stored identity key has %s bits, but you asked for %s.",
                    keylen, bits)
        else:
            LOG.info("Generating identity key. (This may take a while.)")
            key = mixminion.Crypto.pk_generate(bits)
            mixminion.Crypto.pk_PEM_save(key, fn, password)
            LOG.info("Generated %s-bit identity key.", bits)

        return key

    def publishKeys(self, allKeys=0):
        """DOCDOC"""
        keySets = [ ks for _, _, ks in self.keySets ]
        if allKeys:
            LOG.info("Republishing all known keys to directory server")
        else:
            keySets = [ ks for ks in keySets if not ks.isPublished() ]
            if not keySets:
                LOG.trace("publishKeys: no unpublished keys found")
                return
            LOG.info("Publishing %s keys to directory server...",len(keySets))

        rejected = 0
        for ks in keySets:
            status = ks.publish(DIRECTORY_UPLOAD_URL)
            if status == 'error':
                LOG.error("Error publishing a key; giving up")
                return 0
            elif status == 'reject':
                rejected += 1
            else:
                assert status == 'accept'
        if rejected == 0:
            LOG.info("All keys published successfully.")
            return 1
        else:
            LOG.info("%s/%s keys were rejected." , rejected, len(keySets))
            return 0

    def removeIdentityKey(self):
        """Remove this server's identity key."""
        fn = os.path.join(self.keyDir, "identity.key")
        if not os.path.exists(fn):
            LOG.info("No identity key to remove.")
        else:
            LOG.warn("Removing identity key in 10 seconds")
            time.sleep(10)
            LOG.warn("Removing identity key")
            secureDelete([fn], blocking=1)

        dhfile = os.path.join(self.homeDir, 'work', 'tls', 'dhparam')
        if os.path.exists('dhfile'):
            LOG.info("Removing diffie-helman parameters file")
            secureDelete([dhfile], blocking=1)

    def createKeysAsNeeded(self,now=None):
        """DOCDOC"""
        if now is None:
            now = time.time()

        if self.getNextKeygen() > now-10: # 10 seconds of leeway
            return

        if self.keySets:
            lastExpiry = self.keySets[-1][1]
        else:
            lastExpiry = now

        needToCoverUntil = now+PUBLICATION_LATENCY+PREPUBLICATION_INTERVAL
        timeToCover = needToCoverUntil-lastExpiry
        
        lifetime = self.config['Server']['PublicKeyLifetime'].getSeconds()
        nKeys = int(ceilDiv(timeToCover, lifetime))

        LOG.info("Creating %s keys", nKeys)
        self.createKeys(num=nKeys)

    def createKeys(self, num=1, startAt=None):
        """Generate 'num' public keys for this server. If startAt is provided,
           make the first key become valid at 'startAt'.  Otherwise, make the
           first key become valid right after the last key we currently have
           expires.  If we have no keys now, make the first key start now."""
        # FFFF Use this.
        #password = None

        if startAt is None:
            if self.keySets:
                startAt = self.keySets[-1][1]+60
            else:
                startAt = time.time()+60

        startAt = previousMidnight(startAt)

        firstKey, lastKey = self.keyRange

        for _ in xrange(num):
            if firstKey == sys.maxint:
                keynum = firstKey = lastKey = 1
            elif firstKey > 1:
                firstKey -= 1
                keynum = firstKey
            else:
                lastKey += 1
                keynum = lastKey

            keyname = "%04d" % keynum

            nextStart = startAt + self.config['Server']['PublicKeyLifetime'].getSeconds()

            LOG.info("Generating key %s to run from %s through %s (GMT)",
                     keyname, formatDate(startAt),
                     formatDate(nextStart-3600))
            generateServerDescriptorAndKeys(config=self.config,
                                            identityKey=self.getIdentityKey(),
                                            keyname=keyname,
                                            keydir=self.keyDir,
                                            hashdir=self.hashDir,
                                            validAt=startAt)
            startAt = nextStart

        self.checkKeys()

    def regenerateDescriptors(self):
        """DOCDOC"""
        LOG.info("Regenerating server descriptors; keeping old keys.")
        identityKey = self.getIdentityKey()
        for _,_,ks in self.keySets:
            ks.regenerateServerDescriptor(self.config, identityKey)

    def getNextKeygen(self):
        """DOCDOC

           -1 => Right now!
        """
        if not self.keySets:
            return -1

        # Our last current key expires at 'lastExpiry'.
        lastExpiry = self.keySets[-1][1]
        # We want to have keys in the directory valid for
        # PREPUBLICATION_INTERVAL seconds after that, and we assume that
        # a key takes up to PUBLICATION_LATENCY seconds to make it into the
        # directory.
        nextKeygen = lastExpiry - PUBLICATION_LATENCY - PREPUBLICATION_INTERVAL

        LOG.info("Last expiry at %s; next keygen at %s",
                 formatTime(lastExpiry,1), formatTime(nextKeygen, 1))
        return nextKeygen

    def removeDeadKeys(self, now=None):
        """Remove all keys that have expired"""
        self.checkKeys()

        if now is None:
            now = time.time()
            expiryStr = " expired"
        else:
            expiryStr = ""

        cutoff = now - self.keyOverlap

        for va, vu, keyset in self.keySets:
            if vu >= cutoff:
                continue
            name = keyset.keyname
            LOG.info("Removing%s key %s (valid from %s through %s)",
                     expiryStr, name, formatDate(va), formatDate(vu-3600))
            keyset.delete()

        self.checkKeys()

    def _getLiveKeys(self, now=None):
        """Find all keys that are now valid.  Return list of (Valid-after,
           valid-util, keyset)."""
        if not self.keySets:
            return []
        if now is None:
            now = time.time()

        cutoff = now-self.keyOverlap
        # A key is live if
        #     * it became valid before now, and
        #     * it did not become invalid until keyOverlap seconds ago

        return [ (va,vu,k) for (va,vu,k) in self.keySets
                 if va < now and vu > cutoff ]

    def getServerKeysets(self, now=None):
        """Return a ServerKeyset object for the currently live key.

           DOCDOC"""
        # FFFF Support passwords on keys
        keysets = [ ]
        for va, vu, ks in self._getLiveKeys(now):
            ks.load()
            keysets.append(ks)

        if len(keysets) > 2:
            LOG.error("Got >2 active keys! That's not supposed to happen.")

        return keysets

    def _getDHFile(self):
        """Return the filename for the diffie-helman parameters for the
           server.  Creates the file if it doesn't yet exist."""
        dhdir = os.path.join(self.homeDir, 'work', 'tls')
        createPrivateDir(dhdir)
        dhfile = os.path.join(dhdir, 'dhparam')
        if not os.path.exists(dhfile):
            # ???? This is only using 512-bit Diffie-Hellman!  That isn't
            # ???? remotely enough.
            LOG.info("Generating Diffie-Helman parameters for TLS...")
            mixminion._minionlib.generate_dh_parameters(dhfile, verbose=0)
            LOG.info("...done")
        else:
            LOG.debug("Using existing Diffie-Helman parameter from %s",
                           dhfile)

        return dhfile

    def _getTLSContext(self, keys=None):
        """Create and return a TLS context from the currently live key."""
        if keys is None:
            keys = self.getServerKeysets()[-1]
        return mixminion._minionlib.TLSContext_new(keys.getCertFileName(),
                                                   keys.getMMTPKey(),
                                                   self._getDHFile())

    def updateKeys(self, packetHandler, mmtpServer, statusFile=None,when=None):
        """DOCDOC: Return next rotation."""
        self.removeDeadKeys()
        self.currentKeys = keys = self.getServerKeysets(when)
        LOG.info("Updating keys: %s currently valid", len(keys))
        if mmtpServer is not None:
            context = self._getTLSContext(keys[-1])
            mmtpServer.setContext(context)
        if packetHandler is not None:
            packetKeys = []
            hashLogs = []

            for k in keys:
                packetKeys.append(k.getPacketKey())
                hashLogs.append(mixminion.server.HashLog.getHashLog(
                    k.getHashLogFileName(), k.getPacketKeyID()))
            packetHandler.setKeys(packetKeys, hashLogs)

        if statusFile:
            writeFile(statusFile,
                    "".join(["%s\n"%k.getDescriptorFileName() for k in keys]),
                    0644)

        self.nextUpdate = None
        self.getNextKeyRotation(keys)

    def getNextKeyRotation(self, curKeys=None):
        """DOCDOC"""
        if self.nextUpdate is None:
            if curKeys is None:
                if self.currentKeys is None:
                    curKeys = self.getServerKeysets()
                else:
                    curKeys = self.currentKeys
            events = []
            curNames = {}
            #DOCDOC
            for k in curKeys:
                va, vu = k.getLiveness()
                events.append((vu+self.keyOverlap, "RM"))
                curNames[k.keyname] = 1
            for va, vu, k in self.keySets:
                if curNames.has_key(k.keyname): continue
                events.append((va, "ADD"))

            events.sort()
            if not events:
                LOG.info("No future key rotation events.")
                self.nextUpdate = sys.maxint
                return self.nextUpdate

            self.nextUpdate, eventType = events[0]
            if eventType == "RM":
                LOG.info("Next key event: old key is removed at %s",
                         formatTime(self.nextUpdate,1))
            else:
                assert eventType == "ADD"
                LOG.info("Next key event: new key becomes valid at %s",
                         formatTime(self.nextUpdate,1))

        return self.nextUpdate 

    def getAddress(self):
        """Return out current ip/port/keyid tuple"""
        keys = self.getServerKeysets()[0]
        desc = keys.getServerDescriptor()
        return (desc['Incoming/MMTP']['IP'],
                desc['Incoming/MMTP']['Port'],
                desc['Incoming/MMTP']['Key-Digest'])

    def lock(self, blocking=1):
        return self._lock.acquire(blocking)

    def unlock(self):
        self._lock.release()

#----------------------------------------------------------------------
class ServerKeyset:
    """A set of expirable keys for use by a server.

       A server has one long-lived identity key, and two short-lived
       temporary keys: one for subheader encryption and one for MMTP.  The
       subheader (or 'packet') key has an associated hashlog, and the
       MMTP key has an associated self-signed X509 certificate.

       Whether we publish or not, we always generate a server descriptor
       to store the keys' lifetimes.

       When we create a new ServerKeyset object, the associated keys are not
       read from disk unil the object's load method is called."""
    ## Fields:
    # hashlogFile: filename of this keyset's hashlog.
    # packetKeyFile, mmtpKeyFile: filename of this keyset's short-term keys
    # certFile: filename of this keyset's X509 certificate
    # descFile: filename of this keyset's server descriptor.
    #
    # packetKey, mmtpKey: This server's actual short-term keys.
    # DOCDOC serverinfo, validAfter, validUntil,published(File)?, keydir
    def __init__(self, keyroot, keyname, hashroot):
        """Load a set of keys named "keyname" on a server where all keys
           are stored under the directory "keyroot" and hashlogs are stored
           under "hashroot". """
        self.keyroot = keyroot
        self.keyname = keyname
        self.hashroot= hashroot

        self.keydir = keydir = os.path.join(keyroot, "key_"+keyname)
        self.hashlogFile = os.path.join(hashroot, "hash_"+keyname)
        self.packetKeyFile = os.path.join(keydir, "mix.key")
        self.mmtpKeyFile = os.path.join(keydir, "mmtp.key")
        self.certFile = os.path.join(keydir, "mmtp.cert")
        self.descFile = os.path.join(keydir, "ServerDesc")
        self.publishedFile = os.path.join(keydir, "published")
        self.serverinfo = None
        self.validAfter = None
        self.validUntil = None
        self.published = os.path.exists(self.publishedFile)
        if not os.path.exists(keydir):
            createPrivateDir(keydir)

    def delete(self):
        """DOCDOC"""
        files = [self.packetKeyFile,
                 self.mmtpKeyFile,
                 self.certFile,
                 self.descFile,
                 self.publishedFile,
                 self.hashlogFile ]
        files = [f for f in files if os.path.exists(f)]
        hashdir, name = os.path.split(self.hashlogFile)
        if os.path.exists(hashdir):
            start1 = name+"."
            start2 = name+"_"
            for fn in os.listdir(hashdir):
                if fn.startswith(start1) or fn.startswith(start2):
                    files.append(os.path.join(hashdir, fn))

        secureDelete(files, blocking=1)
        os.rmdir(self.keydir)

    def load(self, password=None):
        """Read the short-term keys from disk.  Must be called before
           getPacketKey or getMMTPKey."""
        checkPrivateFile(self.packetKeyFile)
        checkPrivateFile(self.mmtpKeyFile)
        self.packetKey = mixminion.Crypto.pk_PEM_load(self.packetKeyFile,
                                                      password)
        self.mmtpKey = mixminion.Crypto.pk_PEM_load(self.mmtpKeyFile,
                                                    password)
    def save(self, password=None):
        """Save this set of keys to disk."""
        mixminion.Crypto.pk_PEM_save(self.packetKey, self.packetKeyFile,
                                     password)
        mixminion.Crypto.pk_PEM_save(self.mmtpKey, self.mmtpKeyFile,
                                     password)
    def getCertFileName(self): return self.certFile
    def getHashLogFileName(self): return self.hashlogFile
    def getDescriptorFileName(self): return self.descFile
    def getPacketKey(self): return self.packetKey
    def getMMTPKey(self): return self.mmtpKey
    def getPacketKeyID(self):
        "Return the sha1 hash of the asn1 encoding of the packet public key"
        return mixminion.Crypto.sha1(self.packetKey.encode_key(1))
    def getServerDescriptor(self):
        """DOCDOC"""
        if self.serverinfo is None:
            self.serverinfo = ServerInfo(fname=self.descFile)
        return self.serverinfo
    def getLiveness(self):
        """DOCDOC"""
        if self.validAfter is None or self.validUntil is None:
            info = self.getServerDescriptor()
            self.validAfter = info['Server']['Valid-After']
            self.validUntil = info['Server']['Valid-Until']
        return self.validAfter, self.validUntil
    def isPublished(self):
        """DOCDOC"""
        return self.published
    def markAsPublished(self):
        """DOCDOC"""
        contents = "%s\n"%formatTime(time.time(),1)
        writeFile(self.publishedFile, contents, mode=0600)
        self.published = 1
    def markAsUnpublished(self):
        """DOCDOC"""
        tryUnlink(self.publishedFile)
        self.published = 0
    def regenerateServerDescriptor(self, config, identityKey):
        """DOCDOC"""
        self.load()
        self.markAsUnpublished()
        validAt,validUntil = self.getLiveness()
        LOG.info("Regenerating descriptor for keyset %s (%s--%s)",
                 self.keyname, formatTime(validAt,1),
                 formatTime(validUntil,1))
        generateServerDescriptorAndKeys(config, identityKey,
                         self.keyroot, self.keyname, self.hashroot,
                         validAt=validAt, validUntil=validUntil,
                         useServerKeys=1)
        self.serverinfo = self.validAfter = self.validUntil = None

    def checkConsistency(self, config, log=1):
        """DOCDOC"""
        return checkDescriptorConsistency(self.getServerDescriptor(),
                                          config,
                                          log=log,
                                          isPublished=self.published)

    def publish(self, url):
        """DOCDOC Returns 'accept', 'reject', 'error'. """
        fname = self.getDescriptorFileName()
        descriptor = readFile(fname)
        fields = urllib.urlencode({"desc" : descriptor})
        try:
            try:
                f = urllib2.urlopen(url, fields)
                info = f.info()
                reply = f.read()
            except:
                LOG.error_exc(sys.exc_info(),
                              "Error publishing server descriptor")
                return 'error'
        finally:
            f.close()

        if info.get('Content-Type') != 'text/plain':
            LOG.error("Bad content type %s from directory"%info.get(
                'Content-Type'))
            return 'error'
        m = DIRECTORY_RESPONSE_RE.search(reply)
        if not m:
            LOG.error("Didn't understand reply from directory: %s",
                      reply)
            return 'error'
        ok = int(m.group(1))
        msg = m.group(2)
        if not ok:
            LOG.error("Directory rejected descriptor: %r", msg)
            return 'reject'

        LOG.info("Directory accepted descriptor: %r", msg)
        self.markAsPublished()
        return 'accept'
            
DIRECTORY_RESPONSE_RE = re.compile(r'^Status: (0|1)[ \t]*\nMessage: (.*)$',
                                   re.M)

class _WarnWrapper:
    """Helper for 'checkDescriptorConsistency' to keep its implementation
       short.  Counts the number of times it's invoked, and delegates to
       LOG.warn if silence is false."""
    def __init__(self, silence, isPublished):
        self.silence = silence
        self.errors = 0
        self.called = 0
        self.published = isPublished
    def __call__(self, *args):
        self.called = 1
        self.errors += 1
        if not self.published:
            args = list(args)
            args[0] = args[0].replace("published", "in unpublished descriptor")
        if not self.silence:
            LOG.warn(*args)

def checkDescriptorConsistency(info, config, log=1, isPublished=1):
    """Given a ServerInfo and a ServerConfig, compare them for consistency.

       Return true iff info may have come from 'config'.  If 'log' is
       true, warn as well.  Does not check keys.

       DOCDOC returns 'good', 'so-so', 'bad'
    """
    warn = _WarnWrapper(silence = not log, isPublished=isPublished)

    config_s = config['Server']
    info_s = info['Server']
    if info_s['Nickname'] != config_s['Nickname']:
        warn("Mismatched nicknames: %s in configuration; %s published.",
             config_s['Nickname'], info_s['Nickname'])

    idBits = info_s['Identity'].get_modulus_bytes()*8
    confIDBits = config_s['IdentityKeyBits']
    if idBits != confIDBits:
        warn("Mismatched identity bits: %s in configuration; %s published.",
             confIDBits, idBits)
        warn.errors -= 1 # We can't do anything about this!

    if config_s['Contact-Email'] != info_s['Contact']:
        warn("Mismatched contacts: %s in configuration; %s published.",
             config_s['Contact-Email'], info_s['Contact'])

    if info_s['Software'] and info_s['Software'] != (
        "Mixminion %s" % mixminion.__version__):
        warn("Mismatched versions: running %s; %s published.",
             mixminion.__version__, info_s['Software'])

    if config_s['Comments'] != info_s['Comments']:
        warn("Mismatched comments field.")

    if (previousMidnight(info_s['Valid-Until']) !=
        previousMidnight(config_s['PublicKeyLifetime'].getSeconds() +
                         info_s['Valid-After'])):
        warn("Published lifetime does not match PublicKeyLifetime")
        warn("(Future keys will be generated with the correct lifetime")
        warn.errors -= 2 # We can't do anything about this!

    if info_s['Software'] != 'Mixminion %s'%mixminion.__version__:
        warn("Mismatched software versions: running %s; %s published."
             'Mixminion %s'%mixminion.__version__, info_s['Software'])

    info_im = info['Incoming/MMTP']
    config_im = config['Incoming/MMTP']
    if info_im['Port'] != config_im['Port']:
        warn("Mismatched ports: %s configured; %s published.",
             config_im['Port'], info_im['Port'])

    info_ip = info['Incoming/MMTP']['IP']
    if config_im['IP'] == '0.0.0.0':
        guessed = _guessLocalIP()
        if guessed != info_ip:
            warn("Mismatched IPs: Guessed IP (%s); %s published.",
                 guessed, info_ip)
    elif config_im['IP'] != info_ip:
        warn("Mismatched IPs: %s configured; %s published.",
             config_im['IP'], info_ip)

    if config_im['Enabled'] and not info_im.get('Version'):
        warn("Incoming MMTP enabled but not published.")
    elif not config_im['Enabled'] and info_im.get('Version'):
        warn("Incoming MMTP published but not enabled.")

    for section in ('Outgoing/MMTP', 'Delivery/MBOX', 'Delivery/SMTP'):
        info_out = info[section].get('Version')
        config_out = config[section].get('Enabled')
        if not config_out and section == 'Delivery/SMTP':
            config_out = config['Delivery/SMTP-Via-Mixmaster'].get("Enabled")
        if info_out and not config_out:
            warn("%s published, but not enabled.", section)
        if config_out and not info_out:
            warn("%s enabled, but not published.", section)

    if warn.errors:
        return "bad"
    elif warn.called:
        return "so-so"
    else:
        return "good"

#----------------------------------------------------------------------
# Functionality to generate keys and server descriptors

# We have our X509 certificate set to expire a bit after public key does,
# so that slightly-skewed clients don't incorrectly give up while trying to
# connect to us.
CERTIFICATE_EXPIRY_SLOPPINESS = 5*60

def generateServerDescriptorAndKeys(config, identityKey, keydir, keyname,
                                    hashdir, validAt=None, now=None,
                                    useServerKeys=0, validUntil=None):
    #XXXX reorder args
    """Generate and sign a new server descriptor, and generate all the keys to
       go with it.

          config -- Our ServerConfig object.
          identityKey -- This server's private identity key
          keydir -- The root directory for storing key sets.
          keyname -- The name of this new key set within keydir
          hashdir -- The root directory for storing hash logs.
          validAt -- The starting time (in seconds) for this key's lifetime.

          DOCDOC useServerKeys, validUntil
          """

    if useServerKeys:
        serverKeys = ServerKeyset(keydir, keyname, hashdir)
        serverKeys.load()
        packetKey = serverKeys.packetKey
        mmtpKey = serverKeys.mmtpKey # not used
    else:
        # First, we generate both of our short-term keys...
        packetKey = mixminion.Crypto.pk_generate(PACKET_KEY_BYTES*8)
        mmtpKey = mixminion.Crypto.pk_generate(MMTP_KEY_BYTES*8)

        # ...and save them to disk, setting up our directory structure while
        # we're at it.
        serverKeys = ServerKeyset(keydir, keyname, hashdir)
        serverKeys.packetKey = packetKey
        serverKeys.mmtpKey = mmtpKey
        serverKeys.save()

    # FFFF unused
    # allowIncoming = config['Incoming/MMTP'].get('Enabled', 0)

    # Now, we pull all the information we need from our configuration.
    nickname = config['Server']['Nickname']
    contact = config['Server']['Contact-Email']
    comments = config['Server']['Comments']
    if not now:
        now = time.time()
    if not validAt:
        validAt = now

    if config.getInsecurities():
        secure = "no"
    else:
        secure = "yes"

    # Calculate descriptor and X509 certificate lifetimes.
    # (Round validAt to previous mignight.)
    validAt = mixminion.Common.previousMidnight(validAt+30)
    if not validUntil:
        keyLifetime = config['Server']['PublicKeyLifetime'].getSeconds()
        validUntil = previousMidnight(validAt + keyLifetime + 30)
    certStarts = validAt - CERTIFICATE_EXPIRY_SLOPPINESS
    certEnds = validUntil + CERTIFICATE_EXPIRY_SLOPPINESS

    # Create the X509 certificates in any case, in case one of the parameters
    # has changed.
    generateCertChain(serverKeys.getCertFileName(),
                      mmtpKey, identityKey, nickname, certStarts, certEnds)

    mmtpProtocolsIn = mixminion.server.MMTPServer.MMTPServerConnection \
                      .PROTOCOL_VERSIONS[:]
    mmtpProtocolsOut = mixminion.server.MMTPServer.MMTPClientConnection \
                       .PROTOCOL_VERSIONS[:]
    mmtpProtocolsIn.sort()
    mmtpProtocolsOut.sort()
    mmtpProtocolsIn = ",".join(mmtpProtocolsIn)
    mmtpProtocolsOut = ",".join(mmtpProtocolsOut)

    identityKeyID = formatBase64(
                      mixminion.Crypto.sha1(
                          mixminion.Crypto.pk_encode_public_key(identityKey)))

    fields = {
        "IP": config['Incoming/MMTP'].get('IP', "0.0.0.0"),
        "Port": config['Incoming/MMTP'].get('Port', 0),
        "Nickname": nickname,
        "Identity":
           formatBase64(mixminion.Crypto.pk_encode_public_key(identityKey)),
        "Published": formatTime(now),
        "ValidAfter": formatDate(validAt),
        "ValidUntil": formatDate(validUntil),
        "PacketKey":
           formatBase64(mixminion.Crypto.pk_encode_public_key(packetKey)),
        "KeyID": identityKeyID,
        "MMTPProtocolsIn" : mmtpProtocolsIn,
        "MMTPProtocolsOut" : mmtpProtocolsOut,
        "PacketFormat" : "%s.%s"%(mixminion.Packet.MAJOR_NO,
                                  mixminion.Packet.MINOR_NO),
        "mm_version" : mixminion.__version__,
        "Secure" : secure
        }

    # If we don't know our IP address, try to guess
    if fields['IP'] == '0.0.0.0':
        try:
            fields['IP'] = _guessLocalIP()
            LOG.warn("No IP configured; guessing %s",fields['IP'])
        except IPGuessError, e:
            LOG.error("Can't guess IP: %s", str(e))
            raise MixError("Can't guess IP: %s" % str(e))

    # Fill in a stock server descriptor.  Note the empty Digest: and
    # Signature: lines.
    info = """\
        [Server]
        Descriptor-Version: 0.2
        Nickname: %(Nickname)s
        Identity: %(Identity)s
        Digest:
        Signature:
        Published: %(Published)s
        Valid-After: %(ValidAfter)s
        Valid-Until: %(ValidUntil)s
        Packet-Key: %(PacketKey)s
        Packet-Formats: %(PacketFormat)s
        Software: Mixminion %(mm_version)s
        Secure-Configuration: %(Secure)s
        """ % fields
    if contact:
        info += "Contact: %s\n"%contact
    if comments:
        info += "Comments: %s\n"%comments

    # Only advertise incoming MMTP if we support it.
    if config["Incoming/MMTP"].get("Enabled", 0):
        info += """\
            [Incoming/MMTP]
            Version: 0.1
            IP: %(IP)s
            Port: %(Port)s
            Key-Digest: %(KeyID)s
            Protocols: %(MMTPProtocolsIn)s
            """ % fields
        for k,v in config.getSectionItems("Incoming/MMTP"):
            if k not in ("Allow", "Deny"):
                continue
            info += "%s: %s" % (k, _rule(k=='Allow',v))

    # Only advertise outgoing MMTP if we support it.
    if config["Outgoing/MMTP"].get("Enabled", 0):
        info += """\
            [Outgoing/MMTP]
            Version: 0.1
            Protocols: %(MMTPProtocolsOut)s
            """ % fields
        for k,v in config.getSectionItems("Outgoing/MMTP"):
            if k not in ("Allow", "Deny"):
                continue
            info += "%s: %s" % (k, _rule(k=='Allow',v))

    if not config.moduleManager.isConfigured():
        config.moduleManager.configure(config)

    # Ask our modules for their configuration information.
    info += "".join(config.moduleManager.getServerInfoBlocks())

    # Remove extra (leading or trailing) whitespace from the lines.
    lines = [ line.strip() for line in info.split("\n") ]
    # Remove empty lines
    lines = filter(None, lines)
    # Force a newline at the end of the file, rejoin, and sign.
    lines.append("")
    info = "\n".join(lines)
    info = signServerInfo(info, identityKey)

    # Write the desciptor
    writeFile(serverKeys.getDescriptorFileName(), info, mode=0644)

    # This is for debugging: we try to parse and validate the descriptor
    #   we just made.
    # FFFF Remove this once we're more confident.
    inf = ServerInfo(string=info)
    ok = checkDescriptorConsistency(inf, config, log=0, isPublished=0)
    assert ok in ('good', 'so-so')

    return info

def _rule(allow, (ip, mask, portmin, portmax)):
    """Return an external representation of an IP allow/deny rule."""
    if mask == '0.0.0.0':
        ip="*"
        mask=""
    elif mask == "255.255.255.255":
        mask = ""
    else:
        mask = "/%s" % mask

    if portmin==portmax==48099 and allow:
        ports = ""
    elif portmin == 0 and portmax == 65535 and not allow:
        ports = ""
    elif portmin == portmax:
        ports = " %s" % portmin
    else:
        ports = " %s-%s" % (portmin, portmax)

    return "%s%s%s\n" % (ip,mask,ports)

#----------------------------------------------------------------------
# Helpers to guess a reasonable local IP when none is provided.

class IPGuessError(MixError):
    """Exception: raised when we can't guess a single best IP."""
    pass

# Cached guessed IP address
_GUESSED_IP = None

def _guessLocalIP():
    "Try to find a reasonable IP for this host."
    global _GUESSED_IP
    if _GUESSED_IP is not None:
        return _GUESSED_IP

    # First, let's see what our name resolving subsystem says our
    # name is.
    ip_set = {}
    try:
        ip_set[ socket.gethostbyname(socket.gethostname()) ] = 1
    except socket.error:
        try:
            ip_set[ socket.gethostbyname(socket.getfqdn()) ] = 1
        except socket.error:
            pass

    # And in case that doesn't work, let's see what other addresses we might
    # think we have by using 'getsockname'.
    for target_addr in ('18.0.0.1', '10.0.0.1', '192.168.0.1',
                        '172.16.0.1')+tuple(ip_set.keys()):
        # open a datagram socket so that we don't actually send any packets
        # by connecting.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_addr, 9)) #discard port
            ip_set[ s.getsockname()[0] ] = 1
        except socket.error:
            pass

    for ip in ip_set.keys():
        if ip.startswith("127.") or ip.startswith("0."):
            del ip_set[ip]

    # FFFF reject 192.168, 10., 176.16.x

    if len(ip_set) == 0:
        raise IPGuessError("No address found")

    if len(ip_set) > 1:
        raise IPGuessError("Multiple addresses found: %s" % (
                    ", ".join(ip_set.keys())))

    IP = ip_set.keys()[0]
    if IP.startswith("192.168.") or IP.startswith("10.") or \
       IP.startswith("176.16."):
        raise IPGuessError("Only address found is in a private IP block")

    return IP

def generateCertChain(filename, mmtpKey, identityKey, nickname,
                      certStarts, certEnds):
    """Create a two-certificate chain DOCDOC"""
    fname = filename+"_tmp"
    mixminion.Crypto.generate_cert(fname,
                                   mmtpKey, identityKey,
                                   "%s<MMTP>" %nickname,
                                   nickname,
                                   certStarts, certEnds)
    certText = readFile(fname)
    os.unlink(fname)
    mixminion.Crypto.generate_cert(fname,
                                   identityKey, identityKey,
                                   nickname, nickname,
                                   certStarts, certEnds)

    identityCertText = readFile(fname)
    os.unlink(fname)
    writeFile(filename, certText+identityCertText, 0600)

