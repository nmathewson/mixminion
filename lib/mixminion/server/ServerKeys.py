# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerKeys.py,v 1.14 2003/03/26 16:34:08 nickm Exp $

"""mixminion.ServerKeys

   Classes for servers to generate and store keys and server descriptors.
   """
#FFFF We need support for encrypting private keys.

__all__ = [ "ServerKeyring", "generateServerDescriptorAndKeys" ]

import bisect
import os
import socket
import sys
import time

import mixminion._minionlib
import mixminion.Crypto
import mixminion.server.HashLog
import mixminion.server.PacketHandler
import mixminion.server.MMTPServer

from mixminion.ServerInfo import ServerInfo, PACKET_KEY_BYTES, signServerInfo
from mixminion.Common import LOG, MixError, MixFatalError, createPrivateDir, \
     formatBase64, formatDate, formatTime, previousMidnight, secureDelete

#----------------------------------------------------------------------
class ServerKeyring:
    """A ServerKeyring remembers current and future keys, descriptors, and
       hash logs for a mixminion server.

       FFFF We need a way to generate keys as needed, not just a month's
       FFFF worth of keys up front.
       """
    ## Fields:
    # homeDir: server home directory
    # keyDir: server key directory
    # keySloppiness: fudge-factor: how forgiving are we about key liveness?
    # keyIntervals: list of (start, end, keyset Name)
    # liveKey: list of (start, end, keyset name for current key.)
    # nextRotation: time_t when this key expires.
    # keyRange: tuple of (firstKey, lastKey) to represent which key names
    #      have keys on disk.

    ## Directory layout:
    #    MINION_HOME/work/queues/incoming/ [Queue of received,unprocessed pkts]
    #                             mix/ [Mix pool]
    #                             outgoing/ [Messages for mmtp delivery]
    #                             deliver/mbox/ []
    #                      tls/dhparam [Diffie-Hellman parameters]
    #                      hashlogs/hash_1*  [HashLogs of packet hashes
    #                               hash_2*    corresponding to key sets]
    #                                ...
    #                 log [Messages from the server]
    #                 keys/identity.key [Long-lived identity PK]
    #                      key_1/ServerDesc [Server descriptor]
    #                            mix.key [packet key]
    #                            mmtp.key [mmtp key]
    #                            mmtp.cert [mmmtp key x509 cert]
    #                      key_2/...
    #                 conf/miniond.conf [configuration file]
    #                       ....

    # FFFF Support to put keys/queues in separate directories.

    def __init__(self, config):
        "Create a ServerKeyring from a config object"
        self.configure(config)

    def configure(self, config):
        "Set up a SeverKeyring from a config object"
        self.config = config
        self.homeDir = config['Server']['Homedir']
        self.keyDir = os.path.join(self.homeDir, 'keys')
        self.hashDir = os.path.join(self.homeDir, 'work', 'hashlogs')
        self.keySloppiness = config['Server']['PublicKeySloppiness'][2]
        self.checkKeys()

    def checkKeys(self):
        """Internal method: read information about all this server's
           currently-prepared keys from disk."""
        self.keyIntervals = []
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
            d = os.path.join(self.keyDir, dirname)
            si = os.path.join(d, "ServerDesc")
            if os.path.exists(si):
                inf = ServerInfo(fname=si, assumeValid=1)
                # And find out when it's valid.
                t1 = inf['Server']['Valid-After']
                t2 = inf['Server']['Valid-Until']
                self.keyIntervals.append( (t1, t2, keysetname) )
                LOG.debug("Found key %s (valid from %s to %s)",
                               dirname, formatDate(t1), formatDate(t2))
            else:
                LOG.warn("No server descriptor found for key %s"%dirname)

        # Now, sort the key intervals by starting time.
        self.keyIntervals.sort()
        self.keyRange = (firstKey, lastKey)

        # Now we try to see whether we have more or less than 1 key in effect
        # for a given time.
        for idx in xrange(len(self.keyIntervals)-1):
            end = self.keyIntervals[idx][1]
            start = self.keyIntervals[idx+1][0]
            if start < end:
                LOG.warn("Multiple keys for %s.  That's unsupported.",
                              formatDate(end))
            elif start > end:
                LOG.warn("Gap in key schedule: no key from %s to %s",
                              formatDate(end), formatDate(start))

        self.nextKeyRotation = 0 # Make sure that now > nextKeyRotation before
                                 # we call _getLiveKey()
        self._getLiveKey()       # Set up liveKey, nextKeyRotation.

    def getIdentityKey(self):
        """Return this server's identity key.  Generate one if it doesn't
           exist."""
        password = None # FFFF Use this, somehow.
        fn = os.path.join(self.keyDir, "identity.key")
        bits = self.config['Server']['IdentityKeyBits']
        if os.path.exists(fn):
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

    def createKeys(self, num=1, startAt=None):
        """Generate 'num' public keys for this server. If startAt is provided,
           make the first key become valid at 'startAt'.  Otherwise, make the
           first key become valid right after the last key we currently have
           expires.  If we have no keys now, make the first key start now."""
        # FFFF Use this.
        #password = None

        if startAt is None:
            if self.keyIntervals:
                startAt = self.keyIntervals[-1][1]+60
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

            nextStart = startAt + self.config['Server']['PublicKeyLifetime'][2]

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

    def removeDeadKeys(self, now=None):
        """Remove all keys that have expired"""
        self.checkKeys()

        if now is None:
            now = time.time()
            expiryStr = " expired"
        else:
            expiryStr = ""

        cutoff = now - self.keySloppiness
        dirs = [ os.path.join(self.keyDir,"key_"+name)
                  for va, vu, name in self.keyIntervals if vu < cutoff ]

        for dirname, (va, vu, name) in zip(dirs, self.keyIntervals):
            LOG.info("Removing%s key %s (valid from %s through %s)",
                        expiryStr, name, formatDate(va), formatDate(vu-3600))
            files = [ os.path.join(dirname,f)
                                 for f in os.listdir(dirname) ]
            secureDelete(files, blocking=1)
            os.rmdir(dirname)

        self.checkKeys()

    def _getLiveKey(self, when=None):
        """Find the first key that is now valid.  Return (Valid-after,
           valid-util, name)."""
        if not self.keyIntervals:
            self.liveKey = None
            self.nextKeyRotation = 0
            return None

        w = when
        if when is None:
            when = time.time()
            if when < self.nextKeyRotation:
                return self.liveKey

        idx = bisect.bisect(self.keyIntervals, (when, None, None))-1
        k = self.keyIntervals[idx]
        if w is None:
            self.liveKey = k
            self.nextKeyRotation = k[1]

        return k

    def getNextKeyRotation(self):
        """Return the expiration time of the current key"""
        return self.nextKeyRotation

    def getServerKeyset(self):
        """Return a ServerKeyset object for the currently live key."""
        # FFFF Support passwords on keys
        _, _, name = self._getLiveKey()
        keyset = ServerKeyset(self.keyDir, name, self.hashDir)
        keyset.load()
        return keyset

    def getDHFile(self):
        """Return the filename for the diffie-helman parameters for the
           server.  Creates the file if it doesn't yet exist."""
        dhdir = os.path.join(self.homeDir, 'work', 'tls')
        createPrivateDir(dhdir)
        dhfile = os.path.join(dhdir, 'dhparam')
        if not os.path.exists(dhfile):
            LOG.info("Generating Diffie-Helman parameters for TLS...")
            mixminion._minionlib.generate_dh_parameters(dhfile, verbose=0)
            LOG.info("...done")
        else:
            LOG.debug("Using existing Diffie-Helman parameter from %s",
                           dhfile)

        return dhfile

    def getTLSContext(self):
        """Create and return a TLS context from the currently live key."""
        keys = self.getServerKeyset()
        return mixminion._minionlib.TLSContext_new(keys.getCertFileName(),
                                                   keys.getMMTPKey(),
                                                   self.getDHFile())

    def getPacketHandler(self):
        """Create and return a PacketHandler from the currently live key."""
        keys = self.getServerKeyset()
        packetKey = keys.getPacketKey()
        hashlog = mixminion.server.HashLog.HashLog(keys.getHashLogFileName(),
                                                 keys.getMMTPKeyID())
        return mixminion.server.PacketHandler.PacketHandler(packetKey,
                                                     hashlog)


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
    def __init__(self, keyroot, keyname, hashroot):
        """Load a set of keys named "keyname" on a server where all keys
           are stored under the directory "keyroot" and hashlogs are stored
           under "hashroot". """
        keydir  = os.path.join(keyroot, "key_"+keyname)
        self.hashlogFile = os.path.join(hashroot, "hash_"+keyname)
        self.packetKeyFile = os.path.join(keydir, "mix.key")
        self.mmtpKeyFile = os.path.join(keydir, "mmtp.key")
        self.certFile = os.path.join(keydir, "mmtp.cert")
        self.descFile = os.path.join(keydir, "ServerDesc")
        if not os.path.exists(keydir):
            createPrivateDir(keydir)

    def load(self, password=None):
        """Read the short-term keys from disk.  Must be called before
           getPacketKey or getMMTPKey."""
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
    def getMMTPKeyID(self):
        "Return the sha1 hash of the asn1 encoding of the MMTP public key"
        return mixminion.Crypto.sha1(self.mmtpKey.encode_key(1))
    def getServerDescriptor(self):
        return ServerInfo(fname=self.descFile)

def checkDescriptorConsistency(info, config, log=1):
    """DOCDOC"""
    ok = 1
    if log:
        warn = LOG.warn
    else:
        def warn(*_): pass

    config_s = config['Server']
    info_s = info['Server']
    if config_s['Nickname'] and (info_s['Nickname'] != config_s['Nickname']):
        warn("Mismatched nicknames: %s in configuration; %s published.",
             config_s['Nickname'], info_s['Nickname'])
        ok = 0
    
    idBits = info_s['Identity'].get_modulus_bytes()*8
    confIDBits = config_s['IdentityKeyBits']
    if idBits != confIDBits:
        warn("Mismatched identity bits: %s in configuration; %s published.",
             confIDBits, idBits)
        ok = 0

    if config_s['Contact-Email'] != info_s['Contact']:
        warn("Mismatched contacts: %s in configuration; %s published.",
             config_s['Contact-Email'], info_s['Contact'])
        ok = 0

    if info_s['Software'] and info_s['Software'] != mixminion.__version__:
        warn("Mismatched versions: running %s; %s published.",
             mixminion.__version__, info_s['Software'])
        ok = 0

    # XXXX Move IP here
    info_im = info['Incoming/MMTP']
    config_im = config['Incoming/MMTP']
    if info_im['Port'] != config_im['Port']:
        warn("Mismatched ports: %s configured; %s published.",
             config_im['Port'], info_im['Port'])
        ok = 0
    # IP is tricky XXXX    
    #if info['Server']['IP'] != info[

    # XXXX Check protocols
    # XXXX Check enabled

    for section in ('Outgoing/MMTP', 'Delivery/MBOX', 'Delivery/SMTP'):
        info_out = info[section].get('Version')
        config_out = config[section].get('Enabled')
        if not config_out and section == 'Delivery/SMTP':
            config_out = config['Delivery/SMTP-Via-Mixmaster'].get("Enabled")
        if info_out and not config_out:
            warn("%s published, but not enabled.", section)
            ok = 0
        if config_out and not info_out:
            warn("%s enabled, but not published.", section)
            ok = 0

    return ok
        
#----------------------------------------------------------------------
# Functionality to generate keys and server descriptors

# We have our X509 certificate set to expire a bit after public key does,
# so that slightly-skewed clients don't incorrectly give up while trying to
# connect to us.
CERTIFICATE_EXPIRY_SLOPPINESS = 5*60

def generateServerDescriptorAndKeys(config, identityKey, keydir, keyname,
                                    hashdir, validAt=None, now=None):
                                    ## useServerKeys=None):
    """Generate and sign a new server descriptor, and generate all the keys to
       go with it.

          config -- Our ServerConfig object.
          identityKey -- This server's private identity key
          keydir -- The root directory for storing key sets.
          keyname -- The name of this new key set within keydir
          hashdir -- The root directory for storing hash logs.
          validAt -- The starting time (in seconds) for this key's lifetime.
          """

    useServerKeys = None #XXXX004
    
    if useServerKeys is None:
        # First, we generate both of our short-term keys...
        packetKey = mixminion.Crypto.pk_generate(PACKET_KEY_BYTES*8)
        mmtpKey = mixminion.Crypto.pk_generate(PACKET_KEY_BYTES*8)

        # ...and save them to disk, setting up our directory structure while
        # we're at it.
        serverKeys = ServerKeyset(keydir, keyname, hashdir)
        serverKeys.packetKey = packetKey
        serverKeys.mmtpKey = mmtpKey
        serverKeys.save()
    else:
        #XXXX drop this once we've tested and added more validation logic.
        LOG.warn("EXPERIMENTAL FEATURE: Regenerating server descriptor from old keys")
        serverKeys = useServerKeys
        packetKey = serverKeys.getPacketKey()
        mmtpKey = serverKeys.getMMTPKey()

    # FFFF unused
    # allowIncoming = config['Incoming/MMTP'].get('Enabled', 0)

    # Now, we pull all the information we need from our configuration.
    nickname = config['Server']['Nickname']
    if not nickname:
        nickname = socket.gethostname()
        if not nickname or nickname.lower().startswith("localhost"):
            nickname = config['Incoming/MMTP'].get('IP', "<Unknown host>")
        LOG.warn("No nickname given: defaulting to %r", nickname)
    contact = config['Server']['Contact-Email']
    comments = config['Server']['Comments']
    if not now:
        now = time.time()
    if not validAt:
        validAt = now

    # Calculate descriptor and X509 certificate lifetimes.
    # (Round validAt to previous mignight.)
    validAt = mixminion.Common.previousMidnight(validAt+30)
    validUntil = validAt + config['Server']['PublicKeyLifetime'][2]
    certStarts = validAt - CERTIFICATE_EXPIRY_SLOPPINESS
    certEnds = validUntil + CERTIFICATE_EXPIRY_SLOPPINESS + \
               config['Server']['PublicKeySloppiness'][2]

    if useServerKeys is None:
        # Create the X509 certificate.
        mixminion.Crypto.generate_cert(serverKeys.getCertFileName(),
                                       mmtpKey,
                                       "MMTP certificate for %s" %nickname,
                                       certStarts, certEnds)

    mmtpProtocolsIn = mixminion.server.MMTPServer.MMTPServerConnection \
                      .PROTOCOL_VERSIONS[:]
    mmtpProtocolsOut = mixminion.server.MMTPServer.MMTPClientConnection \
                       .PROTOCOL_VERSIONS[:]
    mmtpProtocolsIn.sort()
    mmtpProtocolsOut.sort()
    mmtpProtocolsIn = ",".join(mmtpProtocolsIn)
    mmtpProtocolsOut = ",".join(mmtpProtocolsOut)

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
        "KeyID":
           formatBase64(serverKeys.getMMTPKeyID()),
        "MMTPProtocolsIn" : mmtpProtocolsIn,
        "MMTPProtocolsOut" : mmtpProtocolsOut,
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
        Descriptor-Version: 0.1
        IP: %(IP)s
        Nickname: %(Nickname)s
        Identity: %(Identity)s
        Digest:
        Signature:
        Published: %(Published)s
        Valid-After: %(ValidAfter)s
        Valid-Until: %(ValidUntil)s
        Packet-Key: %(PacketKey)s
        """ % fields
    # XXXX004 add 'packet-formats'
    #   Packet-Formats: 0.2
    # XXXX004 add 'software'
    #   Software: Mixminion %(version)s
    if contact:
        info += "Contact: %s\n"%contact
    if comments:
        info += "Comments: %s\n"%comments

    # Only advertise incoming MMTP if we support it.
    if config["Incoming/MMTP"].get("Enabled", 0):
        info += """\
            [Incoming/MMTP]
            Version: 0.1
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
    f = open(serverKeys.getDescriptorFileName(), 'w')
    try:
        f.write(info)
    finally:
        f.close()

    # This is for debugging: we try to parse and validate the descriptor
    #   we just made.
    # FFFF Remove this once we're more confident.
    ServerInfo(string=info)

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

    return ip_set.keys()[0]
