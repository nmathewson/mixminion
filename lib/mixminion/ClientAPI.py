# Copyright 2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ClientAPI.py,v 1.3 2004/12/02 06:49:03 nickm Exp $

"""mixminion.ClientAPI

   This is a front-end for programs to use client-side Mixminion functionality.
   This includes:
     - Encoding messages into packets
     - Sending packets
     - Parsing paths
     - Etc, etc DOCDOC

   This module is intended to present a semi-stable front-end to the
   other Mixminion client modules.  Client implementors shouldn't need to
   use functions from any other modules.

   DOCDOC discuss dataflow
"""

## XXXX        THIS IS AN UNIMPLEMENTED DRAFT API!

# ============================================================

__all__ = [ "MixError", "ClientEnv", "Mix", "PathSpec", "Path",
            "PacketBody", "Packet", "PacketDest", "MsgDest",
            "AddrMsgDest", "SURBMsgDest", "SURB", "ReceivedPacket",
            ]

# The operations in this file raise 'MixError' on failure.
from mixminion.Common import MixError

class ClientEnv:
    """A ClientEnv is an interface to a Mixminion client environment.  Once
       you allocate a ClientEnv, you should release it with .close() before
       exiting, to make sure all resources are flushed to disk.

       In general, all managed resources are lazy-loaded automatically from
       disk as needed, but you can override the defaults with the
       configuration functions below.

       A ClientEnv manages the following resources:

         - Mixminion configuration (set manually with loadConfig/setConfig, or
           lazy-loaded automatically based on current environment variables).

         - A source of server descriptors (defaults to an automatically
           downloaded, cached, and refreshed server directory).

         - A log of which SURBs have already been used (defaults to a
           disk-backed DB).

         - A 'password manager' that asks the user for passwords as needed to
           decrypt resources, and remembers passwords that have already been
           asked (defaults to a terminal-based implementation).

         - A 'keyring' storing SURB keys (defaults to a password-encrypted
           file on disk).

         - A 'queue' of pending packets that have been generated but not yet
           sent into the mixnet (defaults to a directory on disk).

         - A 'fragment pool' of fragments for messages that are not yet
           complete enough to reassemble.

         - One or more callbacks to receive log messages.

       Additionally, a ClientAPI provides interfaces to use these managed
       resources in order to send and receive Type III packets, by:

         - Querying information about known mixes.

         - Generating paths through the mixnet.

         - Encoding messages into packet bodies.

         - Generating SURBs.

         - Generating Type III packets for transmission into the network.

         - Sending packets into the network and queueing undeliverable
           packets.

         - Managing queued packets (retrying, and deleting old ones)

         - Decoding/decrypting received packets.

         - Reassembling fragmented messages.
    """
    def __init__(self):
        pass

    # ------------------------------------------------------------
    # Configuration functions
    def loadConfig(self, location=None):
        """Read the configuration file for this client.  If 'location'
           is provided, read the configuration stored in the provided
           file.  Otherwise, load the configuration file from the default
           location.

           You don't need to invoke this funtion; if you don't call it,
           the default configuration file will be lazy-loaded on demand.
        """
        pass

    # Advanced:
    def setConfig(self, config):
        """Set the configuration object for thie ClientEnv to 'config'.
           'Config' should be one of: a dict mapping section names to dicts
           mapping key names to values; or a string containing the contents
           of a configuration file; or an object conforming to the
           interface of mixminion.Config.ClientConfig.
        """
        pass

    #------------------------------------------------------------
    # Functions to change the underlying pluggable helper objects.
    # You don't need to fool with these if you want default functionality.

    # Advanced:
    def setDescriptorSource(self, descriptorSource):
        """Override the implementation of the Mix directory with another
           source for server descriptor objects.  Any new descriptor source
           must conform to the interface of
           mixminion.ServerInfo.DescriptorSource
        """
        pass

    def setSURBLog(self, surbLog):
        """Override the implementation of the database used to log
           which SURBs we've used, and when.  Must conform to
           mixminion.ClientUtils.SURBLog."""
        pass

    def setPasswordManager(self, passwordManager):
        """Override the object used to ask for passwords from the user
           and remember passwords that we've received.  Must conform to
           mixminion.ClientUtils.PasswordManager.
        """
        pass

    def setKeyring(self, keyring):
        """Override the object used to store SURB keys, encrypted with the
           user's password.  Must conform to mixminion.ClientUtils.Keyring.
        """
        pass

    def setQueue(self, queue):
        """Override the object used to store pending packets.  Must conform
           to mixminion.ClientUtils.ClientQueue.
        """
        pass

    def setFragmentPool(self, pool):
        """Override the object used to reassemble fragmented messages. Must
           conform to mixminion.ClientUtils.ClientFragmentPool.
        """
        pass

    def addLogHandler(self, func):
        """Add a callback to receive log messages.  The argument
           'func' will be called with a severity (one of
           "TRACE", "DEBUG", "INFO", "WARN", or "ERROR"); a time (in seconds
           since the epoch), and a message (a string) whenever a log event
           occurs.
        """
        pass

    def addStatusLogHandler(self, func):
        """Add a callback to receive --status-fd messages.  The argument
           'func' will be called once for every line that would be sent to
           the status fd, with the line as an argument.
        """
        pass

    # ------------------------------------------------------------
    # Internal helpers.  You don't need to call these.
    def _getConfig(self):
        pass

    def _getClientDirectory(self):
        pass

    def _getSURBLog(self):
        pass

    def _getPasswordManager(self):
        pass

    def _getKeyring(self):
        pass

    def _getQueue(self):
        pass

    def _getFragmentPool(self):
        pass

    # ------------------------------------------------------------
    # Directory-related functions
    def getAllMixNames(self):
        """Return a list of the names of all the mixes we know about.
           Does not force a directory download, even if the directory is
           stale.
        """
        pass

    def getRecommendedMixNames(self):
        """Return a list of the names of all the recommended mixes we know
           about.  Does not force a directory download, even if the directory
           is stale.
        """
        pass

    def getMixByName(self, name):
        """Return a Mix object for a given (case-insensitive) Mix nickname.
           Raise KeyError is no such Mix is known.  Does not force a directory
           download, even if the directory is stale.
        """
        pass

    def updateDirectory(self, force=0):
        """If the directory is stale, or if 'force' is true, download
           a fresh directory.
        """
        pass

    def checkPathSpec(self, pathSpec, messageDest):
        """Given a PathSpec object and a MsgDest object, raise MixError if
           no corresponding valid paths could be generated.
        """
        pass

    def generatePaths(self, pathSpec, messageDest, n=1):
        """Given a PathSpec object and a MsgDest object, return a list of
           'n' Path objects conforming to chosen path spec and dest.
        """
        pass

    # ------------------------------------------------------------
    # Generating packets and SURBs
    def getNFragments(self, message, messageDest, headers=None):
        """Given a message (type string), a MsgDest object, and an optional
           EmailHeaders object, return the number of fragments that
           encodeAndSplit will return for the given message.
        """
        pass

    def encodeAndSplit(self, message, messageDest, headers=None):
        """Given a message (type string), a MsgDest object, and an optional
           EmailHeaders object, return a list of PacketBody objects for this
           message.
        """
        pass

    def generateSURBs(self, n, pathSpec=None,  messageDest=None, identity=None,
                      surbKey=None):
        """Return a list of 'n' SURBs that will traverse paths according
           to pathSpec (defaults to SURBPath in config file), and deliver
           messages to messageDest (defaults to SURBAddress in config file;
           must be an AddrMsgDest).

           By default, uses the default identity in the keyring; you can
           set a different identity from the keyring with 'identity', or
           specify a key directly with 'surbKey'.

           (High-level interface.  You can generate SURBs more directly
           using ClientEnv.generatePaths and generateSURB.)
        """
        pass

    def encryptPackets(self, bodies, messageDest, pathSpec=None,
                       surbList=None):
        """Given a sequence of PacketBody objects and a MsgDest object, generate
           corresponding Packet objects.  If 'pathSpec' is not provided,
           default ForwardPath or ReplyPath in the config file.  If
           'messageDest' indicates a reply, then SURBList should be a
           sequence of SURB objects.

           (High-level interface.  You can encrypt packets more directly
           using ClientEnv.generatePaths and encryptPacket.)
        """
        pass

    # ------------------------------------------------------------
    # Sending and/or queueing packets
    def sendOrQueuePackets(self, packets, queueOnFail=1):
        """Given a sequence of Packet objects, send as many as possible.  If
           'queueOnFail' is true, then add any packets that fail to the queue.
           Returns a list of the packets that were not successfully delivered.
        """
        pass

    def queuePackets(self, packets):
        """Given a sequence of Packet objects, add them all to the queue."""
        pass

    # ------------------------------------------------------------
    # Manipulating the queue
    def flushQueue(self, serverNames=None, maxCount=None):
        """Try to deliver packets from the queue.  If 'serverNames' is provided,
           only send packets whose first hop is in serverNames.  If 'maxCount'
           is provided, send at most 'maxCount' packets."""
        pass

    def cleanQueue(self, serverNames=None, maxAge=30):
        """Delete old packets from the queue.   If 'serverNames' is provided,
           only delete packets whose first hop is in serverNames.  If 'maxAge'
           is provided, only delete packets older than maxAge days.
        """
        pass

    def inspectQueue(self):
        """Return a list of 3-tuples for the packets in the queue, where
           each tuple contains: the PacketDest that will receive the packet;
           the time when the packet was queuee; and an opaque handle.
        """
        pass

    # ------------------------------------------------------------
    # Decoding/decrypting packets
    def decodeArmoredPackets(self, contents):
        """Given a string containing zero or more ASCII-armored Type III
           packets (-----BEGIN TYPE III MESSAGE-----), return a sequence
           of ReceivedPacket objects, decrypting them as necessary.

           May use the configured PasswordManager to extract keys from the
           keyring.
        """
        pass

    # ------------------------------------------------------------
    # Manipulating the fragment pool
    def addFragment(self, fragment):
        """Given a ReceivedFragment, add it to the fragment pool.
        """
        pass

    def getFramentedMessageStatus(self, messageID):
        """Return the status of fragmented message as a 3-tuple of:
           (is-ready, number-of-fragments-in-pool,
           minimum-number-of-additional-fragments needed.)  Return None is no
           such message exists.
        """
        pass

    def reassembleFragmentedMessage(self, messageID):
        """Given the messageID of a fragmented message, return the string
           value of the original message.  Raise MixError if the message
           doesn't exist, or isn't ready to be reassembled.
        """
        pass

    def removeFragmentedMessage(self, messageID):
        """Remove the message 'messageID' from the fragment pool."""
        pass

    def listFragmentedMesasges(self):
        """Return a list of messageIDs for all messages in the fragment pool."""
        pass

    # ------------------------------------------------------------
    # Housekeeping
    def clean(self):
        """Clean up all underlying containers and storage."""
        pass

    # ------------------------------------------------------------
    def close(self):
        """Free all resources held by this ClientEnv, and flush all
           changes to disk.
        """
        pass

# ============================================================
class Mix:
    """A Mix object represents a single Type III remailer."""
    def __init__(self):
        pass
    def getName(self):
        """Return this remailer's nickname."""
        pass
    def getFeature(self, feature):
        """Return the value of a given feature for this remailer."""
        pass
    def _getServerInfoList(self):
        """Helper: return a list of the server descriptors we have for
           this remailer."""
        pass

# ============================================================

def readArmored(file):
    """Read lines from the file-like object 'file', and return a list of
       armored _Encodeable objects from the file.
    """
    pass

class _Encodeable:
    """An _Encodeable object is one that can be conveniently written to disk.
       All _Encodeable objects support the Python pickle protocol, and also
       can be read and written with ----BEGIN---- and ----END---- lines
       using readArmored and writeArmored.
    """
    def armored(self):
        """Return an ASCII-armored representation of this object surrounded
           with -----BEGIN----- and -----END----- lines.
        """
        pass
    def writeArmored(self, file):
        """Write the armored version of this object to the file-like object
           'file'.
        """
        file.write(self.armored())

# XXXX Most of the below classes need more accessor (getFoo) functions.

class PathSpec(_Encodeable):
    """A PathSpec is a description of a class of paths, as describe in
       MIX3:path (path-spec.txt).  Examples include:
            '*3' (a path containing 3 hops)
            '~3' (a path containing approximately 3 hops)
            'foo,?,?,bar' (a path starting with foo, followed by 2 hops,
              ending in bar.)
    """
    def __init__(self, string):
        pass

class Path(_Encodeable):
    """A Path is a sequence of names for mixes in the mix-net, and a message
       destination.  Don't create paths directly; instead, generate them with
       clientEnv.generatePaths().
    """
    def __init__(self, path1, path2, msgDest):
        pass

class PacketBody(_Encodeable):
    """A PacketBody is the encoded contents of a single Type III packet,
       before it is encryped and the Type III headers are added for it to
       be transmitted through the network.

       (Use ClientEnv.encodeAndSplit to encode a message and break it into
       PacketBody objects.)
    """
    def __init__(self, contents):
        pass

class Packet(_Encodeable):
    """A Packet is a single Type III packet, and the address of its first
       hop, ready to be transmitted into the mix network.

       (Use ClientEnv.encryptPackets to encrypt a set of PacketBody objects
       into Packet objects.)"""
    def __init__(self, contents, packetDest):
        pass

class PacketDest(_Encodeable):
    """A PacketDest is an address where a Mix receives packets; we use it
       to describe a packet's first hop.
    """
    def __init__(self, routingType, routingInfo):
        pass

class MsgDest(_Encodeable):
    """A MsgDest is the address for a mssage.  It may be either a SURBMsgDest,
       to indate a message that we will send with one or more SURBs, or an
       AddrMsgDest, to indicate an email address, mbox address, or other
       Type III exit address.
    """
    def __init__(self):
        pass
    def isSURB(self):
        pass

def parseMessageAddress(string):
    """Parse an address given as a string into an AddrMsgDest.  Accepts strings
       of the format:
              mbox:<mailboxname>@<server>
           OR smtp:<email address>
           OR <email address> (smtp is implicit)
           OR drop
           OR 0x<routing type>:<routing info>
           OR 0x<routing type>
    """
    pass

class AddrMsgDest(MsgDest):
    """Indicates the final Type III exit address of a message.  Generate these
       by calling parseMessageAddress."""
    def __init__(self, routingType, routingInfo, pkey=None):
        pass

class SURBMsgDest(MsgDest):
    """Indicates that a Type III message will be delivered by one or more
       SURBs."""
    def __init__(self):
        pass

class SURB(_Encodeable):
    """A single-use reply block, and _possibly_ the decoding handle that
       will be used when the corresponding packet is received.

       (The decodingHandle is only set when the SURB is first generated;
       is is sensitive, and so is *not* encoded along with the SURB.)"""
    def __init__(self, replyBlock, decodingHandle=None):
        pass
    def getDecodingHandle(self):
        pass

class ReceivedPacket(_Encodeable):
    """The (decrypted) contents of a single received Type III packet.
    """
    def __init__(self, contents, decodingHandle, isReply=0, replyIdentity=None):
        pass

    def isFragment(self):
        pass

    def isReply(self):
        pass

    def getSURBIdentity(self):
        pass

class ReceivedFragment(ReceivedPacket):
    """The (decrypted) contents of a single packet containing a fragment
       of a larger message.
    """
    def __init__(self, contents, decodingHandle, isReply=0, replyIdentity=None):
        pass

    def getMessageID(self):
        pass

class ReceivedSingleton(ReceivedPacket, ReceivedMessage):
    """The (decrypted) contents of a single packet containing an entire
       message.
    """
    def __init__(self, contents, decodingHandle, isReply=0, replyIdentity=None):
        pass

    def getContents(self):
        pass

class EmailHeaders:
    """A set of email headers to be prepended to a message before delivery."""
    def __init__(self):
        pass
    def setFrom(self, val):
        pass
    def setSubject(self, val):
        pass
    def setInReplyTo(self, val):
        pass
    def setReferences(self, val):
        pass

