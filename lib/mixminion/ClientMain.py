# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ClientMain

   Code for Mixminion command-line client.
   """

__all__ = [ 'Address', 'ClientKeyring', 'MixminionClient' ]

import getopt
import os
import sys
import time
from types import IntType, StringType

import mixminion.BuildMessage
import mixminion.ClientUtils
import mixminion.ClientDirectory
import mixminion.Config
import mixminion.Crypto
import mixminion.Filestore
import mixminion.MMTPClient

from mixminion.Common import LOG, Lockfile, LockfileLocked, MixError, \
     MixFatalError, MixProtocolBadAuth, MixProtocolError, UIError, \
     UsageError, createPrivateDir, englishSequence, isPrintingAscii, isSMTPMailbox, readFile, \
     stringContains, succeedingMidnight, writeFile, previousMidnight, floorDiv
from mixminion.Packet import encodeMailHeaders, ParseError, parseMBOXInfo, \
     parseReplyBlocks, parseSMTPInfo, parseTextEncodedMessages, \
     parseTextReplyBlocks, ReplyBlock, parseMessageAndHeaders

from mixminion.ServerInfo import displayServerByRouting, ServerInfo

#----------------------------------------------------------------------
# Global variable; holds an instance of Common.Lockfile used to prevent
# concurrent access to the directory cache, packet queue, or SURB log.
_CLIENT_LOCKFILE = None

def clientLock():
    """Acquire the client lock."""
    assert _CLIENT_LOCKFILE is not None
    pidStr = str(os.getpid())
    try:
        _CLIENT_LOCKFILE.acquire(blocking=0, contents=pidStr)
    except LockfileLocked:
        LOG.info("Waiting for pid %s", _CLIENT_LOCKFILE.getContents())
        _CLIENT_LOCKFILE.acquire(blocking=1, contents=pidStr)

def clientUnlock():
    """Release the client lock."""
    _CLIENT_LOCKFILE.release()

def configureClientLock(filename):
    """Prepare the client lock for use."""
    global _CLIENT_LOCKFILE
    _CLIENT_LOCKFILE = Lockfile(filename)

class ClientKeyring:
    """Class to manage storing encrypted keys for a client.  Right now, this
       is limited to a single SURB decryption key.  In the future, we may
       include more SURB keys, as well as end-to-end encryption keys.
    """
    # XXXX Can any more of this class should go into ClientUtils?
    ## Fields
    # keyring: an instance of ClientUtils.Keyring

    # We discard SURB keys after 3 months.
    KEY_LIFETIME = 3*30*24*60*60
    # We don't make new SURBs with any key that will expire in the next
    # month.
    MIN_KEY_LIFETIME_TO_USE = 30*24*60*60

    def __init__(self, keyDir, passwordManager=None):
        """Create a new ClientKeyring, storing its keys in 'keyDir'"""
        if passwordManager is None:
            passwordManager = mixminion.ClientUtils.CLIPasswordManager()
        createPrivateDir(keyDir)

        # XXXX008 remove this.
        # We used to store our keys in a different format.  At this point,
        # it's easier to change the filename.
        obsoleteFn = os.path.join(keyDir, "keyring")
        if os.path.exists(obsoleteFn):
            LOG.warn("Ignoring obsolete keyring stored in %r",obsoleteFn)
        fn = os.path.join(keyDir, "keyring.txt")

        # Setup the keyring.
        self.keyring = mixminion.ClientUtils.Keyring(fn, passwordManager)

    def getSURBKey(self, name="", create=0, password=None):
        """Return a SURB key for a given identity, asking for passwords and
           loading the keyring if necessary..  Return None on failure.

           name -- the SURB key identity
           create -- If true, create a new key if none is found.
           password -- Optionally, a password for the keyring.
        """
        # If we haven't loaded the keyring yet, try to do so.
        if not self.keyring.isLoaded():
            try:
                self.keyring.load(create=create,password=password)
            except mixminion.ClientUtils.BadPassword:
                LOG.error("Incorrect password")
                return None
            if not self.keyring.isLoaded():
                return None


        try:
            key = self.keyring.getNewestSURBKey(
                name,minLifetime=self.MIN_KEY_LIFETIME_TO_USE)
            if key:
                return key
            elif not create:
                return None
            else:
                # No key, but we're allowed to create a new one.
                LOG.info("Creating new key for identity %r", name)
                return self.keyring.newSURBKey(name,
                                               time.time()+self.KEY_LIFETIME)
        finally:
            # Check whether we changed the keyring, and save it if we did.
            # The keyring may have changed even if we didn't generate any
            # new keys, so this check is always necessary.
            if self.keyring.isDirty():
                self.keyring.save()

        raise AssertionError # Unreached.

    def getSURBKeys(self, password=None):
        """Return the keys for _all_ SURB identities as a list of
           (name,key) tuples."""
        try:
            self.keyring.load(create=0,password=password)
        except mixminion.ClientUtils.BadPassword:
            LOG.error("Incorrect password")
        if not self.keyring.isLoaded(): return []
        if self.keyring.isDirty(): self.keyring.save()
        return self.keyring.getAllSURBKeys()

def installDefaultConfig(fname):
    """Create a default, 'fail-safe' configuration in a given file"""
    LOG.warn("No configuration file found. Installing default file in %s",
                  fname)

    fields = { 'ud_default' : mixminion.Config.DEFAULT_USER_DIR }

    writeFile(os.path.expanduser(fname),
              """\
# This file contains your options for the mixminion client.
[Host]
## Use this option to specify a 'secure remove' command.
#ShredCommand: rm -f
## Use this option to specify a nonstandard entropy source.
#EntropySource: /dev/urandom
## Set this option to 'no' to disable permission checking
#FileParanoia: yes

[DirectoryServers]
DirectoryTimeout: 1 minute
# Other options not yet implemented

[User]
## By default, mixminion puts your files in %(ud_default)s,  You can override
## this directory here.
#UserDir: %(ud_default)s

[Security]
## Address to use by default when generating reply blocks
#SURBAddress: <your address here>
## Deault reply block lifetime
#SURBLifetime: 7 days

### Default paths to use if no path given on command line:
## For forward messages
#ForwardPath: ?,?,?:?,FavoriteExit
## For reply messages
#ReplyPath: ?,?,?,FavoriteSwap
## For reply blocks
#SURBPath: ?,?,?,FavoriteExit

[Network]
ConnectionTimeout: 60 seconds
""" % fields)

class MixminionClient:
    #XXXX Once ClientAPI is more solid, this class should be folded into it.

    """Access point for client functionality."""
    ## Fields:
    # config: The ClientConfig object with the current configuration
    # prng: A pseudo-random number generator for padding and path selection
    # keys: A ClientKeyring object.
    # queue: A ClientQueue object.
    # surbLogFilename: The filename used by the SURB log.
    def __init__(self, conf, password_fileno=None):
        """Create a new MixminionClient with a given configuration"""
        self.config = conf

        # Make directories
        userdir = self.config['User']['UserDir']
        createPrivateDir(userdir)
        keyDir = os.path.join(userdir, "keys")
        if password_fileno is None:
            self.pwdManager = mixminion.ClientUtils.CLIPasswordManager()
        else:
            self.pwdManager = mixminion.ClientUtils.FDPasswordManager(password_fileno)
        self.keys = ClientKeyring(keyDir, self.pwdManager)
        self.surbLogFilename = os.path.join(userdir, "surbs", "log")

        # Initialize PRNG
        self.prng = mixminion.Crypto.getCommonPRNG()
        self.queue = mixminion.ClientUtils.ClientQueue(os.path.join(userdir, "queue"))
        self.pool = mixminion.ClientUtils.ClientFragmentPool(os.path.join(userdir, "fragments"))

    def _sortPackets(self, packets, shuffle=1):
        """Helper function.  Takes a list of tuples of (packet,
           ServerInfo/routigInforoutingInfo),
           groups packets with the same routingInfos, and returns a list of
           tuples of (routingInfo, [packet list]).

           If 'shuffle' is true, then the packets within each list, and the
           tuples themselves, are returned in a scrambled order.
        """
        d = {}
        for packet, firstHop in packets:
            if isinstance(firstHop, ServerInfo):
                ri = firstHop.getRoutingInfo()
            else:
                assert (isinstance(firstHop, mixminion.Packet.MMTPHostInfo) or
                        isinstance(firstHop, mixminion.Packet.IPV4Info))
                ri = firstHop
            d.setdefault(ri,[]).append(packet)
        result = d.items()
        if shuffle:
            self.prng.shuffle(result)
            for _, pktList in result:
                self.prng.shuffle(pktList)
        return result


    def sendForwardMessage(self, directory, address, pathSpec, message,
                           startAt, endAt, forceQueue=0, forceNoQueue=0,
                           forceNoServerSideFragments=0):
        """Generate and send a forward message.
            directory -- an instance of ClientDirectory; used to generate
               paths.
            address -- an instance of ExitAddress, used to tell where to
               deliver the message.
            pathSpec -- an instance of PathSpec, describing the path to use.
            message -- the contents of the message to send
            startAt, endAt -- an interval over which all servers in the path
               must be valid.
            forceQueue -- if true, do not try to send the message; simply
               queue it and exit.
            forceNoQueue -- if true, do not queue the message even if delivery
               fails.
            forceNoServerSideFragments -- if true, and the message is too
               large to fit in a single packet, deliver fragment packets to
               the eventual recipient rather than having the exit server
               defragment them.
        """
        assert not (forceQueue and forceNoQueue)

        allPackets = self.generateForwardPackets(
            directory, address, pathSpec, message, forceNoServerSideFragments,
            startAt, endAt)

        for routing, packets in self._sortPackets(allPackets):
            if forceQueue:
                self.queuePackets(packets, routing)
            else:
                self.sendPackets(packets, routing, noQueue=forceNoQueue)

    def sendReplyMessage(self, directory, address, pathSpec, surbList, message,
                         startAt, endAt, forceQueue=0,
                         forceNoQueue=0):
        """Generate and send a reply message.
            directory -- an instance of ClientDirectory; used to generate
               paths.
            address -- an instance of ExitAddress, used to tell where to
               deliver the message.
            pathSpec -- an instance of PathSpec, describing the path to use.
            surbList -- a list of SURBs to consider using for the reply.  We
               use the first N that are neither expired nor used, and mark them
               used.
            message -- the contents of the message to send
            startAt, endAt -- an interval over which all servers in the path
               must be valid.
            forceQueue -- if true, do not try to send the message; simply
               queue it and exit.
            forceNoQueue -- if true, do not queue the message even if delivery
               fails.
        """
        #XXXX write unit tests
        allPackets = self.generateReplyPackets(
            directory, address, pathSpec, message, surbList, startAt, endAt)

        for routing, packets in self._sortPackets(allPackets):
            if forceQueue:
                self.queuePackets(packets, routing)
            else:
                self.sendPackets(packets, routing, noQueue=forceNoQueue)

    def generateReplyBlock(self, address, servers, name="", expiryTime=0):
        """Generate an return a new ReplyBlock object.
            address -- the results of a parseAddress call
            servers -- lists of ServerInfos for the reply leg of the path.
            name -- the name of the identity to use for the reply block.
            expiryTime -- if provided, a time at which the replyBlock must
               still be valid, and after which it should not be used.
        """
        #XXXX write unit tests
        key = self.keys.getSURBKey(name=name, create=1)
        if not key:
            raise UIError("unable to get SURB key")
        exitType, exitInfo, _ = address.getRouting()

        block = mixminion.BuildMessage.buildReplyBlock(
            servers, exitType, exitInfo, key, expiryTime)

        return block

    def generateForwardPackets(self, directory, address, pathSpec, message,
                               noSSFragments, startAt, endAt):
        """Generate packets for a forward message, but do not send
           them.  Return a list of tuples of (the packet body, a
           ServerInfo for the first hop.)

            directory -- an instance of ClientDirectory; used to generate
               paths.
            address -- an instance of ExitAddress, used to tell where to
               deliver the message.
            pathSpec -- an instance of PathSpec, describing the path to use.
            message -- the contents of the message to send
            noSSFragments -- if true, and the message is too large to fit in a
               single packet, deliver fragment packets to the eventual
               recipient rather than having the exit server defragment them.
            startAt, endAt -- an interval over which all servers in the path
               must be valid.
            """
        #XXXX we need to factor more of this long-message logic out to the
        #XXXX common code.  For now, this is a temporary measure.

        if noSSFragments:
            fragmentedMessagePrefix = ""
        else:
            fragmentedMessagePrefix = address.getFragmentedMessagePrefix()
        LOG.info("Generating payload(s)...")
        r = []
        if address.hasPayload():
            payloads = mixminion.BuildMessage.encodeMessage(message, 0,
                                fragmentedMessagePrefix)
            if len(payloads) > 1:
                address.setFragmented(not noSSFragments, len(payloads))
            else:
                address.setFragmented(0,1)
        else:
            payloads = [ mixminion.BuildMessage.buildRandomPayload() ]
            address.setFragmented(0,1)
        routingType, routingInfo, _ = address.getRouting()

        directory.validatePath(pathSpec, address, startAt, endAt,
                               warnUnrecommended=0)

        for p, (path1,path2) in zip(payloads, directory.generatePaths(
            len(payloads), pathSpec, address, startAt, endAt)):

            pkt = mixminion.BuildMessage.buildForwardPacket(
                p, routingType, routingInfo, path1, path2,
                self.prng, suppressTag=address.suppressTag())
            r.append( (pkt, path1[0]) )

        return r

    def generateReplyPackets(self, directory, address, pathSpec, message,
                             surbList, startAt, endAt):
        """Generate a reply message, but do not send it.  Returns
           a tuple of (packet body, ServerInfo for the first hop.)

            directory -- an instance of ClientDirectory; used to generate
               paths.
            address -- an instance of ExitAddress, used to tell where to
               deliver the message.
            pathSpec -- an instance of PathSpec, describing the path to use.
            message -- the contents of the message to send
            surbList -- a list of SURBs to consider using for the reply.  We
               use the first N that are neither expired nor used, and mark them
               used.
            startAt, endAt -- an interval over which all servers in the path
               must be valid.
            """
        #XXXX write unit tests
        assert address.isReply

        payloads = mixminion.BuildMessage.encodeMessage(message, 0, "")

        surbLog = self.openSURBLog() # implies lock
        result = []
        try:
            surbs = surbLog.findUnusedSURBs(surbList, len(payloads),
                                           verbose=1, now=startAt)
            if len(surbs) < len(payloads):
                raise UIError("Not enough usable reply blocks found; all were used or expired.")


            for (surb,payload,(path1,path2)) in zip(surbs,payloads,
                  directory.generatePaths(len(payloads),pathSpec, address,
                                          startAt,endAt)):
                assert path1 and not path2
                LOG.info("Generating packet...")
                pkt = mixminion.BuildMessage.buildReplyPacket(
                    payload, path1, surb, self.prng)

                surbLog.markSURBUsed(surb)
                result.append( (pkt, path1[0]) )

        finally:
            surbLog.close() #implies unlock

        return result

    def openSURBLog(self):
        """Return a new, open SURBLog object for this client; it must be closed
           when no longer in use.
        """
        return mixminion.ClientUtils.SURBLog(self.surbLogFilename)

    def pingServer(self, routingInfo):
        """Given an IPV4Info, try to connect to a server and find out if
           it's up.  Returns a boolean and a status message."""
        timeout = self.config['Network'].get('ConnectionTimeout')
        if timeout:
            timeout = int(timeout)
        else:
            timeout = 60

        try:
            mixminion.MMTPClient.pingServer(routingInfo, timeout)
            return 1, "Server seems to be running"
        except MixProtocolBadAuth:
            return 0, "Server seems to be running, but its key is wrong!"
        except MixProtocolError, e:
            return 0, "Couldn't connect to server: %s" % e

    def sendPackets(self, pktList, routingInfo, noQueue=0, lazyQueue=0,
                    alreadyQueued=0, warnIfLost=1):
        """Given a list of packets and an IPV4Info object, sends the
           packets to the server via MMTP.

           If noQueue is true, do not queue the packets even on failure.
           If lazyQueue is true, only queue the packets on failure.
           XXXX alreadyQueued
           Otherwise, insert the packets in the queue, and remove them on
           success.

           If warnIfLost is true, log a warning if we fail to deliver
           the packets, and we don't queue them.

           XXXX return 1 if all delivered
           """
        #XXXX write unit tests
        timeout = self.config['Network'].get('ConnectionTimeout')
        if timeout:
            timeout = int(timeout)
        else:
            timeout = 60

        if noQueue or lazyQueue:
            handles = []
        else:
            handles = self.queuePackets(pktList, routingInfo)


        packetsSentByIndex = {}
        def callback(idx, packetsSentByIndex=packetsSentByIndex):
            packetsSentByIndex[idx] = 1

        try:
            # May raise TimeoutError
            LOG.info("Connecting...")
            mixminion.MMTPClient.sendPackets(routingInfo,
                                             pktList,
                                             timeout,
                                             callback=callback)

        except:
            exc = sys.exc_info()
        else:
            exc = None
        nGood = len(packetsSentByIndex)
        nBad = len(pktList)-nGood

        try:
            clientLock()
            if nGood:
                LOG.info("... %s sent", nGood)
                LOG.trace("Removing %s successful packets from queue", nGood)
            for idx in packetsSentByIndex.keys():
                if handles and handles[idx]:
                    self.queue.removePacket(handles[idx])
                elif hasattr(pktList[idx], 'remove'):
                    pktList[idx].remove()
            if nGood:
                try:
                    self.queue.cleanQueue()
                except:
                    e2 = sys.exc_info()
                    LOG.error("Error while cleaning queue: %s",e2[1])

            if nBad and noQueue:
                if warnIfLost:
                    LOG.error("Error with queueing disabled: %s/%s lost",
                              nBad, nGood+nBad)
                elif alreadyQueued:
                    LOG.info("Error while delivering packets; %s/%s left in queue",
                             nBad,nGood+nBad)
            elif nBad and lazyQueue:
                LOG.info("Error while delivering packets; %s/%s left in queue",
                         nBad,nGood+nBad)
                badPackets = [ pktList[idx] for idx in xrange(len(pktList))
                               if not packetsSentByIndex.has_key(idx) ]

                self.queuePackets(badPackets, routingInfo)
            elif nBad:
                assert not (noQueue or lazyQueue)
                LOG.info("Error while delivering packets; leaving %s/%s in queue",
                         nBad, nBad+nGood)
            if exc and not nBad:
                LOG.info("Got error after all packets were delivered.")
            if exc:
                LOG.info("Error was: %s", exc[1])
        finally:
                clientUnlock()

        return nGood

    def flushQueue(self, maxPackets=None, handles=None):
        """Try to send packets in the queue to their destinations.  Do not try
           to send more than maxPackets packets.  If not all packets will be
           sent, choose the ones to try at random.

           DOCDOC nicknames
        """
        #XXXX write unit tests
        class PacketProxy:
            def __init__(self,h,queue):
                self.h = h
                self.queue = queue
            def __str__(self):
                return self.queue.getPacket(self.h)[0]
            def __cmp__(self,other):
                return cmp(id(self),id(other))
            def remove(self):
                self.queue.removePacket(self.h)

        LOG.info("Flushing packet queue")
        clientLock()
        try:
            if handles is None:
                handles = self.queue.getHandles()
                LOG.info("Found %s pending packets", len(handles))
            else:
                LOG.info("Flushing %s packets", len(handles))
            if maxPackets is not None:
                handles = mixminion.Crypto.getCommonPRNG().shuffle(handles,
                                                               maxPackets)
            packets = []
            for h in handles:
                try:
                    routing = self.queue.getRouting(h)
                except mixminion.Filestore.CorruptedFile:
                    continue
                packet = PacketProxy(h,self.queue)
                packets.append((packet,routing))
        finally:
            clientUnlock()

        nPackets = len(packets)
        nSent = 0
        for routing, packets in self._sortPackets(packets):
            LOG.info("Sending %s packets to %s...",
                     len(packets), displayServerByRouting(routing))
            try:
                ok = self.sendPackets(packets, routing, noQueue=1,
                                      warnIfLost=0, alreadyQueued=1)
                nSent += ok
            except MixError, e:
                LOG.error("Can't deliver packets to %s: %s; leaving in queue",
                          displayServerByRouting(routing), str(e))

        if nSent == nPackets:
            LOG.info("Queue flushed")
        elif nSent > 0:
            LOG.info("Queue partially flushed")
        elif nSent == 0:
            LOG.info("No packets delivered")
        else:
            raise MixFatalError("BUG: somehow sent %s/%s packets!"
                                %(nSent,nPackets))

    def cleanQueue(self, handles):
        """Remove all packets older than maxAge seconds from the
           client queue."""
        try:
            clientLock()
            byRouting = self._sortPackets(
                [ (h, self.queue.getRouting(h)) for h in handles ],
                shuffle = 0)
            byName = [ (displayServerByRouting(ri), lst)
                       for ri,lst in byRouting ]
            byName.sort()
            if not byName:
                LOG.info("No packets removed.")
            for name, lst in byName:
                LOG.info("Removing %s packets for %s", len(lst), name)
                for h in lst:
                    self.queue.removePacket(h)
            self.queue.cleanQueue()
        finally:
            clientUnlock()

    def queuePackets(self, pktList, routing):
        """Insert all the packets in pktList into the queue, to be sent
           to the server identified by the IPV4Info or MMTPHostInfo object
           'routing'.
        """
        #XXXX write unit tests
        LOG.trace("Queueing packets")
        handles = []
        try:
            clientLock()
            for pkt in pktList:
                h = self.queue.queuePacket(str(pkt), routing)
                handles.append(h)
        finally:
            clientUnlock()
        if len(pktList) > 1:
            LOG.info("Pacekts queued")
        else:
            LOG.info("Packet queued")
        return handles

    def decodeMessage(self, s, force=0, isatty=0):
        """Given a string 's' containing one or more text-encoded messages,
           return a list containing the decoded messages.

           Raise ParseError on malformatted messages.  Unless 'force' is
           true, do not uncompress possible zlib bombs.
        """
        #XXXX write unit tests
        results = []
        foundAFragment = 0
        for msg in parseTextEncodedMessages(s, force=force):
            if msg.isOvercompressed() and not force:
                LOG.warn("Message is a possible zlib bomb; not uncompressing")

            if not msg.isEncrypted():
                if msg.isFragment():
                    self.pool.addFragment(msg.getContents(), "---")
                else:
                    results.append(msg.getContents())
            else:
                assert msg.isEncrypted()
                surbKeys = self.keys.getSURBKeys()
                nym = []
                p = mixminion.BuildMessage.decodePayload(msg.getContents(),
                                                         tag=msg.getTag(),
                                                         userKeys=surbKeys,
                                                         rNym=nym)
                if p:
                    if nym:
                        nym=nym[0]
                    else:
                        nym="default"
                    if p.isSingleton():
                        results.append(p.getUncompressedContents())
                    else:
                        self.pool.addFragment(p,nym)
                else:
                    raise UIError("Unable to decode message")
        if isatty and not force:
            for p in results:
                if not isPrintingAscii(p,allowISO=1):
                    raise UIError("Not writing binary message to terminal: Use -F to do it anyway.")
        return results

def readConfigFile(configFile):
    """Given a configuration file (possibly none) as specified on the command
       line, return a ClientConfig object.

       Tries to look for the configuration file in the following places:
          - as specified on the command line,
          - as specifed in $MIXMINIONRC
          - in ~/.mixminionrc.
          - in ~/mixminionrc

       If the configuration file is not found in the specified location,
       we create a fresh one.
    """
    if configFile is None:
        configFile = os.environ.get("MIXMINIONRC")
    if configFile is None:
        for candidate in ["~/.mixminionrc", "~/mixminionrc"]:
            if os.path.exists(os.path.expanduser(candidate)):
                configFile = candidate
                break
    if configFile is None:
        if sys.platform == 'win32':
            configFile = "~/mixminionrc"
        else:
            configFile = "~/.mixminionrc"
    if configFile is not None:
        configFile = os.path.expanduser(configFile)

    if not os.path.exists(configFile):
        print >>sys.stderr,"Writing default configuration file to %r"%configFile
        installDefaultConfig(configFile)

    try:
        return mixminion.Config.ClientConfig(fname=configFile)
    except (IOError, OSError), e:
        print >>sys.stderr, "Error reading configuration file %r:"%configFile
        print >>sys.stderr, "   ", str(e)
        sys.exit(1)
    except mixminion.Config.ConfigError, e:
        print >>sys.stderr, "Error in configuration file %r"%configFile
        print >>sys.stderr, "   ", str(e)
        sys.exit(1)
    return None #suppress pychecker warning

class CLIArgumentParser:
    """Helper class to parse common command line arguments.

       The following arguments are recognized:
          COMMON
             -h | --help : print usage and exit.
             -f | --config : specify a configuration file.
             -v | --verbose : run verbosely.
          DIRECTORY ONLY
             -D | --download-directory : force/disable directory downloading.
          PATH-RELATED
             -t | --to : specify an exit address
             -R | --reply-block | --reply-block-fd : specify a reply block
             -P | --path : specify a literal path.
          REPLY PATH ONLY
             --lifetime : Required lifetime of new reply blocks.
          MESSAGE-SENDING ONLY:
             --queue | --no-queue : force/disable queueing.

         The class's constructor parses command line options, as required.
         The .init() method initializes a config file, logging, a
           MixminionClient object, or the ClientDirectory object as requested.
         The parsePath method parses the path as given.
    """
    ##Fields:
    #  want*: as given as arguments to __init__
    # [CALL "init()" before using these.
    #  config: ClientConfig, or None.
    #  directory: ClientDirectory, or None.
    #  client: MixminionClient, or None.
    #  keyring: ClientKeyring, or None.
    # [As specified on command line"
    #  path: path string, or None.
    #  nHops: number of hops, or None.
    #  address: exit address, or None.
    #  lifetime: SURB lifetime, or None.
    #  replyBlockFiles: list of SURB filenames. DOCDOC
    #  configFile: Filename of configuration file, or None.
    #  forceQueue: true if "--queue" is set.
    #  forceNoQueue: true if "--no-queue" is set.
    #  verbose: true if verbose mode is set.
    #  download: 1 if the user told us to download the directory, 0 if
    #    they told us not to download it, and None if they didn't say.
    # [Not public]
    #  path1, path2 -- path as generated by parsePath.

    def __init__(self, opts,
                 wantConfig=0, wantClientDirectory=0, wantClient=0, wantLog=0,
                 wantDownload=0, wantForwardPath=0, wantReplyPath=0,
                 minHops=0, ignoreOptions=[]):
        """Parse the command line options 'opts' as returned by getopt.getopt.

           wantConfig -- If true, accept options pertaining to the config file,
              and generate a ClientConfig object when self.init() is called.
           wantClientDiredctory -- If true, accept options pertaining to the
              client directory, and generate a ClientDirectory object when
              self.init() is called.
           wantClient -- If true, generate a MixminionClient when self.init()
              is called.
           wantLog -- If true, configure logging.
           wantDownload -- If true, accept options pertaining to downloading
              a new directory, and download the directory as required.
           wantForawrdPath -- If true, accept options to specify a forward
              path (for forward or reply messages), and enable self.parsePath.
           wantReplyPath -- If true, accept options to specify a path for
              a reply block, and enable self.parsePath.
           minHops -- Smallest allowable value for -H option.
        """
        self.config = None
        self.directory = None
        self.client = None
        self.path1 = None
        self.path2 = None

        if wantForwardPath: wantClientDirectory = 1
        if wantReplyPath: wantClientDirectory = 1
        if wantDownload: wantClientDirectory = 1
        if wantClientDirectory: wantConfig = 1
        if wantClient: wantConfig = 1

        self.wantConfig = wantConfig
        self.wantClientDirectory = wantClientDirectory
        self.wantClient = wantClient
        self.wantLog = wantLog
        self.wantDownload = wantDownload
        self.wantForwardPath = wantForwardPath
        self.wantReplyPath = wantReplyPath

        self.configFile = None
        self.verbose = self.quiet = 0
        self.download = None
        self.password_fileno = None

        self.path = None
        self.nHops = None
        self.exitAddress = None
        self.lifetime = None
        self.replyBlockSources = [] #DOCDOC int is fd, str is filename

        self.forceQueue = None
        self.forceNoQueue = None

        for o,v in opts:
            if o in ignoreOptions: continue
            if o in ('-h', '--help'):
                raise UsageError()
            elif o in ('-f', '--config'):
                self.configFile = v
            elif o in ('-v', '--verbose'):
                self.verbose = 1
            elif o in ('-Q', '--quiet'):
                self.quiet = 1
            elif o in ('-D', '--download-directory'):
                assert wantDownload
                download = v.lower()
                if download in ('0','no','false','n','f'):
                    dl = 0
                elif download in ('1','yes','true','y','t','force'):
                    dl = 1
                else:
                    raise UIError(
                        "Unrecognized value for %s. Expected 'yes' or 'no'"%o)
                if self.download not in (None, dl):
                    raise UIError(
                        "Value of %s for %s conflicts with earlier value" %
                        (v, o))
                self.download = dl
            elif o in ('-t', '--to'):
                assert wantForwardPath or wantReplyPath
                if self.exitAddress is not None:
                    raise UIError("Multiple addresses specified.")
                try:
                    self.exitAddress = mixminion.ClientDirectory.parseAddress(v)
                except ParseError, e:
                    raise UsageError(str(e))
            elif o in ('-R', '--reply-block'):
                assert wantForwardPath
                self.replyBlockSources.append(v)
            elif o == '--reply-block-fd':
                try:
                    self.replyBlockSources.append(int(v))
                except ValueError:
                    raise UIError("%s expects an integer"%o)
            elif o in ('-H', '--hops'):
                assert wantForwardPath or wantReplyPath
                if self.nHops is not None:
                    raise UIError("Multiple %s arguments specified"%o)
                try:
                    self.nHops = int(v)
                    if minHops and self.nHops < minHops:
                        raise UIError("Must have at least %s hops" % minHops)
                except ValueError:
                    raise UIError("%s expects an integer"%o)
            elif o in ('-P', '--path'):
                assert wantForwardPath or wantReplyPath
                if self.path is not None:
                    raise UIError("Multiple paths specified")
                self.path = v
            elif o in ('--lifetime',):
                assert wantReplyPath
                if self.lifetime is not None:
                    raise UIError("Multiple --lifetime arguments specified")
                try:
                    self.lifetime = int(v)
                except ValueError:
                    raise UsageError("%s expects an integer"%o)
            elif o in ('--passphrase-fd',):
                #DOCDOC
                try:
                    self.password_fileno = int(v)
                except ValueError:
                    raise UsageError("%s expects an integer"%o)
            elif o in ('--queue',):
                self.forceQueue = 1
            elif o in ('--no-queue',):
                self.forceNoQueue = 1

        if self.nHops and not self.path:
            self.path = '*%d'% self.nHops
        elif self.nHops:
            raise UIError("You cannot specify both a path (-P/--path) and a number of hops (-H/--hops)")

        if self.quiet and self.verbose:
            raise UsageError("I can't be quiet and verbose at the same time.")

    def init(self):
        """Configure objects and initialize subsystems as specified by the
           command line."""
        if self.verbose:
            severity = "TRACE"
        elif self.quiet:
            severity = "ERROR"
        else:
            severity = "INFO"

        if self.wantConfig:
            self.config = readConfigFile(self.configFile)
            if self.wantLog:
                LOG.configure(self.config)
                LOG.setMinSeverity(severity)
            mixminion.Common.configureShredCommand(self.config)
            mixminion.Common.configureFileParanoia(self.config)
            if not self.verbose:
                try:
                    LOG.setMinSeverity("WARN")
                    mixminion.Crypto.init_crypto(self.config)
                finally:
                    LOG.setMinSeverity(severity)
            else:
                mixminion.Crypto.init_crypto(self.config)

            userdir = self.config['User']['UserDir']
            configureClientLock(os.path.join(userdir, "lock"))
        else:
            if self.wantLog:
                LOG.setMinSeverity(severity)
            userdir = None

        if self.wantClient:
            assert self.wantConfig
            LOG.debug("Configuring client")
            self.client = MixminionClient(self.config, self.password_fileno)

        if self.wantClientDirectory:
            assert self.wantConfig
            assert _CLIENT_LOCKFILE
            LOG.debug("Configuring server list")
            self.directory = mixminion.ClientDirectory.ClientDirectory(
                userdir, _CLIENT_LOCKFILE)
            self.directory.configure(self.config)
            self.directory._installAsKeyIDResolver()

        if self.wantDownload:
            assert self.wantClientDirectory
            timeout = int(self.config['DirectoryServers']['DirectoryTimeout'])
            if self.download != 0:
                try:
                    clientLock()
                    self.directory.updateDirectory(forceDownload=self.download,
                                                   timeout=timeout)
                finally:
                    clientUnlock()

        if self.wantClientDirectory or self.wantDownload:
            self.directory.checkSoftwareVersion(client=1)

    def parsePath(self):
        # Sets: exitAddress, pathSpec.
        if self.wantReplyPath and self.exitAddress is None:
            address = self.config['Security'].get('SURBAddress')
            if address is None:
                raise UIError("No recipient specified; exiting.  (Try "
                              "using -t <your-address>)")
            try:
                self.exitAddress = mixminion.ClientDirectory.parseAddress(address)
            except ParseError, e:
                raise UIError("Error in SURBAddress: %s" % e)
        elif self.exitAddress is None and self.replyBlockSources == []:
            raise UIError("No recipients specified; exiting. (Try using "
                          "-t <recipient-address>")
        elif self.exitAddress is not None and self.replyBlockSources:
            raise UIError("Cannot use both a recipient and a reply block")
        elif self.replyBlockSources:
            useRB = 1
            surbs = []
            for fn in self.replyBlockSources:
                if isinstance(fn, IntType):
                    f = os.fdopen(fn, 'rb')
                    try:
                        s = f.read()
                    finally:
                        f.close()
                elif fn == '-':
                    s = sys.stdin.read()
                else:
                    assert isinstance(fn, StringType)
                    s = readFile(fn, 1)
                try:
                    if stringContains(s,
                                      "-----BEGIN TYPE III REPLY BLOCK-----"):
                        surbs.extend(parseTextReplyBlocks(s))
                    else:
                        surbs.extend(parseReplyBlocks(s))
                except ParseError, e:
                        raise UIError("Error parsing %s: %s" % (fn, e))
            self.surbList = surbs
            self.exitAddress = mixminion.ClientDirectory.ExitAddress(isReply=1)
        else:
            assert self.exitAddress is not None
            useRB = 0

        isSURB = isReply = 0
        if self.wantReplyPath:
            p = 'SURBPath'; isSURB = 1
            defHops = self.config['Security'].get("SURBPathLength", 4)
        elif useRB:
            p = 'ReplyPath'; isReply = 1
            defHops = self.config['Security'].get("PathLength", 6)
        else:
            p = 'ForwardPath'
            defHops = self.config['Security'].get("PathLength", 6)
        if self.path is None:
            self.path = self.config['Security'].get(p, "*")

        if isSURB:
            if self.lifetime is not None:
                duration = self.lifetime * 24*60*60
            else:
                duration = int(self.config['Security']['SURBLifetime'])
        else:
            duration = 24*60*60

        self.startAt = time.time()
        self.endAt = previousMidnight(self.startAt+duration)

        self.pathSpec = mixminion.ClientDirectory.parsePath(
            self.config, self.path, self.nHops, isReply=isReply, isSURB=isSURB,
            defaultNHops=defHops)
        self.directory.validatePath(self.pathSpec, self.exitAddress,
                                    self.startAt, self.endAt)

    def generatePaths(self, n):
        return self.directory.generatePaths(n,self.pathSpec,self.exitAddress,
                                            self.startAt,self.endAt)

_SEND_USAGE = """\
Usage: %(cmd)s [options] <-t address>|<--to=address>|
                          <-R reply-block>|--reply-block=reply-block>
Options:
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -D <yes|no>, --download-directory=<yes|no>
                             Force the client to download/not to download a
                               fresh directory.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
  -i <file>, --input=<file>  Read the message from <file>. (Defaults to stdin.)
  -P <path>, --path=<path>   Specify an explicit message path.
  -t address, --to=address   Specify the recipient's address.
  -R <file>, --reply-block=<file>
                             %(Send)s the message to a reply block in <file>,
                             or '-' for a reply block read from stdin.
  --subject=<str>, --from=<str>, --in-reply-to=<str>, --references=<str>
                             Specify an email header for the exiting message.
  --deliver-fragments        If the message is too long to fit in a single
                             packet, then deliver multiple fragmented packets
                             to the recipient instead of having the server
                             reassemble the message.
  --reply-block-fd=<N>       DOCDOC
%(extra)s

EXAMPLES:
  %(Send)s a message contained in a file <data> to user@domain.
      %(cmd)s -t user@domain -i data
  As above, but force 6 hops.
      %(cmd)s -t user@domain -i data -P '*6'
  As above, but use a random number of hops (about 6).
      %(cmd)s -t user@domain -i data -P '~6'
  As above, but use the server nicknamed Foo for the first hop and the server
  whose descriptor is stored in bar/baz for the last hop.
      %(cmd)s -t user@domain -i data -P 'Foo,~4,bar/baz'
  As above, but switch legs of the path after the second hop.
      %(cmd)s -t user@domain -i data -P 'Foo,?:~3,bar/baz'
  Specify an explicit path
      %(cmd)s -t user@domain -i data -P 'Foo,Bar,Baz,Quux,Fee,Fie,Foe'
  Specify an explicit path with a swap point
      %(cmd)s -t user@domain -i data -P 'Foo,Bar,Baz,Quux:Fee,Fie,Foe'
  %(Send)s the message to a reply block stored in 'FredsBlocks', using a
  randomly chosen first leg.
      %(cmd)s -t user@domain -i data -R FredsBlocks
  %(Send)s the message to a reply block stored in 'FredsBlocks', specifying
  the first leg.
      %(cmd)s -t user@domain -i data -R FredsBlocks -P 'Foo,Bar,Baz'
  Read the message from standard input.
      %(cmd)s -t user@domain
  Force a fresh directory download
      %(cmd)s -D yes
  %(Send)s a message without downloading a new directory, even if the current
  directory is out of date.
      %(cmd)s -D no -t user@domain -i data
""".strip()

def sendUsageAndExit(cmd, error=None):
    """Print a usage message for the mixminion send command (and family)
       and exit."""
    if error:
        print >>sys.stderr, "ERROR: %s"%error
        print >>sys.stderr, "For usage, run 'mixminion send --help'"
        sys.exit(1)
    if cmd.endswith(" queue"):
        print _SEND_USAGE % { 'cmd' : cmd, 'send' : 'queue', 'Send': 'Queue',
                              'extra' : '' }
    else:
        print _SEND_USAGE % { 'cmd' : cmd, 'send' : 'send', 'Send': 'Send',
                              'extra' : """\
  --queue                    Queue the message; don't send it.
  --no-queue                 Do not attempt to queue the message.""" }
    sys.exit(0)

if sys.platform == 'win32':
    EOF_STR = "Ctrl-Z, Return"
else:
    EOF_STR = "Ctrl-D"

def runClient(cmd, args):
    """[Entry point]  Generate an outgoing mixminion message and possibly
       send it.  Implements 'mixminion send' and 'mixminion queue'."""

    # Are we queueing?
    queueMode = 0
    if cmd.endswith(" queue"):
        queueMode = 1

    ###
    # Parse and validate our options.
    options, args = getopt.getopt(args, "hvQf:D:t:H:P:R:i:",
             ["help", "verbose", "quiet", "config=", "download-directory=",
              "to=", "hops=", "path=", "reply-block=", "reply-block-fd=",
              "input=", "queue", "no-queue",
              "subject=", "from=", "in-reply-to=", "references=",
              "deliver-fragments", ])

    if not options:
        sendUsageAndExit(cmd)

    inFile = None
    h_subject = h_from = h_irt = h_references = None
    no_ss_fragment = 0
    for opt,val in options:
        if opt in ('-i', '--input'):
            inFile = val
        elif opt == '--subject':
            h_subject = val
        elif opt == '--from':
            h_from = val
        elif opt == '--in-reply-to':
            h_irt = val
        elif opt == '--references':
            h_references = val
        elif opt == '--deliver-fragments':
            no_ss_fragment = 1

    if args:
        sendUsageAndExit(cmd,"Unexpected arguments")

    try:
        parser = CLIArgumentParser(options, wantConfig=1,wantClientDirectory=1,
                                   wantClient=1, wantLog=1, wantDownload=1,
                                   wantForwardPath=1)
        if queueMode and parser.forceNoQueue:
            raise UsageError("Can't use --no-queue option with queue command")
        if parser.forceQueue and parser.forceNoQueue:
            raise UsageError("Can't use both --queue and --no-queue")
    except UsageError, e:
        e.dump()
        sendUsageAndExit(cmd)

    # Encode the headers early so that we die before reading the message if
    # they won't work.
    try:
        headerStr = encodeMailHeaders(subject=h_subject, fromAddr=h_from,
                                      inReplyTo=h_irt, references=h_references)
    except MixError, e:
        raise UIError("Invalid headers: %s"%e)

    if inFile in (None, '-') and '-' in parser.replyBlockSources:
        raise UIError(
            "Can't read both message and reply block from stdin")

    # FFFF Make queueing configurable from .mixminionrc
    forceQueue = queueMode or parser.forceQueue
    forceNoQueue = parser.forceNoQueue

    parser.init()
    client = parser.client
    parser.parsePath()
    address = parser.exitAddress
    address.setHeaders(parseMessageAndHeaders(headerStr+"\n")[1])

    # Get our surb, if any.
    if address.isReply and inFile in ('-', None):
        # We check to make sure that we have a valid SURB before reading
        # from stdin.
        surblog = client.openSURBLog()
        try:
            s = surblog.findUnusedSURBs(parser.surbList)
            if s is None:
                raise UIError("No unused and unexpired reply blocks found.")
        finally:
            surblog.close()

    # Read the message.
    # XXXX Clean up this ugly control structure.
    if address and inFile is None and not address.hasPayload():
        message = None
        LOG.info("Sending dummy message")
    else:
        if address and not address.hasPayload():
            raise UIError("Cannot send a message in a DROP packet")

        if inFile is None:
            inFile = "-"

        try:
            if inFile == '-':
                print "Enter your message now.  Type %s when you are done."%(
                        EOF_STR)
                message = sys.stdin.read()
            else:
                message = readFile(inFile)
        except KeyboardInterrupt:
            print "Interrupted.  Message not sent."
            sys.exit(1)

        message = "%s%s" % (headerStr, message)

        address.setExitSize(len(message))

    if parser.exitAddress.isReply:
        client.sendReplyMessage(
            parser.directory, parser.exitAddress, parser.pathSpec,
            parser.surbList, message,
            parser.startAt, parser.endAt, forceQueue, forceNoQueue)
    else:
        client.sendForwardMessage(
            parser.directory, parser.exitAddress, parser.pathSpec,
            message, parser.startAt, parser.endAt, forceQueue, forceNoQueue,
            forceNoServerSideFragments=no_ss_fragment)

_PING_USAGE = """\
Usage: mixminion ping [options] serverName
Options
  -h, --help:             Print this usage message and exit.
  -v, --verbose           Display extra debugging messages.
  -f FILE, --config=FILE  Use a configuration file other than ~/.mixminionrc
  -D <yes|no>, --download-directory=<yes|no>
                          Force the client to download/not to download a
                            fresh directory.
"""
def runPing(cmd, args):
    """[Entry point] Send link padding to servers to see if they're up."""
    if len(args) == 1 and args[0] in ('-h', '--help'):
        print _PING_USAGE
        sys.exit(0)

    options, args = getopt.getopt(args, "hvQf:D:",
             ["help", "verbose", "quiet", "config=", "download-directory=", ])

    if len(args) == 0:
        raise UsageError("(No servers provided)")

    print "==========================================================="
    print "WARNING: Pinging a server is potentially dangerous, since"
    print "      it might alert people that you plan to use the server"
    print "      for your messages.  Even if you ping *all* the servers,"
    print "      an attacker can see _when_ you pinged the servers and"
    print "      use this information to help a traffic analysis attack."
    print
    print "      This command is for testing only, and will go away before"
    print "      Mixminion 1.0.  By then, all listed servers will be"
    print "      reliable anyway.  <wink>"
    print "==========================================================="

    parser = CLIArgumentParser(options, wantConfig=1,
                               wantClientDirectory=1, wantClient=1,
                               wantLog=1, wantDownload=1)

    parser.init()

    directory = parser.directory
    client = parser.client

    for arg in args:
        if '.' in arg:
            addrport = arg.split(":",1)
            if len(addrport) == 2:
                try:
                    port = int(addrport[1])
                except ValueError:
                    raise UIError("Invalid port: %r"%addrport[1])

            else:
                arg = "%s:48099"%arg
                port = 48099
            addr = addrport[0]
            routing = mixminion.Packet.MMTPHostInfo(addr,port,"\x00"*20)
            name = arg
        else:
            info = directory.getServerInfo(arg,
                                       startAt=time.time(), endAt=time.time(),
                                       strict=1)
            routing = info.getRoutingInfo()
            name = info.getNickname()

        ok, status = client.pingServer(routing)
        print ">>>", status
        print name, (ok and "is up" or "is down")

_IMPORT_SERVER_USAGE = """\
Usage: %(cmd)s [options] <filename> ...
Options:
   -h, --help:             Print this usage message and exit.
   -v, --verbose           Display extra debugging messages.
   -f FILE, --config=FILE  Use a configuration file other than ~/.mixminionrc

EXAMPLES:
  Import a ServerInfo from the file MyServer into our local directory.
      %(cmd)s MyServer
""".strip()

def importServer(cmd, args):
    """[Entry point] Manually add a server to the client directory."""
    options, args = getopt.getopt(args, "hf:vQ",
                     ['help', 'config=', 'verbose', 'quiet'])

    try:
        parser = CLIArgumentParser(options, wantConfig=1,wantClientDirectory=1,
                                   wantLog=1)
    except UsageError, e:
        e.dump()
        print _IMPORT_SERVER_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    directory = parser.directory

    try:
        clientLock()
        for filename in args:
            print "Importing from", filename
            try:
                directory.importFromFile(filename)
            except MixError, e:
                print "Error while importing %s: %s" % (filename, e)
    finally:
        clientUnlock()

    print "Done."

_LIST_SERVERS_USAGE = """\
Usage: %(cmd)s [options] [server names]
Options:
  -h, --help:                Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~/.mixminionrc
  -D <yes|no>, --download-directory=<yes|no>
                             Force the client to download/not to download a
                               fresh directory.

  -R, --recommended          Only display recommended servers.
  -T, --with-time            Display validity intervals for server descriptors.
  --no-collapse              Don't combine descriptors with adjacent times.
  -s <str>,--separator=<str> Separate features with <str> instead of tab.
  -c, --cascade              Pretty-print results, cascading by descriptors.
  -C, --cascade-features     Pretty-print results, cascading by features.
  -J, --justify              Justify features into columns
  -F <name>,--feature=<name> Select which server features to list.
  --list-features            Display a list of all recognized features.

EXAMPLES:
  List all currently known servers.
      %(cmd)s
  Same as above, but explicitly name the features to be listed.
      %(cmd)s -F caps -F status
""".strip()

def listServers(cmd, args):
    """[Entry point] Print info about """
    options, args = getopt.getopt(args, "hf:D:vQF:JTRs:cC",
                                  ['help', 'config=', "download-directory=",
                                   'verbose', 'quiet', 'feature=', 'justify',
                                   'with-time', "no-collapse", "recommended",
                                   "separator=", "cascade","cascade-features",
                                   'list-features' ])
    try:
        parser = CLIArgumentParser(options, wantConfig=1,
                                   wantClientDirectory=1,
                                   wantLog=1, wantDownload=1,
                                   ignoreOptions=['-R'])
    except UsageError, e:
        e.dump()
        print _LIST_SERVERS_USAGE % {'cmd' : cmd}
        sys.exit(1)
    features = []
    cascade = 0
    showTime = 0
    goodOnly = 0
    separator = None
    justify = 0
    listFeatures = 0
    for opt,val in options:
        if opt in ('-F', '--feature'):
            features.extend(val.split(","))
        elif opt in ('-T', '--with-time'):
            showTime = 1
        elif opt == ('--no-collapse'):
            showTime = 2
        elif opt in ('-R', '--recommended'):
            goodOnly = 1
        elif opt in ('-s', '--separator'):
            separator = val
        elif opt in ('-c', '--cascade'):
            cascade = 1
        elif opt in ('-C', '--cascade-features'):
            cascade = 2
        elif opt in ('-J', '--justify'):
            justify = 1
        elif opt == ('--list-features'):
            listFeatures = 1

    if listFeatures:
        features = mixminion.Config.getFeatureList(ServerInfo)
        features.append(("caps",))
        features.append(("status",))
        for f in features:
            if len(f)>1:
                print "%-30s (abbreviate as %s)" % (
                    f[0], englishSequence(f[1:],compound="or"))
            else:
                print f[0]
        return

    if not features:
        if goodOnly:
            features = [ 'caps' ]
        else:
            features = [ 'caps', 'status' ]

    if separator is None:
        if justify:
            separator = ' '
        else:
            separator = '\t'

    parser.init()
    directory = parser.directory

    # Look up features in directory.
    featureMap = directory.getFeatureMap(features,goodOnly=goodOnly)

    # If any servers are listed on the command line, restrict to those
    # servers.
    if args:
        lcargs = [ arg.lower() for arg in args ]
        lcfound = {}
        restrictedMap = {}
        for nn,v in featureMap.items():
            if nn.lower() in lcargs:
                restrictedMap[nn] = v
                lcfound[nn.lower()] = 1
        for arg in args:
            if not lcfound.has_key(arg.lower()):
                if goodOnly:
                    raise UIError("No recommended descriptors found for %s"%
                                  arg)
                else:
                    raise UIError("No descriptors found for %s"%arg)
        featureMap = restrictedMap

    # Collapse consecutive server descriptors with matching features.
    if showTime < 2:
        featureMap = mixminion.ClientDirectory.compressFeatureMap(
            featureMap, ignoreGaps=(not showTime), terse=(not showTime))

    # Now display the result.
    for line in mixminion.ClientDirectory.formatFeatureMap(
        features,featureMap,showTime,cascade,separator,justify):
        print line


_UPDATE_SERVERS_USAGE = """\
Usage: %(cmd)s [options]
Options:
  -h, --help:                Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~/.mixminionrc
                             (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Download a new list of servers.  (Note that the 'mixminion send' and
  the 'mixminion generate-surbs' commands do this by default.)
      %(cmd)s
""".strip()

def updateServers(cmd, args):
    options, args = getopt.getopt(args, "hvQf:",
               ['help', 'quiet', 'verbose', 'config='])

    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantClientDirectory=1,
                                   wantLog=1)
    except UsageError, e:
        e.dump()
        print _UPDATE_SERVERS_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    directory = parser.directory
    config = parser.config
    timeout = int(config['DirectoryServers']['DirectoryTimeout'])
    try:
        clientLock()
        directory.updateDirectory(forceDownload=1, timeout=timeout)
    finally:
        clientUnlock()
    print "Directory updated"

_CLIENT_DECODE_USAGE = """\
Usage: %(cmd)s [options] -i <file>|--input=<file>
Options:
  -h, --help:                Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~/.mixminionrc
                             (You can also use MIXMINIONRC=FILE)
  -F, --force:               Decode the input files, even if they seem
                             overcompressed.
  -o <file>, --output=<file> Write the results to <file> rather than stdout.
  -i <file>, --input=<file>  Read the results from <file>.
  --passphrase-fd=<N>        Read passphrase from file descriptor N instead
                               of asking on the console.

EXAMPLES:
  Decode message(s) stored in 'NewMail', writing the result to stdout.
      %(cmd)s -i NewMail
  Decode message(s) stored in 'NewMail', writing the result to 'Decoded'.
      %(cmd)s -i NewMail -o  Decoded
""".strip()

def clientDecode(cmd, args):
    """[Entry point] Decode a message."""
    options, args = getopt.getopt(args, "hvQf:o:Fi:",
          ['help', 'verbose', 'quiet', 'config=',
           'output=', 'force', 'input=', 'passphrase-fd=',])

    outputFile = '-'
    inputFile = None
    force = 0
    for o,v in options:
        if o in ('-o', '--output'):
            outputFile = v
        elif o in ('-F', '--force'):
            force = 1
        elif o in ('-i', '--input'):
            inputFile = v

    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantClient=1,
                                   wantLog=1)
    except UsageError, e:
        e.dump()
        print _CLIENT_DECODE_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    if args:
        msg = "Unexpected arguments."
        if len(args) == 1:
            msg += " (Did you mean '-i %s'?)" % args[0]
        raise UIError(msg)

    if not inputFile:
        raise UIError("No input file specified")

    parser.init()
    client = parser.client

    if outputFile == '-':
        out = sys.stdout
    else:
        # ???? Should we sometimes open this in text mode?
        out = open(outputFile, 'wb')

    tty = os.isatty(out.fileno())

    if inputFile == '-':
        s = sys.stdin.read()
    else:
        try:
            s = readFile(inputFile)
        except OSError, e:
            LOG.error("Could not read file %s: %s", inputFile, e)
    try:
        res = client.decodeMessage(s, force=force, isatty=tty)
    except ParseError, e:
        raise UIError("Couldn't parse message: %s"%e)

    for r in res:
        out.write(r)
    out.close()

_GENERATE_SURB_USAGE = """\
Usage: %(cmd)s [options]
Options:
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -D <yes|no>, --download-directory=<yes|no>
                             Force the client to download/not to download a
                               fresh directory.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
  -P <path>, --path=<path>   Specify an explicit path.
  -t address, --to=address   Specify the block's address. (Defaults to value
                               in configuration file.)
  -o <file>, --output=<file> Write the reply blocks to <file> instead of
                               stdout.
  -b, --binary               Write the reply blocks in binary mode instead
                               of ascii mode.
  -n <N>, --count=<N>        Generate <N> reply blocks. (Defaults to 1.)
  --identity=<name>          Specify a pseudonymous identity.
  --passphrase-fd=<N>        Read passphrase from file descriptor N instead
                               of asking on the console.

EXAMPLES:
  Generate a reply block to deliver messages to the address given in
  ~/.mixminiond.conf; choose a path at random; write the block to stdout.
      %(cmd)s
  As above, but force change address to deliver to user@domain.
      %(cmd)s -t user@domain
  As above, but force a 6-hop path.
      %(cmd)s -t user@domain -P '*6'
  As above, but force the first hop to be 'Foo' and the last to be 'Bar'.
      %(cmd)s -t user@domain 'Foo,*4,Bar'
  As above, but write the reply block to the file 'MyBlocks'.
      %(cmd)s -t user@domain -P 'Foo,*4,Bar' -o MyBlocks
  As above, but write the reply block in binary mode.
      %(cmd)s -t user@domain -P 'Foo,*4,Bar' -o MyBlocks -b
  As above, but generate 100 reply blocks.
      %(cmd)s -t user@domain -P 'Foo,*4,Bar' -o MyBlocks -b -n 100
  Specify an explicit path.
      %(cmd)s -P 'Foo,Bar,Baz,Quux'
  Generate 10 reply blocks without downloading a new directory, even if the
  current directory is out of date.
      %(cmd)s -D no -n 10
""".strip()

def generateSURB(cmd, args):
    options, args = getopt.getopt(args, "hvQf:D:t:H:P:o:bn:",
          ['help', 'verbose', 'quiet', 'config=', 'download-directory=',
           'to=', 'hops=', 'path=', 'lifetime=', 'passphrase-fd=',
           'output=', 'binary', 'count=', 'identity='])

    outputFile = '-'
    binary = 0
    count = 1
    identity = ""
    for o,v in options:
        if o in ('-o', '--output'):
            outputFile = v
        elif o in ('-b', '--binary'):
            binary = 1
        elif o in ('-n', '--count'):
            try:
                count = int(v)
            except ValueError:
                print "ERROR: %s expects an integer" % o
                sys.exit(1)
        elif o in ('--identity',):
            identity = v
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantClient=1,
                                   wantLog=1, wantClientDirectory=1,
                                   wantDownload=1, wantReplyPath=1)
    except UsageError, e:
        e.dump()
        print _GENERATE_SURB_USAGE % { 'cmd' : cmd }
        sys.exit(0)

    if args:
        print >>sys.stderr, "ERROR: Unexpected arguments"
        print _GENERATE_SURB_USAGE % { 'cmd' : cmd }
        sys.exit(0)

    parser.init()

    client = parser.client

    parser.parsePath()

    if outputFile == '-':
        out = sys.stdout
    elif binary:
        out = open(outputFile, 'wb')
    else:
        out = open(outputFile, 'w')

    for path1,path2 in parser.generatePaths(count):
        assert path2 and not path1
        surb = client.generateReplyBlock(parser.exitAddress, path2,
                                         name=identity,
                                         expiryTime=parser.endAt)
        if binary:
            out.write(surb.pack())
        else:
            out.write(surb.packAsText())

    if outputFile != '-':
        out.close()

_INSPECT_SURBS_USAGE = """\
Usage: %(cmd)s [options] <files>
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Examine properties of reply blocks stored in 'FredsBlocks'.
      %(cmd)s FredsBlocks
""".strip()

def inspectSURBs(cmd, args):
    options, args = getopt.getopt(args, "hvQf:",
             ["help", "verbose", "quiet", "config=", ])

    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1)
    except UsageError, e:
        e.dump()
        print _INSPECT_SURBS_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()

    surblog = parser.client.openSURBLog()

    try:
        for fn in args:
            s = readFile(fn, 1)
            print "==== %s"%fn
            try:
                if stringContains(s, "-----BEGIN TYPE III REPLY BLOCK-----"):
                    surbs = parseTextReplyBlocks(s)
                else:
                    surbs = parseReplyBlocks(s)

                for surb in surbs:
                    used = surblog.isSURBUsed(surb) and "yes" or "no"
                    print surb.format()
                    print "Used:", used
            except ParseError, e:
                print "Error while parsing: %s"%e
    finally:
        surblog.close()

_FLUSH_QUEUE_USAGE = """\
Usage: %(cmd)s [options]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
  -n <n>, --count=<n>        Send no more than <n> packets from the queue.

EXAMPLES:
  Try to send all currently queued packets.
      %(cmd)s
DOCDOC
""".strip()

def flushQueue(cmd, args):
    options, args = getopt.getopt(args, "hvQf:n:",
             ["help", "verbose", "quiet", "config=", "count="])
    count=None
    for o,v in options:
        if o in ('-n','--count'):
            try:
                count = int(v)
            except ValueError:
                print "ERROR: %s expects an integer" % o
                sys.exit(1)
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1,
                                   wantClientDirectory=len(args))
    except UsageError, e:
        e.dump()
        print _FLUSH_QUEUE_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client

    if args:
        handles = parser.client.queue.getHandlesByDestAndAge(
            args, parser.directory, notAfter=None)
    else:
        handles = None

    client.flushQueue(count, handles)

_CLEAN_QUEUE_USAGE = """\
Usage: %(cmd)s  [options] [servername...]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
  -d <n>, --days=<n>         Remove all packets older than <n> days old.

EXAMPLES:
  Remove all pending packets older than one week.
      %(cmd)s -d 7
DOCDODC
""".strip()

def cleanQueue(cmd, args):
    options, args = getopt.getopt(args, "hvQf:d:",
             ["help", "verbose", "quiet", "config=", "days=",])
    days = 60
    for o,v in options:
        if o in ('-d','--days'):
            try:
                days = int(v)
            except ValueError:
                print "ERROR: %s expects an integer" % o
                sys.exit(1)
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1,
                                   wantClientDirectory=len(args))
    except UsageError, e:
        e.dump()
        print _CLEAN_QUEUE_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client
    notAfter = time.time() - days*24*60*60
    if args:
        handles = parser.client.queue.getHandlesByDestAndAge(
            args, parser.directory, notAfter)
    else:
        handles = parser.client.queue.getHandlesByAge(notAfter)

    client.cleanQueue(handles)

_LIST_QUEUE_USAGE = """\
Usage: %(cmd)s [options]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Describe the current contents of the queue.
      %(cmd)s
""".strip()

def listQueue(cmd, args):
    options, args = getopt.getopt(args, "hvQf:D:",
                                  ["help", "verbose", "quiet", "config=",
                                   'download-directory=',])
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1, wantClientDirectory=1)
    except UsageError, e:
        e.dump()
        print _LIST_QUEUE_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client

    try:
        clientLock()
        res = client.queue.inspectQueue()
    finally:
        clientUnlock()

    if not res:
        print "(No packets in queue)"
        return

    res_items = [ (displayServerByRouting(ri),count,date)
                  for ri,(count,date) in res.items() ]
    res_items.sort()
    now = time.time()
    for server, count, date in res_items:
        days = floorDiv(now-date, 24*60*60)
        if days < 1:
            days = "<1"
        print "%2d packets for %s (oldest is %s days old)"%(
            count, server, days)

_LIST_FRAGMENTS_USAGE = """\
Usage: %(cmd)s [options]
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)

EXAMPLES:
  Describe the state of fragmented messages currently being reassembled.
      %(cmd)s
""".strip()

def listFragments(cmd, args):
    options, args = getopt.getopt(args, "hvQf:D:",
                                  ["help", "verbose", "quiet", "config=",
                                   'download-directory=',])
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1, wantClientDirectory=1)
    except UsageError, e:
        e.dump()
        print _LIST_FRAGMENTS_USAGE % { 'cmd' : cmd }
        sys.exit(1)

    parser.init()
    client = parser.client

    try:
        clientLock()
        res = client.pool.formatMessageList()
    finally:
        clientUnlock()

    if not res:
        print "(No fragments being reassembled)"
        return

    for line in res:
        print line


_REASSEMBLE_USAGE = """\
Usage: %(cmd)s [options] <message-id> ...
  -h, --help                 Print this usage message and exit.
  -v, --verbose              Display extra debugging messages.
  -f <file>, --config=<file> Use a configuration file other than ~.mixminionrc
                               (You can also use MIXMINIONRC=FILE)
""".strip()

def reassemble(cmd, args):
    options, args = getopt.getopt(args, "hvQf:D:Po:",
                                  ["help", "verbose", "quiet", "config=",
                                   'download-directory=','--purge',
                                   '--output'])
    reassemble = 1
    if cmd.endswith("purge-fragments"):
        reassemble = 0
    try:
        parser = CLIArgumentParser(options, wantConfig=1, wantLog=1,
                                   wantClient=1, wantClientDirectory=1)
    except UsageError, e:
        e.dump()
        print _REASSEMBLE_USAGE % { 'cmd' : cmd }
        print """\
  -P, --purge                Remove the message from the pool.
  -o <file>, --output=<file> Write the message to a file instead of stdout
""".strip()
        sys.exit(1)
    purge = not reassemble
    outfilename = None
    for o,v in options:
        if o in ('-o', '--output'):
            outfilename = v
        elif o in ("-P", "--purge"):
            purge = 1

    if not args:
        print "No message IDs provided."
        return

    parser.init()
    client = parser.client

    closeoutfile = 0
    if reassemble:
        out = sys.stdout
        if outfilename not in ('-',None):
            out = open(outfilename, 'wb')
            closeoutfile = 1

    try:
        clientLock()
        removed = []
        for msgid in args:
            if reassemble:
                msg = client.pool.getMessage(msgid)
            if purge:
                removed.append(msgid)
        client.pool.removeMessages(removed)
        if reassemble:
            out.write(msg)
    finally:
        clientUnlock()
        if reassemble and closeoutfile:
            out.close()
