# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: PacketHandler.py,v 1.29 2003/10/13 17:30:24 nickm Exp $

"""mixminion.server.PacketHandler: Code to process mixminion packets"""

import binascii
import threading
import types

from mixminion.Common import encodeBase64, formatBase64, LOG
import mixminion.Crypto as Crypto
import mixminion.Packet as Packet
import mixminion.Common as Common
import mixminion.BuildMessage

from mixminion.ServerInfo import PACKET_KEY_BYTES
from mixminion.Common import MixError, isPrintingAscii

__all__ = [ 'PacketHandler', 'ContentError', 'DeliveryPacket', 'RelayedPacket']

class ContentError(Common.MixError):
    """Exception raised when a packed is malformatted or unacceptable."""
    pass

class PacketHandler:
    """Class to handle processing packets.  Given an incoming packet,
       it removes one layer of encryption, does all necessary integrity
       checks, swaps headers if necessary, re-pads, and decides whether
       to drop the message, relay the message, or send the message to
       an exit handler."""
    ## Fields:
    # privatekeys: a list of 2-tuples of
    #      (1) a RSA private key that we accept
    #      (2) a HashLog objects corresponding to the given key
    def __init__(self, privatekeys=(), hashlogs=()):
        """Constructs a new packet handler, given a sequence of
           private key object for header encryption, and a sequence of
           corresponding hashlog object to prevent replays.

           The lists must be equally long.  When a new packet is
           processed, we try each of the private keys in sequence.  If
           the packet is decodeable with one of the keys, we log it in
           the corresponding entry of the hashlog list.
        """
        self.privatekeys = []
        self.lock = threading.Lock()

        assert type(privatekeys) in (types.ListType, types.TupleType)
        assert type(hashlogs) in (types.ListType, types.TupleType)

        self.setKeys(privatekeys, hashlogs)

    def setKeys(self, keys, hashlogs):
        """Change the keys and hashlogs used by this PacketHandler.
           Arguments are as to PacketHandler.__init__
        """
        self.lock.acquire()
        newKeys = {}
        try:
            # Build a set of asn.1-encoded public keys in *new* set.
            for k in keys:
                newKeys[k.encode_key(1)] = 1
                if k.get_modulus_bytes() != PACKET_KEY_BYTES:
                    raise Common.MixFatalError("Incorrect packet key length")
            # For all old public keys, if they aren't in the new set, close
            # their hashlogs.
            for k, h in self.privatekeys:
                if not newKeys.get(k.encode_key(1)):
                    h.close()
            # Now, set the keys.
            self.privatekeys = zip(keys, hashlogs)
        finally:
            self.lock.release()

    def syncLogs(self):
        """Sync all this PacketHandler's hashlogs."""
        try:
            self.lock.acquire()
            for _, h in self.privatekeys:
                h.sync()
        finally:
            self.lock.release()

    def close(self):
        """Close all this PacketHandler's hashlogs."""
        try:
            self.lock.acquire()
            for _, h in self.privatekeys:
                h.close()
        finally:
            self.lock.release()

    def processMessage(self, msg):
        """Given a 32K mixminion message, processes it completely.

           Return one of:
                    None [if the message should be dropped.]
                    a DeliveryPacket object
                    a RelayedPacket object

           May raise CryptoError, ParseError, or ContentError if the packet
           is malformatted, misencrypted, unparseable, repeated, or otherwise
           unhandleable.

           WARNING: This implementation does nothing to prevent timing
           attacks: dropped messages, messages with bad digests, replayed
           messages, and exit messages are all processed faster than
           forwarded messages.  You must prevent timing attacks elsewhere."""

        # Break into headers and payload
        pkt = Packet.parsePacket(msg)
        header1 = Packet.parseHeader(pkt.header1)
        encSubh = header1[:Packet.ENC_SUBHEADER_LEN]
        header1 = header1[Packet.ENC_SUBHEADER_LEN:]

        assert len(header1) == Packet.HEADER_LEN - Packet.ENC_SUBHEADER_LEN
        assert len(header1) == (128*16) - 256 == 1792

        # Try to decrypt the first subheader.  Try each private key in
        # order.  Only fail if all private keys fail.
        subh = None
        e = None
        self.lock.acquire()
        try:
            for pk, hashlog in self.privatekeys:
                try:
                    subh = Crypto.pk_decrypt(encSubh, pk)
                    break
                except Crypto.CryptoError, err:
                    e = err
        finally:
            self.lock.release()
        if not subh:
            # Nobody managed to get us the first subheader.  Raise the
            # most-recently-received error.
            raise e

        if len(subh) != Packet.MAX_SUBHEADER_LEN:
            raise ContentError("Bad length in RSA-encrypted part of subheader")

        subh = Packet.parseSubheader(subh) #may raise ParseError

        # Check the version: can we read it?
        if subh.major != Packet.MAJOR_NO or subh.minor != Packet.MINOR_NO:
            raise ContentError("Invalid protocol version")

        # Check the digest of all of header1 but the first subheader.
        if subh.digest != Crypto.sha1(header1):
            raise ContentError("Invalid digest")

        # Get ready to generate message keys.
        keys = Crypto.Keyset(subh.secret)

        # Replay prevention
        replayhash = keys.get(Crypto.REPLAY_PREVENTION_MODE, Crypto.DIGEST_LEN)
        if hashlog.seenHash(replayhash):
            raise ContentError("Duplicate message detected.")
        else:
            hashlog.logHash(replayhash)

        # If we're meant to drop, drop now.
        rt = subh.routingtype
        if rt == Packet.DROP_TYPE:
            return None

        # Prepare the key to decrypt the header in counter mode.  We'll be
        # using this more than once.
        header_sec_key = Crypto.aes_key(keys.get(Crypto.HEADER_SECRET_MODE))

        # Prepare key to generate padding
        junk_key = Crypto.aes_key(keys.get(Crypto.RANDOM_JUNK_MODE))

        # Pad the rest of header 1
        header1 += Crypto.prng(junk_key,
                               Packet.OAEP_OVERHEAD + Packet.MIN_SUBHEADER_LEN
                               + subh.routinglen)

        assert len(header1) == (Packet.HEADER_LEN - Packet.ENC_SUBHEADER_LEN
                             + Packet.OAEP_OVERHEAD+Packet.MIN_SUBHEADER_LEN
                                + subh.routinglen)
        assert len(header1) == 1792 + 42 + 42 + subh.routinglen == \
               1876 + subh.routinglen

        # Decrypt the rest of header 1, encrypting the padding.
        header1 = Crypto.ctr_crypt(header1, header_sec_key)

        # If the subheader says that we have extra routing info that didn't
        # fit in the RSA-encrypted part, get it now.
        overflowLength = subh.getOverflowLength()
        if overflowLength:
            subh.appendOverflow(header1[:overflowLength])
            header1 = header1[overflowLength:]

        assert len(header1) == (
            1876 + subh.routinglen 
            - max(0,subh.routinglen-Packet.MAX_ROUTING_INFO_LEN))

        header1 = subh.underflow + header1

        assert len(header1) == Packet.HEADER_LEN

        # Decrypt the payload.
        payload = Crypto.lioness_decrypt(pkt.payload,
                              keys.getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE))

        # If we're an exit node, there's no need to process the headers
        # further.
        if rt >= Packet.MIN_EXIT_TYPE:
            return DeliveryPacket(rt, subh.getExitAddress(),
                                  keys.get(Crypto.APPLICATION_KEY_MODE),
                                  subh.getTag(), payload)

        # If we're not an exit node, make sure that what we recognize our
        # routing type.
        if rt not in (Packet.SWAP_FWD_IPV4_TYPE, Packet.FWD_IPV4_TYPE):
            raise ContentError("Unrecognized Mixminion routing type")

        # Decrypt header 2.
        header2 = Crypto.lioness_decrypt(pkt.header2,
                           keys.getLionessKeys(Crypto.HEADER_ENCRYPT_MODE))

        # If we're the swap node, (1) decrypt the payload with a hash of
        # header2... (2) decrypt header2 with a hash of the payload...
        # (3) and swap the headers.
        if Packet.typeIsSwap(rt):
            hkey = Crypto.lioness_keys_from_header(header2)
            payload = Crypto.lioness_decrypt(payload, hkey)

            hkey = Crypto.lioness_keys_from_payload(payload)
            header2 = Crypto.lioness_decrypt(header2, hkey)

            header1, header2 = header2, header1

        # Build the address object for the next hop
        address = Packet.parseIPV4Info(subh.routinginfo)

        # Construct the message for the next hop.
        pkt = Packet.Packet(header1, header2, payload).pack()

        return RelayedPacket(address, pkt)

class RelayedPacket:
    """A packet that is to be relayed to another server; returned by
       returned by PacketHandler.processMessage."""
    ## Fields:
    # address -- an instance of IPV4Info
    # msg -- a 32K packet.
    def __init__(self, address, msg):
        """Create a new packet, given an instance of IPV4Info and a 32K
           packet."""
        assert isinstance(address, Packet.IPV4Info)
        assert len(msg) == 1<<15
        self.address = address
        self.msg = msg

    def isDelivery(self):
        """Return true iff this packet is a delivery (non-relay) packet."""
        return 0

    def getAddress(self):
        """Return an instance of IPV4Info indicating the address where this
           packet is to be delivered."""
        return self.address

    def getPacket(self):
        """Returns the 32K contents of this packet."""
        return self.msg

class DeliveryPacket:
    """A packet that is to be delivered via some exit module; returned by
       PacketHandler.processMessage"""
    ##Fields:
    # exitType -- a 2-byte integer indicating which exit module to use.
    # address -- a string encoding the address to deliver to.
    # key -- the 16-byte application key
    # tag -- the 20-byte delivery handle
    # payload -- the unencoded 28K payload
    # contents -- until decode is called, None.  After decode is called,
    #     the actual contents of this message as delivered.
    # type -- until decode is called, None.  After decode is called,
    #     one of 'plain' (plaintext message), 'long' (overcompressed message),
    #     'enc' (encrypted message), or 'err' (malformed message).
    # headers -- a map from key to value for the delivery headers in
    #     this message's payload.  In the case of a fragment, or a
    #     non-plaintext message, the map is empty.
    # isfrag -- Is this packet a fragment of a complete message?  If so, the
    #     type must be 'plain'.
    # dPayload -- An instance of mixminion.Packet.Payload for this object.
    # error -- None, or a string containing an error encountered while trying
    #     to decode the payload.
    def __init__(self, routingType, routingInfo, applicationKey,
                 tag, payload):
        """Construct a new DeliveryPacket."""
        assert 0 <= routingType <= 0xFFFF
        assert len(applicationKey) == 16
        #assert len(tag) == 20 #XXXX006 make tag system sane.
        assert len(tag) == 20 or routingType == Packet.FRAGMENT_TYPE
        assert len(payload) == 28*1024
        self.exitType = routingType
        self.address = routingInfo
        self.key = applicationKey
        self.tag = tag
        self.payload = payload
        self.contents = None
        self.type = None
        self.headers = None
        self.isfrag = 0
        self.dPayload = None
        self.error = None

    def __getstate__(self):
        return "V0", self.__dict__
        
    def __setstate__(self, state):
        if type(state) == types.DictType:
            #XXXX006 remove this case.
            self.__dict__.update(state)
            if not hasattr(self, 'isfrag'):
                self.isfrag = 0
            if not hasattr(self, 'dPayload'):
                self.dPayload = None
            if not hasattr(self, 'error'):
                self.error = None
            if not hasattr(self, 'headers'):
                self.headers = {}
        elif state[0] == 'V0':
            self.__dict__.update(state[1])
        else:
            raise MixError("Unrecognized state version %s", state[0])

    def isDelivery(self):
        """Return true iff this packet is a delivery (non-relay) packet."""
        return 1

    def getExitType(self): return self.exitType
    def getAddress(self): return self.address
    def getTag(self): return self.tag
    def getApplicationKey(self): return self.key
    def getPayload(self): return self.payload

    def getContents(self):
        """Return the decoded contents of this packet."""
        if self.type is None: self.decode()
        return self.contents

    def getDecodedPayload(self):
        """Return an instance of mixminion.Packet.Payload for this packet."""
        if self.type is None: self.decode()
        return self.dPayload

    def isPlaintext(self):
        """Return true iff this packet is a plaintext, forward packet."""
        if self.type is None: self.decode()
        return self.type == 'plain'

    def isOvercompressed(self):
        """Return true iff this packet is an overcompressed, plaintext, forward
           packet."""
        if self.type is None: self.decode()
        return self.type == 'long'

    def isFragment(self):
        """Return true iff this packet is part of a fragmented message."""
        if self.type is None: self.decode()
        return self.isfrag

    def isEncrypted(self):
        """Return true iff this packet may be an encrypted forward or
           reply packet."""
        if self.type is None: self.decode()
        return self.type == 'enc'

    def isPrintingAscii(self):
        """Return true iff this packets contents are printing characters
           suitable for inclusion in a text transport medium."""
        if self.type is None: self.decode()
        return isPrintingAscii(self.contents, allowISO=1)

    def isError(self):
        """Return true iff this packet is malformed."""
        if self.type is None: self.decode()
        return self.type == 'err'

    def decode(self):
        """Helper method: Determines this message's type and contents."""
        if self.payload is None:
            return
        message = self.payload
        self.contents = None
        try:
            self.dPayload = mixminion.BuildMessage.decodePayload(message,
                                                                 self.tag)
            if self.dPayload is None:
                # encrypted message
                self.type = 'enc'
                self.contents = message
                self.headers = {}
            elif self.dPayload.isSingleton():
                # forward message, singleton.
                self.type = 'plain'
                body = self.dPayload.getUncompressedContents()
                self.contents, self.headers = \
                               Packet.parseMessageAndHeaders(body)
            else:
                # forward message, fragment.
                self.isfrag = 1
                self.type = 'plain'
                self.contents = message
                self.headers = {}
        except Packet.CompressedDataTooLong, _:
            self.contents = Packet.parsePayload(message).getContents()
            self.type = 'long'
            self.headers = {}
        except MixError, e:
            self.contents = message
            self.error = str(e)
            self.type = 'err'
            self.headers = {}

        self.payload = None

    def getAsciiContents(self):
        """Return the contents of this message, encoded in base64 if they are
           not already printable."""
        if self.type is None:
            self.decode()

        if self.type == 'plain' and isPrintingAscii(self.contents, allowISO=1):
            return self.contents
        else:
            return encodeBase64(self.contents)

    def getHeaders(self):
        """Return a dict containing the headers for this message."""
        if self.type is None:
            self.decode()
        if self.headers is None:
            LOG.warn("getHeaders found no decoded headers")
            return {}
        return self.headers

    def getAsciiTag(self):
        """Return a base64-representation of this message's decoding handle."""
        return formatBase64(self.tag)

    def getTextEncodedMessage(self):
        """Return a Packet.TextEncodedMessage object for this packet."""
        tag = None
        if self.isOvercompressed():
            tp = 'LONG'
        elif self.isEncrypted():
            tp = 'ENC'
            tag = self.tag
        elif self.isPrintingAscii():
            assert self.isPlaintext()
            tp = 'TXT'
        elif self.isFragment():
            assert self.isPlaintext()
            tp = 'FRAG'
        else:
            assert self.isPlaintext()
            tp = 'BIN'

        return Packet.TextEncodedMessage(self.contents, tp, tag)
