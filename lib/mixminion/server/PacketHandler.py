# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: PacketHandler.py,v 1.10 2003/02/13 06:30:23 nickm Exp $

"""mixminion.PacketHandler: Code to process mixminion packets on a server"""

import base64

import mixminion.Crypto as Crypto
import mixminion.Packet as Packet
import mixminion.Common as Common
import mixminion.BuildMessage

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
    # privatekey: list of RSA private keys that we accept
    # hashlog: list of HashLog objects corresponding to the keys.
    def __init__(self, privatekey, hashlog):
        """Constructs a new packet handler, given a private key object for
           header encryption, and a hashlog object to prevent replays.

           A sequence of private keys may be provided, if you'd like the
           server to accept messages encrypted with any of them.  Beware,
           though: PK decryption is expensive.  Also, a hashlog must be
           provided for each private key.
        """
        try:
            # Check whether we have a key or a sequence of keys.
            _ = privatekey[0]
            assert len(hashlog) == len(privatekey)

            self.privatekey = privatekey
            self.hashlog = hashlog
        except TypeError:
            # Privatekey is not be subscriptable; we must have only one.
            self.privatekey = (privatekey, )
            self.hashlog = (hashlog, )

    def syncLogs(self):
        """Sync all this PacketHandler's hashlogs."""
        for h in self.hashlog:
            h.sync()

    def close(self):
        """Close all this PacketHandler's hashlogs."""
        for h in self.hashlog:
            h.close()

    def processMessage(self, msg):    
        """Given a 32K mixminion message, processes it completely.

           Return one of:
                    None [if the mesesage should be dropped.]
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
        msg = Packet.parseMessage(msg)
        header1 = Packet.parseHeader(msg.header1)

        # Try to decrypt the first subheader.  Try each private key in
        # order.  Only fail if all private keys fail.
        subh = None
        e = None
        for pk, hashlog in zip(self.privatekey, self.hashlog):
            try:
                subh = Crypto.pk_decrypt(header1[0], pk)
                break
            except Crypto.CryptoError, err:
                e = err
        if not subh:
            # Nobody managed to get us the first subheader.  Raise the
            # most-recently-received error.
            raise e

        subh = Packet.parseSubheader(subh) #may raise ParseError

        # Check the version: can we read it?
        if subh.major != Packet.MAJOR_NO or subh.minor != Packet.MINOR_NO:
            raise ContentError("Invalid protocol version")

        # Check the digest of all of header1 but the first subheader.
        if subh.digest != Crypto.sha1(header1[1:]):
            raise ContentError("Invalid digest")

        # Get ready to generate message keys.
        keys = Crypto.Keyset(subh.secret)

        # Replay prevention
        replayhash = keys.get(Crypto.REPLAY_PREVENTION_MODE, 20)
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

        # If the subheader says that we have extra blocks of routing info,
        # decrypt and parse them now.
        if subh.isExtended():
            nExtra = subh.getNExtraBlocks()
            if (rt < Packet.MIN_EXIT_TYPE) or (nExtra > 15):
                # None of the native methods allow multiple blocks; no
                # size can be longer than the number of bytes in the rest
                # of the header.
                raise ContentError("Impossibly long routing info length")

            extra = Crypto.ctr_crypt(header1[1:1+nExtra], header_sec_key)
            subh.appendExtraBlocks(extra)
            remainingHeader = header1[1+nExtra:]
        else:
            nExtra = 0
            remainingHeader = header1[1:]

        # Decrypt the payload.
        payload = Crypto.lioness_decrypt(msg.payload,
                              keys.getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE))

        # If we're an exit node, there's no need to process the headers
        # further.
        if rt >= Packet.MIN_EXIT_TYPE:
            return DeliveryPacket(rt, subh.getExitAddress(),
                                  keys.get(Crypto.APPLICATION_KEY_MODE),
                                  subh.getTag(), payload)

        # If we're not an exit node, make sure that what we recognize our
        # routing type.
        if rt not in (Packet.SWAP_FWD_TYPE, Packet.FWD_TYPE):
            raise ContentError("Unrecognized Mixminion routing type")

        # Pad the rest of header 1
        remainingHeader = remainingHeader +\
                          Crypto.prng(keys.get(Crypto.PRNG_MODE),
                                      Packet.HEADER_LEN-len(remainingHeader))

        # Decrypt the rest of header 1, encrypting the padding.
        header1 = Crypto.ctr_crypt(remainingHeader, header_sec_key, nExtra*128)

        # Decrypt header 2.
        header2 = Crypto.lioness_decrypt(msg.header2,
                           keys.getLionessKeys(Crypto.HEADER_ENCRYPT_MODE))

        # If we're the swap node, (1) decrypt the payload with a hash of
        # header2... (2) decrypt header2 with a hash of the payload...
        # (3) and swap the headers.
        if rt == Packet.SWAP_FWD_TYPE:
            hkey = Crypto.lioness_keys_from_header(header2)
            payload = Crypto.lioness_decrypt(payload, hkey)

            hkey = Crypto.lioness_keys_from_payload(payload)
            header2 = Crypto.lioness_decrypt(header2, hkey)

            header1, header2 = header2, header1

        # Build the address object for the next hop
        address = Packet.parseIPV4Info(subh.routinginfo)

        # Construct the message for the next hop.
        msg = Packet.Message(header1, header2, payload).pack()

        return RelayedPacket(address, msg)
        
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
    def __init__(self, routingType, routingInfo, applicationKey,
                 tag, payload):
        """Construct a new DeliveryPacket."""
        assert 0 <= routingType <= 0xFFFF
        assert len(applicationKey) == 16
        assert len(tag) == 20
        assert len(payload) == 28*1024
        self.exitType = routingType
        self.address = routingInfo
        self.key = applicationKey
        self.tag = tag
        self.payload = payload
        self.contents = None
        self.type = None

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

    def isPlaintext(self):
        """Return true iff this packet is a plaintext, forward packet."""
        if self.type is None: self.decode()
        return self.type == 'plain'

    def isOvercompressed(self):
        """Return true iff this packet is an overcompressed, plaintext, forward
           packet."""
        if self.type is None: self.decode()
        return self.type == 'long'

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
            self.contents = mixminion.BuildMessage.decodePayload(message,
                                                                 self.tag)
            if self.contents is None:
                # encrypted message
                self.type = 'enc'
                self.contents = message
            else:
                # forward message
                self.type = 'plain'
                # self.contents is right
        except Packet.CompressedDataTooLong, _:
            self.contents = (mixminion.Packet.parsePayload(message)
                                             .getContents())
            self.type = 'long'
        except MixError:
            self.contents = message
            self.type = 'err'

        self.payload = None

    def getAsciiContents(self):
        """Return the contents of this message, encoded in base64 if they are
           not already printable."""
        if self.type is None:
            self.decode()

        if self.type == 'plain' and isPrintingAscii(self.contents, allowISO=1):
            return self.contents
        else:
            return base64.encodestring(self.contents)

    def getAsciiTag(self):
        """Return a base64-representation of this message's decoding handle."""
        return base64.encodestring(self.tag).strip()

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
        else:
            assert self.isPlaintext()
            tp = 'BIN'
            
        return Packet.TextEncodedMessage(self.contents, tp, tag)
