# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: PacketHandler.py,v 1.8 2002/09/10 14:45:30 nickm Exp $

"""mixminion.PacketHandler: Code to process mixminion packets"""

import mixminion.Crypto as Crypto
import mixminion.Packet as Packet
import mixminion.Modules as Modules
import mixminion.Common as Common

__all__ = [ 'PacketHandler', 'ContentError' ]

class ContentError(Common.MixError):
    """Exception raised when a packed is malformatted or unacceptable."""
    pass

class PacketHandler:
    """Class to handle processing packets.  Given an incoming packet,
       it removes one layer of encryption, does all necessary integrity
       checks, swaps headers if necessary, re-pads, and decides whether
       to drop the message, relay the message, or send the message to
       an exit handler."""
    
    def __init__(self, privatekey, hashlog):
        """Constructs a new packet handler, given a private key object for
           header encryption, and a hashlog object to prevent replays.

           A sequence of private keys may be provided, if you'd like the
           server to accept messages encrypted with any of them.  Beware,
           though: PK decryption is expensive.  Also, a hashlog must be
           provided for each private key.
        """
        try:
            # Check whether we have a key or a tuple of keys.
            _ = privatekey[0]
            assert len(hashlog) == len(privatekey)
            
            self.privatekey = privatekey
            self.hashlog = hashlog
        except:
	    # XXXX Don't do except:; name an exception.
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

           Returns one of:
                    None [if the mesesage should be dropped.]
                    ("EXIT",
                       (routing_type, routing_info, application_key,
                        payload)) [if this is the exit node]
                    ("QUEUE", (ipv4info, message_out))
                        [if this is a forwarding node]

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
        if rt == Modules.DROP_TYPE:
            return None

        # Prepare the key to decrypt the header in counter mode.  We'll be
        # using this more than once.
        header_sec_key = Crypto.aes_key(keys.get(Crypto.HEADER_SECRET_MODE))

        # If the subheader says that we have extra blocks of routing info,
        # decrypt and parse them now.
        if subh.isExtended():
            nExtra = subh.getNExtraBlocks() 
            if (rt < Modules.MIN_EXIT_TYPE) or (nExtra > 15):
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
        if rt >= Modules.MIN_EXIT_TYPE:
            return ("EXIT",
                    (rt, subh.routinginfo,
                     keys.get(Crypto.APPLICATION_KEY_MODE),
                     payload))

        # If we're not an exit node, make sure that what we recognize our
        # routing type.
        if rt not in (Modules.SWAP_FWD_TYPE, Modules.FWD_TYPE):
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
        if rt == Modules.SWAP_FWD_TYPE:
	    hkey = Crypto.lioness_keys_from_header(header2)
	    payload = Crypto.lioness_decrypt(payload, hkey)

            hkey = Crypto.lioness_keys_from_payload(payload)
            header2 = Crypto.lioness_decrypt(header2, hkey)

            header1, header2 = header2, header1

        # Build the address object for the next hop
        address = Packet.parseIPV4Info(subh.routinginfo)

        # Construct the message for the next hop.
        msg = Packet.Message(header1, header2, payload).pack()

        return ("QUEUE", (address, msg))
