# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerProcess.py,v 1.4 2002/05/31 12:47:58 nickm Exp $

import mixminion.Crypto as Crypto
import mixminion.Formats as Formats
from mixminion.Formats import MAJOR_NO, MINOR_NO
import mixminion.Modules as Modules
import mixminion.Common as Common

__all__ = [ 'ServerProcess', 'ContentError' ]

class ContentError(Common.MixError):
    """XXXX"""
    pass

class ServerProcess:
    def __init__(self, privatekey, hashlog, exitHandler, forwardHandler):
        """XXXX"""
        self.privatekey = privatekey
        self.hashlog = hashlog
        self.exitHandler = exitHandler
        self.forwardHandler = forwardHandler

    # Raises ParseError, ContentError.
    def processMessage(self, msg):
        """XXXX"""
        r = self._processMessage(msg)
        if r != None:
            m, a = r
            assert m in ("EXIT", "QUEUE")
            if m == "EXIT":
                self.exitHandler.handle(*a)
            else:
                self.forwardHandler.handle(*a)

    # Raises ParseError, ContentError, SSLError.
    #  Returns oneof (None), (EXIT, argl), ("QUEUE", (ipv4info, msg))
    def _processMessage(self, msg):
        """XXXX"""
        # XXXX Comment better
        msg = Formats.parseMessage(msg)
        header1 = Formats.parseHeader(msg.header1)
        subh = header1[0]
        subh = Crypto.pk_decrypt(subh, self.privatekey)
        subh = Formats.parseSubheader(subh)

        if subh.major != MAJOR_NO or subh.minor != MINOR_NO:
            raise ContentError("Invalid protocol version")

        digest = Crypto.sha1(header1[1:])
        if digest != subh.digest:
            raise ContentError("Invalid digest")

        keys = Crypto.Keyset(subh.secret)
        # Replay prevention
        replayhash = keys.get(Crypto.REPLAY_PREVENTION_MODE, 20)
        if self.hashlog.seenHash(replayhash):
            raise ContentError("Duplicate message detected.")
        else:
            self.hashlog.logHash(replayhash)

        rt = subh.routingtype
        if rt == Modules.DROP_TYPE:
            return None

        header_sec_key = Crypto.aes_key(keys.get(Crypto.HEADER_SECRET_MODE))

        if subh.isExtended():
            nExtra = subh.getNExtraBlocks() 
            if (rt < Modules.MIN_EXIT_TYPE) or (nExtra > 15):
                raise ContentError("Impossibly long routing info length")
                
            extra = Crypto.ctr_crypt(header1[1:1+nExtra], header_sec_key)
            subh.appendExtraBlocks(extra)
            remainingHeader = header1[1+nExtra:]
        else:
            nExtra = 0
            remainingHeader = header1[1:]

        payload = Crypto.lioness_decrypt(msg.payload,
                              keys.getLionessKeys(Crypto.PAYLOAD_ENCRYPT_MODE))

        # XXXX This doesn't match what George said: it bails out too early.
        # XXXX Also, it doesn't return the headers.
        if rt >= Modules.MIN_EXIT_TYPE:
            return ("EXIT",
                    (rt, subh.routinginfo,
                     keys.get(Crypto.APPLICATION_KEY_MODE),
                     payload))

        if rt not in (Modules.SWAP_FWD_TYPE, Modules.FWD_TYPE):
            raise ContentError("Unrecognized mixminion type")

        remainingHeader = remainingHeader +\
                          Crypto.prng(keys.get(Crypto.PRNG_MODE),
                                      Formats.HEADER_LEN-len(remainingHeader))

        header1 = Crypto.ctr_crypt(remainingHeader, header_sec_key, nExtra*128)

        header2 = Crypto.lioness_decrypt(msg.header2,
                           keys.getLionessKeys(Crypto.HEADER_ENCRYPT_MODE))

        if rt == Modules.SWAP_FWD_TYPE:
            hkey = Crypto.lioness_keys_from_payload(payload)
            header2 = Crypto.lioness_decrypt(header2, hkey)
            header1, header2 = header2, header1

        address = Formats.parseIPV4Info(subh.routinginfo)

        msg = Formats.Message(header1, header2, payload).pack()

        return ("QUEUE", (address, msg))
