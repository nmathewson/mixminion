# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerProcess.py,v 1.2 2002/05/29 17:46:23 nickm Exp $

import mixminion.Crypto as Crypto
import mixminion.Formats as Formats
import mixminion.Modules as Modules
import mixminion.Common as Common

class ContentError(Common.MixError):
    pass

class ServerProcess:
    def __init__(self, privatekey, hashlog, exitHandler, forwardHandler):
        self.privatekey = privatekey
        self.hashlog = hashlog
        self.exitHandler = exitHandler
        self.forwardHandler = forwardHandler

    # Raises ParseError, ContentError.
    def processMessage(self, msg):
        r = self._processMessage(msg)
        if r != None:
            m, a = r
            apply(m, a)

    # Raises ParseError, ContentError, SSLError.
    #  Returns oneof (None), (method, argl)
    def _processMessage(self, msg):
        msg = Formats.parseMessage(msg)
        header1 = Formats.parseHeader(msg.header1)
        subh = header1[0]
        subh = Crypto.pk_decrypt(subh, self.privatekey)
        subh = Formats.parseSubheader(subh)

        if subh.major != 3 or subh.minor != 0:
            raise ContentError("Invalid protocol version")

        digest = Crypto.sha1(header1[1:])
        if digest != subh.digest:
            raise ContentError("Invalid digest")

        # XXXX Need to decrypt extra routing info.
        if subh.isExtended():
            nExtra = subh.getNExtraBlocks() 
            if nExtra > 15:
                raise ContentError("Impossibly long routing info length")
            extra = header1[1:1+nExtra]
            subh.appendExtraBlocks(extra)
            remainingHeader = header1[1+nExtra:]
        else:
            remainingHeader = header1[1:]

        # Replay prevention
        keys = Crypto.Keyset(subh.master)
        replayhash = keys.get(Crypto.REPLAY_PREVENTION_MODE, 20)
        if self.hashlog.seenHash(replayhash):
            raise ContentError("Duplicate message detected.")
        else:
            self.hashlog.logHash(replayhash)
            
        if type == Modules.DROP_TYPE:
            return None

        payload = Crypto.lioness_decrypt(msg.payload,
                                         keys.get(Crypto.PAYLOAD_ENCRYPT_MODE))

        # XXXX This doesn't match what George said.
        if type > Modules.MIN_EXIT_TYPE:
            return (self.exitHandler.processMessage,
                    (subh.routingtype, subh.routinginfo,
                     keys.get(Crypto.APPLICATION_KEY_MODE),
                     payload))

        if type not in (SWAP_FWD_TYPE, FWD_TYPE):
            raise ContentError("Unrecognized mixminion type")

        remainingHeader = remainingHeader +\
                          Crypto.prng(keys.get(Crypto.PRNG_MODE),
                                     FORMATS.HEADER_LEN-len(remainingHeader))
        header1 = Crypto.ctr_crypt(remainingHeader,
                                   keys.get(Crypto.HEADER_SECRET_MODE))
        
        header2 = Crypto.lioness_decrypt(msg.header2,
                                         keys.get(Crypto.HEADER_ENCRYPT_MODE))

        if type == Modules.SWAP_FWD_TYPE:
            hkey = Crypto.get_lioness_keys_from_payload(payload)
            header2 = Crypto.lioness_decrypt(msg.header2, hkey)
            header1, header2 = header2, header1

        address = Formats.parseIPV4Info(subh.routinginfo)

        msg = Formats.Message(header1, header2, payload).pack()

        return (self.forwardHandler.queue, (address.ip,
                                            address.port,
                                            address.keyid,
                                            msg))
