# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Fragments.py,v 1.1 2003/08/14 19:37:24 nickm Exp $

"""mixminion.BuildMessage

   Code to fragment and reassemble messages."""

import mixminion._minionlib
import mixminion.Filestore
from mixminion.Crypto import getCommonPRNG, whiten, unwhiten
from mixminion.Common import LOG, previousMidnight, MixError, MixFatalError

MAX_FRAGMENTS_PER_CHUNK = 32
EXP_FACTOR = 1.33333333333

class _FragmentationParams:
    """DOCDOC"""
    ## Fields:
    # k, n, length, fec, chunkSize, fragmentCapacity, dataFragments,
    # totalFragments, paddingLen, paddedLen
    def __init__(self, length, overhead):
        assert overhead in (0, ENC_FWD_OVERHEAD)
        self.length = length
        self.fragCapacity = PAYLOAD_LEN - FRAGMENT_PAYLOAD_OVERHEAD - overhead
        # minimum number of payloads to hold msg, without fragmentation
        # or padding.
        minFragments = ceilDiv(length, self.fragCapacity)
        # Number of data fragments per chunk.
        self.k = 2
        while k < minFragments and k < 16:
            self.k *= 2
        # Number of chunks.
        self.nChunks = ceilDiv(minFragments, k)
        # Data in  a single chunk
        self.chunkSize = self.fragCapacity * self.k
        # Length of data to fill chunks
        self.paddedLen = self.nChunks * self.fragCapacity * self.k
        # Length of padding needed to fill all chunks with data.
        self.paddingLen = self.paddedLen - length
        # Number of total fragments per chunk.
        self.n = math.ceil(EXP_FACTOR * k)
        # FEC object
        self.fec = None

    def getFEC(self):
        if self.fec is None:
            self.fec = _getFEC(self.k, self.n)
        return self.fec

    def getPosition(self, index):
        """DOCDOC"""
        chunk, pos = divmod(index, self.n)
        return chunk, pos

    def getFragments(self, s, paddingPRNG=None):
        if paddingPRNG is None:
            paddingPRNG = getCommonPRNG()

        self.getFEC()
        assert s.length == self.length
        s = whiten(s)
        s += paddingPRNG.getBytes(self.paddingLen)
        assert len(s) == self.paddedLen
        
        chunks = []
        for i in xrange(self.nChunks):
            chunks.append( s[i*self.chunkSize:(i+1)*self.chunkSize] )
        del s

        fragments = []
        for i in xrange(self.nChunks):
            blocks = []
            for j in xrange(self.k):
                blocks.append( chunks[i][j*self.fragCapacity:
                                         (j+1)*self.fragCapacity] )
            chunks[i] = None
            for j in xrange(p.n):
                fragments.append( self.fec.encode(j, blocks) )
        return fragments

# ======================================================================
#DOCDOC this entire section

class MismatchedFragment(Exception):
    pass

class UnneededFragment(Exception):
    pass

class _FragmentMetadata:
    def __init__(self, messageid, hash, idx, size, isChunk, chunkNum, overhead,
                 insertedDate):
        self.messageid = messageid
        self.hash = hash
        self.idx = idx
        self.size = size
        self.isChunk = isChunk
        self.chunkNum = chunkNum
        self.overhead = overhead
        self.insertedDate = insertedDate

    def __getstate__(self):
        return ("V0", self.messageid, self.hash, self.idx, self.size,
                self.isChunk, self.chunkNum, self.insertedDate)

    def __setstate__(self, o):
        if state[0] == 'V0':
            (_, self.messageid, self.hash, self.idx, self.size,
             self.isChunk, self.chunkNum, self.insertedDate) = state
        else:
            raise MixFatalError("Unrecognized fragment state")

class MessageState:
    def __init__(self, messageid, hash, length, overhead):
        self.messageid = messageid
        self.hash = hash
        self.overhead = overhead
        # chunkno -> handle,fragmentmeta
        self.chunks = {} 
        # chunkno -> idxwithinchunk -> (handle,fragmentmeta)
        self.fragmentsByChunk = []
        self.params = _FragmentationParams(length, overhead)
        for i in xrange(self.params.nChunks):
            self.fragmentsByChunk.append({})
        # chunkset: ready chunk num -> 1
        self.readyChunks = {}
        
    def isDone(self):
        return len(self.chunks) == self.params.nChunks

    def getChunkHandles(self):
        return [ self.chunks[i][0] for i in xrange(self.params.nChunks) ]

    def addChunk(self, h, fm):
        # h is handle
        # fm is fragmentmetadata
        assert fm.isChunk
        assert fm.messageid == self.messageid
        if (fm.size != self.params.length or
            fm.hash != self.hash or
            fm.overhead != self.overhead or
            self.chunks.has_key(fm.chunkNum)):
            raise MismatchedFragment
        
        self.chunks[fm.chunkNum] = (h,fm)

    def addFragment(self, h, fm):
        # h is handle
        # fm is fragmentmetadata
        assert fm.messageid == self.messageid

        if (fm.hash != self.hash or
            fm.size != self.params.length or
            fm.overhead != self.overhead):
            raise MismatchedFragment
        
        chunkNum, pos = self.params.getPosition(idx)

        if self.chunks.has_key(chunkNum):
            raise UnneededFragment
        
        if self.fragmentsByChunk[chunkNum].has_key(pos):
            raise MismatchedFragment

        self.fragmentsByChunk[chunkNum][pos] = (h, fm)

        if len(self.fragmentsByChunk(chunkNum)) >= self.params.k:
            self.readyChunks[chunkNum] = 1

    def hasReadyChunks(self):
        return len(self.readyChunks) != 0

    def getReadyChunks(self):
        """DOCDOC"""
        # return list of [ (chunkno, [(h, fm)...]) )
        r = []
        for chunkno in self.readyChunks.keys():
            ch = self.fragmentsByChunk[chunkno].values()[:self.params.k]
            r.append( (chunkno, ch) )
        return r

class _FragmentDB(mixminion.Filestore.DBBase):
    def __init__(self, location):
        mixminion.Filestore.DBBase.__init__(self, location, "fragment")
    def markStatus(self, msgid, status, today):
        assert status in ("COMPLETED", "REJECTED")
        if now is None:
            now = time.time()
        self[msgid] = (status, today)
    def getStatusAndTime(self, msgid):
        return self.get(msgid, None)
    def _encodeKey(self, k):
        return binascii.b2a_hex(k)
    def _encodeVal(self, v):
        status, tm = v
        return "%s-%s"%(
            {"COMPLETED":"C", "REJECTED":"R"}[status], str(tm))
    def _decodeVal(self, v):
        status = {"C":"COMPLETED", "R":"REJECTED"}[v[0]]
        tm = int(tm[2:])
        return status, tm

class FragmentPool:
    """DOCDOC"""
    ##
    # messages : map from 
    def __init__(self, dir):
        self.store = mixminion.Filestore.StringMetadataStore(dir,create=1,
                                                             scrub=1)
        self.log = _FragmentDB(dir+"_db")
        self.rescan()

    def getState(self, fm):
        try:
            return self.states[fm.messageid]
        except KeyError:
            state = MessageState(messageid=fm.messageid,
                                 hash=fm.hash,
                                 length=fm.size,
                                 overhead=fm.overhead)
            self.states[fm.messageid] = state
            return state
        
    def rescan(self):
        self.store.loadAllMetadata()
        meta = self.store._metadata_cache
        self.states = states = {}
        badMessageIDs = {}
        unneededHandles = []
        for h, fm in meta.items():
            try:
                mid = fm.messageid
                if badMessageIDs.has_key(mid):
                    continue
                state = self.getState(fm)
                if fm.isChunk:
                    state.addChunk(h, fm)
                else:
                    state.addFragment(h, fm)
            except MismatchedFragment:
                badMessageIDs[mid] = 1
            except UnneededFragment:
                unneededHandles.append(h)

        for h in unneededHandles:
            fm = meta[h]
            LOG.debug("Removing unneeded fragment %s from message ID %r",
                      fm.idx, fm.messageid)
            self.removeMessage(h)

        self._abortMessageIDs(badMessageIDs, today)

    def _abortMessageIDs(self, messageIDSet, today=None):
        if today is None:
            today = previousMidnight(time.time())
        else:
            today = previousMidnight(today)
        LOG.debug("Removing bogus messages by IDs: %s", messageIDSet.keys())
        for mid in messageIDSet.keys():
            self.markStatus(mid, "REJECTED", today)
        for h, fm in self._metadata_cache.items():
            if messageIDSet.has_key(fm.messageid):
                self.removeMessage(h)

    def _getPacketMetadata(self, fragmentPacket):
        return  _FragmentMetadata(messageid=fragmentPacket.msgID,
                                  idx=fragmentPacket.index,
                                  hash=fragmentPacket.hash,
                                  size=fragmentPacket.msgLen,
                                  isChunk=0,
                                  chunkNum=None,
                                  overhead=fragmentPacket.getOverhead(),
                                  insertedDate=previousMidnight(now))
        
    def addFragment(self, fragmentPacket, now=None):
        if now is None:
            now = time.time()
        today = previousMidnight(now)

        meta = self._getFragmentMetadata(fragmentPacket)
        state = self.getState(meta)
        try:
            state.addFragment(fragmentPacket)
            h = self.store.queueMessageAndMetadata(fragmentPacket.data, meta)
        except MismatchedFragment:
            # remove other fragments, mark msgid as bad.            
            self._abortMessageIDs({ meta.id : 1}, now)
        except UnneededFragment:
            LOG.debug("Dropping unneeded fragment %s of message %r",
                      fragmentPacket.idx, fragmentPacket.msgID)

    def getReadyMessage(self, msgid):
        s = self.states.get(msgid)
        if not s or not s.isDone():
            return None

        hs = s.getChunkHandles()
        return "".join([self.state.getMessage(h) for h in hs])

    def deleteMessage(self, msgid):
        s = self.states.get(msgid)
        if not s or not s.isDone():
            return None

        hs = s.getChunkHandles()
        for h in hs:
            self.store.removeMessage(h)

    def getReadyMessages(self):
        return [ msgid
                 for msgid,state in self.states.items()
                 if state.isDone() ]

    def unchunkMessages(self):
        for msgid, state in self.states.items():
            if not state.hasReadyChunks():
                continue
            for chunkno, lst in state.getReadyChunks():
                vs = []
                minDate = min([fm.insertedDate for h,fm in lst])
                for h,fm in lst:
                    vs.append((state.getPos(fm.index)[1],
                               self.store.getMessage(h)))
                chunkText = self.store.params.getFEC().decode(vs)
                fm2 = _FragmentMetadata(state.mesageid, state.hash,
                                        state.idx, 1, chunkno, state.overhead,
                                        minDate)
                h2 = self.store.queueMessage(chunkText)
                self.store.setMetadata(h2, fm2)
                for h,fm in lst:
                    self.store.removeMessage(h)
            
# ======================================================================

_fectab = {}

def _getFEC(k,n):
    """DOCDOC: Note race condition """
    try:
        return _fectab[(k,n)]
    except KeyError:
        f = mixminion._minionlib.FEC_generate(k,n)
        _fectab[(k,n)] = f
        return f
    
