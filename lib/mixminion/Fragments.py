# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Fragments.py,v 1.3 2003/08/18 00:41:10 nickm Exp $

"""mixminion.BuildMessage

   Code to fragment and reassemble messages."""

import binascii
import math
import time
import mixminion._minionlib
import mixminion.Filestore
from mixminion.Crypto import ceilDiv, getCommonPRNG, whiten, unwhiten
from mixminion.Common import LOG, previousMidnight, MixError, MixFatalError
from mixminion.Packet import ENC_FWD_OVERHEAD, PAYLOAD_LEN, \
     FRAGMENT_PAYLOAD_OVERHEAD

__all__ = [ "FragmentPool", "FragmentationParams" ]

MAX_FRAGMENTS_PER_CHUNK = 32
EXP_FACTOR = 1.33333333333

class FragmentationParams:
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
        assert minFragments >= 2
        # Number of data fragments per chunk.
        self.k = 2
        while self.k < minFragments and self.k < 16:
            self.k *= 2
        # Number of chunks.
        self.nChunks = ceilDiv(minFragments, self.k)
        # Number of total fragments per chunk.
        self.n = int(math.ceil(EXP_FACTOR * self.k))
        # Data in  a single chunk
        self.chunkSize = self.fragCapacity * self.k
        # Length of data to fill chunks
        self.paddedLen = self.nChunks * self.fragCapacity * self.k
        # Length of padding needed to fill all chunks with data.
        self.paddingLen = self.paddedLen - length
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
        assert len(s) == self.length
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
            for j in xrange(self.n):
                fragments.append( self.fec.encode(j, blocks) )
        return fragments

# ======================================================================
#DOCDOC this entire section

class FragmentPool:
    """DOCDOC"""
    ##
    # messages : map from 
    def __init__(self, dir):
        self.store = mixminion.Filestore.StringMetadataStore(dir,create=1,
                                                             scrub=1)
        self.db = _FragmentDB(dir+"_db")
        self.rescan()

    def sync(self):
        self.db.sync()

    def close(self):
        self.db.close()

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
        self.store.loadAllMetadata(lambda: None)
        meta = self.store._metadata_cache
        self.states = states = {}
        badMessageIDs = {}
        unneededHandles = []
        for h, fm in meta.items():
            if not fm:
                LOG.debug("Removing fragment %s with missing metadata", h)
                self.store.removeMessage(h)
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
            self.store.removeMessage(h)

        self._deleteMessageIDs(badMessageIDs, "REJECTED")

    def _deleteMessageIDs(self, messageIDSet, why, today=None):
        assert why in ("REJECTED", "COMPLETED")
        if today is None:
            today = previousMidnight(time.time())
        else:
            today = previousMidnight(today)
        if why == 'REJECTED':
            LOG.debug("Removing bogus messages by IDs: %s",
                      messageIDSet.keys())
        else:
            LOG.debug("Removing completed messages by IDs: %s",
                      messageIDSet.keys())
        for mid in messageIDSet.keys():
            self.db.markStatus(mid, why, today)
            try:
                del self.states[mid]
            except KeyError:
                pass
        for h, fm in self.store._metadata_cache.items():
            if messageIDSet.has_key(fm.messageid):
                self.store.removeMessage(h)


    def _getFragmentMetadata(self, fragmentPacket):
        now=time.time()
        return  _FragmentMetadata(messageid=fragmentPacket.msgID,
                                  idx=fragmentPacket.index,
                                  hash=fragmentPacket.hash,
                                  size=fragmentPacket.msgLen,
                                  isChunk=0,
                                  chunkNum=None,
                                  overhead=fragmentPacket.getOverhead(),
                                  insertedDate=previousMidnight(now))
        
    def addFragment(self, fragmentPacket, now=None):
        #print "---"
        if now is None:
            now = time.time()
        today = previousMidnight(now)

        s = self.db.getStatusAndTime(fragmentPacket.msgID)
        if s:
            #print "A"
            LOG.debug("Dropping fragment of %s message %r",
                      s[0].lower(), fragmentPacket.msgID)
            return
            
        meta = self._getFragmentMetadata(fragmentPacket)
        state = self.getState(meta)
        try:
            # print "B"
            state.addFragment(None, meta, noop=1)
            h = self.store.queueMessageAndMetadata(fragmentPacket.data, meta)
            state.addFragment(h, meta)
            #print "C"
        except MismatchedFragment:
            # remove other fragments, mark msgid as bad.
            #print "D"
            self._deleteMessageIDs({ meta.messageid : 1}, "REJECTED", now)
        except UnneededFragment:
            #print "E"
            LOG.debug("Dropping unneeded fragment %s of message %r",
                      fragmentPacket.index, fragmentPacket.msgID)

    def getReadyMessage(self, msgid):
        s = self.states.get(msgid)
        if not s or not s.isDone():
            return None

        hs = s.getChunkHandles()
        msg = "".join([self.store.messageContents(h) for h in hs])
        msg = unwhiten(msg[:s.params.length])
        return msg                      

    def markMessageCompleted(self, msgid, rejected=0):
        s = self.states.get(msgid)
        if not s or not s.isDone():
            return None
        if rejected:
            self._deleteMessageIDs({msgid: 1}, "REJECTED")
        else:
            self._deleteMessageIDs({msgid: 1}, "COMPLETED")

    def listReadyMessages(self):
        return [ msgid
                 for msgid,state in self.states.items()
                 if state.isDone() ]

    def unchunkMessages(self):
        for msgid, state in self.states.items():
            if not state.hasReadyChunks():
                continue
            # refactor as much of this as possible into state. XXXX 
            for chunkno, lst in state.getReadyChunks():
                vs = []
                minDate = min([fm.insertedDate for h,fm in lst])
                for h,fm in lst:
                    vs.append((state.params.getPosition(fm.idx)[1],
                               self.store.messageContents(h)))
                chunkText = "".join(state.params.getFEC().decode(vs))
                del vs
                fm2 = _FragmentMetadata(state.messageid, state.hash,
                                        1, state.params.length, 1,
                                        chunkno,
                                        state.overhead,
                                        minDate)
                h2 = self.store.queueMessageAndMetadata(chunkText, fm2)
                #XXXX005 handle if crash comes here!
                for h,fm in lst:
                    self.store.removeMessage(h)
                state.fragmentsByChunk[chunkno] = {}
                state.addChunk(h2, fm2)

# ======================================================================

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
        self.params = FragmentationParams(length, overhead)
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
            #print "MIS-C-1"
            raise MismatchedFragment
        
        self.chunks[fm.chunkNum] = (h,fm)

        if self.fragmentsByChunk[fm.chunkNum]:
            LOG.warn("Found a chunk with unneeded fragments for message %r",
                     self.messageid)
            #XXXX005 the old fragments need to be removed.
            
    def addFragment(self, h, fm, noop=0):
        # h is handle
        # fm is fragmentmetadata
        assert fm.messageid == self.messageid

        if (fm.size != self.params.length or
            fm.overhead != self.overhead):
            #print "MIS-1"
            #print (fm.hash, fm.size, fm.overhead)
            #print (self.hash, self.params.length, self.overhead)
            raise MismatchedFragment
        
        chunkNum, pos = self.params.getPosition(fm.idx)
        if chunkNum >= self.params.nChunks:
            raise MismatchedFragment

        if (self.chunks.has_key(chunkNum) or
            len(self.fragmentsByChunk[chunkNum]) >= self.params.k):
            #print "UNN-2"
            raise UnneededFragment
        
        if self.fragmentsByChunk[chunkNum].has_key(pos):
            #print "MIS-3"
            raise MismatchedFragment

        if noop:
            return
        assert h
        self.fragmentsByChunk[chunkNum][pos] = (h, fm)

        if len(self.fragmentsByChunk[chunkNum]) >= self.params.k:
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
        self.sync()
    def markStatus(self, msgid, status, today):
        assert status in ("COMPLETED", "REJECTED")
        if today is None:
            today = time.time()
        today = previousMidnight(today)
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
        tm = int(v[2:])
        return status, tm

            
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
    
    
