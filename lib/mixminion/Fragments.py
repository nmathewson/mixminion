# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Fragments.py,v 1.15 2004/03/23 00:05:32 nickm Exp $

"""mixminion.BuildMessage

   Code to fragment and reassemble messages."""

import binascii
import math
import time
import mixminion._minionlib
import mixminion.Filestore
from mixminion.Crypto import ceilDiv, getCommonPRNG, sha1, whiten, unwhiten
from mixminion.Common import disp64, LOG, previousMidnight, MixError, \
     MixFatalError
from mixminion.Packet import ENC_FWD_OVERHEAD, PAYLOAD_LEN, \
     FRAGMENT_PAYLOAD_OVERHEAD

__all__ = [ "FragmentPool", "FragmentationParams" ]

# Largest number of allowed fragments in a single chunk.  Must be a power
# of two.
MAX_FRAGMENTS_PER_CHUNK = 16
# Minimum proportion of extra packets to add to each chunk.
EXP_FACTOR = 1.3333333333333333

class FragmentationParams:
    """Class to track the padding, chunking, and fragmentation required
       for a message of a given length to be packed into fragments of a
       given capacity."""
    ## Fields:
    # length -- size (in octets) of the original message.
    # k -- number of input packets for each chunk (also number of packets
    #    from a chunk required to reconstruct it.)
    # n -- number of output packets for each chunk.
    # fragmentCapacity -- number of bytes we can fit in a single fragment.
    #    (28KB - overhead)
    # chunkSize -- number of input bytes in a single chunk.  Equal to
    #    k*fragmentCapacity.
    # nChunks -- number of total chunks in message.
    # paddingLen -- bytes added to message before fragmentation
    # paddedLen -- length of message after padding; equal to chunkSize*nChunks
    # fec -- mixminion._minionlib.FEC object to encode/decode chunks;
    #    lazy-initialized by getFEC()
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
        while self.k < minFragments and self.k < MAX_FRAGMENTS_PER_CHUNK:
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
        """Return a FEC object to fragment or defragment messages with
           these parameters"""
        if self.fec is None:
            self.fec = _getFEC(self.k, self.n)
        return self.fec

    def getPosition(self, index):
        """Return a chunk,index-within-chunk tuple for a packet with index
           'index'"""
        chunk, pos = divmod(index, self.n)
        return chunk, pos

    def getFragments(self, s, paddingPRNG=None):
        """Given a string of length self.length, whiten it, pad it,
           and fragmment it.  Return a list of the fragments, in order.
           (Note -- after building the fragment packets, be sure to shuffle
           them into a random order.)"""
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
class FragmentPool:
    """Class to hold and manage fragmented messages as they are
       reconstructed."""
    ## Fields:
    # states -- map from messageid to MessageState.  Reconstructed by
    #    rescan().
    # db -- instance of FragmentDB.
    # store -- instance of StringMetadataStore.  The messages are either
    #    the contents of invidual fragments or reconstructed chunks.
    #    The metadata are instances of FragmentMetadata.
    def __init__(self, dir):
        """Open a FragmentPool storing fragments in 'dir' and records of
           old messages in 'dir_db'.
           """
        self.store = mixminion.Filestore.StringMetadataStore(
            dir,create=1)
        self.db = FragmentDB(dir+"_db")
        self.rescan()

    def cleanQueue(self, deleteFn=None):
        """Expunge all removed fragments from disk. See Filestore.cleanQueue"""
        self.store.cleanQueue(deleteFn)

    def sync(self):
        """Flush pending changes to disk."""
        self.db.sync()

    def close(self):
        """Release open resources for this pool."""
        self.db.close()
        del self.db
        del self.store
        del self.states

    def addFragment(self, fragmentPacket, nym=None, now=None, verbose=0):
        """Given an instance of mixminion.Packet.FragmentPayload, record
           the fragment if appropriate and update the state of the
           fragment pool if necessary.  Returns the message ID that was
           updated, or None if the fragment was redundant or misformed.

              fragmentPacket -- the new fragment to add.
              nym -- a string representing the identity that received this
                  fragment.  [Tracking nyms is important, to prevent an
                  attack where we send 2 fragments to 'MarkTwain' and 2
                  fragments to 'SClemens', and see that the message is
                  reconstructed.]
              verbose -- if true, log information at the INFO level;
                  otherwise, log at DEBUG.
        """
        if verbose:
            say = LOG.info
        else:
            say = LOG.debug
        if now is None:
            now = time.time()
        today = previousMidnight(now)

        # If the message has already been rejected or completed, we can
        # drop this packet.
        s = self.db.getStatusAndTime(fragmentPacket.msgID)
        if s:
            say("Dropping fragment of %s message %r",
                s[0].lower(), disp64(fragmentPacket.msgID,12))
            return None

        # Otherwise, create a new metadata object for this fragment...
        meta = FragmentMetadata(messageid=fragmentPacket.msgID,
                                 idx=fragmentPacket.index,
                                 size=fragmentPacket.msgLen,
                                 isChunk=0,
                                 chunkNum=None,
                                 overhead=fragmentPacket.getOverhead(),
                                 insertedDate=today,
                                 nym=nym,
                                 digest=sha1(fragmentPacket.data))
        # ... and allocate or find the MessageState for this message.
        state = self._getState(meta)
        try:
            # Check whether we can/should add this message, but do not
            # add it.
            state.addFragment(None, meta, noop=1)
            # No exception was thrown; queue the message.
            h = self.store.queueMessageAndMetadata(fragmentPacket.data, meta)
            # And *now* update the message state.
            state.addFragment(h, meta)
            say("Stored fragment %s of message %s",
                fragmentPacket.index+1, disp64(fragmentPacket.msgID,12))
            return fragmentPacket.msgID
        except MismatchedFragment, s:
            # Remove the other fragments, mark msgid as bad.
            LOG.warn("Found inconsistent fragment %s in message %s: %s",
                     fragmentPacket.index+1, disp64(fragmentPacket.msgID,12),
                     s)
            self._deleteMessageIDs({ meta.messageid : 1}, "REJECTED", now)
            return None
        except UnneededFragment:
            # Discard this fragment; we don't need it.
            say("Dropping unneeded fragment %s of message %s",
                fragmentPacket.index+1, disp64(fragmentPacket.msgID,12))
            return None

    def getReadyMessage(self, msgid):
        """Return the complete message associated with messageid 'msgid'.
           (If no such complete message is found, return None.)  The
           resulting message is unwhitened, but not uncompressed."""
        s = self.states.get(msgid)
        if not s or not s.isDone():
            return None

        hs = s.getChunkHandles()
        msg = "".join([self.store.messageContents(h) for h in hs])
        msg = unwhiten(msg[:s.params.length])
        return msg

    def markMessageCompleted(self, msgid, rejected=0):
        """Release all resources associated with the messageid 'msgid', and
           reject future packets for that messageid.  If 'rejected', the
           message has been abandoned and not sent; otherwise, the message
           has been sent.
        """
        s = self.states.get(msgid)
        if not s or not s.isDone():
            return None
        if rejected:
            self._deleteMessageIDs({msgid: 1}, "REJECTED")
        else:
            self._deleteMessageIDs({msgid: 1}, "COMPLETED")

    def listReadyMessages(self):
        """Return a list of all messageIDs that have been completely
           reconstructed."""
        return [ msgid
                 for msgid,state in self.states.items()
                 if state.isDone() ]

    def unchunkMessages(self):
        """If any messages are ready for partial or full reconstruction,
           reconstruct as many of their chunks as possible."""
        for msgid, state in self.states.items():
            if not state.hasReadyChunks():
                continue
            state.reconstruct(self.store)

    def expireMessages(self, cutoff):
        """Remove all pending messages that were first inserted before
           'cutoff'. """
        expiredMessageIDs = {}
        for s in self.states.values():
            if s.inserted < cutoff:
                expiredMessageIDs[s.messageid] = 1
        self._deleteMessageIDs(expiredMessageIDs, "REJECTED")

    def rescan(self):
        """Check all fragment metadata objects on disk, and reconstruct our
           internal view of message states.
        """
        # Delete all internal state; reload FragmentMetadatas from disk.
        self.store.loadAllMetadata(lambda: None)
        meta = self.store._metadata_cache
        self.states = {}
        badMessageIDs = {} # map from bad messageID to 1
        unneededHandles = [] # list of handles that aren't needed.
        for h, fm in meta.items():
            if not fm:
                LOG.debug("Removing fragment %s with missing metadata", h)
                self.store.removeMessage(h)
                continue
            try:
                mid = fm.messageid
                if badMessageIDs.has_key(mid):
                    # We've already decided to reject fragments with this ID.
                    pass
                else:
                    # All is well; try to register the fragment/chunk.  If it's
                    # redundant or inconsistent, raise an exception.
                    state = self._getState(fm)
                    if fm.isChunk:
                        state.addChunk(h, fm)
                    else:
                        state.addFragment(h, fm)
            except MismatchedFragment:
                # Mark the message ID for this fragment as inconsistent.
                badMessageIDs[mid] = 1
            except UnneededFragment:
                LOG.warn("Found redundant fragment %s in pool", h)
                # Remember that this message is unneeded.
                unneededHandles.append(h)

        # Check for fragments superseded by chunks -- those are unneeded too.
        for s in self.states.values():
            unneededHandles.extend(s.getUnneededFragmentHandles())

        # Delete unneeded fragments.
        for h in unneededHandles:
            try:
                fm = meta[h]
            except KeyError:
                continue
            LOG.debug("Removing unneeded fragment %s from message ID %r",
                      fm.idx, fm.messageid)
            self.store.removeMessage(h)

        # Now nuke inconsistent messages.
        self._deleteMessageIDs(badMessageIDs, "REJECTED")

    def _deleteMessageIDs(self, messageIDSet, why, today=None):
        """Helper function. Remove all the fragments and chunks associated
           with a given message, and mark the message as delivered or
           undeliverable.

              messageIDSet -- a map from 20-byte messageID to 1.
              why -- 'REJECTED' or 'COMPLETED' or '?'
        """
        assert why in ("REJECTED", "COMPLETED", "?")
        if not messageIDSet:
            return
        if today is None:
            today = time.time()
        today = previousMidnight(today)
        if why == 'REJECTED':
            LOG.debug("Removing bogus messages by IDs: %s",
                      messageIDSet.keys())
        elif why == "COMPLETED":
            LOG.debug("Removing completed messages by IDs: %s",
                      messageIDSet.keys())
        else:
            LOG.debug("Removing messages by IDs: %s",
                      messageIDSet.keys())

        for mid in messageIDSet.keys():
            if why == "?":
                state = self.states[mid]
                if state.isDone:
                    whythis = "COMPLETED"
                else:
                    whythis = "REJECTED"
            else:
                whythis = why
            self.db.markStatus(mid, whythis, today)
            try:
                del self.states[mid]
            except KeyError:
                pass
        for h, fm in self.store._metadata_cache.items():
            if messageIDSet.has_key(fm.messageid):
                self.store.removeMessage(h)

    def _getState(self, fm):
        """Helper function.  Return the MessageState object associated with
           a given FragmentMetadata; allocate it if necessary."""
        try:
            return self.states[fm.messageid]
        except KeyError:
            state = MessageState(messageid=fm.messageid,
                                 length=fm.size,
                                 overhead=fm.overhead,
                                 inserted=fm.insertedDate,
                                 nym=fm.nym)
            self.states[fm.messageid] = state
            return state

    def getStateByMsgID(self, msgid):
        """Given a message ID (either a 20-byte full ID or a 12-byte
           pretty-printed ID prefix), return a MessageState object for
           the corresponding message, or None if the message is not
           recognized."""
        if len(msgid) == 20:
            return self.state.get(msgid,None)
        elif len(msgid) == 12:
            target = binascii.a2b_base64(msgid)
            for i in self.states.keys():
                if i.startswith(target):
                    return self.states[i]
        return None

    def listMessages(self):
        """Return a map from pretty-printed message ID to dicts mapping:
               'size' to the size of the message, in bytes
               'nym' to the pseudonym receiving the message
               'have' to the number of packets we have so far
               'need' to the number of additional packets we need.
        """
        result = {}
        for msgid in self.states.keys():
            state = self.states[msgid]
            have, need = state.getCompleteness()
            result[disp64(msgid,12)] = {
                'size' : state.params.length,
                'nym' : state.nym,
                'have' : have,
                'need' : need
                }
        return result

# ======================================================================

class MismatchedFragment(Exception):
    """Exception raised when a fragment isn't compatible with the other
       fragments with a given message ID.  Because fragments are
       integrity-checked on their way in, inconsistent fragments mean the
       message is corrupt."""
    pass

class UnneededFragment(Exception):
    """Exception raised when a fragment is unneeded, and doesn't need to be
       stored to disk."""
    pass

class FragmentMetadata:
    """Persistent metadata object to hold the state of a given fragment or
       reconstructed chunk."""
    ## Fields
    # messageid -- unique 20-byte identifier for the message this fragment
    #    comes from.
    # idx -- index of the fragment within the message.  In the case of a
    #    chunk, it's equal to chunkNum.
    # size -- total length of the message.
    # isChunk -- true iff this is a reconstructed chunk.
    # chunkNum -- number of the chunk to which this fragment belongs.
    # overhead -- Payload overhead for this fragment.  Equal to 0 or
    #    ENC_FWD_OVERHEAD.
    # insertedDate -- Midnight GMT before the day this fragment was received.
    # nym -- name of the identity that received this fragment.
    # digest -- digest of the fragment/chunk; None for pre-0.0.7
    def __init__(self, messageid, idx, size, isChunk, chunkNum, overhead,
                 insertedDate, nym, digest):
        self.messageid = messageid
        self.idx = idx
        self.size = size
        self.isChunk = isChunk
        self.chunkNum = chunkNum
        self.overhead = overhead
        self.insertedDate = insertedDate
        self.nym = nym
        self.digest = digest

    def __getstate__(self):
        return ("V1", self.messageid, self.idx, self.size,
                self.isChunk, self.chunkNum, self.overhead, self.insertedDate,
                self.nym, self.digest)

    def __setstate__(self, state):
        if state[0] == 'V0':
            (_, self.messageid, self.idx, self.size,
             self.isChunk, self.chunkNum, self.overhead, self.insertedDate,
             self.nym) = state
            self.digest = None
        elif state[0] == 'V1':
            (_, self.messageid, self.idx, self.size,
             self.isChunk, self.chunkNum, self.overhead, self.insertedDate,
             self.nym,self.digest) = state
        else:
            raise MixFatalError("Unrecognized fragment state")

class MessageState:
    """Helper class.  Tracks the status of the reconstruction of a
       single message.  MessageState objects are not persistent, and must
       be reconstructed from FragmentMetadata objects whenever a
       fragment pool is rescanned.
    """
    ## Fields:
    # messageid -- the 20-byte message ID of this message.
    # overhead -- the overhead for messages sent via this message
    # inserted -- the midnight (GMT) of the day on the first packet
    #     associated with this message was inserted.
    # nym -- the name of the identity receiving this message.  Used to
    #     prevent linkage attacks.
    #
    # params -- an instance of FragmentationParams for this message.
    # chunks -- a map from chunk number to tuples of (handle within the pool,
    #     FragmentMetadata object).  For completed chunks.
    # fragmentsByChunk -- a list mapping chunk number to maps from
    #     index-within-chunk to (handle,FragmentMetadata)
    # readyChunks -- a map whose keys are the numbers of chunks that
    #     are ready for reconstruction, but haven't been reconstructed
    #     yet.
    def __init__(self, messageid, length, overhead, inserted, nym):
        """Create a new MessageState.
        """
        self.messageid = messageid
        self.overhead = overhead
        self.inserted = inserted
        self.nym = nym
        # chunkno -> handle,fragmentmeta
        self.chunks = {}
        # chunkno -> idxwithinchunk -> (handle,fragmentmeta)
        self.fragmentsByChunk = []
        self.params = FragmentationParams(length, overhead)
        for _ in xrange(self.params.nChunks):
            self.fragmentsByChunk.append({})
        # chunkset: ready chunk num -> 1
        self.readyChunks = {}

    def isDone(self):
        """Return true iff we have reconstructed all the chunks for this
           message."""
        return len(self.chunks) == self.params.nChunks

    def getChunkHandles(self):
        """Requires self.isDone().  Return an in-order list for the handles
           of the reconstructed chunks of this message."""
        assert self.isDone()
        return [ self.chunks[i][0] for i in xrange(self.params.nChunks) ]

    def getCompleteness(self):
        """Return a tuple of (have,need), where 'need' is the final number
           of packets needed to reconstruct the message, and 'have' is the
           number we have so far."""
        need = self.params.k * self.params.nChunks
        have = self.params.k * len(self.chunks)
        for d in self.fragmentsByChunk:
            have += min(len(d),self.params.k)
        return have, need

    def addChunk(self, h, fm):
        """Register a chunk with handle h and FragmentMetadata fm.  If the
           chunk is inconsistent with other fragments of this message,
           raise MismatchedFragment."""
        assert fm.isChunk
        assert fm.messageid == self.messageid
        if fm.size != self.params.length:
            raise MismatchedFragment("Mismatched message length")
        if fm.overhead != self.overhead:
            raise MismatchedFragment("Mismatched packet overhead")
        if self.chunks.has_key(fm.chunkNum):
            raise MismatchedFragment("Duplicate chunks")
        if fm.nym != self.nym:
            raise MismatchedFragment("Fragments received for differing identities")

        if self.inserted > fm.insertedDate:
            self.inserted = fm.insertedDate
        self.chunks[fm.chunkNum] = (h,fm)

        if self.fragmentsByChunk[fm.chunkNum]:
            LOG.warn("Found a chunk with unneeded fragments for message %r",
                     self.messageid)

        if self.readyChunks.get(fm.chunkNum):
            del self.readyChunks[fm.chunkNum]

    def addFragment(self, h, fm, noop=0):
        """Register a fragment with handle h and FragmentMetadata fm.  If the
           fragment is inconsistent with the other fragments of this message,
           raise MismatchedFragment.  If the fragment isn't neeeded (because
           enough fragments for its chunks have already been received),
           raise UnneededFragment).  If 'noop' is true, do not add this
           fragment--just raise exceptions as needed."""
        assert fm.messageid == self.messageid

        if fm.size != self.params.length:
            raise MismatchedFragment("mismatched message size")
        if fm.overhead != self.overhead:
            raise MismatchedFragment("mismatched fragment payload size")
        if fm.nym != self.nym:
            raise MismatchedFragment("mismatched identities")

        chunkNum, pos = self.params.getPosition(fm.idx)
        if chunkNum >= self.params.nChunks:
            raise MismatchedFragment

        if (self.chunks.has_key(chunkNum) or
            len(self.fragmentsByChunk[chunkNum]) >= self.params.k):
            raise UnneededFragment

        if self.fragmentsByChunk[chunkNum].has_key(pos):
            previous = self.fragmentsByChunk[chunkNum][pos][1]
            if previous.digest is None or previous.digest == fm.digest:
                raise UnneededFragment("already seen this fragment")
            else:
                raise MismatchedFragment("multiple fragments for one position")

        if noop:
            return
        assert h
        if self.inserted > fm.insertedDate:
            self.inserted = fm.insertedDate
        self.fragmentsByChunk[chunkNum][pos] = (h, fm)

        if len(self.fragmentsByChunk[chunkNum]) >= self.params.k:
            self.readyChunks[chunkNum] = 1

    def hasReadyChunks(self):
        """Return true iff some of the chunks in this message are pending
           reconstruction."""
        return len(self.readyChunks) != 0

    def reconstruct(self, store):
        """If any of the chunks in this message are pending reconstruction,
           reconstruct them in a given store."""
        if not self.readyChunks:
            return
        for chunkno in self.readyChunks.keys():
            # Get the first K fragments in the chunk. (list of h,fm)
            ch = self.fragmentsByChunk[chunkno].values()[:self.params.k]
            minDate = min([fm.insertedDate for h, fm in ch])
            # Build a list of (position-within-chunk, fragment-contents).
            frags = [(self.params.getPosition(fm.idx)[1],
                      store.messageContents(h)) for h,fm in ch]
            chunkText = "".join(self.params.getFEC().decode(frags))
            del frags
            fm2 = FragmentMetadata(messageid=self.messageid,
                                   idx=chunkno, size=self.params.length,
                                   isChunk=1, chunkNum=chunkno,
                                   overhead=self.overhead,
                                   insertedDate=minDate, nym=self.nym,
                                   digest=sha1(chunkText))
            # Queue the chunk.
            h2 = store.queueMessageAndMetadata(chunkText, fm2)
            del chunkText
            # Remove superceded fragments.
            for h, fm in ch:
                store.removeMessage(h)
            # Update this MessageState object.
            self.fragmentsByChunk[chunkno] = {}
            del self.readyChunks[chunkno]
            self.addChunk(h2, fm2)

    def getUnneededFragmentHandles(self):
        """Returns any handles for fragments that have been superceded by
           chunks."""
        r = []
        for chunkno in self.chunks.keys():
            r.extend([ h for h,_ in self.fragmentsByChunk[chunkno].values()])
        return r

class FragmentDB(mixminion.Filestore.DBBase):
    """Internal class. Uses a database background (such as dbm, berkely db,
       gdbm, etc.) to remember which message IDs have already been
       reconstructed or noted as corrupt
    """
    def __init__(self, location):
        """Open a new FragmentDB; stores its data in files beginning with
           'location'."""
        mixminion.Filestore.DBBase.__init__(self, location, "fragment")
        self.sync()
    def markStatus(self, msgid, status, today=None):
        """Note fragments for a message with message ID 'msgid' should no
           longer be stored.  'status' is one of 'COMPLETED' or 'REJECTED',
           depending on whether the message was delivered or undeliverable."""
        assert status in ("COMPLETED", "REJECTED")
        if today is None:
            today = time.time()
        today = previousMidnight(today)
        self[msgid] = (status, today)
    def getStatusAndTime(self, msgid):
        """Given a messageID, return a 2-tuple of status,resolutiondate.
           Return None if the message is still deliverable."""
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
# Internal lazy-generated cache from (k,n) to _minionlib.FEC object.
# Note that we only use k,n for a limited set of k,n.
def _blankFECtable():
    """Return a map from permissible k,n tuples to FEC objects"""
    f = {}
    k = 2
    while k <= MAX_FRAGMENTS_PER_CHUNK:
        f[(k, int(math.ceil(EXP_FACTOR*k)))] = None
        k *= 2
    return f

# global map.
_fectab = _blankFECtable()

def _getFEC(k,n):
    """Given k and n parameters, return a FEC object to fragment and
       reconstruct messages given those parameters."""
    # There's a possible race condition here where two threads note
    # that a given set of parameters haven't been generated, and both
    # generate them.  This is harmless.
    f = _fectab[(k,n)]
    if f is None:
        f = _fectab[(k,n)] = mixminion._minionlib.FEC_generate(k,n)
    return f

