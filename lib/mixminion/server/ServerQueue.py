# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerQueue.py,v 1.27 2003/07/24 03:36:59 nickm Exp $

"""mixminion.server.ServerQueue

   Facility for fairly secure, directory-based, unordered queues.
   """

import os
import time
import stat
import sys
import cPickle
import threading

import mixminion.Filestore

from mixminion.Common import MixError, MixFatalError, secureDelete, LOG, \
     createPrivateDir, readPickled, writePickled, formatTime, readFile
from mixminion.Crypto import getCommonPRNG

__all__ = [ 'Queue', 'DeliveryQueue', 'TimedMixPool', 'CottrellMixPool',
            'BinomialCottrellMixPool' ]

# Mode to pass to open(2) for creating a new file, and dying if it already
# exists.
_NEW_MESSAGE_FLAGS = os.O_WRONLY+os.O_CREAT+os.O_EXCL
# On windows or mac, binary != text.
_NEW_MESSAGE_FLAGS += getattr(os, 'O_BINARY', 0)

# Any inp_* files older than INPUT_TIMEOUT seconds old are assumed to be
# trash.
INPUT_TIMEOUT = 6000

Queue = mixminion.Filestore.MixedStore

class _DeliveryState:
    """Helper class: holds the state needed to schedule delivery or
       eventual abandonment of a message in a DeliveryQueue."""
    ## Fields:
    # queuedTime: time at which the corresponding message was first
    #    inserted into the queue.
    # lastAttempt: The most recent time at which we attempted to
    #    deliver the message. (None means 'never').
    # address: Pickleable object holding address information.  Delivery
    #    code uses this field to group messages by address before loading
    #    them all from disk.
    def __init__(self, queuedTime=None, lastAttempt=None, address=None):
        """Create a new _DeliveryState for a message received at
           queuedTime (default now), whose last delivery attempt was
           at lastAttempt (default never)."""
        if queuedTime is None:
            queuedTime = time.time()
        self.queuedTime = queuedTime
        self.lastAttempt = lastAttempt
        self.address = address

    def __getstate__(self):
        # For pickling.  All future versions of deliverystate will pickle
        #   to a tuple, whose first element will be a version string.
        return ("V1", self.queuedTime, self.lastAttempt, self.address)

    def __setstate__(self, state):
        # For pickling.
        if state[0] == "V1":
            self.queuedTime = state[1]
            self.lastAttempt = state[2]
            self.address = state[3]
        elif state[0] == "V0":
            #XXXX006 remove this case.
            # 0.0.4 used a format that didn't have an 'address' field.
            self.queuedTime = state[1]
            self.lastAttempt = state[2]
            self.address = None
        else:
            raise MixFatalError("Unrecognized delivery state")

    def getNextAttempt(self, retrySchedule, now=None):
        """Return the next time when we should try to deliver this message
           according to the provided retrySchedule.  If the time returned
           is in the past, then immediate delivery is okay.  If the time
           returned is None, this message has expired and should be forgotten.
        """
        if not now:
            now = time.time()

        last = self.lastAttempt

        # If we've never tried to deliver the message, it's ready to
        # go immediately.
        if last is None:
            return now

        # Otherwise, we count from the time the message was first queued,
        # until we find a scheduled delivery that falls after the last
        # attempted delivery.
        #
        # This scheduled delivery may be in the past.  That's okay: it only
        # means that we've missed a scheduled delivery, and we can try again
        # immediately.
        attempt = self.queuedTime
        for interval in retrySchedule:
            attempt += interval
            if attempt > last:
                return attempt

        # Oops: there are no scheduled deliveries after the last delivery.
        # Time to drop this message.
        return None

    def setLastAttempt(self, when):
        """Update time of the last attempted delivery."""
        self.lastAttempt = when

class PendingMessage:
    """PendingMessage represents a message in a DeliveryQueue, for delivery
       to a specific address.  See DeliveryQueue._deliverMessages for more
       information about the interface."""
    ##
    # queue: the deliveryqueue holding this message
    # handle: the handle for this message in the queue
    # address: The address passed to queueDeliveryMessage for this message,
    #     or None
    # message: The object queued as this message, or None if the object
    #     has not yet been loaded.
    def __init__(self, handle, queue, address, message=None):
        self.handle = handle
        self.queue = queue
        self.address = address
        self.message = message

    def getAddress(self):
        return self.address

    def getHandle(self):
        return self.handle

    def succeeded(self):
        """Mark this message as having been successfully deleted, removing
           it from the queue."""
        self.queue.deliverySucceeded(self.handle)
        self.queue = self.message = None

    def failed(self, retriable=0, now=None):
        """Mark this message as has having failed delivery, either rescheduling
           it or removing it from the queue."""
        self.queue.deliveryFailed(self.handle, retriable, now=now)
        self.queue = self.message = None

    def getMessage(self):
        """Return the underlying object stored in the delivery queue, loading
           it from disk if necessary."""
        if self.message is None:
            self.message = self.queue.getObject(self.handle)
        return self.message

class DeliveryQueue(mixminion.Filestore.ObjectMetadataStore):
    """A DeliveryQueue implements a queue that greedily sends messages to
       outgoing streams that occasionally fail.  All underlying messages
       are pickled objects.  Additionally, we store metadata about
       attempted deliveries in the past, so we know when to schedule the
       next delivery.

       This class is abstract. Implementors of this class should subclass
       it to add a _deliverMessages method.  Multiple invocations of this
       method may be active at a given time.  Upon success or failure, this
       method should cause deliverySucceeded or deliveryFailed to be called
       as appropriate.

       Users of this class will probably only want to call the
       queueMessage, sendReadyMessages, and nextMessageReadyAt methods.

       This class caches information about the directory state; it won't
       play nice if multiple instances are looking at the same directory.
    """
    ###
    # Fields:
    #    sendable -- A list of handles for all messages that we're not
    #           currently sending.
    #    pending -- Dict from handle->time_sent, for all messages that we're
    #           currently sending.
    #    retrySchedule -- a list of intervals at which delivery of messages
    #           should be reattempted, as described in "setRetrySchedule".
    #    nextAttempt -- a dict from handle->time-of-next-scheduled-delivery,
    #           for all handles.  Not meaningful for handles in 'pending'.
    #           If the time is in the past, delivery can be tried now.
    #           If None, the message may be removable.
    #
    # XXXX Refactor as many of these fields as possible into _DeliveryState.
    #
    # Files:
    #    meta_* : a pickled _DeliveryState object for each message in the
    #        queue.
    #    rmv_meta_*: a dead metafile, waiting for removal.

    def __init__(self, location, retrySchedule=None, now=None):
        """Create a new DeliveryQueue object that stores its files in
           <location>.  If retrySchedule is provided, it is interpreted as
           in setRetrySchedule."""
        mixminion.Filestore.ObjectMetadataStore.__init__(
            self, location, create=1, scrub=1)
        self.retrySchedule = None
        self._rescan()
        if retrySchedule is not None:
            self.setRetrySchedule(retrySchedule, now)
        else:
            self.setRetrySchedule([0], now)
        self._repOk()

    def setRetrySchedule(self, schedule, now=None):
        """Set the retry schedule for this queue.  A retry schedule is
           a list of integers, each representing a number of seconds.
           For example, a schedule of [ 120, 120, 3600, 3600 ] will
           cause undeliverable messages to be retried after 2 minutes,
           then 2 minutes later, then 1 hour later, then 1 hour later.

           Retry schedules are not strictly guaranteed, for two reasons:
             1) Message delivery can fail _unretriably_, in which case
                no further attempts are made.
             2) Retries are only actually attempted when sendReadyMessages
                is called.  If the schedule specifies retry attempts at
                10-second intervals, but sendReadyMessages is invoked only
                every 30 minutes, messages will only me retried once every
                30 minutes.
        """
        try:
            self._lock.acquire()
            self.retrySchedule = schedule[:]
            self._rebuildNextAttempt(now)
        finally:
            self._lock.release()

    def _rescan(self, now=None):
        """Helper: Rebuild the internal state of this queue from the
           underlying directory.  Trashes 'pending' and 'sendable'."""
        try:
            self._lock.acquire()
            self.pending = {}
            self.nextAttempt = {}
            self.sendable = self.getAllMessages()
            self._loadState()
            self._rebuildNextAttempt(now)
            self._repOk()
        finally:
            self._lock.release()

    def _getDeliveryState(self,h):
        return self.getMetadata(h)

    def _loadState(self):
        """Read all DeliveryState objects from the disk."""
        self.loadAllMetadata(lambda h: _DeliveryState())

    def _rebuildNextAttempt(self, now=None):
        """Helper: Reconstruct self.nextAttempt from self.retrySchedule and
           self.deliveryState.

           Callers must hold self._lock.
        """
        if self.retrySchedule is None:
            rs = [0]
        else:
            rs = self.retrySchedule

        nextAttempt = {}
        for h,ds in self._metadata_cache.items():
            nextAttempt[h] = ds.getNextAttempt(rs, now)
        self.nextAttempt = nextAttempt
        self._repOk()

    def _repOk(self):
        """Raise an assertion error if the internal state of this object is
           nonsensical."""
        # XXXX Later in the release cycle, we should call this *even* less.
        # XXXX It adds ~8-9ms on my laptop for ~400 messages
        try:
            self._lock.acquire()

            allHandles = self.getAllMessages()
            knownHandles = self.pending.keys() + self.sendable
            allHandles.sort()
            knownHandles.sort()
            if allHandles != knownHandles:
                LOG.error("_repOK: %s != %s", allHandles, knownHandles)
                assert allHandles == knownHandles
            dsHandles = self._metadata_cache.keys()
            naHandles = self.nextAttempt.keys()
            dsHandles.sort()
            naHandles.sort()
            assert allHandles == dsHandles
            assert allHandles == naHandles
        finally:
            self._lock.release()

    def queueDeliveryMessage(self, msg, address=None, now=None):
        """Schedule a message for delivery.
             msg -- the message.  This can be any pickleable object.
        """
        assert self.retrySchedule is not None
        try:
            self._lock.acquire()
            handle = self.queueObject(msg)
            self.sendable.append(handle)
            
            ds = _DeliveryState(now,None,address)
            self.setMetadata(handle, ds)
            self.nextAttempt[handle] = \
                     ds.getNextAttempt(self.retrySchedule, now)
            LOG.trace("ServerQueue got message %s for %s",
                      handle, self.dir)
        finally:
            self._lock.release()

        return handle

    def _inspect(self,handle):
        """Returns a (msg, inserted, lastAttempt, nextAttempt) tuple
           for a given message handle.  For testing. """
        self._repOk()
        o = self.getObject(handle)
        ds = self._getDeliveryState(handle)
        return (o, ds.queuedTime, ds.lastAttempt, self.nextAttempt[handle])

    def removeExpiredMessages(self, now=None):
        """Remove every message expired in this queue according to the
           current schedule.  Ordinarily, messages are removed when
           their last delivery is over.  Occasionally, however,
           changing the schedule while the system is down can make calling
           this method useful."""
        try:
            self._lock.acquire()
            for h in self.sendable:
                if self.nextAttempt[h] is None:
                    self.removeMessage(h)
        finally:
            self._lock.release()

    def sendReadyMessages(self, now=None):
        """Sends all messages which are not already being sent, and which
           are scheduled to be sent."""
        assert self.retrySchedule is not None
        self._repOk()
        if now is None:
            now = time.time()
        LOG.trace("ServerQueue checking for deliverable messages in %s",
                  self.dir)
        try:
            self._lock.acquire()
            handles = self.sendable
            messages = []
            self.sendable = []
            for h in self.pending.keys():
                LOG.trace("     [%s] is pending delivery", h)
            for h in handles:
                assert not self.pending.has_key(h)
                next = self.nextAttempt[h]
                if next is None:
                    LOG.trace("     [%s] is expired", h)
                    self.removeMessage(h)
                elif next <= now:
                    LOG.trace("     [%s] is ready for delivery", h)
                    state = self._getDeliveryState(h)
                    if state is None:
                        addr = None
                    else:
                        addr = state.address
                    messages.append(PendingMessage(h,self,addr))
                    self.pending[h] = now
                else:
                    LOG.trace("     [%s] is not yet ready for redelivery", h)
                    self.sendable.append(h)
        finally:
            self._lock.release()

        if messages:
            self._deliverMessages(messages)
        self._repOk()

    def _deliverMessages(self, msgList):
        """Abstract method; Invoked with a list of PendingMessage objects
           every time we have a batch of messages to send.

           For every PendingMessage object on the list, the object's
           .succeeded() or .failed() method should eventually be called, or
           the message will sit in the queue indefinitely, without being
           retried."""

        # We could implement this as a single _deliverMessage(h,addr)
        # method, but that wouldn't allow implementations to batch
        # messages being sent to the same address.

        raise NotImplementedError("_deliverMessages")

    def removeMessage(self, handle):
        try:
            self._lock.acquire()
            mixminion.Filestore.BaseMetadataStore.removeMessage(self, handle)
            try:
                del self.pending[handle]
                pending = 1
            except KeyError:
                pending = 0

            try:
                del self.nextAttempt[handle]
            except KeyError:
                LOG.error("Removing message %s with no nextAttempt", handle)

            try:
                del self.sendable[self.sendable.index(handle)]
            except ValueError:
                if not pending:
                    LOG.error("Removing message %s in neither "
                              "'sendable' nor 'pending' list", handle)
        finally:
            self._lock.release()

    def removeAll(self, secureDeleteFn=None):
        try:
            self._lock.acquire()
            mixminion.Filestore.ObjectMetadataStore.removeAll(self,
                                                              secureDeleteFn)
            self.pending = {}
            self.nextAttempt = {}
            self.sendable = []
            self.cleanQueue()
        finally:
            self._lock.release()

    def deliverySucceeded(self, handle):
        """Removes a message from the outgoing queue.  This method
           should be invoked after the corresponding message has been
           successfully delivered.
        """
        assert self.retrySchedule is not None

        LOG.trace("ServerQueue got successful delivery for %s from %s",
                  handle, self.dir)
        self.removeMessage(handle)

    def deliveryFailed(self, handle, retriable=0, now=None):
        """Removes a message from the outgoing queue, or requeues it
           for delivery at a later time.  This method should be
           invoked after the corresponding message has been
           unsuccessfully delivered."""
        assert self.retrySchedule is not None
        LOG.trace("ServerQueue failed to deliver %s from %s",
                  handle, self.dir)
        try:
            self._lock.acquire()
            try:
                lastAttempt = self.pending[handle]
            except KeyError:
                # This should never happen
                LOG.error_exc(sys.exc_info(),
                              "Handle %s was not pending", handle)
                return

            if retriable:
                # If we can retry the message, update the deliveryState
                # with the most recent attempt, and see if there's another
                # attempt in the future.
                try:
                    ds = self._getDeliveryState(handle)
                except KeyError:
                    # This should never happen
                    LOG.error_exc(sys.exc_info(),
                                  "Handle %s had no state", handle)
                    ds = _DeliveryState(now)
                    self.setMetadata(handle, ds)

                ds.setLastAttempt(lastAttempt)
                nextAttempt = ds.getNextAttempt(self.retrySchedule, now)
                if nextAttempt is not None:
                    LOG.trace("     (We'll try %s again at %s)", handle,
                              formatTime(nextAttempt, 1))
                    # There is another scheduled delivery attempt.  Remember
                    # it, mark the message sendable again, and save our state.
                    self.nextAttempt[handle] = nextAttempt
                    self.sendable.append(handle)
                    try:
                        del self.pending[handle]
                    except KeyError:
                        LOG.error("Handle %s was not pending", handle)

                    self.setMetadata(handle, ds)
                    return

                # Otherwise, fallthrough.

            # If we reach this point, the message is undeliverable.
            LOG.trace("     (Giving up on %s)", handle)
            self.removeMessage(handle)
        finally:
            self._lock.release()

class TimedMixPool(Queue):
    """A TimedMixPool holds a group of files, and returns some of them
       as requested, according to a mixing algorithm that sends a batch
       of messages every N seconds."""
    ## Fields:
    #   interval: scanning interval, in seconds.
    def __init__(self, location, interval=600):
        """Create a TimedMixPool that sends its entire batch of messages
           every 'interval' seconds."""
        Queue.__init__(self, location, create=1, scrub=1)
        self.interval = interval

    def getBatch(self):
        """Return handles for all messages that the pool is currently ready
           to send in the next batch"""
        return self.pickRandom()

    def getInterval(self):
        return self.interval

class CottrellMixPool(TimedMixPool):
    """A CottrellMixPool holds a group of files, and returns some of them
       as requested, according the Cottrell (timed dynamic-pool) mixing
       algorithm from Mixmaster."""
    ## Fields:
    # interval: scanning interval, in seconds.
    # minPool: Minimum number of messages to keep in pool.
    # minSend: Minimum number of messages above minPool before we consider
    #      sending.
    # sendRate: Largest fraction of the pool to send at a time.
    def __init__(self, location, interval=600, minPool=6, minSend=1,
                 sendRate=.7):
        """Create a new queue that yields a batch of message every 'interval'
           seconds, always keeps <minPool> messages in the pool, never sends
           unless it has <minPool>+<minSend> messages, and never sends more
           than <sendRate> * the current pool size.

           If 'minSend'==1, this is a real Cottrell (type II style) mix pool.
           Otherwise, this is a generic 'timed dynamic-pool' mix pool.  (Note
           that there is still a matter of some controversy whether it ever
           makes sense to set minSend != 1.)
           """
        # Note that there was a bit of confusion here: earlier versions
        # implemented an algorithm called "mixmaster" that wasn't actually the
        # mixmaster algorithm.  I picked up the other algorithm from an early
        # draft of Roger, Paul, and Andrei's 'Batching Taxonomy' paper (since
        # corrected); they seem to have gotten it from Anja Jerichow's
        # Phd. thesis ("Generalization and Security Improvement of
        # Mix-mediated Anonymous Communication") of 2000.
        #
        # *THIS* is the algorithm that the current 'Batching Taxonomy' paper
        # says that Cottrell says is the real thing.

        TimedMixPool.__init__(self, location, interval)
        self.minPool = minPool
        self.minSend = minSend
        self.sendRate = sendRate

    def _getBatchSize(self):
        "Helper method: returns the number of messages to send."
        pool = self.count()
        if pool >= (self.minPool + self.minSend):
            sendable = pool - self.minPool
            return min(sendable, max(1, int(pool * self.sendRate)))
        else:
            return 0

    def getBatch(self):
        "Returns a list of handles for the next batch of messages to send."
        n = self._getBatchSize()
        if n:
            return self.pickRandom(n)
        else:
            return []

class _BinomialMixin:
    """Mixin class.  Given a MixPool that defines a _getBatchSize function,
       replaces the getBatch function with one that -- instead of sending N
       messages from a pool of size P, sends each message with probability
       N/P."""
    def getBatch(self):
        n = self._getBatchSize()
        count = self.count()
        if n == 0 or count == 0:
            return []
        msgProbability = n / float(count)
        rng = getCommonPRNG()
        return rng.shuffle([ h for h in self.getAllMessages()
                             if rng.getFloat() < msgProbability ])

class BinomialCottrellMixPool(_BinomialMixin,CottrellMixPool):
    """Same algorithm as CottrellMixPool, but instead of sending N messages
       from the pool of size P, sends each message with probability N/P."""
