# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerQueue.py,v 1.33.2.1 2003/09/28 03:57:33 nickm Exp $

"""mixminion.server.ServerQueue

   Facilities for retriable delivery queues, and for mix pools.
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
from mixminion.Filestore import CorruptedFile

__all__ = [ 'DeliveryQueue', 'TimedMixPool', 'CottrellMixPool',
            'BinomialCottrellMixPool' ]

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
    # pendingAt: None (if we're not sending this message), or a time
    #    at which we begain sending this message.
    # nextAttempt: None, or the time at which we'll next try to send
    #    this message.  This field is invalid until someone calls
    #    setNextAttempt.  If the time is in the past, delivery can
    #    be tried now.  If None, the message may be removable.
    def __init__(self, queuedTime=None, lastAttempt=None, address=None):
        """Create a new _DeliveryState for a message received at
           queuedTime (default now), whose last delivery attempt was
           at lastAttempt (default never)."""
        if queuedTime is None:
            queuedTime = time.time()
        self.queuedTime = queuedTime
        self.lastAttempt = lastAttempt
        self.address = address
        self.pending = None
        self.nextAttempt = None
        self.remove = 0
        
    def isPending(self):
        """Return true iff we are currently trying to deliver this message."""
        return self.pending is not None

    def setPending(self, now=None):
        """Note that we are now trying to deliver this message, so that we
           don't try to deliver it twice at the same time."""
        if now is None:
            now = time.time()
        self.pending = now

    def setNonPending(self):
        """Note that we are no longer trying to deliver this message, so that
           we can try it again later."""
        self.pending = None

    def isRemovable(self):
        """Return true iff this message is old enough to be removed."""
        return self.remove
    
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

        self.pending = None
        self.nextAttempt = None
        self.remove = 0

    def setNextAttempt(self, retrySchedule, now=None):
        """Return the next time when we should try to deliver this message
           according to the provided retrySchedule.  If the time returned
           is in the past, then immediate delivery is okay.  If the time
           returned is None, this message has expired and should be forgotten.
        """
        if not now:
            now = time.time()

        self.remove = 0
        last = self.lastAttempt

        # If we've never tried to deliver the message, it's ready to
        # go immediately.
        if last is None:
            self.nextAttempt = now
            return

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
                self.nextAttempt = attempt
                return

        # Oops: there are no scheduled deliveries after the last delivery.
        # Time to drop this message.
        self.nextAttempt = None
        self.remove = 1

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
           it from disk if necessary. May raise CorruptedFile."""
        if self.message is None:
            self.message = self.queue.store.getObject(self.handle)
        return self.message

class DeliveryQueue:
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
    #   store -- An ObjectMetadataStore to back this queue.  The objects
    #      are instances of whatever deliverable object this queue contains;
    #      the metadata are instances of _DeliveryState.
    #   retrySchedule -- a list of intervals at which delivery of messages
    #      should be reattempted, as described in "setRetrySchedule".
    #   _lock -- a reference to the RLock used to control access to the
    #      store.
    def __init__(self, location, retrySchedule=None, now=None, name=None):
        """Create a new DeliveryQueue object that stores its files in
           <location>.  If retrySchedule is provided, it is interpreted as
           in setRetrySchedule.  Name, if present, is a human-readable
           name used in log messages."""
        self.store = mixminion.Filestore.ObjectMetadataStore(
            location,create=1,scrub=1)
        self._lock = self.store._lock
        if name is None:
            self.qname = os.path.split(location)[1]
        else:
            self.qname = name

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
           underlying directory.  After calling 'rescan',
           _rebuildNextAttempt must be called to recalculate our
           delivery schedule."""
        try:
            self._lock.acquire()
            self.store.loadAllMetadata(lambda h: _DeliveryState())
            self._rebuildNextAttempt(now)
            self._repOk()
        finally:
            self._lock.release()

    def getAllMessages(self):
        """Return handles for all messages in the store."""
        return self.store.getAllMessages()

    def count(self):
        """Return the number of messages in the store."""
        return self.store.count()

    def _rebuildNextAttempt(self, now=None):
        """Helper: Reconstruct self.nextAttempt from self.retrySchedule and
           self.deliveryState.

           Callers must hold self._lock.
        """
        if self.retrySchedule is None:
            rs = [0]
        else:
            rs = self.retrySchedule

        for ds in self.store._metadata_cache.values():
            ds.setNextAttempt(rs, now)
        self._repOk()

    def _repOk(self):
        """Raise an assertion error if the internal state of this object is
           nonsensical."""
        # XXXX Later in the release cycle, we should call this *even* less.
        # XXXX It adds ~8-9ms on my laptop for ~400 messages
        try:
            self._lock.acquire()

            allHandles = self.store.getAllMessages()
            allHandles.sort()
            dsHandles = self.store._metadata_cache.keys()
            dsHandles.sort()
            assert allHandles == dsHandles
        finally:
            self._lock.release()

    def queueDeliveryMessage(self, msg, address=None, now=None):
        """Schedule a message for delivery.
             msg -- the message.  This can be any pickleable object.
        """
        assert self.retrySchedule is not None
        try:
            self._lock.acquire()
            ds = _DeliveryState(now,None,address)
            ds.setNextAttempt(self.retrySchedule, now)
            handle = self.store.queueObjectAndMetadata(msg, ds)
            LOG.trace("DeliveryQueue got message %s for %s",
                      handle, self.qname)
        finally:
            self._lock.release()

        return handle

    def _inspect(self,handle):
        """Returns a (msg, inserted, lastAttempt, nextAttempt) tuple
           for a given message handle.  For testing. """
        self._repOk()
        o = self.store.getObject(handle)
        ds = self.store.getMetadata(handle)
        return (o, ds.queuedTime, ds.lastAttempt, ds.nextAttempt)

    def removeExpiredMessages(self, now=None):
        """Remove every message expired in this queue according to the
           current schedule.  Ordinarily, messages are removed when
           their last delivery is over.  Occasionally, however,
           changing the schedule while the system is down can make calling
           this method useful."""
        try:
            self._lock.acquire()
            #XXXX
            for h, ds in self.store._metadata_cache.items():
                if ds.isRemovable():
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
        LOG.trace("DeliveryQueue checking for deliverable messages in %s",
                  self.qname)
        try:
            self._lock.acquire()
            messages = []
            for h in self.store._metadata_cache.keys():
                try:
                    state = self.store.getMetadata(h)
                except CorruptedFile:
                    continue
                if state.isPending():
                    LOG.trace("     [%s] is pending delivery", h)
                    continue
                elif state and state.isRemovable():
                    LOG.trace("     [%s] is expired", h)
                    self.removeMessage(h)
                elif (not state) or state.nextAttempt <= now:
                    LOG.trace("     [%s] is ready for delivery", h)
                    if state is None:
                        addr = None
                    else:
                        addr = state.address
                    messages.append(PendingMessage(h,self,addr))
                    state.setPending(now)
                else:
                    LOG.trace("     [%s] is not yet ready for redelivery", h)
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
        self.store.removeMessage(handle)

    def cleanQueue(self, secureDeleteFn=None):
        self.store.cleanQueue(secureDeleteFn)

    def removeAll(self, secureDeleteFn=None):
        try:
            self._lock.acquire()
            self.store.removeAll(secureDeleteFn)
            self.cleanQueue()
        finally:
            self._lock.release()

    def deliverySucceeded(self, handle):
        """Removes a message from the outgoing queue.  This method
           should be invoked after the corresponding message has been
           successfully delivered.
        """
        assert self.retrySchedule is not None

        LOG.trace("DeliveryQueue got successful delivery for %s from %s",
                  handle, self.qname)
        self.removeMessage(handle)

    def deliveryFailed(self, handle, retriable=0, now=None):
        """Removes a message from the outgoing queue, or requeues it
           for delivery at a later time.  This method should be
           invoked after the corresponding message has been
           unsuccessfully delivered."""
        assert self.retrySchedule is not None
        LOG.trace("DeliveryQueue failed to deliver %s from %s",
                  handle, self.qname)
        try:
            self._lock.acquire()
            try:
                ds = self.store.getMetadata(handle)
            except KeyError:
                ds = None
            except CorruptedFile:
                return

            if ds is None:
                # This should never happen
                LOG.error_exc(sys.exc_info(),
                              "Handle %s had no state", handle)
                ds = _DeliveryState(now)
                ds.setNextAttempt(self.retrySchedule, now)
                self.store.setMetadata(handle, ds)
                return

            if not ds.isPending():
                LOG.error("Handle %s was not pending", handle)
                return

            last = ds.pending
            ds.setNonPending()

            if retriable:
                # If we can retry the message, update the deliveryState
                # with the most recent attempt, and see if there's another
                # attempt in the future.
                ds.setLastAttempt(last)
                ds.setNextAttempt(self.retrySchedule, now)
                if ds.nextAttempt is not None:
                    # There is another scheduled delivery attempt.  Remember
                    # it, mark the message sendable again, and save our state.
                    LOG.trace("     (We'll try %s again at %s)", handle,
                              formatTime(ds.nextAttempt, 1))

                    self.store.setMetadata(handle, ds)
                    return
                else:
                    assert ds.isRemovable()
                # Otherwise, fallthrough.

            # If we reach this point, the message is undeliverable, either
            # because 'retriable' is false, or because we've run out of
            # retries.
            LOG.trace("     (Giving up on %s)", handle)
            self.removeMessage(handle)
        finally:
            self._lock.release()

class TimedMixPool(mixminion.Filestore.ObjectStore):
    """A TimedMixPool holds a group of files, and returns some of them
       as requested, according to a mixing algorithm that sends a batch
       of messages every N seconds."""
    ## Fields:
    #   interval: scanning interval, in seconds.
    def __init__(self, location, interval=600):
        """Create a TimedMixPool that sends its entire batch of messages
           every 'interval' seconds."""
        mixminion.Filestore.ObjectStore.__init__(
            self, location, create=1, scrub=1)
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
