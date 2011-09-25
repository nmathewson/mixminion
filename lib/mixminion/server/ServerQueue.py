# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.

"""mixminion.server.ServerQueue

   Facilities for retriable delivery queues, and for mix pools.
   """

import cPickle
import math
import os
import operator
import time
import stat
import sys
import threading

import mixminion.Filestore

from mixminion.Common import MixError, MixFatalError, secureDelete, LOG, \
     createPrivateDir, readPickled, writePickled, formatTime, readFile, \
     ceilDiv
from mixminion.Crypto import getCommonPRNG
from mixminion.Filestore import CorruptedFile

__all__ = [ 'DeliveryQueue', 'TimedMixPool', 'CottrellMixPool',
            'BinomialCottrellMixPool', 'PerAddressDeliveryQueue' ]

def _calculateNext(lastAttempt, firstAttempt, retrySchedule, canDrop, now):
    """DOCDOC"""
    # If we've never tried to deliver the message, it's ready to
    # go immediately.
    if lastAttempt is None:
        return now

    # Otherwise, we count from the time the message was first queued,
    # until we find a scheduled delivery that falls after the last
    # attempted delivery.
    #
    # This scheduled delivery may be in the past.  That's okay: it only
    # means that we've missed a scheduled delivery, and we can try again
    # immediately.
    attempt = firstAttempt
    for interval in retrySchedule:
        attempt += interval
        if attempt > lastAttempt:
            return attempt

    # Oops: there are no scheduled deliveries after the last delivery.
    # Time to drop this message, or go into holding mode.
    if canDrop:
        return None
    else:
        if not retrySchedule or retrySchedule[-1]<5:
            #DOCDOC
            retrySchedule = [3600]
        attempt += (ceilDiv(lastAttempt-attempt+60,retrySchedule[-1]) *
                    retrySchedule[-1])
        return attempt

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
    #    them all from disk.  Must be usable as hash key.
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
        else:
            #XXXX008 This is way too extreme.
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

        self.nextAttempt = _calculateNext(self.lastAttempt, self.queuedTime,
                                          retrySchedule, canDrop=1, now=now)
        if self.nextAttempt is None:
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

    def succeeded(self,now=None):
        """Mark this message as having been successfully deleted, removing
           it from the queue."""
        self.queue.deliverySucceeded(self.handle,now=now)
        self.queue = self.message = None

    def failed(self, retriable=0, now=None):
        """Mark this message as has having failed delivery, either rescheduling
           it or removing it from the queue."""
        self.queue.deliveryFailed(self.handle, retriable, now=now)
        self.queue = self.message = None

    def getMessage(self):
        """Return the underlying object stored in the delivery queue, loading
           it from disk if necessary. May raise CorruptedFile."""
        assert self.handle is not None
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
       queueDeliveryMessage, sendReadyMessages, and nextMessageReadyAt
       methods.

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
        self._repOK()

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
            self._repOK()
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
           self.deliveryState. DOCDOC

           Callers must hold self._lock.
        """
        if self.retrySchedule is None:
            rs = [0]
        else:
            rs = self.retrySchedule

        for ds in self.store._metadata_cache.values():
            ds.setNextAttempt(rs, now)
        self._repOK()

    def _repOK(self):
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
        self._repOK()
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
        self._repOK()
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
                    #LOG.trace("     [%s] is pending delivery", h)
                    continue
                elif state.isRemovable():
                    #LOG.trace("     [%s] is expired", h)
                    self.removeMessage(h)
                elif state.nextAttempt <= now:
                    #LOG.trace("     [%s] is ready for delivery", h)
                    if state is None:
                        addr = None
                    else:
                        addr = state.address
                    messages.append(PendingMessage(h,self,addr))
                    state.setPending(now)
                else:
                    #LOG.trace("     [%s] is not yet ready for redelivery", h)
                    continue
        finally:
            self._lock.release()

        self._deliverMessages(messages)
        self._repOK()

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

    def deliverySucceeded(self, handle, now=None):
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

class _AddressState:
    """DOCDOsC"""
    def __init__(self, address):
        self.address = address
        self.lastSuccess = self.lastFailure = self.firstFailure = None

    def __getstate__(self):
        return ("ADDR-V1", self.address, self.lastSuccess,
                self.lastFailure, self.firstFailure)

    def __setstate__(self, state):
        if state[0] == 'ADDR-V1':
            _, self.address, self.lastSuccess, self.lastFailure, \
               self.firstFailure = state
        else:
            #XXXX008 This is way too extreme.
            raise MixFatalError("Unrecognized delivery state")

        self.nextAttempt = None

    def setNextAttempt(self, retrySchedule, now=None):
        if not now:
            now = time.time()

        self.nextAttempt = _calculateNext(self.lastFailure,
                                          self.firstFailure,
                                          retrySchedule, canDrop=0, now=now)

    def getLastActivity(self):
        events = [ e for e in [self.lastSuccess, self.lastFailure]
                   if e is not None ]
        if events:
            return max(events)
        else:
            return None

    def succeeded(self, now=None):
        if not now:
            now = time.time()
        self.lastSuccess = now
        self.lastFailure = None
        self.firstFailure = None

    def failed(self, attempt, now=None):
        if not now:
            now = time.time()
        if not self.firstFailure:
            self.firstFailure = attempt
        self.lastFailure = attempt

class PerAddressDeliveryQueue(DeliveryQueue):

    """Implementats the same interface as DeliveryQueue, but retries
       messages on a per-address basis rather than a per-message
       basis.  That is, if any message to the address X fails, we wait
       for the first retry interval before retrying _any_ messages fo
       address X; and when address X succeeds again, we retry _all_
       messages to X.
    """
    # This turns out to have important anonymity implications: Suppose
    # that we retry messages independently, and that our retry policy
    # is 'every 1 hour for 1 day, every 12 hours for 1 week'.  Suppose
    # that the server B is down.  The following sequence of events
    # could occur:
    #
    #  1. At Hour 0, we receive message M1, and soon try to
    #     deliver it to B; it fails, we hold it in the queue.  We
    #     retry M1 every hour for 24 hours.
    #
    #  2. At Hour 30, B comes back up again.
    #
    #  3. At Hour 32, we receive message M2, and soon try to
    #     deliver it.  The delivery succeeds.
    #
    #  4. At Hour 36, we reattempt message M1 and succeed.
    #
    # An observer who is watching us can tell that the message which
    # we delivered to B in step 3 could not have been the same message
    # as we attempted to deliver in step 1.  Furthermore, such an
    # oberver can deduce that the message we attempted to deliver in
    # step 1 was successfully delivered in step 4.  This information
    # could be helpful to traffic analysis.
    #
    # With the algorithm implemented in this class, the address B
    # would be retried at Hour 36, and both messages M1 and M2 would
    # be delivered at the same time.  The adversary knows that at
    # least one of M1 and M2 has been waiting around since hour 0, but
    # does not know which of them (if either!) arrived later.
    #
    # We use this algorithm for packet delivery.  With email, on the
    # other hand, we just pass messages to our MTA and let it cope
    # correctly: most (all?) MTAs use a retry algorithm equivalent to
    # this one.

    # DOCDOC 
    def __init__(self, location, retrySchedule=None, now=None, name=None):
        self.addressStateDB = mixminion.Filestore.WritethroughDict(
            filename=os.path.join(location,"addressStatus.db"),
            purpose="address state")
        if retrySchedule is None:
            retrySchedule = [3600]
        DeliveryQueue.__init__(self, location=location,
                               retrySchedule=retrySchedule, now=now, name=name)

    def sync(self):
        self._lock.acquire()
        try:
            self.addressStateDB.sync()
        finally:
            self._lock.release()

    def _rescan(self):
        try:
            self._lock.acquire()
            DeliveryQueue._rescan(self)
        finally:
            self._lock.release()

    def _rebuildNextAttempt(self, now=None):
        self._lock.acquire()
        try:
            for ds in self.store._metadata_cache.values():
                if not self.addressStateDB.has_key(str(ds.address)):
                    as = _AddressState(ds.address)
                    self.addressStateDB[str(ds.address)] = as
            if not self.retrySchedule:
                rs = [3600]
                self.totalLifetime = 3600
            else:
                rs = self.retrySchedule
                self.totalLifetime = reduce(operator.add,self.retrySchedule,0)
            for as in self.addressStateDB.values():
                as.setNextAttempt(rs, now)
            self._repOK()
        finally:
            self._lock.release()

    def removeExpiredMessages(self, now=None):
        """DOCDOC"""
        assert self.retrySchedule is not None
        self._lock.acquire()
        try:
            have = {}
            for h, ds in self.store._metadata_cache.items():
                if ds.queuedTime + self.totalLifetime < now:
                    self.removeMessage(h)
                else:
                    have[ds.address]=1

            for k, as in self.addressStateDB.items():
                if have.has_key(as.address):
                    continue
                lastActivity = as.getLastActivity()
                if lastActivity and (
                    lastActivity + self.totalLifetime < now):
                    del self.addressStateDB[k]
        finally:
            self._lock.release()

    def _getAddressState(self, address, now=None):
        try:
            as = self.addressStateDB[str(address)]
        except KeyError:
            as = self.addressStateDB[str(address)] = _AddressState(address)
            as.setNextAttempt(self.retrySchedule, now)
        return as

    def queueDeliveryMessage(self, msg, address, now=None):
        self._getAddressState(address, now=now)
        return DeliveryQueue.queueDeliveryMessage(self,msg,address,now)

    def sendReadyMessages(self, now=None):
        if now is None:
            now = time.time()
        self._lock.acquire()
        try:
            messages = []
            for h in self.store._metadata_cache.keys():
                try:
                    state = self.store.getMetadata(h)
                except CorruptedFile:
                    continue
                if state.isPending():
                    #LOG.trace("     [%s] is pending delivery", h)
                    continue
                elif state.queuedTime + self.totalLifetime < now:
                    #LOG.trace("     [%s] is expired", h)
                    self.removeMessage(h)
                    continue
                addressState = self._getAddressState(state.address, now)
                if addressState.nextAttempt <= now:
                    #LOG.trace("     [%s] is ready for next attempt on %s", h,
                    #          state.address)
                    messages.append(PendingMessage(h,self,state.address))
                    state.setPending(now)
                else:
                    #LOG.trace("     [%s] will wait for next attempt on %s",h,
                    #          state.address)
                    continue
        finally:
            self._lock.release()

            self._deliverMessages(messages)

    def cleanQueue(self, secureDeleteFn=None):
        self.sync()
        self.store.cleanQueue(secureDeleteFn)

    def close(self):
        self.addressStateDB.close()

    def deliverySucceeded(self, handle, now=None):
        assert self.retrySchedule is not None
        self._lock.acquire()
        try:
            LOG.trace("PerAddressDeliveryQueue got successful delivery for %s from %s",
                      handle, self.qname)
            try:
                mState = self.store.getMetadata(handle)
            except CorruptedFile:
                mState = None
            if mState:
                aState = self._getAddressState(mState.address, now)
                aState.succeeded(now=now)
                aState.setNextAttempt(self.retrySchedule, now)
                self.addressStateDB[str(mState.address)] = aState

            self.removeMessage(handle)
        finally:
            self._lock.release()

    def deliveryFailed(self, handle, retriable=0, now=None):
        assert self.retrySchedule is not None
        if now is None:
            now = time.time()
        self._lock.acquire()
        try:
            try:
                mState = self.store.getMetadata(handle)
            except KeyError:
                mState = None
            except CorruptedFile:
                mState = None

            if mState is None:
                # This should never happen
                LOG.error_exc(sys.exc_info(),
                              "Handle %s had no state; removing", handle)
                self.removeMessage(handle)
                return
            elif not mState.isPending():
                LOG.error("Handle %s was not pending", handle)
                return

            last = mState.pending
            mState.setNonPending()
            if not retriable:
                LOG.trace("     (Giving up on %s)", handle)
                self.removeMessage(handle)

            aState = self._getAddressState(mState.address, now)
            aState.failed(attempt=last,now=now)
            aState.setNextAttempt(self.retrySchedule,now=now)
            self.addressStateDB[str(aState.address)] = aState # flush to db.
        finally:
            self._lock.release()

    def _inspect(self,handle):
        """Returns a (msg, state, addressState) tuple for a given
           message handle.  For testing."""
        self._repOK()
        o = self.store.getObject(handle)
        ds = self.store.getMetadata(handle)
        as = self._getAddressState(ds.address)
        return (o, ds, as)

    def _repOK(self):
        """Raise an assertion error if the internal state of this object is
           nonsensical."""
        # XXXX Later in the release cycle, we should call this *even* less.
        # XXXX It adds ~8-9ms on my laptop for ~400 messages
        self._lock.acquire()
        try:
            DeliveryQueue._repOK(self)
            for h in self.store._metadata_cache.keys():
                ds = self.store._metadata_cache[h]
                as = self._getAddressState(ds.address)
                assert as.address == ds.address
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


class _BinomialMixin:
    """Mixin class.  Given a MixPool that defines a _getBatchSize function,
       replaces the getBatch function with one that -- instead of sending N
       messages from a pool of size P, sends each message with probability
       N/P.  (Alternatively, the MixPool can define a _getFraction function,
       in which case we'll send messages with probabilty _getFraction().)"""
    def _getFraction(self):
        n = self._getBatchSize()
        count = self.count()
        if n == 0 or count == 0:
            return 0.0
        return  n / float(count)

    def getBatch(self):
        msgProbability = self._getFraction()
        rng = getCommonPRNG()
        return rng.shuffle([ h for h in self.getAllMessages()
                             if rng.getFloat() < msgProbability ])


class BinomialCottrellMixPool(_BinomialMixin,CottrellMixPool):
    """Same algorithm as CottrellMixPool, but instead of sending N messages
       from the pool of size P, sends each message with probability N/P."""

if 0:
    class BinomialPlusMixPool(_BinomialMixin,CottrellMixPool):
        """As presented in Serjantov, PET 2007, 'A Fresh Look at the
        Generalized Mix Framework.'  (Testing only.)"""
        constant_K = 0.01
        def _getFraction(self):
            """ g(M) = 1 - \frac{(M-n)e^{-kM}+n}{M} """
            M = self.count()
            n = self.minPool

            return 1 - ( (M - n)*math.exp(-self.constant_K * M) + n )/float(M)

    class LogGeneralMixPool(_BinomialMixin, TimedMixPool):
        """As presented in Serjantov, PET 2007, 'A Fresh Look at the
           Generalized Mix Framework.'  (Testing only.  Not necessarily
           optimal.)"""
        def _getFraction(self):
            M = self.count()
            return 1 - math.log(M)/float(M)

    class SqrtGeneralMixPool(_BinomialMixin, TimedMixPool):
        """As presented in Serjantov, PET 2007, 'A Fresh Look at the
           Generalized Mix Framework.'  (Testing only.  Not necessarily
           optimal.)"""
        def _getFraction(self):
            M = self.count()
            return 1 - math.sqrt(M)/float(M)


