# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerQueue.py,v 1.3 2003/01/13 06:35:52 nickm Exp $

"""mixminion.server.ServerQueue

   Facility for fairly secure, directory-based, unordered queues.
   """

import os
import base64
import time
import stat
import cPickle
import threading

from mixminion.Common import MixError, MixFatalError, secureDelete, LOG, \
     createPrivateDir
from mixminion.Crypto import getCommonPRNG

__all__ = [ 'Queue', 'DeliveryQueue', 'TimedMixQueue', 'CottrellMixQueue',
            'BinomialCottrellMixQueue' ]

# Mode to pass to open(2) for creating a new file, and dying if it already
# exists.
_NEW_MESSAGE_FLAGS = os.O_WRONLY+os.O_CREAT+os.O_EXCL
# On windows or mac, binary != text.
_NEW_MESSAGE_FLAGS += getattr(os, 'O_BINARY', 0)

# Any inp_* files older than INPUT_TIMEOUT seconds old are assumed to be
# trash.
INPUT_TIMEOUT = 6000

class Queue:
    """A Queue is an unordered collection of files with secure insert, move,
       and delete operations.

       Implementation: a queue is a directory of 'messages'.  Each
       filename in the directory has a name in one of the following
       formats:
             rmv_HANDLE  (A message waiting to be deleted)
             msg_HANDLE  (A message waiting in the queue.
             inp_HANDLE  (An incomplete message being created.)
       (Where HANDLE is a randomly chosen 12-character selection from the
       characters 'A-Za-z0-9+-'.  [Collision probability is negligable.])

       Threading notes:  Although Queue itself is threadsafe, you'll want
       to synchronize around any multistep operations that you want to
       run atomicly.  Use Queue.lock() and Queue.unlock() for this.

       In the Mixminion server, no queue currently has more than one producer
       or more than one consumer ... so synchronization turns out to be
       fairly easy.
       """
       # How negligible are the chances of collision?  A back-of-the-envelope
       # approximation: The chance of a collision reaches .1% when you have 3e9
       # messages in a single queue.  If Alice somehow manages to accumulate a
       # 96 gigabyte backlog, we'll have bigger problems than name
       # collision... such as the fact that most Unices behave badly when
       # confronted with 3 billion files in the same directory... or the fact
       # that, at today's processor speeds, it will take Alice 3 or 4 CPU-years
       # to clear her backlog.
       #
       # Threading: If we ever get more than one producer, we're fine.  With
       #    more than one consumer, we'll need to modify DeliveryQueue below.
       

    # Fields:   dir--the location of the queue.
    #           n_entries: the number of complete messages in the queue.
    #                 <0 if we haven't counted yet.
    #           _lock: A lock that must be held while modifying or accessing
    #                 the queue object.  Filesystem operations are allowed
    #                 without holding the lock, but they must not be visible
    #                 to users of the queue.
    def __init__(self, location, create=0, scrub=0):
        """Creates a queue object for a given directory, 'location'.  If
           'create' is true, creates the directory if necessary.  If 'scrub'
           is true, removes any incomplete or invalidated messages from the
           Queue."""

        secureDelete([]) # Make sure secureDelete is configured. HACK!

        self._lock = threading.RLock()
        self.dir = location

        if not os.path.isabs(location):
            LOG.warn("Queue path %s isn't absolute.", location)

        if os.path.exists(location) and not os.path.isdir(location):
            raise MixFatalError("%s is not a directory" % location)

        createPrivateDir(location, nocreate=(not create))

        if scrub:
            self.cleanQueue()

        # Count messages on first time through.
        self.n_entries = -1

    def lock(self):
        """Prevent access to this queue from other threads."""
        self._lock.acquire()

    def unlock(self):
        """Release the lock on this queue."""
        self._lock.release()

    def queueMessage(self, contents):
        """Creates a new message in the queue whose contents are 'contents',
           and returns a handle to that message."""
        f, handle = self.openNewMessage()
        f.write(contents)
        self.finishMessage(f, handle) # handles locking
        return handle

    def queueObject(self, object):
        """Queue an object using cPickle, and return a handle to that
           object."""
        f, handle = self.openNewMessage()
        cPickle.dump(object, f, 1)
        self.finishMessage(f, handle) # handles locking
        return handle

    def count(self, recount=0):
        """Returns the number of complete messages in the queue."""
        try:
            self._lock.acquire()
            if self.n_entries >= 0 and not recount:
                return self.n_entries
            else:
                res = 0
                for fn in os.listdir(self.dir):
                    if fn.startswith("msg_"):
                        res += 1
                self.n_entries = res
                return res
        finally:
            self._lock.release()
            
    def pickRandom(self, count=None):
        """Returns a list of 'count' handles to messages in this queue.
           The messages are chosen randomly, and returned in a random order.

           If there are fewer than 'count' messages in the queue, all the
           messages will be retained."""
        handles = self.getAllMessages() # handles locking

        return getCommonPRNG().shuffle(handles, count)

    def getAllMessages(self):
        """Returns handles for all messages currently in the queue.
           Note: this ordering is not guaranteed to be random"""
        self._lock.acquire()
        hs = [fn[4:] for fn in os.listdir(self.dir) if fn.startswith("msg_")]
        self._lock.release()
        return hs

    def removeMessage(self, handle):
        """Given a handle, removes the corresponding message from the queue."""
        self.__changeState(handle, "msg", "rmv") # handles locking.

    def removeAll(self):
        """Removes all messages from this queue."""
        try:
            self._lock.acquire()
            for m in os.listdir(self.dir):
                if m[:4] in ('inp_', 'msg_'):
                    self.__changeState(m[4:], m[:3], "rmv")
            self.n_entries = 0
            self.cleanQueue()
        finally:
            self._lock.release()

    def moveMessage(self, handle, queue):
        """Given a handle and a queue, moves the corresponding message from
           this queue to the queue provided.  Returns a new handle for
           the message in the destination queue."""
        # Since we're switching handle, we don't want to just rename;
        # We really want to copy and delete the old file.
        try:
            self._lock.acquire()
            newHandle = queue.queueMessage(self.messageContents(handle))
            self.removeMessage(handle)
        finally:
            self._lock.release()

        return newHandle

    def getMessagePath(self, handle):
        """Given a handle for an existing message, return the name of the
           file that contains that message."""
        # We don't need to lock here: the handle is still valid, or it isn't.
        return os.path.join(self.dir, "msg_"+handle)

    def openMessage(self, handle):
        """Given a handle for an existing message, returns a file descriptor
           open to read that message."""
        # We don't need to lock here; the handle is still valid, or it isn't.
        return open(os.path.join(self.dir, "msg_"+handle), 'rb')

    def messageContents(self, handle):
        """Given a message handle, returns the contents of the corresponding
           message."""
        try:
            self._lock.acquire()
            f = open(os.path.join(self.dir, "msg_"+handle), 'rb')
            s = f.read()
            f.close()
            return s
        finally:
            self._lock.release()

    def getObject(self, handle):
        """Given a message handle, read and unpickle the contents of the
           corresponding message."""
        try:
            self._lock.acquire()
            f = open(os.path.join(self.dir, "msg_"+handle), 'rb')
            res = cPickle.load(f)
            f.close()
            return res
        finally:
            self._lock.release()

    def openNewMessage(self):
        """Returns (file, handle) tuple to create a new message.  Once
           you're done writing, you must call finishMessage to
           commit your changes, or abortMessage to reject them."""
        handle = self.__newHandle()
        fname = os.path.join(self.dir, "inp_"+handle)
        fd = os.open(fname, _NEW_MESSAGE_FLAGS, 0600)
        return os.fdopen(fd, 'wb'), handle

    def finishMessage(self, f, handle):
        """Given a file and a corresponding handle, closes the file
           commits the corresponding message."""
        f.close()
        self.__changeState(handle, "inp", "msg")

    def abortMessage(self, f, handle):
        """Given a file and a corresponding handle, closes the file
           rejects the corresponding message."""
        f.close()
        self.__changeState(handle, "inp", "rmv")

    def cleanQueue(self, secureDeleteFn=None):
        """Removes all timed-out or trash messages from the queue.

           Returns 1 if a clean is already in progress; otherwise
           returns 0.

           DOCDOC secureDeleteFn
        """
        # We don't need to hold the lock here; we synchronize via the
        # filesystem.

        rmv = []
        allowedTime = int(time.time()) - INPUT_TIMEOUT
        for m in os.listdir(self.dir):
            if m.startswith("rmv_"):
                rmv.append(os.path.join(self.dir, m))
            elif m.startswith("inp_"):
                s = os.stat(m)
                if s[stat.ST_MTIME] < allowedTime:
                    self.__changeState(m[4:], "inp", "rmv")
                    rmv.append(os.path.join(self.dir, m))
        if secureDeleteFn:
            secureDeleteFn(rmv)
        else:
            secureDelete(rmv, blocking=1)
        return 0

    def __changeState(self, handle, s1, s2):
        """Helper method: changes the state of message 'handle' from 's1'
           to 's2', and changes the internal count."""
        try:
            self._lock.acquire()
            try:
                os.rename(os.path.join(self.dir, s1+"_"+handle),
                          os.path.join(self.dir, s2+"_"+handle))
            except OSError, e:
                contents = os.listdir(self.dir)
                LOG.error("Error while trying to change %s from %s to %s: %s",
                          handle, s1, s2, e)
                LOG.error("Directory %s contains: %s", self.dir, contents)
                self.count(1)
                return
                
            if self.n_entries < 0:
                return
            if s1 == 'msg' and s2 != 'msg':
                self.n_entries -= 1
            elif s1 != 'msg' and s2 == 'msg':
                self.n_entries += 1
        finally:
            self._lock.release()

    def __newHandle(self):
        """Helper method: creates a new random handle."""
        junk = getCommonPRNG().getBytes(9)
        return base64.encodestring(junk).strip().replace("/","-")

class DeliveryQueue(Queue):
    """A DeliveryQueue implements a queue that greedily sends messages
       to outgoing streams that occasionally fail.  Messages in a
       DeliveryQueue are no longer unstructured text, but rather
       tuples of: (n_retries, addressing info, msg).

       This class is abstract. Implementors of this class should
       subclass it to add a _deliverMessages method.  Multiple
       invocations of this method may be active at a given time.  Upon
       success or failure, this method should cause deliverySucceeded
       or deliveryFailed to be called as appropriate.

       Users of this class will probably only want to call the queueMessage,
       sendReadyMessages, and nextMessageReadyAt methods.

       This class caches information about the directory state; it
       won't play nice if multiple instances are looking at the same
       directory.
    """
    # XXXX separating addr was a mistake.
    
    ###
    # Fields:
    #    sendable -- A list of handles for all messages
    #           that we're not currently sending.
    #    pending -- Dict from handle->1, for all messages that we're
    #           currently sending.

    def __init__(self, location, retrySchedule=None):
        Queue.__init__(self, location, create=1, scrub=1)
        self._rescan()
        if retrySchedule is None:
            self.retrySchedule = None
        else:
            self.retrySchedule = retrySchedule[:]

    def setRetrySchedule(self, schedule):#DOCDOC
        self.retrySchedule = schedule[:]

    def _rescan(self):
        """Rebuild the internal state of this queue from the underlying
           directory."""
        try:
            self._lock.acquire()
            self.pending = {}
            self.sendable = self.getAllMessages()
        finally:
            self._lock.release()

    def queueMessage(self, msg):
        if 1: raise MixError("Tried to call DeliveryQueue.queueMessage.")

    def queueDeliveryMessage(self,  msg, retry=0, nextAttempt=0):
        """Schedule a message for delivery.
             addr -- An object to indicate the message's destination
             msg -- the message itself
             retry -- how many times so far have we tried to send?
             DOCDOC"""
        try:
            self._lock.acquire()
            #DOCDOC nextAttempt 
            handle = self.queueObject( (retry, None, msg, nextAttempt) )
            self.sendable.append(handle)
        finally:
            self._lock.release()

        return handle

    def get(self,handle):
        """Returns a (n_retries, addr, msg, nextAttempt?) payload for a given
           message handle."""
        o = self.getObject(handle)
        if len(o) == 3:# XXXX For legacy queues; delete after 0.0.3
            o = o + (0,)
        return o[0], o[2], o[3]

    def sendReadyMessages(self, now=None):
        """Sends all messages which are not already being sent."""
        if now is None:
            now = time.time()
        try:
            self._lock.acquire()
            handles = self.sendable
            messages = []
            self.sendable = []
            for h in handles:
                retries,msg, nextAttempt = self.get(h)
                if nextAttempt <= now:
                    messages.append((h, msg, retries))
                    self.pending[h] = now
                else:
                    self.sendable.append(h)
        finally:
            self._lock.release()
        if messages:
            self._deliverMessages(messages)

    def _deliverMessages(self, msgList):
        """Abstract method; Invoked with a list of
           (handle, message, n_retries) tuples every time we have a batch
           of messages to send.

           For every handle in the list, delierySucceeded or deliveryFailed
           should eventually be called, or the message will sit in the queue
           indefinitely, without being retried."""

        # We could implement this as a single _deliverMessage(h,addr,m,n)
        # method, but that wouldn't allow implementations to batch
        # messages being sent to the same address.

        raise NotImplementedError("_deliverMessages")

    def deliverySucceeded(self, handle):
        """Removes a message from the outgoing queue.  This method
           should be invoked after the corresponding message has been
           successfully delivered.
        """
        try:
            self._lock.acquire()
            #XXXX003 be more robust in the presence of errors here.
            self.removeMessage(handle)
            del self.pending[handle]
        finally:
            self._lock.release()

    def deliveryFailed(self, handle, retriable=0):
        """Removes a message from the outgoing queue, or requeues it
           for delivery at a later time.  This method should be
           invoked after the corresponding message has been
           successfully delivered."""
        try:
            #XXXX003 be more robust in the presence of errors here.
            self._lock.acquire()
            lastAttempt = self.pending[handle]
            del self.pending[handle]
            if retriable:
                # Queue the new one before removing the old one, for
                # crash-proofness.  First, fetch the old information...
                retries, msg, schedAttempt = self.get(handle)

                # Multiple retry intervals may have passed in between the most
                # recent failed delivery attempt (lastAttempt) and the time
                # it was schedule (schedAttempt).  Increment 'retries' and
                # efore it (prevAttempt).  Increment 'retries' to reflect the
                # number of retry intervals that have passed between first
                # sending the message and nextAttempt.
                #DOCDOC
                if self.retrySchedule and retries < len(self.retrySchedule):
                    nextAttempt = schedAttempt
                    if nextAttempt == 0:
                        nextAttempt = lastAttempt
                    while retries < len(self.retrySchedule):
                        nextAttempt += self.retrySchedule[retries]
                        retries += 1
                        if nextAttempt > lastAttempt:
                            break
                    if retries <= len(self.retrySchedule):
                        self.queueDeliveryMessage(msg, retries, nextAttempt)
                elif not self.retrySchedule:
                    #LEGACY XXXX003
                    retries += 1
                    nextAttempt = 0
                    if retries < 10:
                        self.queueDeliveryMessage(msg, retries, nextAttempt)
                                              
            self.removeMessage(handle)
        finally:
            self._lock.release()

class TimedMixQueue(Queue):
    """A TimedMixQueue holds a group of files, and returns some of them
       as requested, according to a mixing algorithm that sends a batch
       of messages every N seconds."""
    # FFFF : interval is unused.
    ## Fields:
    #   interval: scanning interval, in seconds.
    def __init__(self, location, interval=600):
        """Create a TimedMixQueue that sends its entire batch of messages
           every 'interval' seconds."""
        Queue.__init__(self, location, create=1, scrub=1)
        self.interval = interval

    def getBatch(self):
        """Return handles for all messages that the pool is currently ready
           to send in the next batch"""
        return self.pickRandom()

    def getInterval(self):
        return self.interval

class CottrellMixQueue(TimedMixQueue):
    """A CottrellMixQueue holds a group of files, and returns some of them
       as requested, according the Cottrell (timed dynamic-pool) mixing
       algorithm from Mixmaster."""
    # FFFF : interval is unused.
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
           than <sendRate> * the corrent pool size.

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
        # Phd. thesis ("Generalisation and Security Improvement of
        # Mix-mediated Anonymous Communication") of 2000.
        #
        # *THIS* is the algorithm that the current 'Batching Taxonomy' paper
        # says that Cottrell says is the real thing.

        TimedMixQueue.__init__(self, location, interval)
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

class BinomialCottrellMixQueue(CottrellMixQueue):
    """Same algorithm as CottrellMixQueue, but instead of sending N messages
       from the pool of size P, sends each message with probability N/P."""
    def getBatch(self):
        n = self._getBatchSize()
        if n == 0:
            return []
        msgProbability = n / float(self.count())
        rng = getCommonPRNG()
        return rng.shuffle([ h for h in self.getAllMessages()
                             if rng.getFloat() < msgProbability ])
