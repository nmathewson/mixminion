# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Queue.py,v 1.4 2002/12/16 02:40:11 nickm Exp $

"""mixminion.server.Queue

   Facility for fairly secure, directory-based, unordered queues.
   """

import os
import base64
import time
import stat
import cPickle

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

# If we've been cleaning for more than CLEAN_TIMEOUT seconds, assume the
# old clean is dead.
CLEAN_TIMEOUT = 120

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
       """
       # How negligible?  A back-of-the-envelope approximation: The chance
       # of a collision reaches .1% when you have 3e9 messages in a single
       # queue.  If Alice somehow manages to accumulate a 96 gigabyte
       # backlog, we'll have bigger problems than name collision... such
       # as the fact that most Unices behave badly when confronted with
       # 3 billion files in the same directory... or the fact that,
       # at today's processor speeds, it will take Alice 3 or 4
       # CPU-years to clear her backlog.

    # Fields:   rng--a random number generator for creating new messages
    #                and getting a random slice of the queue.
    #           dir--the location of the queue.
    #           n_entries: the number of complete messages in the queue.
    #                 <0 if we haven't counted yet.
    def __init__(self, location, create=0, scrub=0):
        """Creates a queue object for a given directory, 'location'.  If
           'create' is true, creates the directory if necessary.  If 'scrub'
           is true, removes any incomplete or invalidated messages from the
           Queue."""

        secureDelete([]) # Make sure secureDelete is configured. HACK!

        self.rng = getCommonPRNG()
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

    def queueMessage(self, contents):
        """Creates a new message in the queue whose contents are 'contents',
           and returns a handle to that message."""
        f, handle = self.openNewMessage()
        f.write(contents)
        self.finishMessage(f, handle)
        return handle

    def queueObject(self, object):
        """Queue an object using cPickle, and return a handle to that
           object."""
        f, handle = self.openNewMessage()
        cPickle.dump(object, f, 1)
        self.finishMessage(f, handle)
        return handle

    def count(self, recount=0):
        """Returns the number of complete messages in the queue."""
        if self.n_entries >= 0 and not recount:
            return self.n_entries
        else:
            res = 0
            for fn in os.listdir(self.dir):
                if fn.startswith("msg_"):
                    res += 1
            self.n_entries = res
            return res

    def pickRandom(self, count=None):
        """Returns a list of 'count' handles to messages in this queue.
           The messages are chosen randomly, and returned in a random order.

           If there are fewer than 'count' messages in the queue, all the
           messages will be retained."""
        handles = [ fn[4:] for fn in os.listdir(self.dir)
                           if fn.startswith("msg_") ]

        return self.rng.shuffle(handles, count)

    def getAllMessages(self):
        """Returns handles for all messages currently in the queue.
           Note: this ordering is not guaranteed to be random"""
        return [fn[4:] for fn in os.listdir(self.dir) if fn.startswith("msg_")]

    def removeMessage(self, handle):
        """Given a handle, removes the corresponding message from the queue."""
        self.__changeState(handle, "msg", "rmv")

    def removeAll(self):
        """Removes all messages from this queue."""
        for m in os.listdir(self.dir):
            if m[:4] in ('inp_', 'msg_'):
                self.__changeState(m[4:], m[:3], "rmv")
        self.n_entries = 0
        self.cleanQueue()

    def moveMessage(self, handle, queue):
        """Given a handle and a queue, moves the corresponding message from
           this queue to the queue provided.  Returns a new handle for
           the message in the destination queue."""
        # Since we're switching handle, we don't want to just rename;
        # We really want to copy and delete the old file.
        newHandle = queue.queueMessage(self.messageContents(handle))
        self.removeMessage(handle)
        return newHandle

    def getMessagePath(self, handle):
        """Given a handle for an existing message, return the name of the
           file that contains that message."""
        return os.path.join(self.dir, "msg_"+handle)

    def openMessage(self, handle):
        """Given a handle for an existing message, returns a file descriptor
           open to read that message."""
        return open(os.path.join(self.dir, "msg_"+handle), 'rb')

    def messageContents(self, handle):
        """Given a message handle, returns the contents of the corresponding
           message."""
        f = open(os.path.join(self.dir, "msg_"+handle), 'rb')
        s = f.read()
        f.close()
        return s

    def getObject(self, handle):
        """Given a message handle, read and unpickle the contents of the
           corresponding message."""
        f = open(os.path.join(self.dir, "msg_"+handle), 'rb')
        res = cPickle.load(f)
        f.close()
        return res

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

    def cleanQueue(self):
        """Removes all timed-out or trash messages from the queue.

           Returns 1 if a clean is already in progress; otherwise
           returns 0.
        """

        now = time.time()
        cleanFile = os.path.join(self.dir,".cleaning")

        cleaning = 1
        while cleaning:
            try:
                # Try to get the .cleaning lock file.  If we can create it,
                # we're the only cleaner around.
                fd = os.open(cleanFile, os.O_WRONLY+os.O_CREAT+os.O_EXCL, 0600)
                os.write(fd, str(now))
                os.close(fd)
                cleaning = 0
            except OSError:
                try:
                    # If we can't create the file, see if it's too old.  If it
                    # is too old, delete it and try again.  If it isn't, there
                    # may be a live clean in progress.
                    s = os.stat(cleanFile)
                    if now - s[stat.ST_MTIME] > CLEAN_TIMEOUT:
                        os.unlink(cleanFile)
                    else:
                        return 1
                except OSError:
                    # If the 'stat' or 'unlink' calls above fail, then
                    # .cleaning must not exist, or must not be readable
                    # by us.
                    if os.path.exists(cleanFile):
                        # In the latter case, bail out.
                        return 1

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
        secureDelete(rmv, blocking=1)
        return 0

    def __changeState(self, handle, s1, s2):
        """Helper method: changes the state of message 'handle' from 's1'
           to 's2', and changes the internal count."""
        os.rename(os.path.join(self.dir, s1+"_"+handle),
                  os.path.join(self.dir, s2+"_"+handle))
        if self.n_entries < 0:
            return
        if s1 == 'msg' and s2 != 'msg':
            self.n_entries -= 1
        elif s1 != 'msg' and s2 == 'msg':
            self.n_entries += 1

    def __newHandle(self):
        """Helper method: creates a new random handle."""
        junk = self.rng.getBytes(9)
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
    ###
    # Fields:
    #    sendable -- A list of handles for all messages
    #           that we're not currently sending.
    #    pending -- Dict from handle->1, for all messages that we're
    #           currently sending.

    def __init__(self, location):
        Queue.__init__(self, location, create=1, scrub=1)
        self._rescan()

    def _rescan(self):
        """Rebuild the internal state of this queue from the underlying
           directory."""
        self.pending = {}
        self.sendable = self.getAllMessages()

    def queueMessage(self, msg):
        if 1: raise MixError("Tried to call DeliveryQueue.queueMessage.")

    def queueDeliveryMessage(self, addr, msg, retry=0):
        """Schedule a message for delivery.
             addr -- An object to indicate the message's destination
             msg -- the message itself
             retry -- how many times so far have we tried to send?"""

        handle = self.queueObject( (retry, addr, msg) )
        self.sendable.append(handle)

        return handle

    def get(self,handle):
        """Returns a (n_retries, addr, msg) payload for a given
           message handle."""
        return self.getObject(handle)

    def sendReadyMessages(self):
        """Sends all messages which are not already being sent."""

        handles = self.sendable
        messages = []
        self.sendable = []
        for h in handles:
            retries, addr, msg = self.getObject(h)
            messages.append((h, addr, msg, retries))
            self.pending[h] = 1
        if messages:
            self._deliverMessages(messages)

    def _deliverMessages(self, msgList):
        """Abstract method; Invoked with a list of
           (handle, addr, message, n_retries) tuples every time we have a batch
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
        self.removeMessage(handle)
        del self.pending[handle]

    def deliveryFailed(self, handle, retriable=0):
        """Removes a message from the outgoing queue, or requeues it
           for delivery at a later time.  This method should be
           invoked after the corresponding message has been
           successfully delivered."""
        del self.pending[handle]
        if retriable:
            # Queue the new one before removing the old one, for
            # crash-proofness
            retries, addr, msg = self.getObject(handle)
            # FFFF This test makes us never retry past the 10th attempt.
            # FFFF That's wrong; we should be smarter.
            if retries <= 10:
                self.queueDeliveryMessage(addr, msg, retries+1)
        self.removeMessage(handle)

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

           If 'minSend'==1, this is a real Cottrell (type-II) mix pool.
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
        return self.rng.shuffle([ h for h in self.getAllMessages()
                                    if self.rng.getFloat() < msgProbability ])

def _secureDelete_bg(files, cleanFile):
    """Helper method: delete files in another thread, removing 'cleanFile'
       once we're done.

       XXXX No longer used: cleanup is a lot faster than it once was, now
       XXXX that we no longer overwrite repeatedly.  If we reinstate it,
       XXXX it should be a separate process, not a frequent forker."""

    pid = os.fork()
    if pid != 0:
        return pid
    # Now we're in the child process.
    try:
        secureDelete(files, blocking=1)
    except OSError:
        # This is sometimes thrown when shred finishes before waitpid.
        pass
    try:
        os.unlink(cleanFile)
    except OSError:
        pass
    os._exit(0)
    return None # Never reached.
