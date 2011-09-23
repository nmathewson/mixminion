# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ThreadUtils.py,v 1.11 2005/06/04 13:54:14 nickm Exp $

"""mixminion.ThreadUtils

   Helper code for threading-related operations, including queues and
   RW-locks.
   """

__all__ = [ 'MessageQueue', 'QueueEmpty', 'ClearableQueue', 'TimeoutQueue',
            'RWLock', 'ProcessingThread', 'BackgroundingDecorator' ]

import sys
import threading
import time
from mixminion.Common import LOG

import thread
_get_ident = thread.get_ident
del thread

#----------------------------------------------------------------------
# Queues

# Imported here so we can get it in mixminion.server without being shadowed
# by the old Queue.py file.
from Queue import Queue, Empty
MessageQueue = Queue
QueueEmpty = Empty
del Queue
del Empty

try:
    q = MessageQueue()
    q.not_full
except:
    BUILTIN_QUEUE_USES_CONDITIONS = 0
else:
    BUILTIN_QUEUE_USES_CONDITIONS = 1
del q

if BUILTIN_QUEUE_USES_CONDITIONS:
    class ClearableQueue(MessageQueue):
        """Extended version of python's Queue class that supports removing
           all the items from the queue."""
        def clear(self):
            """Remove all the items from this queue."""
            # If the queue is empty, return.
            self.not_empty.acquire()
            try:
                if self._empty(): return
                self._clear()
                self.not_full.notify()
            finally:
                self.not_empty.release()

        def _clear(self):
            """Backend for _clear"""
            self.queue.clear()
else:
    class ClearableQueue(MessageQueue):
        """Extended version of python's Queue class that supports removing
           all the items from the queue."""
        def clear(self):
            """Remove all the items from this queue."""
            # If the queue is empty, return.
            if not self.esema.acquire(0):
                return
            self.mutex.acquire()
            was_full = self._full()
            self._clear()
            assert self._empty()
            # If the queue used to be full, it isn't anymore.
            if was_full:
                self.fsema.release()
            self.mutex.release()

        def _clear(self):
            """Backend for _clear"""
            del self.queue[:]


try:
    q = MessageQueue()
    q.put(3)
    q.get(timeout=10)
    BUILTIN_QUEUE_HAS_TIMEOUT = 1
except TypeError:
    BUILTIN_QUEUE_HAS_TIMEOUT = 0
del q

if BUILTIN_QUEUE_HAS_TIMEOUT:
    TimeoutQueue = ClearableQueue
else:
    class TimeoutQueue(ClearableQueue):
        """Helper class for Python 2.2. and earlier: extends the 'get'
           functionality of Queue.Queue to support a 'timeout' argument.
           If 'block' is true and timeout is provided, wait for no more
           than 'timeout' seconds before raising QueueEmpty.

           In Python 2.3 and later, this interface is standard.
        """
        def get(self, block=1, timeout=None):
            if timeout is None or not block:
                return MessageQueue.get(self, block)

            # This logic is adapted from 'Condition' in the Python
            # threading module.
            _time = time.time
            _sleep = time.sleep
            deadline = timeout+_time()
            delay = .0005
            while 1:
                try:
                    return MessageQueue.get(self,0)
                except QueueEmpty:
                    remaining = deadline-_time()
                    if remaining <= 0:
                        raise
                    delay = min(delay*2,remaining,0.2)
                    _sleep(delay)

            raise AssertionError # unreached, appease pychecker

#----------------------------------------------------------------------
class DummyLock:
    """Fake lock-like object to use when no locking is needed."""
    def __init__(self):
        pass
    def acquire(self):
        pass
    def release(self):
        pass

#----------------------------------------------------------------------
# RW locks
#
# Adapted from the msrw class in the sync.py module in the Python
# distribution's Demo/threads directory, but modified to use
# threading.Condition.

class RWLock:
    """A lock that allows multiple readers at a time, but only one writer."""
    # Changes from sync.mrsw:
    #    *  Use threading.Condition instead of sync.condition.
    #    *  Document everything.
    #    *  Don't hold on to rwOK forever when there's an error.
    #    *  Enable recursive invocation of read_in.  Formerly, if thread A
    #       called read_in, thread B called write_in, and thread A called
    #       read_in again, the code would deadlock: the second read_in
    #       would block until write_in succeeded, and write_in would block
    #       until the first read_in was done.
    #
    #       There's a commented-out alternative implementation that makes
    #       recursive invocation an error.  But that doesn't seem to be needed.
    def __init__(self):
        # critical-section lock & the data it protects
        self.rwOK = threading.Lock()
        self.nr = 0  # number readers actively reading (not just waiting)
        self.nw = 0  # number writers either waiting to write or writing
        self.writer = 0  # thread_ident iff some thread is writing
        self.write_depth = 0 # for recursive write_in invocation.
        # map from each current reader's thread_ident to recursion depth.
        self.readers = {}

        # conditions
        self.readOK  = threading.Condition(self.rwOK)  # OK to unblock readers
        self.writeOK = threading.Condition(self.rwOK)  # OK to unblock writers

    def read_in(self):
        """Acquire the lock for reading. Block while any threads are currently
           writing or waiting to write."""
        self.rwOK.acquire()
        try:
            ident = _get_ident()
            if self.writer == ident:
                raise ValueError("Tried to acquire read lock while holding write lock.")

            try:
                self.readers[ident] += 1
                self.nr += 1
                return
            except KeyError:
                pass

            while self.nw:
                self.readOK.wait()
            self.nr = self.nr + 1
            self.readers[ident] = 1
        finally:
            self.rwOK.release()

    def read_out(self):
        """Release the lock for reading.  When no more readers are active,
           activate the writers (if any)."""
        self.rwOK.acquire()
        try:
            ident = _get_ident()

            if self.nr <= 0:
                raise ValueError, '.read_out() invoked without an active reader'
            try:
                n = self.readers[ident]
            except KeyError:
                raise ValueError("read_out called without matching read_in.")
            if n == 1:
                del self.readers[ident]
            else:
                self.readers[ident] = n-1
                self.nr -= 1
                return

            self.nr = self.nr - 1
            if self.nr == 0:
                self.writeOK.notify()
        finally:
            self.rwOK.release()

    def write_in(self):
        """Acquire the lock for writing. Block while any threads are reading
           or writing.
        """
        self.rwOK.acquire()
        try:
            ident = _get_ident()
            if self.readers.has_key(ident):
                raise ValueError("write_in called while acting as reader")
            if self.writer == ident:
                self.write_depth += 1
                return
            self.nw = self.nw + 1
            while self.writer or self.nr:
                self.writeOK.wait()
            self.writer = ident
            self.write_depth = 1
        finally:
            self.rwOK.release()

    def write_out(self):
        """Release the lock for writing."""
        self.rwOK.acquire()
        try:
            ident = _get_ident()
            if not self.writer:
                raise ValueError, \
                      '.write_out() invoked without an active writer'
            if self.writer != ident:
                raise ValueError("write_out() called by non-writer")
            self.write_depth -= 1
            if self.write_depth > 0:
                return
            self.writer = 0
            self.nw = self.nw - 1
            if self.nw:
                self.writeOK.notify()
            else:
                self.readOK.notifyAll()
        finally:
            self.rwOK.release()

    def write_to_read(self):
        """Simultaneously release the lock as a writer, and become a reader."""
        self.rwOK.acquire()
        try:
            if not self.writer:
                raise ValueError, \
                      '.write_to_read() invoked without an active writer'
            ident = _get_ident()
            if self.writer != ident:
                raise ValueError("write_out() called by non-writer")
            assert self.write_depth == 1
            self.write_depth -= 1
            self.writing = 0
            self.nw = self.nw - 1
            self.nr = self.nr + 1
            self.readers[ident] = 1
            if not self.nw:
                self.readOK.notifyAll()
        finally:
            self.rwOK.release()

#----------------------------------------------------------------------
# Processing threads: used to make tasks happen in background.

#XXXX008 add tests for these.

class ProcessingThread(threading.Thread):
    """Background thread to handle CPU-intensive functions.

       Currently used to process packets in the background."""
    # Fields:
    #   mqueue: a ClearableQueue of callable objects.
    #   threadName: the name of this thread (used in log msgs)
    class _Shutdown:
        """Callable that raises itself when called.  Inserted into the
           queue when it's time to shut down."""
        def __call__(self):
            raise self

    def __init__(self, name="processing thread"):
        """Create a new processing thread."""
        threading.Thread.__init__(self)
        self.mqueue = ClearableQueue()
        self.threadName = name

    def shutdown(self,flush=1):
        """Tells this thread to shut down once the current job is done."""
        LOG.info("Telling %s to shut down.", self.threadName)
        if flush:
            self.mqueue.clear()
        self.mqueue.put(ProcessingThread._Shutdown())

    def addJob(self, job):
        """Adds a job to the message queue.  A job is a callable object
           to be invoked by the processing thread.  If the job raises
           ProcessingThread._Shutdown, the processing thread stops running."""
        self.mqueue.put(job)

    def run(self):
        """Internal: main body of processing thread."""
        try:
            while 1:
                job = self.mqueue.get()
                job()
        except ProcessingThread._Shutdown:
            LOG.info("Shutting down %s",self.threadName)
            return
        except:
            LOG.error_exc(sys.exc_info(),
                          "Exception in %s; shutting down thread.",
                          self.threadName)

class BackgroundingDecorator:
    """Wraps an underlying object, and makes all method calls to the wrapped
       object happen in a processing thread.

       Return values from wrapped methods are lost.

       Methods and attributes starting with _ are not wrapped;
       otherwise, attribute access is not available.
    """
    #FFFF We could retain return values by adding some kind of a thunk
    #FFFF system, or some kind of callback system.  But neither is needed
    #FFFF right now.
    class _AddJob:
        "Helper: A wrapped function for the underlying object."
        def __init__(self, processingThread, fn):
            self.thread = processingThread
            self.fn = fn
        def __call__(self, *args, **kwargs):
            def callback(self=self, args=args, kwargs=kwargs):
                self.fn(*args, **kwargs)
            self.thread.addJob(callback)

    def __init__(self, processingThread, obj):
        """Create a new BackgroundingDecorator to redirect calls to the
           methods of obj to processingThread."""
        self._thread = processingThread
        self._baseObject = obj

    def __getattr__(self, attr):
        if attr[0]=='_': return getattr(self._baseObject,attr)#XXXX
        fn = getattr(self._baseObject,attr)
        return self._AddJob(self._thread,fn)
