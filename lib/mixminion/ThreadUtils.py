# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ThreadUtils.py,v 1.2 2004/03/06 00:04:38 nickm Exp $

"""mixminion.ThreadUtils

   Helper code for threading-related operations, including queues and
   RW-locks.
   """

__all__ = [ 'MessageQueue', 'QueueEmpty', 'ClearableQueue', 'TimeoutQueue',
            'RWLock' ]

import threading
import time

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
        self.writing = 0  # 1 iff some thread is writing
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
            try:
                self.readers[ident] += 1
                self.nr += 1
                return
            except KeyError:
                pass
            #if self.readers.has_key(ident):
            #    raise ValueError("RWLock.read_in called recursively.")

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
            if self.nr <= 0:
                raise ValueError, '.read_out() invoked without an active reader'
            ident = _get_ident()
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
            #try:
            #    del self.readers[_get_ident()]
            #except KeyError:
            #    raise ValueError("read_out called without matching read_in.")

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
            if self.readers.has_key(_get_ident()):
                raise ValueError("write_in called while acting as reader")
            self.nw = self.nw + 1
            while self.writing or self.nr:
                self.writeOK.wait()
            self.writing = 1
        finally:
            self.rwOK.release()

    def write_out(self):
        """Release the lock for writing."""
        self.rwOK.acquire()
        try:
            if not self.writing:
                raise ValueError, \
                      '.write_out() invoked without an active writer'
            self.writing = 0
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
            if not self.writing:
                raise ValueError, \
                      '.write_to_read() invoked without an active writer'
            self.writing = 0
            self.nw = self.nw - 1
            self.nr = self.nr + 1
            self.readers[_get_ident()] = 1
            if not self.nw:
                self.readOK.notifyAll()
        finally:
            self.rwOK.release()
