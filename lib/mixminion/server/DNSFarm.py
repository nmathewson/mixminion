# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DNSFarm.py,v 1.8 2004/01/09 00:46:12 nickm Exp $

"""mixminion.server.DNSFarm: code to implement asynchronous DNS resolves with
   background threads and cachhe the results.
   """

import socket
import threading
import time
import sys
from mixminion.Common import LOG
from mixminion.NetUtils import getIP, nameIsStaticIP
from mixminion.ThreadUtils import TimeoutQueue, QueueEmpty

__all__ = [ 'DNSCache' ]

class _Pending:
    """Class to represent resolves that we're waiting for an answer on."""
    def __cmp__(self,o):
        return cmp(type(self), type(o))
PENDING = _Pending()

# We never shutdown threads if doing so would leave fewer than MIN_THREADS.
MIN_THREADS = 2
# We never shutdown threads if doing so would leave fewer than MIN_FREE_THREADS
# idle threads.
MIN_FREE_THREADS = 1
# We never start a new thread if doing so would make more than MAX_THREADS.
MAX_THREADS = 8
# Subject to MIN_THREADS and MIN_FREE_THREADS, we shutdown threads when
# they're idele for more than MAX_THREAD_IDLE seconds.
MAX_THREAD_IDLE = 5*60
# We clear entries from the DNS cache when they're more than MAX_ENTRY_TTL
# seconds old.
MAX_ENTRY_TTL = 30*60

class DNSCache:
    """Class to cache answers to DNS requests and manager DNS threads."""
    ## Fields:
    # _isShutdown: boolean: are the threads shutting down?  (While the
    #     threads are shutting down, we don't answer any requests.)
    # cache: map from name to PENDING or getIP result.
    # callbacks: map from name to list of callback functions. (See lookup
    #     for definition of callback.)
    # lock: Lock to control access to this class's shared state.
    # nBusyThreads: Number of threads that are currently handling requests.
    # nLiveThreads: Number of threads that are currently running.
    # queue: Instance of TimeoutQueue that holds either names to resolve,
    #     or instances of None to shutdown threads.
    # threads: List of DNSThreads, some of which may be dead.
    def __init__(self):
        """Create a new DNSCache"""
        self.cache = {}
        self.callbacks = {}
        self.lock = threading.RLock()
        self.queue = TimeoutQueue()
        self.threads = []
        self.nLiveThreads = 0
        self.nBusyThreads = 0
        self._isShutdown = 0
        self.cleanCache()
    def getNonblocking(self, name):
        """Return the cached result for the lookup of name.  If we're
           waiting for an answer, return PENDING.  If there is no cached
           result, return None.
        """
        try:
            self.lock.acquire()
            return self.cache.get(name)
        finally:
            self.lock.release()
    def lookup(self,name,cb):
        """Look up the name 'name', and pass the result to the callback
           function 'cb' when we're done.  The result will be of the
           same form as the return value of NetUtils.getIP: either
           (Family, Address, Time) or ('NOENT', Reason, Time).

           Note: The callback may be invoked from a different thread.  Either
           this thread or a DNS thread will block until the callback finishes,
           so it shouldn't be especially time-consuming.
        """
        # Check for a static IP first; no need to resolve that.
        v = nameIsStaticIP(name)
        if v is not None:
            cb(name,v)
            return

        try:
            self.lock.acquire()
            v = self.cache.get(name)
            # If we don't have a cached answer, add cb to self.callbacks
            if v is None or v is PENDING:
                self.callbacks.setdefault(name, []).append(cb)
            # If we aren't looking up the answer, start looking it up.
            if v is None:
                LOG.trace("DNS cache starting lookup of %r", name)
                self._beginLookup(name)
        finally:
            self.lock.release()
        # If we _did_ have an answer, invoke the callback now.
        if v is not None and v is not PENDING:
            LOG.trace("DNS cache returning cached value %s for %r",
                      v,name)
            cb(name,v)

    def shutdown(self, wait=0):
        """Tell all the DNS threads to shut down.  If 'wait' is true,
           don't wait until all the theads have completed."""
        try:
            self.lock.acquire()
            self._isShutdown = 1
            self.queue.clear()
            for _ in xrange(self.nLiveThreads*2):
                self.queue.put(None)
        finally:
            self.lock.release()

        if wait:
            for thr in self.threads:
                thr.join()

    def cleanCache(self,now=None):
        """Remove all expired entries from the cache."""
        if now is None:
            now = time.time()
        try:
            self.lock.acquire()

            # Purge old entries from the
            cache = self.cache
            for name in cache.keys():
                v = cache[name]
                if v is PENDING: continue
                if now-v[2] > MAX_ENTRY_TTL:
                    del cache[name]

            # Remove dead threads from self.threads.
            liveThreads = [ thr for thr in self.threads if thr.isAlive() ]
            self.threads = liveThreads

            # Make sure we have enough threads.
            if len(self.threads) < MIN_THREADS:
                for _ in xrange(len(self.threads)-MIN_THREADS):
                    self.threads.append(DNSThread(self))
                    self.threads[-1].start()
        finally:
            self.lock.release()

    def _beginLookup(self,name):
        """Helper function: Begin looking up 'name'.

           Caller must hold self.lock
        """
        self.cache[name] = PENDING
        if self._isShutdown:
            # If we've shut down the threads, don't queue the request at
            # all; it'll stay pending indefinitely.
            return
        # Queue the request.
        self.queue.put(name)
        # If there aren't enough idle threads, and if we haven't maxed
        # out the threads, start a new one.
        if (self.nLiveThreads < self.nBusyThreads + MIN_FREE_THREADS
            and self.nLiveThreads < MAX_THREADS):
            thread = DNSThread(self)
            thread.start()
            self.threads.append(thread)
    def _lookupDone(self,name,val):
        """Helper function: invoked when we get the answer 'val' for
           a lookup of 'name'.
           """
        try:
            self.lock.acquire()
            # Insert the value in the cache.
            self.cache[name]=val
            # Get the callbacks for the name, if any.
            cbs = self.callbacks.get(name,[])
            try:
                del self.callbacks[name]
            except KeyError:
                pass
        finally:
            self.lock.release()
        # Now that we've released the lock, invoke the callbacks.
        for cb in cbs:
            cb(name,val)
    def _adjLiveThreads(self,n):
        """Helper: adjust the number of live threads by n"""
        self.lock.acquire()
        self.nLiveThreads += n
        self.lock.release()
    def _adjBusyThreads(self,n):
        """Helper: adjust the number of busy threads by n"""
        self.lock.acquire()
        self.nBusyThreads += n
        self.lock.release()

class DNSThread(threading.Thread):
    """Helper class: used by DNSCache to implement name resolution."""
    ## Fields:
    # dnscache: The DNSCache object that should receive our answers
    def __init__(self, dnscache):
        """Create a new DNSThread"""
        threading.Thread.__init__(self)
        self.dnscache = dnscache
        self.setDaemon(1) # When the process exits, don't wait for this thread.
    def run(self):
        """Thread body: pull questions from the DNS thread queue and
           answer them."""
        queue = self.dnscache.queue
        _lookupDone = self.dnscache._lookupDone
        _adjBusyThreads = self.dnscache._adjBusyThreads
        _adjLiveThreads = self.dnscache._adjLiveThreads
        try:
            _adjLiveThreads(1)
            try:
                while 1:
                    # Get a question from the queue, but don't wait more than
                    # MAX_THREAD_IDLE seconds
                    hostname = queue.get(timeout=MAX_THREAD_IDLE)
                    # If the question is None, shutdown.
                    if hostname is None:
                        return
                    # Else, resolve the IP and send the answer to the dnscache
                    _adjBusyThreads(1)
                    result = getIP(hostname)
                    _lookupDone(hostname, result)
                    _adjBusyThreads(-1)
            except QueueEmpty:
                LOG.debug("DNS thread shutting down: idle for %s seconds.",
                         MAX_THREAD_IDLE)
            except:
                LOG.error_exc(sys.exc_info(),
                              "Exception in DNS thread; shutting down.")
        finally:
            _adjLiveThreads(-1)

