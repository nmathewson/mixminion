# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DNSFarm.py,v 1.3 2003/11/07 08:11:36 nickm Exp $

"""mixminion.server.DNSFarm DOCDOC"""

import socket
import threading
import time
import sys
from mixminion.Common import LOG, TimeoutQueue, QueueEmpty
from mixminion.NetUtils import getIP

__all__ = [ 'DNSCache' ]

class _Pending:
    def __cmp__(self,o):
        return cmp(type(self), type(o))
PENDING = _Pending

MIN_THREADS = 2
MIN_FREE_THREADS = 1
MAX_THREADS = 8
MAX_THREAD_IDLE = 5*60
MAX_ENTRY_TTL = 15*60


class DNSCache:
    """DOCDOC"""
    def __init__(self):
        self.cache = {} # name -> getIP return / PENDING
        self.callbacks = {}
        self.lock = threading.RLock()
        self.queue = TimeoutQueue()
        self.threads = []
        self.nLiveThreads = 0
        self.nBusyThreads = 0
        self.cleanCache()
    def getNonblocking(self, name):
        try:
            self.lock.acquire()
            return self.cache.get(name)
        finally:
            self.lock.release()
    def lookup(self,name,cb):
        try:
            self.lock.acquire()
            v = self.cache.get(name)
            if v is None or v is PENDING:
                self.callbacks.setdefault(name, []).append(cb)
            #XXXX006 We should check for literal addresses before we queue
            if v is None:
                self._beginLookup(name)
        finally:
            self.lock.release()
        if v is not None and v is not PENDING:
            cb(name,v)
    def shutdown(self, wait=0):
        try:
            self.lock.acquire()
            self.queue.clear()
            for _ in xrange(self.nLiveThreads*2):
                self.queue.put(None)
            if wait:
                for thr in self.threads:
                    thr.join()
        finally:
            self.lock.release()
    def cleanCache(self):
        try:
            self.lock.acquire()

            # Purge old entries
            now = time.time()
            cache = self.cache            
            for name in cache.keys():
                v = cache[name]
                if v is PENDING: continue
                if now-v[2] > MAX_ENTRY_TTL:
                    del cache[name]

            # Remove dead threads from self.threads
            self.threads = [ thr for thr in self.threads
                             if thr.isLive() ]

            # Make sure we have enough threads.
            if len(self.threads) < MIN_THREADS:
                for _ in xrange(len(self.threads)-MIN_THREADS):
                    self.threads.append(DNSThread(self))
                    self.threads[-1].start()
        finally:
            self.lock.release()
    def _beginLookup(self,name):
        # Must hold lock
        self.cache[name] = PENDING
        self.queue.put(name)
        if (self.nLiveThreads < self.nBusyThreads + MIN_FREE_THREADS
            and self.nLiveThreads < MAX_THREADS):
            self.threads.append(DNSThread(self))
            self.threads[-1].start()
    def _lookupDone(self,name,val):
        try:
            self.lock.acquire()
            self.cache[name]=val
            cbs = self.callbacks.get(name,[])
            try:
                del self.callbacks[name]
            except KeyError:
                pass
        finally:
            self.lock.release()
        for cb in cbs:
            cb(name,val)
    def _adjLiveThreads(self,n):
        self.lock.acquire()
        self.nLiveThreads += n
        self.lock.release()
    def _adjBusyThreads(self,n):
        self.lock.acquire()
        self.nBusyThreads += n
        self.lock.release()

class DNSThread(threading.Thread):
    def __init__(self, dnscache):
        threading.Thread.__init__(self)
        self.dnscache = dnscache
        self.setDaemon(1)
    def run(self):
        self.dnscache._adjLiveThreads(1)
        try:
            try:
                while 1:
                    hostname = self.dnscache.queue.get(timeout=MAX_THREAD_IDLE)
                    if hostname is None:
                        return
                    self.dnscache._adjBusyThreads(1)
                    result = getIP(hostname)
                    self.dnscache._lookupDone(hostname, result)
                    self.dnscache._adjBusyThreads(-1)
            except QueueEmpty:
                LOG.debug("DNS thread shutting down: idle for %s seconds.",
                         MAX_THREAD_IDLE)
            except:
                LOG.error_exc(sys.exc_info(),
                              "Exception in DNS thread; shutting down.")
        finally:
            self.dnscache.adjLiveThreads(-1)


