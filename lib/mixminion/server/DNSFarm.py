# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DNSFarm.py,v 1.1 2003/10/13 17:32:25 nickm Exp $

"""mixminion.server.DNSFarm DOCDOC"""

import socket
import threading
import time
import sys
from mixminion.Common import LOG, TimeoutQueue, QueueEmpty

__all__ = [ 'DNSCache' ]

class _Pending:
    def __cmp__(self,o):
        return cmp(type(self), type(o))
PENDING = _Pending
NOENT = -1

MIN_THREADS = 2
MIN_FREE_THREADS = 1
MAX_THREADS = 8
MAX_THREAD_IDLE = 5*60
MAX_ENTRY_TTL = 15*60
PREFER_INET4 = 1

class DNSCache:
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
            if v is None:
                self.callbacks.setdefault(name, []).append(cb)
                self._beginLookup(name)
        finally:
            self.lock.release()
        if v is not None:
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
            self.threads = [ thr for thr in self.threads()
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

if hasattr(socket, 'getaddrinfo'):
    def getIP(name):
        try:
            r = socket.getaddrinfo(name, None)
            inet4 = [ addr[4][0] for addr in r if addr[0] == socket.AF_INET ]
            inet6 = [ addr[4][0] for addr in r if addr[0] == socket.AF_INET6 ]
            if not (inet4 or inet6):
                LOG.error("getaddrinfo returned no inet addresses!")
                return (NOENT, "No inet addresses returned", time.time())
            best4=best6=None
            now=time.time()
            if inet4: best4=(socket.AF_INET,inet4[0],now)
            if inet6: best6=(socket.AF_INET,inet6[0],now)
            if PREFER_INET4:
                res = best4 or best6
            else:
                res = best6 or best4
            protoname = (res[0] == socket.AF_INET) and "inet" or "inet6"
            LOG.trace("Result for getaddrinfo(%r): %s:%s (%d others dropped)",
                      name,protoname,res[1],len(r)-1)
            return res
        except socket.error, e:
            LOG.trace("Result for getaddrinfo(%r): error:%r",name,e)
            if len(e.args) == 2:
                return (NOENT, str(e[1]), time.time())
            else:
                return (NOENT, str(e), time.time())            
else:
    def getIP(name):
        '''return family/NOENT, address/error, time'''
        try:
            r = socket.gethostbyname(name)
            LOG.trace("Result for gethostbyname(%r): inet:%r",name,r)
            return (socket.AF_INET, r, time.time())
        except socket.error, e:
            LOG.trace("Result for gethostbyname(%r): error:%r",name,e)
            if len(e.args) == 2:
                return (NOENT, str(e[1]), time.time())
            else:
                return (NOENT, str(e), time.time())
