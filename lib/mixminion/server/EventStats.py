# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: EventStats.py,v 1.1 2003/03/26 16:36:46 nickm Exp $

"""mixminion.server.EventStats

   Classes to gather time-based server statistics"""

__all__ = [ 'EventLog', 'NilEventLog' ]

import cPickle
import os
from threading import RLock
from time import time

from mixminion.Common import formatTime, LOG

EVENTS = [ 'ReceivedPacket',
           'AttemptedRelay',
           'SuccessfulRelay', 'FailedRelay', 'UnretriableRelay',
           'AttemptedDelivery',
           'SuccessfulDelivery', 'FailedDelivery', 'UnretriableDelivery',
            ]

class NilEventLog:
    def __init__(self):
        pass
    def save(self):
        pass
    def log(self, event, arg=None):
        pass

class EventLog(NilEventLog):
    # Fields:
    # count (event -> arg -> value)
    # lastRotation
    # filename, historyFile
    # rotateInterval
    def __init__(self, filename, historyFile, interval):
        NilEventLog.__init__(self)
        if os.path.exists(filename):
            # XXXX If this doesn't work, then we should 
            f = open(filename, 'rb')
            self.__dict__.update(cPickle.load(f))
            f.close()
            assert self.count is not None
            assert self.lastRotation is not None
        else:
            self.count = {}
            for e in EVENTS:
                self.count[e] = {}
            self.lastRotation = time()
        self.filename = filename
        self.historyFilename = historyFile
        self.rotateInterval = interval
        self._lock = RLock()
        self.save()

    def save(self):
        try:
            self._lock.acquire()
            if time() > self.lastRotation + self.rotateInterval:
                self._rotate()
            self._save()
        finally:
            self._lock.release()
            
    def _save(self):
        # Must hold lock
        LOG.debug("Syncing statistics to disk")
        tmpfile = self.filename + "_tmp"
        try:
            os.unlink(tmpfile)
        except:
            pass
        f = open(tmpfile, 'wb')
        cPickle.dump({ 'count' : self.count, 'filename' : self.filename,
                       'lastRotation' : self.lastRotation },
                     f, 1)
        f.close()
        os.rename(tmpfile, self.filename)

    def log(self, event, arg=None):
        try:
            self._lock.acquire()
            if time() > self.lastRotation + self.rotateInterval:
                self._rotate()
            try:
                self.count[event][arg] += 1
            except KeyError:
                try:
                    self.count[event][arg] = 1
                except KeyError:
                    raise KeyError("No such event: %r" % event)
        finally:
            self._lock.release()

    def _rotate(self, now=None):
        # XXXX Change behavior: rotate indexed on midnight.
        
        # Must hold lock
        LOG.debug("Flushing statistics log")
        if now is None:
            now = time()
        f = open(self.historyFilename, 'a')
        self.dump(f)
        f.close()
        
        self.count = {}
        for e in EVENTS:
            self.count[e] = {}
        self.lastRotation = now
        self._save()

    def dump(self, f):
        try:
            self._lock.acquire()
            startTime = self.lastRotation
            endTime = time()
            print >>f, "========== From %s to %s:" % (formatTime(startTime,1),
                                                      formatTime(endTime,1))
            for event in EVENTS:
                count = self.count[event]
                if len(count) == 0:
                    print >>f, "  %s: 0" % event
                    continue
                elif len(count) == 1 and count.keys()[0] is None:
                    print >>f, "  %s: %s" % (event, count[None])
                    continue
                print >>f, "  %s:" % event
                total = 0
                args = count.keys()
                args.sort()
                length = max([ len(str(arg)) for arg in args ])
                fmt = "    %"+str(length)+"s: %s"
                for arg in args:
                    v = count[arg]
                    if arg is None: arg = "{Unknown}"
                    print >>f, fmt % (arg, v)
                    total += v
                print >>f, fmt % ("Total", total)
        finally:
            self._lock.release()

def setLog(eventLog):
    global THE_EVENT_LOG
    global log
    global save
    THE_EVENT_LOG = eventLog
    log = THE_EVENT_LOG.log
    save = THE_EVENT_LOG.save

def configureLog(config):
    if config['Server']['LogStats']:
        LOG.info("Enabling statistics logging")
        statsfile = config['Server']['StatsFile']
        if not statsfile:
            homedir = config['Server']['Homedir']
            statsfile = os.path.join(homedir, "stats")
        workfile = statsfile + ".work"
        setLog(EventLog(
            workfile, statsfile, config['Server']['StatsInterval'][2]))
    else:
        LOG.info("Statistics logging disabled")

setLog(NilEventLog())
