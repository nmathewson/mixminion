# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: EventStats.py,v 1.5 2003/06/05 05:24:23 nickm Exp $

"""mixminion.server.EventStats

   Classes to gather time-based server statistics"""

__all__ = [ 'EventLog', 'NilEventLog' ]

import os
from threading import RLock
from time import time

from mixminion.Common import formatTime, LOG, previousMidnight, floorDiv, \
     createPrivateDir, MixError, readPickled, tryUnlink, writePickled

# _EVENTS: a list of all recognized event types.
_EVENTS = [ 'ReceivedPacket',
           'AttemptedRelay',
           'SuccessfulRelay', 'FailedRelay', 'UnretriableRelay',
           'AttemptedDelivery',
           'SuccessfulDelivery', 'FailedDelivery', 'UnretriableDelivery',
            ]

class NilEventLog:
    """Null implementation of EventLog interface: ignores all events and
       logs nothing.
    """
    def __init__(self):
        pass
    def save(self, now=None):
        """Flushes this eventlog to disk."""
        pass
    def rotate(self, now=None):
        """Move the pending events from this EventLog into a
           summarized text listing, and start a new pool.  Requires
           that it's time to rotate.
        """
        pass
    def getNextRotation(self):
        """Return a time after which it's okay to rotate the log."""
        return 0
    def _log(self, event, arg=None):
        """Notes that an event has occurred.
           event -- the type of event to note
           arg -- an optional topic of the event.
        """
        pass
    def receivedPacket(self, arg=None):
        """Called whenever a packet is received via MMTP."""
        self._log("ReceivedPacket", arg)
    def attemptedRelay(self, arg=None):
        """Called whenever we attempt to relay a packet via MMTP."""
        self._log("AttemptedRelay", arg)
    def successfulRelay(self, arg=None):
        """Called whenever packet delivery via MMTP succeeds"""
        self._log("SuccessfulRelay", arg)
    def failedRelay(self, arg=None):
        """Called whenever packet delivery via MMTP fails retriably"""
        self._log("FailedRelay", arg)
    def unretriableRelay(self, arg=None):
        """Called whenever packet delivery via MMTP fails unretriably"""
        self._log("UnretriableRelay", arg)
    def attemptedDelivery(self, arg=None):
        """Called whenever we attempt to deliver a message via an exit
           module.
        """
        self._log("AttemptedDelivery", arg)
    def successfulDelivery(self, arg=None):
        """Called whenever we successfully deliver a message via an exit
           module.
        """
        self._log("SuccessfulDelivery", arg)
    def failedDelivery(self, arg=None):
        """Called whenever an attempt to deliver a message via an exit
           module fails retriably.
        """
        self._log("FailedDelivery", arg)
    def unretriableDelivery(self, arg=None):
        """Called whenever an attempt to deliver a message via an exit
           module fails unretriably.
        """
        self._log("UnretriableDelivery", arg)

class EventLog(NilEventLog):
    """An EventLog records events, aggregates them according to some time
       periods, and logs the totals to disk.

       Currently we retain two log files: one holds an interval-by-interval
       human-readable record of past intervals; the other holds a pickled
       record of events in the current interval.

       We take some pains to avoid flushing the statistics when too
       little time has passed.  We only rotate an aggregated total to disk
       when:
           - An interval has passsed since the last rotation time
         AND
           - We have accumulated events for at least 75% of an interval's
             worth of time.

       The second requirement prevents the following unpleasant failure mode:
           - We set the interval to '1 day'.  At midnight on monday,
             we rotate.  At 00:05, we go down.  At 23:55 we come back
             up.  At midnight at tuesday, we noticing that it's been one
             day since the last rotation, and rotate again -- thus making
             a permanent record that reflects 10 minutes worth of traffic,
             potentially exposing more about individual users than we should.
    """
    ### Fields:
    # count: a map from event name -> argument|None -> total events received.
    # lastRotation: the time at which we last flushed the log to disk and
    #     reset the log.
    # filename, historyFile: Names of the pickled and long-term event logs.
    # rotateInterval: Interval after which to flush the current statistics
    #     to disk.
    # _lock: a threading.RLock object that must be held when modifying this
    #     object.
    # accumulatedTime: number of seconds since last rotation that we have
    #     been logging events.
    # lastSave: last time we saved the file.
    ### Pickled format:
    # Map from {"count","lastRotation","accumulatedTime"} to the values
    # for those fields.
    def __init__(self, filename, historyFile, interval):
        """Intializes an EventLog that caches events in 'filename', and
           periodically writes to 'historyFile' every 'interval' seconds."""
        NilEventLog.__init__(self)
        if os.path.exists(filename):
            self.__dict__.update(readPickled(filename))
            assert self.count is not None
            assert self.lastRotation is not None
            assert self.accumulatedTime is not None
        else:
            self.count = {}
            for e in _EVENTS:
                self.count[e] = {}
            self.lastRotation = time()
            self.accumulatedTime = 0
        self.filename = filename
        self.historyFilename = historyFile
        for fn in filename, historyFile:
            parent = os.path.split(fn)[0]
            createPrivateDir(parent)
        self.rotateInterval = interval
        self.lastSave = time()
        self._setNextRotation()
        self._lock = RLock()
        self.save()

    def save(self, now=None):
        """Write the statistics in this log to disk, rotating if necessary."""
        try:
            self._lock.acquire()
            self._save(now)
        finally:
            self._lock.release()

    def _save(self, now=None):
        """Implements 'save' method.  For internal use.  Must hold self._lock
           to invoke."""
        LOG.debug("Syncing statistics to disk")
        if not now: now = time()
        tmpfile = self.filename + "_tmp"
        tryUnlink(tmpfile)
        self.accumulatedTime += int(now-self.lastSave)
        self.lastSave = now
        writePickled(self.filename, { 'count' : self.count,
                                      'lastRotation' : self.lastRotation,
                                      'accumulatedTime' : self.accumulatedTime,
                                      })

    def _log(self, event, arg=None):
        try:
            self._lock.acquire()
            try:
                self.count[event][arg] += 1
            except KeyError:
                try:
                    self.count[event][arg] = 1
                except KeyError:
                    raise KeyError("No such event: %r" % event)
        finally:
            self._lock.release()

    def getNextRotation(self):
        return self.nextRotation

    def rotate(self,now=None):
        if now is None: now = time()
        if now < self.nextRotation:
            raise MixError("Not ready to rotate event stats")
        try:
            self._lock.acquire()
            self._rotate(now)
        finally:
            self._lock.release()

    def _rotate(self, now=None):
        """Flush all events since the last rotation to the history file,
           and clears the current event log."""

        # Must hold lock
        LOG.debug("Flushing statistics log")
        if now is None: now = time()

        f = open(self.historyFilename, 'a')
        self.dump(f, now)
        f.close()

        self.count = {}
        for e in _EVENTS:
            self.count[e] = {}
        self.lastRotation = now
        self._save(now)
        self.accumulatedTime = 0
        self._setNextRotation(now)

    def dump(self, f, now=None):
        """Write the current data to a file handle 'f'."""
        if now is None: now = time()
        try:
            self._lock.acquire()
            startTime = self.lastRotation
            endTime = now
            print >>f, "========== From %s to %s:" % (formatTime(startTime,1),
                                                      formatTime(endTime,1))
            for event in _EVENTS:
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
                length = max((length, 10))
                fmt = "    %"+str(length)+"s: %s"
                for arg in args:
                    v = count[arg]
                    if arg is None: arg = "{Unknown}"
                    print >>f, fmt % (arg, v)
                    total += v
                print >>f, fmt % ("Total", total)
        finally:
            self._lock.release()

    def _setNextRotation(self, now=None):
        """Helper function: calculate the time when we next rotate the log."""
        # ???? Lock to 24-hour cycle

        # This is a little weird.  We won't save *until*:
        #       - .75 * rotateInterval seconds are accumulated.
        #  AND  - rotateInterval seconds have elapsed since the last
        #         rotation.
        #
        # IF the rotation interval is divisible by one hour, we also
        #  round to the hour, up to 5 minutes down and 55 up.
        if not now: now = time()

        accumulatedTime = self.accumulatedTime + (now - self.lastSave)
        secToGo = max(0, self.rotateInterval * 0.75 - accumulatedTime)
        self.nextRotation = max(self.lastRotation + self.rotateInterval,
                                now + secToGo)

        if self.nextRotation < now:
            self.nextRotation = now

        if (self.rotateInterval % 3600) == 0:
            mid = previousMidnight(self.nextRotation)
            rest = self.nextRotation - mid
            self.nextRotation = mid + 3600 * floorDiv(rest+55*60, 3600)

def configureLog(config):
    """Given a configuration file, set up the log.  May replace the log global
       variable.
    """
    global log
    if config['Server']['LogStats']:
        LOG.info("Enabling statistics logging")
        homedir = config['Server']['Homedir']
        statsfile = config['Server'].get('StatsFile')
        if not statsfile:
            statsfile = os.path.join(homedir, "stats")
        workfile = os.path.join(homedir, "work", "stats.tmp")
        log = EventLog(
           workfile, statsfile, config['Server']['StatsInterval'].getSeconds())
        LOG.info("Statistics logging enabled")
    else:
        log = NilEventLog()
        LOG.info("Statistics logging disabled")

# Global variable: The currently configured event log.
log = NilEventLog()
