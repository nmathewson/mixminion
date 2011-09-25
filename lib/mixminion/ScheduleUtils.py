# Copyright 2002-2011 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.ScheduleUtils

   Simple implementation of a block-until-it's-time-to-do-something scheduler.
   """

import time
import threading

__all__ = [ 'ScheduledEvent', 'OneTimeEvent', 'RecurringEvent',
            'RecurringComplexEvent', 'RecurringBackgroundEvent',
            'RecurringComplexBackgroundEvent', 'Scheduler' ]

class ScheduledEvent:
    """Abstract base class for a scheduleable event."""
    def getNextTime(self):
        """Return the next time when this event should be called.  Return
           -1 for 'never' and 'None' for 'currently unknown'.
        """
        raise NotImplementedError("getNextTime")
    def __call__(self):
        """Invoke this event."""
        raise NotImplementedError("__call__")

class OneTimeEvent:
    """An event that will be called exactly once."""
    def __init__(self, when, func):
        """Create an event to call func() at the time 'when'."""
        self.when = when
        self.func = func
    def getNextTime(self):
        return self.when
    def __call__(self):
        self.func()
        self.when = -1

class RecurringEvent:
    """An event that will be called at regular intervals."""
    def __init__(self, when, func, repeat):
        """Create an event to call func() at the time 'when', and every
           'repeat' seconds thereafter."""
        self.when = when
        self.func = func
        self.repeat = repeat
    def getNextTime(self):
        return self.when
    def __call__(self):
        try:
            self.func()
        finally:
            self.when += self.repeat

class RecurringComplexEvent(RecurringEvent):
    """An event that will be called at irregular intervals."""
    def __init__(self, when, func):
        """Create an event to invoke func() at time 'when'.  func() must
           return -1 for 'do not call again', or a time when it should next
           be called."""
        RecurringEvent.__init__(self, when, func, None)
    def __call__(self):
        self.when = self.func()

class RecurringBackgroundEvent:
    """An event that will be called at regular intervals, and scheduled
       as a background job.  Does not reschedule the event while it is
       already in progress."""
    def __init__(self, when, scheduleJob, func, repeat):
        """Create an event to invoke 'func' at time 'when' and every
           'repeat' seconds thereafter.   The function 'scheduleJob' will
           be invoked with a single callable object in order to run that
           callable in the background.
        """
        self.when = when
        self.scheduleJob = scheduleJob
        self.func = func
        self.repeat = repeat
        self.running = 0
        self.lock = threading.Lock()
    def getNextTime(self):
        self.lock.acquire()
        try:
            if self.running:
                return None
            else:
                return self.when
        finally:
            self.lock.release()
    def __call__(self):
        self.lock.acquire()
        try:
            if self.running:
                return
            self.running = 1
        finally:
            self.lock.release()

        self.scheduleJob(self._background)
    def _background(self):
        """Helper function: this one is actually invoked by the background
           thread."""
        self.func()
        self.lock.acquire()
        try:
            now = time.time()
            while self.when < now:
                self.when += self.repeat
            self.running = 0
        finally:
            self.lock.release()

class RecurringComplexBackgroundEvent(RecurringBackgroundEvent):
    """An event to run a job at irregular intervals in the background."""
    def __init__(self, when, scheduleJob, func):
        """Create an event to invoke 'func' at time 'when'.  func() must
           return -1 for 'do not call again', or a time when it should next
           be called.

           The function 'scheduleJob' will be invoked with a single
           callable object in order to run that callable in the
           background.
        """
        RecurringBackgroundEvent.__init__(self, when, scheduleJob, func, None)
    def _background(self):
        next = self.func()
        self.lock.acquire()
        try:
            self.when = next
            self.running = 0
        finally:
            self.lock.release()

class Scheduler:
    """Base class: used to run a bunch of events periodically."""
    ##Fields:
    # scheduledEvents: a list of ScheduledEvent objects.
    # schedLock: a threading.RLock object to protect the list scheduledEvents
    #   (but not the events themselves).
    #XXXX008 needs more tests
    def __init__(self):
        """Create a new scheduler."""
        self.scheduledEvents = []
        self.schedLock = threading.RLock()

    def firstEventTime(self):
        """Return the time at which an event will first occur."""
        self.schedLock.acquire()
        try:
            if not self.scheduledEvents:
                return -1
            first = 0
            for e in self.scheduledEvents:
                t = e.getNextTime()
                if t in (-1,None): continue
                if not first or t < first:
                    first = t
            return first
        finally:
            self.schedLock.release()

    def scheduleEvent(self, event):
        """Add a ScheduledEvent to this scheduler"""
        when = event.getNextTime()
        if when == -1:
            return
        self.schedLock.acquire()
        try:
            self.scheduledEvents.append(event)
        finally:
            self.schedLock.acquire()

    #XXXX008 -- these are only used for testing.
    def scheduleOnce(self, when, name, cb):
        self.scheduleEvent(OneTimeEvent(when,cb))

    def scheduleRecurring(self, first, interval, name, cb):
        self.scheduleEvent(RecurringEvent(first, cb, interval))

    def scheduleRecurringComplex(self, first, name, cb):
        self.scheduleEvent(RecurringComplexEvent(first, cb))

    def processEvents(self, now=None):
        """Run all events that need to get called at the time 'now'."""
        if now is None:
            now = time.time()
        self.schedLock.acquire()
        try:
            events = [(e.getNextTime(),e) for e in self.scheduledEvents]
            self.scheduledEvents = [e for t,e in events if t != -1]
            runnable = [(t,e) for t,e in events
                        if t not in (-1,None) and t <= now]
        finally:
            self.schedLock.release()
        runnable.sort()
        for _,e in runnable:
            e()
