# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Queue.py,v 1.2 2002/06/25 11:41:08 nickm Exp $

"""mixminion.Queue

   Facility for a fairly secure, directory-based, unordered queue.
   """

import os
import base64
import time
import stat

from mixminion.Common import MixError, MixFatalError, secureDelete
from mixminion.Crypto import AESCounterPRNG

__all__ = [ 'Queue' ]

# Mode to pass to open(2) for creating a new file, and dying if it already
# exists.
_NEW_MESSAGE_MODE = os.O_WRONLY+os.O_CREAT+os.O_EXCL
# On windows or mac, binary != text.
_NEW_MESSAGE_MODE += getattr(os, 'O_BINARY', 0)

# Any inp_* files older than INPUT_TIMEOUT seconds old are assumed to be
# trash.
INPUT_TIMEOUT = 600

class Queue:
    """A Queue is an unordered collection of files with secure remove and
       move operations.

       Implementation: a queue is a directory of 'messages'.  Each
       filename in the directory has a name in one of the following
       formats:

             rmv_HANDLE   (A message waiting to be deleted)
             msg_HANDLE  (A message waiting in the queue.
             inp_HANDLE  (An incomplete message being created.)
       (Where HANDLE is a randomly chosen 8-character selection from the
       characters 'A-Za-z0-9+-'.  [Collision probability is negligable.])
       """
    # Fields:   rng--a random number generator for creating new messages
    #                and getting a random slice of the queue.
    #           dir--the location of the queue.
    def __init__(self, location, create=0, scrub=0):
        """Creates a queue object for a given directory, 'location'.  If
           'create' is true, creates the directory if necessary.  If 'scrub'
           is true, removes any incomplete or invalidated messages from the
           Queue."""
        self.rng = AESCounterPRNG()
        self.dir = location

        if not os.path.isabs(location):
            #FFFF Need a warning mechanism.
            print "Warning: queue path '%s' isn't absolute"%location

        if os.path.exists(location) and not os.path.isdir(location):
            raise MixFatalError("%s is not a directory" % location)

        if not os.path.exists(location):
            if create:
                os.mkdir(location, 0700)
            else:
                raise MixFatalError("No directory for queue %s" % location)

        # Check permissions
        mode = os.stat(location)[stat.ST_MODE]
        if mode & 0077:
            # FFFF be more Draconian.
            # FFFF Need a warning mechanism.
            print "Worrisome mode %o on directory %s" % (mode, location)

        if scrub:
            self.cleanQueue(1)

    def queueMessage(self, contents):
        """Creates a new message in the queue whose contents are 'contents',
           and returns a handle to that message."""
        f, handle = self.openNewMessage()
        f.write(contents)
        self.finishMessage(f, handle)
        return handle

    def count(self):
        """Returns the number of complete messages in the queue."""
        res = 0
        for fn in os.listdir(self.dir):
            if fn.startswith("msg_"):
                res += 1
        return res

    def pickRandom(self, count=None):
        """Returns a list of 'count' handles to messages in this queue.
           The messages are chosen randomly, and returned in a random order.

           If there are fewer than 'count' messages in the queue, all the
           messages will be retained."""

        messages = [fn for fn in os.listdir(self.dir) if fn.startswith("msg_")]

        n = len(messages)
        if count is None:
            count = n
        else:
            count = min(count, n)

        # This permutation algorithm yields all permutation with equal
        # probability (assuming a good rng); others do not.
        for i in range(count-1):
            swap = i+self.rng.getInt(n-i-1)
            v = messages[swap]
            messages[swap] = messages[i]
            messages[i] = v

        return [m[4:] for m in messages[:count]]

    def removeMessage(self, handle):
        """Given a handle, removes the corresponding message from the queue."""
        self.__changeState(handle, "msg", "rmv")
        secureDelete(os.path.join(self.dir, "rmv_"+handle))

    def removeAll(self):
        """Removes all messages from this queue."""
        removed = []
        for m in os.listdir(self.dir):
            if m[:4] in ('inp_', 'msg_'):
                self.__changeState(m[4:], m[:3], "rmv")
                removed.append(os.path.join(self.dir, "rmv_"+m[4:]))
        secureDelete(removed)

    def moveMessage(self, handle, queue):
        """Given a handle and a queue, moves the corresponding message from
           this queue to the queue provided.  Returns a new handle for
           the message in the destination queue."""
        # Since we're switching handle, we don't want to just rename;
        # We really want to copy and delete the old file.
        newHandle = queue.queueMessage(self.messageContents(handle))
        self.removeMessage(handle)
        return newHandle

    def openMessage(self, handle):
        """Given a handle for an existing message, returns a file descriptor
           open to read that message."""
        return open(os.path.join(self.dir, "msg_"+handle), 'rb')

    def messageContents(self, handle):
        """Given a messagge handle, returns the contents of the corresponding
           message."""
        f = open(os.path.join(self.dir, "msg_"+handle), 'rb')
        s = f.read()
        f.close()
        return s

    def openNewMessage(self):
        """Returns (file, handle) tuple to create a new message.  Once
           you're done writing, you must call finishMessage to
           commit your changes, or abortMessage to reject them."""
        handle = self.__newHandle()
        fname = os.path.join(self.dir, "inp_"+handle)
        fd = os.open(fname, _NEW_MESSAGE_MODE, 0600)
        return os.fdopen(fd, 'w'), handle

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
        secureDelete(os.path.join(self.dir, "rmv_"+handle))

    def cleanQueue(self, initial=0):
        """Removes all timed-out or trash messages from the queue.  If
           'initial', assumes we're starting up and nobody's already removing
           messages.  Else, assumes halfway-removed messages are garbage."""
        rmv = []
        allowedTime = int(time.time()) - INPUT_TIMEOUT
        for m in os.listdir(self.dir):
            if initial and m.startswith("rmv_"):
                rmv.append(os.path.join(self.dir, m))
            elif m.startswith("inp_"):
                s = os.stat(m)
                if s[stat.ST_MTIME] < allowedTime:
                    self.__changeState(m[4:], "inp", "rmv")
                    rmv.append(os.path.join(self.dir, m))
        secureDelete(rmv)

    def __changeState(self, handle, s1, s2):
        """Helper method: changes the state of message 'handle' from 's1'
           to 's2'."""
        os.rename(os.path.join(self.dir, s1+"_"+handle),
                  os.path.join(self.dir, s2+"_"+handle))

    def __newHandle(self):
        """Helper method: creates a new random handle."""
        junk = self.rng.getBytes(6)
        return base64.encodestring(junk).strip().replace("/","-")
