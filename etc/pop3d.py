# pop3d.py - A python implementation of the POP3 standard (RFC 1939)
#
# version: 0.0.1 (dodgy/experimental)
#
# author: George Danezis (gd216@cl.cam.ac.uk)
#         (for the mixminion project, and inspired by the smtpd.py server)
#
# overview:
#    To implement any functionality extend the 'POP3Server' class,
#    and redefine the methods:
#    - get_pop3_messages(self, user, passd)
#   (is called after authentication USER + PASS)
#    To provide a list of messages for the user.
#    Return an empty list if no messages are available for this user,
#    and None if the user does not exist or the password was not correct 
#    - set_pop3_messages(self, user, msgs)
#    (Is called when the connection is ended ie. QUIT)
#    'msgs' is a list of the remaining messages.
#    Return 'None' if the messages have been correctly stored,
#    or a string containing an error message.
#
# TODO:
# - Refactor UIDL + LIST
# - Refactor TOP + RETR
# - Unify the checks for command parameters
# - Make a command line interface

import sys
import os
import pwd
import errno
import getopt
import time
import socket
import asyncore
import asynchat

import re
import copy
import md5
import base64


class Devnull:
    def write(self, msg): pass
    def flush(self): pass


# Routines to 'byte stuff' the messages to be transmitted
LFCR = re.compile('[^\r](\n)+')
DOTSTUFF = re.compile('\r\n\.\r\n')

def byte_stuff(msg):
    m = LFCR.sub(lambda x: x.group(0)[0]+'\r\n'*(len(x.group(0))-1), msg)
    if m[-2:] <> '\r\n':
        m += '\r\n'
    m = DOTSTUFF.sub('\r\n..\r\n',m)
    return m

DEBUGSTREAM = Devnull()
NEWLINE = '\n'
EMPTYSTRING = ''
__version__ = 'Python POP3d version 0.0.1 (dodgy/experimental)'

# The channel abstraction takes care of the socket and the session.
class POP3Channel(asynchat.async_chat):
    # The three states POP3 can be in.
    AUTH = 0
    TRAN = 1
    UPDA = 3

    def __init__(self, server, conn, addr):
        asynchat.async_chat.__init__(self, conn)
        # Store values
        self.__server = server
        self.__conn = conn
        self.__addr = addr
        self.__line = []

        # Store received information
        self.__state = self.AUTH
        self.__username = None
        self.__password = None
        self.__messages = None
        self.__oldmessages = None

        # TODO: check that it IS localhost
        self.__peer = conn.getpeername()
        print >> DEBUGSTREAM, 'Peer:', repr(self.__peer)

        # The server goes first.
        self.push('+OK %s' % (__version__))
        self.set_terminator('\r\n')

    # Overrides base class for convenience
    # always add a CRLF
    def push(self, msg):
        asynchat.async_chat.push(self, msg + '\r\n')

    # Implementation of base class abstract method
    def collect_incoming_data(self, data):
        self.__line.append(data)

    # Implementation of base class abstract method
    def found_terminator(self):
        line = EMPTYSTRING.join(self.__line)
        self.__line = []

        if not line:
            # An empty command?
            # This should not happen!
            self.push('-ERR No POP3 command')
            return

        # Cut the command
        print line
        method = None
        i = line.find(' ')
            
        # Make the command upper case
        if i < 0:
            command = line.upper()
            arg = None
        else:
            command = line[:i].upper()
            arg = line[i+1:].strip()

        # Find the corresponding command in the class
        method = getattr(self, 'pop3_' + command, None)
        if not method:
            self.push('-ERR Command %s not recognised' % command)
            return
        method(arg)
        return

    # The user name message
    def pop3_USER(self,arg):
        if self.__state <> self.AUTH:
            self.push('-ERR Not in authorisation phase')
            return
        if arg == '' or arg == None:
            self.push('-ERR \'%s\' bad user name' % arg)
            return
        if arg.find(' ') > -1:
            self.push('-ERR \'%s\' bad user name' % arg)
            return
        self.__username = arg
        self.push('+OK Welcome %s' % arg)
        return

    # The user name password
    #
    # This is also the routine that takes care of the
    # transition between AUTH and TRAN states.
    #
    # It calls the "get_pop3_messages" as overwridden by
    # programmer to get a list of available messages for this user.
    def pop3_PASS(self,arg):
        if self.__state <> self.AUTH:
            self.push('-ERR Not in authorisation phase')
            return
        if arg == '' or arg == None:
            self.push('-ERR No password?')
            return
        if self.__username == None:
            self.push('-ERR No username provided!')
            return
        if self.__messages <> None:
            self.push('-ERR Internal messup')
            return
        self.__password = arg
        self.__messages = self.__server.get_pop3_messages(self.__username,
                                                          self.__password)
        if self.__messages == None:
            self.push('-ERR Authentication failure')
            self.__username = None
            self.__password = None
            return
        # For each message it makes a tuple (message number, message)
        # The numbers start at one (1)

        # Old messages is ALWAYS the list as returned by 'get_pop3_messages'
        self.__oldmessages = (lambda y: map(lambda k: (k+1,y[k]),range(len(y))))(self.__messages)

        # We will be deleting messages from '__messages'
        self.__messages = copy.deepcopy(self.__oldmessages)
        self.__state = self.TRAN
        self.push('+OK Accepted')
        return

    # Returns agregate statistics
    def pop3_STAT(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR STAT not authorised')
            return

        if self.__messages == None:
            self.push('-ERR Internal error')
            return

        # How many messages
        l = len(self.__messages)
        # The overall size
        if self.__messages == []:
            s = 0
        else:
            s = reduce(lambda x,y: x+y,map(lambda (x,y): len(y),self.__messages))
        
        self.push('+OK %i %i' % (l,s))
        return

    # provides a list of messages
    def pop3_LIST(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR LIST not authorised')
            return

        if self.__messages == None:
            self.push('-ERR Internal error')
            return

        if arg == None:
            if self.__messages == []:
                self.push('+OK 0 messages (0 octets)')
                return
            else:
                l = len(self.__messages)
                s = reduce(lambda x,y: x+y,map(lambda (x,y): len(y),self.__messages))
                self.push('+OK %i messages (%i octets)' % (l,s))
                for (i,j) in self.__messages:
                    self.push('%i %i' % (i,len(j)))
                self.push('.')
                return
        else:
            if not  arg.isdigit():
                self.push('-ERR %s not a decimal number' % arg)
                return
            
            m = filter(lambda (x,y): x == int(arg),self.__messages)
            if m == []:
                self.push('-ERR no such message')
                return
            else:
                [(i,j)] = m
                self.push('+OK %i %i' % (i, len(j)))
                return

    # Retrieving a message
    def pop3_RETR(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR RETR not authorised')
            return

        if self.__messages == None:
            self.push('-ERR Internal error')
            return

        if arg == None:
            self.push('-ERR No message number')
            return

        if not arg.isdigit():
            self.push('-ERR %s not a decimal number' % arg)
            return

        m = filter(lambda (x,y): x == int(arg),self.__messages)
        if m == []:
            self.push('-ERR no such message')
            return
        else:
            [(i,j)] = m
            m2 = byte_stuff(j)
            self.push('+OK %s octets' % len(m2))
            self.push(m2+'.')
            return

    # Delete a message
    #
    # note that the message is deleted from the __messages list,
    # but the __oldmessages list is not touched. All messages can
    # therefore be undeleted if there is no clean close down of the
    # connection or if a RSET command is received.
    def pop3_DELE(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR DELE not authorised')
            return

        if self.__messages == None:
            self.push('-ERR Internal error')
            return

        if arg == None:
            self.push('-ERR No message number')
            return

        if not arg.isdigit():
            self.push('-ERR %s not a decimal number' % arg)
            return

        m = filter(lambda (x,y): x == int(arg),self.__messages)
        if m == []:
            self.push('-ERR no such message')
            return
        else:
            self.__messages.remove(m[0])
            self.push('+OK message deleted')
            return

    # Does nothing but only in TRAN mode :)
    def pop3_NOOP(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR NOOP not authorised')
            return
        
        self.push('+OK I am getting bored')
        return

    # Undeletes all messages
    #
    # It copies __oldmessages back into __messages
    def pop3_RSET(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR RSET not authorised')
            return

        self.__messages = copy.deepcopy(self.__oldmessages)
        self.push('+OK undeleted everything')
        return

    # It closes the connection after having reported back
    # to the server which messages must be deleted and which
    # are to be stored.
    def pop3_QUIT(self,arg):
        if self.__state == self.AUTH:
            self.push('+OK Bye')
            self.close_when_done()
            return
        
        if self.__state == self.TRAN:
            # We will do something more smart than just returning the
            # remaining messages. We will return tuple (0|1,m) indicating
            # that a message has been deleted or not.

            # the remaining messages
            m = map(lambda (x,y): y, self.__messages)

            # The list we will return
            ret = []
            for (x,msg) in self.__oldmessages:
                if msg in m:
                    ret += [(0,msg)]
                else:
                    ret += [(1,msg)]
            
            status = self.__server.set_pop3_messages(self.__username, ret)
            if status == None:
                self.push('+OK Bye')
            else:
                self.push('-ERR %s' % status)
            self.close_when_done()
            return

    # Command to return the header and n first lines of message.
    def pop3_TOP(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR TOP not authorised')
            return

        if self.__messages == None:
            self.push('-ERR Internal error')
            return

        if arg == None:
            self.push('-ERR No message number')
            return

        # Parses the two arguments: file / no of lines
        b1 = arg.find(' ')
        if b1 < 0:
            self.push('-ERR Two integer parameters are needed')
            return
        a1 = arg[:b1]
        a2 = arg[b1+1:]
        
        if not a1.isdigit() or not a2.isdigit():
            self.push('-ERR \'%s\' or \'%s\' not a decimal number' % (a1,a2))
            return

        # Gets the right message
        m = filter(lambda (x,y): x == int(a1),self.__messages)
        if m == []:
            self.push('-ERR no such message')
            return
        else:
            # Extracts the header and first n lines
            [(i,j)] = m
            m2 = byte_stuff(j)
            b = re.search('\r\n\r\n',m2)
            if b != None:
                b = b.start()
                head = m2[:b]
                body = re.split('\r\n',m2[b+4:])
                m2 = head+'\r\n\r\n'
                top_len = int(a2)
                for i in range(top_len):
                    m2 += body[i]+'\r\n'
                
            self.push('+OK %s octets' % len(m2))
            self.push(m2+'.')
            return

    # Optional commands

    # Like list but returns unique ids instead of file lengths
    def pop3_UIDL(self,arg):
        if self.__state <> self.TRAN:
            self.push('-ERR UIDL not authorised')
            return

        if self.__messages == None:
            self.push('-ERR Internal error')
            return

        if arg == None:
            if self.__messages == []:
                self.push('+OK 0 messages (0 octets)')
                return
            else:
                l = len(self.__messages)
                s = reduce(lambda x,y: x+y,map(lambda (x,y): len(y),self.__messages))
                self.push('+OK %i messages (%i octets)' % (l,s))
                for (i,j) in self.__messages:
                    # The unique id is the 14 first characters
                    # of the md5 of the message encoded in base64
                    md = md5.new()
                    md.update(j)
                    md_res = (base64.encodestring(md.digest()))[:14]
                    self.push('%i %s' % (i,md_res))
                self.push('.')
                return
        else:
            if not  arg.isdigit():
                self.push('-ERR %s not a decimal number' % arg)
                return
            
            m = filter(lambda (x,y): x == int(arg),self.__messages)
            if m == []:
                self.push('-ERR no such message')
                return
            else:
                [(i,j)] = m
                md = md5.new()
                md.update(j)
                md_res = (base64.encodestring(md.digest()))[:14]
                self.push('+OK %i %s' % (i, md_res))
                return

# The actual server that listens to the port, and redirects connections.
# Redifine:
# - get_pop3_messages(self, user, passd)
#   (is called after authentication USER + PASS)
#   To provide a list of messages for the user.
#   Return an empty list if no messages are available for this user,
#   and None if the user does not exist or the password was not correct 
#
# - set_pop3_messages(self, user, msgs)
#   (Is called when the connection is ended ie. QUIT)
#   'msgs' is a list of the remaining messages.
#   Return 'None' if the messages have been correctly stored,
#   or a string containing an error message.
class POP3Server(asyncore.dispatcher):
    def __init__(self, localaddr):
        self._localaddr = localaddr
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        # try to re-use a server port if possible
        self.socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR,
            self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) | 1)
        self.bind(localaddr)
        self.listen(5)
        print '%s started at %s\n\tLocal addr: %s\n\t' % (
            self.__class__.__name__, time.ctime(time.time()),
            localaddr)

    def handle_accept(self):
        conn, addr = self.accept()
        print >> DEBUGSTREAM, 'Incoming connection from %s' % repr(addr)
        channel = POP3Channel(self, conn, addr)

    # API for "doing something useful with the message"
    def get_pop3_messages(self, user, passd):
        """Override this abstract method to handle messages from the client.

        This method should return a sequence fo message, that will be presented
        to the user. If none is returned, there has been an error.

        If an empty sequence in returned there are no messages.

        """
        return []
    
        raise UnimplementedError

    def set_pop3_messages(self, user, msgs):
        """Override this method to update the message store.

        This method should return None if no errors have occured in storing
        the messages left, otherwise it should return an error string.

        """
      
        # sample implementation simply prints messages
        print 'New box', user, msgs
        return None # No errors


