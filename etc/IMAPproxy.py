import pop3d

import mmUtils


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
import getpass
import imaplib
import cPickle
import email

def md5hash(m):
    md = md5.new()
    md.update(m)
    md_res = (base64.encodestring(md.digest()))
    return md_res[:22]

class IMAPproxy(pop3d.POP3Server):
    """ An IMAP to POP3 proxy that fetches anonymous mail

    It then delivers it to the POP3 mail box.
    """
    def __init__(self, localaddr, ser, passwd):
        "Server and Mixminion must be specified"
        self.__server = ser
        print 'IMAP login on %s' % (ser)
        self.__pass = passwd
        pop3d.POP3Server.__init__(self,localaddr)
        self.__cachedIDs = []
        
    # API for "doing something useful with the message"
    def get_pop3_messages(self, user, passd):

        # Get the IMAP messages
        try:
            M = imaplib.IMAP4(self.__server)
            M.login(user, passd)
            M.select()
            # Filter for anonymous messages 
            typ, data = M.search(None, '(HEADER "X-Anonymous" "yes")')
            ms = []
            for num in data[0].split():
                typ, data = M.fetch(num, '(RFC822)')
                ms = ms + [data[0][1]]
            M.logout()
        except M.error, inst:
            print "IMAP exception:",inst
            # TODO: Should really include an "error" message here.
            return []


        # Implement a list of previously seen messages.
        # The list of messages confirmed by the mail client
        if 'seen_files.dat' in os.listdir('.'):
            print 'loading seen file'
            seenlist = cPickle.load(file('seen_files.dat','r'))
        else:
            seenlist = []

        # Filter out messages that are already seen.
        ms = filter(lambda x:not md5hash(x) in seenlist,ms)
        self.__cachedIDs = map(lambda x: md5hash(x), ms)

        # Decodes the anonymous messages

        # The decode routine does not like '\r\n' so
        # I need to transform everything to '\n'
        ms = map(lambda x:re.sub('\r\n','\n',x),ms)

        # How to recognise a SURB:
        surbPat = re.compile('(?:- )?(-----BEGIN TYPE III REPLY BLOCK-----)([^\-]*)(?:- )?(-----END TYPE III REPLY BLOCK-----)',re.S)

         # The list of surbs cached by the client.
        if 'surb_file.dat' in os.listdir('.'):
            surb_file = cPickle.load(file('surb_file.dat','r'))
        else:
            surb_file = {}

        ms2 = []
        for m in ms:
            msg = email.message_from_string(m)
            # Decode the body of the message
            bx = mmUtils.decode(msg.get_payload(),passd)

            # By default allow no reply.
            reply_addrs = '%s@nym.taz' % 'anonymous'

            # Extract any SURBs and store them.
            rs = surbPat.findall(bx)
            rs = map(lambda (x,y,z): "%s%s%s" % (x,y,z),rs)

            if len(rs) > 0:
                bx = surbPat.sub('',bx)
                surb_file[md5hash(rs[0])[:10]] = rs
                reply_addrs = '%s@nym.taz' % md5hash(rs[0])[:10]

            # Set the reply addresses with none@nym.taz or the SURB IDs.
            del msg['Return-Path']
            msg['Return-Path'] = reply_addrs
            new_from = re.sub('([^<]*@[^>]*)',reply_addrs,msg['From'])
            del msg['From']
            msg['From'] = new_from
            msg.set_payload(bx)
            ms2 += [msg.as_string()]

        # Add '\r\n' back at the end of each line!
        m2 = map(lambda x:re.sub('\n','\r\n',x),ms2)

        # Save the SURBs
        cPickle.dump(surb_file,file('surb_file.dat','w'))

        return m2

    def set_pop3_messages(self, user, msgs):
        # Loads the list of seen (by the client) messages 
        seenlist = []
        if 'seen_files.dat' in os.listdir('.'):
            seenlist = cPickle.load(file('seen_files.dat','r'))
        else:
            seenlist = []

        # Stores the IDs of seen messages
        for (i,(d,m)) in zip(range(len(msgs)),msgs):
            if d:
                seenlist += [self.__cachedIDs[i]]

        cPickle.dump(seenlist,file('seen_files.dat','w'))
        self.__cachedIDs =[]
        return None # No errors


if __name__ == '__main__':
    import __main__
    proxy = IMAPproxy(('127.0.0.1', 20110),'imap.hermes.cam.ac.uk',getpass.getpass())

    try:
        asyncore.loop()
    except KeyboardInterupt:
        pass
