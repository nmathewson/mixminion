#! /usr/bin/env python
# Copyright (c) 2003-2004 George Danezis; see LICENSE for copying info.

"""An SMTP mixminion proxy that anonymizes your email traffic

Syntax: minionSMTP [-hV] [localhost:localport]
-h, --help          - prints this help message
-V, --version       - prints the version
localhost:localport - changes the default hostname and port

By default it listens on the address 127.0.0.1 port 20025 for
incoming SMTP traffic. It then extracts the subject line, the
nickname contained in the "from" field, and the body of the message
and relays them anonymously through the mixminion network to all
receivers.

The nickname is the portion of the from field that does not contain
the email address e.g. for Red Monkey <red.monkey@jungle.za> the
nickname "Red Monkey" will be extracted. This can be set by most email
clients. Note that not all mixminion exit nodes support custom
nicknames.

MIME is supported but only the text/plain parts are relayed. The
others contain too much information to be safe.

You need to have installed mixminion and the program also needs 
to be on your path. See http://mixminion.net for more information.

Bugs and comments to "George.Danezis@cl.cam.ac.uk"
"""

import sys
import os
import time
import asyncore
import getopt

import smtpd
import email
import re

import mmUtils
import getpass
import cPickle

program = sys.argv[0]
__version__ = 'Mixminion SMTP proxy - 0.0.1'

class minionSMTP(smtpd.SMTPServer):

    def __init__(self, localaddr,passwd):
        self.__passwd = passwd
        smtpd.SMTPServer.__init__(self,localaddr,localaddr)
        print '%s started at %s\n\tLocal addr: %s\n\t' % (
            self.__class__.__name__, time.ctime(time.time()),
            localaddr)

    def process_message(self, peer, mailfrom, rcpttos, data):
        """ Provides the SMTP to mixminion forwarding mechanism.

        Mail is accepted through SMTP. The address of the receipients
        is extracted and anonymous messages are sent to all of them.

        Only the body of the message is forwarded, but also the subject
        and nickname contained in the headers are extracted and sent along. 
        """

        # print peer,mailfrom,rcpttos,data

        # Use the email package to extract headers and body.
        msg = email.message_from_string(data)

        # Extract the message subject
        if 'subject' in msg:
            subject = msg['subject']
        else:
            subject = ''

        # Extract "from" field nickname and return address
	import re
        nickname = ''
        retaddrs = None
        if 'from' in msg:
            m = re.search('^([^@<]*)', msg['from'])
            if m != None:
                nickname = m.group(1).strip()

            m = re.search('([^< ]*@[^> ]*)', msg['from'])
            if m != None:
                retaddrs = m.group(1).strip()

        print "Started sending"

        # Extract the body of the message
        body = None
        if msg.is_multipart():
            for msgx in msg.get_payload():
                # It should also contain the encoding, hmmm...
                # maybe I should check for it too.
                if msgx['content-type'].find('text/plain') != -1:
                   body = msgx.get_payload()
        else:
            body = msg.get_payload()

        # Check that a body was found
        if body == None:
            print "No body found - make sure you send some text/plain"
            return "501 no text/plain body found"

        if retaddrs != None:
            surb = mmUtils.getSURB(retaddrs,nickname,self.__passwd)
            print surb,retaddrs,nickname,self.__passwd
            body = body +'\n'+surb[0]

        # Base mixminion command
        cmd = []
        
        # Augment the command with a nickname
        if nickname != '':
            cmd.append('--from=\"%s\"' % nickname)

        if subject != '':
            cmd.append('--subject=\"%s\"' % subject)

        for address in rcpttos:
            taz = re.findall('([^@]*)@nym.taz',address)

            # Reply to anonymous sender case.
            if len(taz) > 0:
                surb_id = taz[0]
                if surb_id == 'anonymous':
                    # TODO: send back an error message
                    print 'Cannot send to anonymous'
                    continue
                surb_file = {}
                if 'surb_file.dat' in os.listdir('.'):
                    surb_file = cPickle.load(file('surb_file.dat','r'))

                if surb_file.has_key(surb_id):
                    surb_list = surb_file[surb_id]
                    if len(surb_list) == 0:
                        # Send back an error message
                        print 'No more SURBs available'
                        del surb_file[surb_id]
                    else:
                        result = mmUtils.reply(body,surb_list[0],cmd)
                        print result
                        m = re.search("sent", result)
            
                        if m == None:
                            return "502 Mixminion did not confirm sending"
                        else:
                            surb_file[surb_id] = surb_list[1:]
                            print "Done"

                    cPickle.dump(surb_file,file('surb_file.dat','w'))
                else:
                    print 'No address known for: %s@nym.taz'%taz[0]
            else:
                # For each address it sends the message using mixminion.
                result = mmUtils.send(body,address,cmd)
                m = re.search("sent", result)
            
                if m == None:
                    return "502 Mixminion did not confirm sending"
                else:
                    print "Done"
        # raise UnimplementedError

if __name__ == '__main__':
    # Parse the command line arguments
    # -V, --version   - gives the version
    # -h, --help      - gives some help
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], 'Vh',
            ['version', 'help'])
    except getopt.error, e:
        print e

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print __doc__
            sys.exit(0)
        elif opt in ('-V', '--version'):
            print >> sys.stderr, __version__
            sys.exit(0)
    
    # parse the rest of the arguments
    if len(args) < 1:
        localspec = '127.0.0.1:20025'
    else:
        localspec = args[0]

    # split into host/port pairs
    i = localspec.find(':')
    if i < 0:
        print 'Bad local spec: %s' % localspec
    localhost = localspec[:i]
    try:
        localport = int(localspec[i+1:])
    except ValueError:
        print 'Bad local port: %s' % localspec

    proxy = minionSMTP((localhost,localport),getpass.getpass())
    # proxy = smtpd.DebuggingServer(('127.0.0.1',20025),None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass
