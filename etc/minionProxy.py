"""An SMTP and POP3 server that anonymize all traffic using mixminion

Syntax: python minionProxy.py [-Vh] [-H imap_host] [-P pop3_port] [-S smtp_port] [-L local_host]
-h, --help          - prints this help message
-V, --version       - prints the version
-H, --host          - The remote IMAP host to connect and fetch messages from.
-P, --pop3port      - The local POP3 port (default is 20110)
-S, --smtpport      - The local SMTP port (default is 20025)
-L, --localhost     - The local address servers bind to (default "127.0.0.1")

The minionProxy acts as a local SMTP and POP3 server, and your
favorite email client can be configured to talk to it. It extracts the
subject line, the nickname contained in the "from" field, and the body
of the message and relays them anonymously through the mixminion
network to all receivers. The nickname is the portion of the "from"
field that does not contain the email address e.g. for Red Monkey
<red.monkey@jungle.za> the nickname "Red Monkey" will be
extracted. This can be set by most email clients. Note that not all
mixminion exit nodes support custom nicknames.

Each anonymous message sent out has attached a Single Use Reply Block,
that can be used by your correspondant to reply (once) to your
message. The email portion of the "from" field is encoded as the
recipient email address (e.g. "red.monkey@jungle.za" for the example
above)

(Only) Anonymous messages available on the IMAP server specified are
automatically decoded and can be downloaded using the simple POP3
protocol. Note that the username and password you specify (using your
mail client) for the POP3 server is used in fact to authenticate with
the IMAP server. If the messages contain single use reply blocks the
address of the form "xxxxxx@nym.taz" can be used to reply. Otherwise
it is not possible to reply (and the reply address is
"anonymous@nym.taz")

You need to have the mixminion program on your path for minionProxy
to work. Download it at: http://mixminion.net
For comments and BUGS contact "George.Danezis@cl.cam.ac.uk" """

from IMAPproxy import *
from minionSMTP import *
import getpass

import asyncore

program = sys.argv[0]
__version__ = 'Mixminion SMTP/POP3 form IMAP proxy - 0.0.1'

if __name__ == '__main__':
    import __main__

    imap_address = None
    local_host = '127.0.0.1'
    smtp_port = 20025
    imap_port = 20110
    # Parse the command line arguments
    # -V, --version   - gives the version
    # -h, --help      - gives some help
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], 'VhH:P:S:L:',
            ['version', 'help','host','pop3port','smtpport','localhost'])
    except getopt.error, e:
        print e

        print opts
    for opt, arg in opts:
        if opt in ('-H', '--host'):
            imap_address = arg
            print opt,arg,imap_address
        elif opt in ('-I', '--imapport'):
            try:
                imap_port = int(arg)
            except ValueError:
                print 'POP3 port is not a number'
                pass
        elif opt in ('-L', '--localhost'):
            local_host = arg
        elif opt in ('-S', '--smtlport'):
            try:
                imap_port = int(arg)
            except:
                print 'SMTP port is not a number'
                pass
        elif opt in ('-h', '--help'):
            print __doc__
            sys.exit(0)
        elif opt in ('-V', '--version'):
            print >> sys.stderr, __version__
            sys.exit(0)

    print 'Mixminion password:'
    mm_Pass = getpass.getpass()
    if imap_address != None:
        proxy1 = IMAPproxy((local_host, imap_port),imap_address,mm_Pass)
    proxy2 = minionSMTP((local_host,smtp_port),mm_Pass)
    
    try:
        asyncore.loop()
    except KeyboardInterupt:
        print 'Bye...'
        pass
