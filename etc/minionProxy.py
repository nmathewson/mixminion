from IMAPproxy import *
from minionSMTP import *
import getpass

import asyncore

imap_address = 'imap.hermes.cam.ac.uk'
local_host = '127.0.0.1'
smtp_port = 20025
imap_port = 20110

if __name__ == '__main__':
    import __main__
    print 'Mixminion password:'
    mm_Pass = getpass.getpass()
    proxy1 = IMAPproxy((local_host, imap_port),imap_address,mm_Pass)
    proxy2 = minionSMTP((local_host,smtp_port),mm_Pass)
    
    try:
        asyncore.loop()
    except KeyboardInterupt:
        pass
