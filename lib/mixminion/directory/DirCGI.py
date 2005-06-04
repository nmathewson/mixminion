# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DirCGI.py,v 1.9 2005/06/04 13:55:04 nickm Exp $

"""mixminion.directory.DirCGI

   Backend for directory-publish CGI.
   """

__all__ = [ ]

# Edit this to the configured value "Homedir" in .mixminion_dir.cf
DIRECTORY_BASE = "/home/nickm/src/MixminionDirectory"

import cgi
import os
import sys
from mixminion.directory.Directory import Directory
from mixminion.directory.ServerInbox import ServerQueuedException
from mixminion.Common import UIError

try:
    import cgitb
except ImportError:
    cgitb = None

def run():
    if cgitb is not None:
        cgitb.enable()
    assert sys.version_info[:3] >= (2,2,0)

    def err(s):
        print "Status: 0\nMessage:",s
        sys.exit(0)

    print "Content-type: text/plain\n\n"

    form = cgi.FieldStorage()
    if not form.has_key('desc'):
        err("no desc field found")

    desc = form.getfirst('desc')
    assert type(desc) == type('')

    d = Directory(location=DIRECTORY_BASE)
    inbox = d.getInbox()

    address = "<%s:%s>" % (os.environ.get("REMOTE_ADDR"),
                           os.environ.get("REMOTE_PORT"))

    try:
        os.umask(022)
        inbox.receiveServer(desc, address)
        print "Status: 1\nMessage: Accepted."
    except UIError, e:
        print "Status: 0\nMessage: %s"%e
    except ServerQueuedException, e:
        print "Status: 1\nMessage: %s"%e
