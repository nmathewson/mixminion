# Copyright 2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DirCGI.py,v 1.2 2003/05/27 04:56:48 nickm Exp $

"""mixminion.directory.DirCGI

   Backend for directory-publish CGI.
   """

__all__ = [ ]

DIRECTORY_BASE = None

import cgi
import os
import sys
from mixminion.directory.Directory import Directory

assert sys.version_info[:3] >= (2,2,0)

try:
    import cgitb; cgitb.enable()
except ImportError:
    pass

def err(s):
    print "Status: 0\nMessage:",s
    sys.exit(0)

print "Content-type: text/plain\n\n"

form = cgi.FieldStorage()
if not form.has_key['desc']:
    err("no desc field found")

desc = form['desc']

if type(desc) == type([]):
    err("too many desc fields")

d = Directory(location=DIRECTORY_BASE)
inbox = d.getInbox()

address = "<%s:%s>" % (os.environ.get("REMOTE_ADDR"),
                       os.environ.get("REMOTE_PORT"))

inbox.receiveServer(desc, address)
