# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: __init__.py,v 1.23 2003/02/09 22:30:58 nickm Exp $

"""mixminion

   Client and shared code for type III anonymous remailers.
   """

# This version string is generated from setup.py; don't edit it.
__version__ = "0.0.3alpha"
# DOCDOC
version_info = (0, 0, 3, 'a', 0)
__all__ = [ 'server', 'directory' ]

## This next segment keeps pychecker from making spurious complaints.
import sys
if sys.modules.has_key("pychecker"):
    import mixminion.ClientMain
    import mixminion.server
    import mixminion.test
    import mixminion.testSupport
del sys
