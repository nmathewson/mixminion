# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: __init__.py,v 1.14 2002/12/31 04:34:16 nickm Exp $

"""mixminion

   Client and shared code for type III anonymous remailers.
   """

__version__ = "0.0.2a0"
__all__ = [ 'server', 'directory' ]

## import mixminion.BuildMessage
## import mixminion.Crypto
## import mixminion.Common
## import mixminion.Config
## import mixminion.MMTPClient
## import mixminion.Packet
## import mixminion.ServerInfo

## This next segment keeps pychecker from making spurious complaints.
import sys
if sys.modules.has_key("pychecker"):
    import mixminion.ClientMain
    import mixminion.server
    import mixminion.test
    import mixminion.testSupport
del sys
