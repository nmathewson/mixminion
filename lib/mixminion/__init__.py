# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: __init__.py,v 1.12 2002/12/16 17:43:24 nickm Exp $

"""mixminion

   Client and shared code for type III anonymous remailers.
   """

__version__ = "0.0.1"
__all__ = [ 'server' ]

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
