# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Common.py,v 1.3 2002/06/02 06:11:16 nickm Exp $

"""mixminion.Common

   Common functionality and utility code for Mixminion"""

__all__ = [ 'MixError', 'MixFatalError' ]

class MixError(Exception):
    """Base exception class for all Mixminion errors"""
    pass

class MixFatalError(MixError):
    """Exception class for unrecoverable Mixminion errors."""
    pass
