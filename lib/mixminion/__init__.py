# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: __init__.py,v 1.24 2003/02/12 01:22:14 nickm Exp $

"""mixminion

   Client and shared code for type III anonymous remailers.
   """

# This version string is generated from setup.py; don't edit it.
__version__ = "0.0.3alpha"
# This 5-tuple encodes the version number for comparison.  Don't edit it.
# The first 3 numbers are the version number; the 4th is:
#          0 for alpha
#         50 for beta
#         99 for release candidate
#        100 for release.
# The 5th is a patchlevel.  If -1, it is suppressed.
# Either the 4th or 5th number may be a string.  If so, it is not meant to
#   succeed or preceed any other sub-version with the same a.b.c version
#   number.
version_info = (0, 0, 3, 0, -1)
__all__ = [ 'server', 'directory' ]

def version_tuple_to_string(t):
    assert len(t) == 5
    if t[3] == 0:
        s1 = "alpha"
    elif t[3] == 50:
        s1 = "beta"
    elif t[3] == 99:
        s1 = "rc"
    elif t[3] == 100:
        s1 = ""
    else:
        s1 = "(%s)"%t[3]
    if t[4] > -1:
        if s1:
            s2 = "p%s"%t[4]
        else:
            s2 = str(t[4])
    else:
        s2 = ""
    return "%s.%s.%s%s%s" % (t[0],t[1],t[2],s1,s2)

assert __version__ == version_tuple_to_string(version_info)

## This next segment keeps pychecker from making spurious complaints.
import sys
if sys.modules.has_key("pychecker"):
    import mixminion.ClientMain
    import mixminion.server
    import mixminion.test
    import mixminion.testSupport
del sys
