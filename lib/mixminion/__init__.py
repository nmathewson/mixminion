# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: __init__.py,v 1.47 2003/09/05 21:45:19 nickm Exp $

"""mixminion

   Client and shared code for type III anonymous remailers.
   """

# This version string is generated from setup.py; don't edit it.
__version__ = "0.0.5"
# This 5-tuple encodes the version number for comparison.  Don't edit it.
# The first 3 numbers are the version number; the 4th is:
#          0 for alpha
#         50 for beta
#         99 for release candidate
#        100 for release.
# The 5th is a patchlevel.  If -1, it is suppressed.
# The 4th or 5th number may be a string.  If so, it is not meant to
#   succeed or precede any other sub-version with the same a.b.c version
#   number.
version_info = (0, 0, 5, 100, -1)
__all__ = [ 'server', 'directory' ]

def version_tuple_to_string(t):
    assert len(t) == 5
    major, minor, sub, status, patch = t
    if status == 0:
        s1 = "alpha"
    elif status == 50:
        s1 = "beta"
    elif status == 98:
        s1 = "pre"
    elif status == 99:
        s1 = "rc"
    elif status == 100:
        s1 = ""
    elif type(status) == type(1):
        s1 = "(%s)"%status
    else:
        s1 = status
    if patch != -1:
        if not s1:
            s2 = ".%s"%patch
        else:
            s2 = str(patch)
    else:
        s2 = ""
    return "%s.%s.%s%s%s" % (t[0],t[1],t[2],s1,s2)

def parse_version_string(s):
    import re
    r = re.compile(r'(\d+)\.(\d+)\.(\d+)(?:([^\d\(]+|\(\d+\))(\d+)?)?')
    m = r.match(s)
    if not m:
        raise ValueError
    major, minor, sub, status, patch = m.groups()
    if not status or status in ('.', 'p'):
        status = 100
    elif status == 'rc':
        status = 99
    elif status == 'pre':
        status = 98
    elif status == 'beta':
        status = 50
    elif status == 'alpha':
        status = 0
    elif status[0] == '(' and status[-1] == ')':
        try:
            status = int(status[1:-1])
        except ValueError:
            status = status
    else:
        status = status
    if not patch:
        patch = -1
    else:
        try:
            patch = int(patch)
        except ValueError:
            patch = patch
    return (int(major), int(minor), int(sub), status, patch)

def cmp_versions(a,b):
    r = cmp(a[0],b[0])
    if r: return r
    r = cmp(a[1],b[1])
    if r: return r
    r = cmp(a[2],b[2])
    if r: return r
    if type(a[3]) == type(b[3]) == type(1):
        r = cmp(a[3],b[3])
        if r: return r
    elif a[3] != b[3]:
        raise ValueError, "Can't compare versions"

    return cmp(a[4],b[4])

assert __version__ == version_tuple_to_string(version_info)
assert parse_version_string(__version__) == version_info
assert cmp_versions(version_info, version_info) == 0

## This next segment keeps pychecker from making spurious complaints.
import sys
if sys.modules.has_key("pychecker"):
    import mixminion.ClientMain
    import mixminion.server
    import mixminion.test
    import mixminion.testSupport
del sys
