# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.NetUtils

   This module holds helper code for network-related operations."""

__all__ = [ ]

import errno
import re
import select
import signal
import socket
import string
import sys
import time
from mixminion.Common import LOG, TimeoutError, _ALLCHARS
import mixminion._minionlib

#======================================================================
# Global vars

# When we get IPv4 and IPv6 addresses for the same host, which do we use?
PREFER_INET4 = 1  # For now, _always_ prefer IPv4

# Local copies of socket.AF_INET4 and socket.AF_INET6.  (AF_INET6 may be
#  unsupported.)
AF_INET = socket.AF_INET
AF_INET6 = getattr(socket, "AF_INET6", "<Sorry, no IP6>")

# For windows -- list of errno values that we can expect when blocking IO
# blocks on a connect.
IN_PROGRESS_ERRNOS = [ getattr(errno, ename)
   for ename in [ "EINPROGRESS", "WSAEWOULDBLOCK"]
   if hasattr(errno,ename) ]
del ename

IPTOS_THROUGHPUT = getattr(mixminion._minionlib, "IPTOS_THROUGHPUT", None)

#======================================================================
def optimizeThroughput(sock):
    """Set the socket options on 'sock' to maximize throughput."""
    if not IPTOS_THROUGHPUT:
        return
    if sys.platform in ('cygwin', 'dgux', 'sni-sysv'):
        # According to rumor, these platforms handle socket.IP_TOS
        # incorrectly.  I'm too chicken to take the chance until
        # I hear differetly.
        return
    sock.setsockopt(socket.SOL_IP, socket.IP_TOS, IPTOS_THROUGHPUT)

#======================================================================
if hasattr(socket, 'getaddrinfo'):
    def getIPs(name):
        r = []
        ai = socket.getaddrinfo(name,None)
        now = time.time()
        for family, _, _, _, addr in ai:
            if family not in (AF_INET, AF_INET6):
                continue
            r.append((family, addr[0], now))
        return r
else:
    def getIPs(name):
        addr = socket.gethostbyname(name)
        return [ (AF_INET, addr, time.time()) ]

getIPs.__doc__ = \
     """Resolve the hostname 'name' and return a list of answers.  Each
        answer is a 3-tuple of the form: (Family, Address, Time), where
        Family is AF_INET or AF_INET6, Address is an IPv4 or IPv6 address,
        and Time is the time at which the answer was returned.  Raise
        a subclass of socket.error if no answers are found."""

def getIP(name, preferIP4=PREFER_INET4):
    """Resolve the hostname 'name' and return the 'best' answer.  An
       answer is either a 3-tuple as returned by getIPs, or a 3-tuple of
       ('NOENT', reason, Time) if no answers were found.

       If both IPv4 and IPv6 addresses are found, return an IPv4 address
       iff preferIPv4 is true.

       If this host does not support IPv6, never return an IPv6 address;
       return a ('NOENT', reason, Time) tuple if only ipv6 addresses are
       found.
    """
    _,haveIP6 = getProtocolSupport()
    if not haveIP6: haveIP4 = 1
    try:
        r = getIPs(name)
        inet4 = [ addr for addr in r if addr[0] == AF_INET ]
        inet6 = [ addr for addr in r if addr[0] == AF_INET6 ]
        if not (inet4 or inet6):
            LOG.warn("getIP returned no inet addresses for %r",name)
            return ("NOENT", "No inet addresses returned", time.time())
        if inet6 and not inet4 and not haveIP6:
            return ("NOENT",
                 "All addresses were IPv6, and this host has no IPv6 support",
                 time.time())
        best4=best6=None
        if inet4: best4=inet4[0]
        if inet6: best6=inet6[0]
        if preferIP4:
            res = best4 or best6
        else:
            res = best6 or best4
        assert res
        assert res[0] in (AF_INET, AF_INET6)
        assert nameIsStaticIP(res[1])
        protoname = (res[0] == AF_INET) and "inet" or "inet6"
        LOG.trace("Result for getIP(%r): %s:%s (%d others dropped)",
                  name,protoname,res[1],len(r)-1)
        return res
    except socket.error, e:
        LOG.trace("Result for getIP(%r): error:%r",name,e)
        if len(e.args) == 2:
            return ("NOENT", str(e[1]), time.time())
        else:
            return ("NOENT", str(e), time.time())

#----------------------------------------------------------------------

_SOCKETS_SUPPORT_TIMEOUT = hasattr(socket.SocketType, "settimeout")

def connectWithTimeout(sock,dest,timeout=None):
    """Same as sock.connect, but timeout after 'timeout' seconds.  This
       functionality is built-in to Python2.3 and later."""
    if timeout is None:
        return sock.connect(dest)
    elif _SOCKETS_SUPPORT_TIMEOUT:
        t = sock.gettimeout()
        try:
            sock.settimeout(timeout)
            try:
                return sock.connect(dest)
            except socket.error, e:
                if e[0] in IN_PROGRESS_ERRNOS:
                    raise TimeoutError("Connection timed out")
                else:
                    raise
        finally:
            sock.settimeout(t)
    else:
        sock.setblocking(0)
        try:
            try:
                sock.connect(dest)
            except socket.error, e:
                if e[0] not in IN_PROGRESS_ERRNOS:
                    raise
            fd = sock.fileno()
            try:
                _,wfds,_ = select.select([],[fd],[], timeout)
            except select.error, e:
                raise
            if not wfds:
                raise TimeoutError("Connection timed out")
##             try:
##                 sock.connect(dest)
##             except select.error, e:
##                 if e[0] != errno.EISCONN:
##                     raise
        finally:
            sock.setblocking(1)

#----------------------------------------------------------------------

_PREV_DEFAULT_TIMEOUT = None

def setAlarmTimeout(timeout):
    """Begin a timeout with signal.alarm"""
    if hasattr(signal, 'alarm'):
        # Windows doesn't have signal.alarm.
        def sigalrmHandler(sig,_): pass
        signal.signal(signal.SIGALRM, sigalrmHandler)
        signal.alarm(timeout)

def clearAlarmTimeout(timeout):
    """End a timeout set with signal.alarm"""
    if hasattr(signal, 'alarm'):
        signal.alarm(0)

def setGlobalTimeout(timeout,noalarm=0):
    """Set the global connection timeout to 'timeout' -- either with
       signal.alarm or socket.setdefaulttimeout, whiche ever we support.
       (If noalarm is true, don't use signal.alarm.)"""
    global _PREV_DEFAULT_TIMEOUT
    assert timeout > 0
    if _SOCKETS_SUPPORT_TIMEOUT:
        _PREV_DEFAULT_TIMEOUT = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
    elif not noalarm:
        setAlarmTimeout(timeout)

def exceptionIsTimeout(ex):
    """Return true iff ex is likely to be a timeout."""
    if isinstance(ex, socket.error):
        if ex[0] in IN_PROGRESS_ERRNOS:
            return 1
        elif ex[0] == errno.EINTR and not _SOCKETS_SUPPORT_TIMEOUT:
            return 1
    return 0

def unsetGlobalTimeout(noalarm=0):
    """Clear the global timeout."""
    global _PREV_DEFAULT_TIMEOUT
    if _SOCKETS_SUPPORT_TIMEOUT:
        socket.setdefaulttimeout(_PREV_DEFAULT_TIMEOUT)
    elif hasattr(signal, 'alarm') and not noalarm:
        signal.alarm(0)

#----------------------------------------------------------------------
_PROTOCOL_SUPPORT = None

def getProtocolSupport():
    """Return a 2-tuple of booleans: do we support IPv4, and do we
      support IPv6?"""
    global _PROTOCOL_SUPPORT
    if _PROTOCOL_SUPPORT is not None:
        return _PROTOCOL_SUPPORT

    res = [0,0]
    for pos, familyname, loopback in ((0, "AF_INET", "127.0.0.1"),
                                      (1, "AF_INET6", "::1")):
        family = getattr(socket, familyname, None)
        if family is None: continue
        s = None
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.connect((loopback, 9)) # discard port
            res[pos] = 1 # Everything worked, so we must have IP(foo) support.
        except socket.error:
            pass
        if s is not None:
            s.close()

    _PROTOCOL_SUPPORT = tuple(res)
    return _PROTOCOL_SUPPORT

#----------------------------------------------------------------------

# Regular expression to match a dotted quad.
_ip_re = re.compile(r'^\d+\.\d+\.\d+\.\d+$')

def normalizeIP4(ip):
    """If IP is an IPv4 address, return it in canonical form.  Raise
       ValueError if it isn't."""

    i = ip.strip()

    # inet_aton is a bit more permissive about spaces and incomplete
    # IP's than we want to be.  Thus we use a regex to catch the cases
    # it doesn't.
    if not _ip_re.match(i):
        raise ValueError("Invalid IP %r" % i)
    try:
        socket.inet_aton(i)
    except socket.error:
        raise ValueError("Invalid IP %r" % i)

    return i

_IP6_CHARS="01233456789ABCDEFabcdef:."

def normalizeIP6(ip6):
    """If IP is an IPv6 address, return it in canonical form.  Raise
       ValueError if it isn't."""
    ip = ip6.strip()
    bad = ip6.translate(_ALLCHARS, _IP6_CHARS)
    if bad:
        raise ValueError("Invalid characters %r in address %r"%(bad,ip))
    if len(ip) < 2:
        raise ValueError("IPv6 address %r is too short"%ip)

    items = ip.split(":")
    if not items:
        raise ValueError("Empty IPv6 address")
    if items[:2] == ["",""]:
        del items[0]
    if items[-2:] == ["",""]:
        del items[-1]
    foundNils = 0
    foundWords = 0 # 16-bit words

    for item in items:
        if item == "":
            foundNils += 1
        elif '.' in item:
            normalizeIP4(item)
            if item is not items[-1]:
                raise ValueError("Embedded IPv4 address %r must appear at end of IPv6 address %r"%(item,ip))
            foundWords += 2
        else:
            try:
                val = string.atoi(item,16)
            except ValueError:
                raise ValueError("IPv6 word %r did not parse"%item)
            if not (0 <= val <= 0xFFFF):
                raise ValueError("IPv6 word %r out of range"%item)
            foundWords += 1

    if foundNils > 1:
        raise ValueError("Too many ::'s in IPv6 address %r"%ip)
    elif foundNils == 0 and foundWords < 8:
        raise ValueError("IPv6 address %r is too short"%ip)
    elif foundWords > 8:
        raise ValueError("IPv6 address %r is too long"%ip)

    return ip

def nameIsStaticIP(name):
    """If 'name' is a static IPv4 or IPv6 address, return a 3-tuple as getIP
       would return.  Else return None."""
    name = name.strip()
    if ':' in name:
        try:
            val = normalizeIP6(name)
            return (AF_INET6, val, time.time())
        except ValueError:
            return None
    elif name and name[0].isdigit():
        try:
            val = normalizeIP4(name)
            return (AF_INET, val, time.time())
        except ValueError:
            return None
    else:
        return None

