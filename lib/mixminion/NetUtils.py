# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# Id: ClientMain.py,v 1.89 2003/06/05 18:41:40 nickm Exp $

"""mixminion.NetUtils

   This module holds helper code for network-related operations."""

__all__ = [ ]

import errno
import select
import signal
import socket
import time
from mixminion.Common import LOG, TimeoutError

#======================================================================
PREFER_INET4 = 1
AF_INET = socket.AF_INET
try:
    AF_INET6 = socket.AF_INET6
except AttributeError:
    AF_INET6 = "<Sorry, no IP6>"

# For windows -- list of errno values that we can expect when blocking IO
# blocks on a connect.
IN_PROGRESS_ERRNOS = [ getattr(errno, ename) 
   for ename in [ "EINPROGRESS", "WSAEWOULDBLOCK"]
   if hasattr(errno,ename) ]
del ename

#======================================================================
if hasattr(socket, 'getaddrinfo'):
    def getIPs(name):
        """DOCDOC"""
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
        
def getIP(name, preferIP4=PREFER_INET4):
    try:
        r = getIPs(name)
        inet4 = [ addr for addr in r if addr[0] == AF_INET ]
        inet6 = [ addr for addr in r if addr[0] == AF_INET6 ]
        if not (inet4 or inet6):
            LOG.error("getIP returned no inet addresses!")
            return ("NOENT", "No inet addresses returned", time.time())
        if inet4: best4=inet4[0]
        if inet6: best6=inet6[0]
        if preferIP4:
            res = best4 or best6
        else:
            res = best6 or best4
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
    """DOCDOC; sock must be blocking."""
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
                    raise TimeoutError()
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
                raise TimeoutError()
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
    if hasattr(signal, 'alarm'):
        def sigalrmHandler(sig,_): pass
        signal.signal(signal.SIGALRM, sigalrmHandler)
        signal.alarm(timeout)

def clearAlarmTimeout(timeout):
    if hasattr(signal, 'alarm'):
        signal.alarm(0)

def setGlobalTimeout(timeout,noalarm=0):
    global _PREV_DEFAULT_TIMEOUT
    assert timeout > 0
    if _SOCKETS_SUPPORT_TIMEOUT:
        _PREV_DEFAULT_TIMEOUT = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
    elif not noalarm:
        setAlarmTimeout(timeout)

def exceptionIsTimeout(ex):
    if isinstance(ex, socket.error):
        if ex[0] in IN_PROGRESS_ERRNOS:
            return 1
        elif ex[0] == errno.EINTR and not _SOCKETS_SUPPORT_TIMEOUT:
            return 1
    return 0

def unsetGlobalTimeout(noalarm=0):
    global _PREV_DEFAULT_TIMEOUT
    if _SOCKETS_SUPPORT_TIMEOUT:
        socket.setdefaulttimeout(_PREV_DEFAULT_TIMEOUT)
    elif hasattr(signal, 'alarm') and not noalarm:
        signal.alarm(0)

#----------------------------------------------------------------------
_PROTOCOL_SUPPORT = None

def getProtocolSupport():
    """DOCDOC"""
    global _PROTOCOL_SUPPORT
    if _PROTOCOL_SUPPORT is not None:
        return _PROTOCOL_SUPPORT

    res = [0,0]
    for pos, familyname, loopback in ((0, "AF_INET", "127.0.0.1"),
                                      (1, "AF_INET6", "::1")):
        family = getattr(socket, familyname)
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
            
    _PROTOCOL_SUPPORT = res
    return res
