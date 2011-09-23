# Copyright 2005 Nick Mathewson.  See LICENSE for licensing information.

"""mixminion.SExpression

   Implementation of Rivest's s-expressions as defined at
         http://theory.lcs.mit.edu/~rivest/sexp.txt
   and as used in SPKI and and SDSI.

   Mixminion doesn't use some of the features here; this is intended
   as a general-use pure-python implementation of the "proposed" SExpr
   standard.

   The functions below, we represent an s-epression as a set of nested
   sequences of strings.  For example, the s-expression
        (hello world (1 2 3) x)
   may be represented in python as
        ("hello", "world", ["1", "2", "3"], "x")
   or as
        ("hello", "world", ("1", "2", "3"), "x")

   Strings with 'display hints' are encoded as instances of the
   DisplayHint class below.

"""

__all__ = [ "DisplayHint",
            "write_canonical", "parse_canonical", "encode_canonical",
            "write_pretty", "parse", "encode_pretty"
            ]

import base64
import binascii
import re
import sys
import types

class DisplayHint:
    def __init__(self, hint, s):
        self.hint = hint
        self.s = s
    def getHint(self):
        return self.hint
    def __str__(self):
        return self.s

def _writeRaw(write,s):
    write(str(len(s)))
    write(":")
    write(s)

_TOKEN_RE = re.compile(r"[a-zA-Z\-\.\/\_\:\*\+\=][a-zA-Z0-9\-\.\/\_\:\*\+\=]*")
def _writeToken(write,s):
    assert _TOKEN_RE.match(s)
    write(s)

def _writeCanon_atom(write, rep):
    if isinstance(rep, types.StringType):
        _writeRaw(write, rep)
        return 1
    try:
        getHint = rep.getHint
    except AttributeError:
        return 0
    else:
        write("[")
        _writeRaw(write,getHint())
        write("]")
        _writeRaw(str(rep))
        return 1

def write_canonical(write, rep):
    if _writeCanon_atom(write, rep):
        return

    stack = []
    idx = 0
    write("(")
    while 1:
        while idx == len(rep):
            write(")")
            try:
                rep,idx = stack.pop()
            except IndexError:
                return
        if _writeCanon_atom(write,rep[idx]):
            idx += 1
            continue
        stack.append((rep,idx+1))
        rep = rep[idx]
        idx = 0
        write("(")

def _enc_raw(rep):
    if isinstance(rep, types.StringType):
        return "%s:%s"%(len(rep), rep)
    try:
        getHint = rep.getHint
    except AttributeError:
        return None
    else:
        hint = getHint()
        return "[%s:%s]%s:%s"%(len(hint),hint,len(rep),rep)

def encode_canonical(rep):
    s = _enc_raw(rep)
    if s is not None:
        return s
    stack = []
    idx = 0
    result = [ "(" ]
    add = result.append
    while 1:
        while idx == len(rep):
            add(")")
            try:
                rep,idx = stack.pop()
            except IndexError:
                return "".join(result)
        s = _enc_raw(rep[idx])
        if s is not None:
            add(s)
            idx += 1
            continue
        stack.append((rep,idx+1))
        rep = rep[idx]
        idx = 0
        add("(")

_RAW_PAT = re.compile(r'^[1-9][0-9]*:')

def _parseRaw_s(s, hint=0):
    if not hint and s[0] == '[':
        hint, rest = _parseRaw_s(s[1:], 1)
        if rest[:1] != "]":
            raise FormatError
        s, rest = _parseRaw_s(rest[1:], 1)
        return DisplayHint(hint, s), rest
    m = _RAW_PAT.match(s)
    if not m:
        raise FormatError()
    lngth = int(m.group(0)[:-1])
    s = s[m.end():]
    if len(s)<lngth:
        raise FormatError()
    return s[:lngth], s[lngth:]

class FormatError(Exception):
    pass

def parse_canonical(s):
    cur = top = []
    stack = []
    while s:
        first = s[0]
        if first not in '()':
            item, s = _parseRaw_s(s)
            cur.append(item)
            continue
        elif first == '(':
            next = []
            cur.append(next)
            stack.append(cur)
            cur = next
            s = s[1:]
        else:
            try:
                cur = stack.pop()
            except IndexError:
                raise FormatError()
            s = s[1:]
    if stack or len(top) != 1:
        raise FormatError()
    return top[0]

_TOKEN_RE = re.compile(r'''
  \s*(?:
        ([0-9]+:)                               | # Raw string: 1
        ([a-zA-Z0-9\-\.\/\_\:\*\+\=]
         [a-zA-Z0-9\-\.\/\_\:\*\+\=0-9]*)       | # Token: 2
        (?:([0-9]*)\#([a-fA-F0-9\s]*)\#)        | # Hex string: 3,4
        (?:([0-9]*)\|([a-zA-Z0-9\+\/\=\s]*)\|)  | # Base 64: 5,6
        (?:([0-9]*)\"((?:[^\\\"]+|\\.)*)\")     | # Quoted: 7,8
        (\()                                    | # Open paren: 9
        (\))                                    | # Close pare: 10
        (\[)                                      # Start of a display hint: 11
     )
   ''', re.X+re.DOTALL)

_QUOTED_CHAR_RE = re.compile(r'''
     \\\\ | \\[abtnvfr] | \\ \r \n ? | \\ \n \r ? |
     \\x[A-Fa-f0-9]{2} | \\[0-7]{1,3}
   ''', re.X)

_QUOTED_CHAR_MAP =  { 'a' : '\a',
                      'b' : '\b',
                      't' : '\t',
                      'n' : '\n',
                      'v' : '\v',
                      'f' : '\f',
                      'r' : '\r',
                      }


def _unescape_quoted_char(m):
    s = m.group(0)
    try:
        return _QUOTED_CHAR_MAP[s[1]]
    except KeyError:
        pass
    if s[1] in "\n\r":
        return ""
    elif s[1] == 'x':
        return chr(int(s[2:],16))
    else:
        return chr(int(s[1:],8))

def _parse_tok(s):
    "s -> (string or 1[(] or 2[)], rest) "
    m = _TOKEN_RE.match(s)
    if not m:
        if s.isspace():
            return None, None
        else:
            raise FormatError()
    rest = s[m.end():]
    g = m.groups()
    if g[1]: # raw string
        ln = int(g[1][:-1])
        return rest[:ln], rest[ln:]
    elif g[2]: # token
        return g[2], rest
    elif g[4]: # Hex string
        r = binascii.a2b_hex(g[4])
        if g[3]:
            ln = int(g[3])
            if ln != len(r):
                raise FormatError()
        return r, rest
    elif g[6]: # Base64 string
        m4 = len(g[6])%4
        if m4:
            g[6] += ("="*(4-m4))
        r = binascii.a2b_base64(g[6])
        if g[5]:
            ln = int(g[5])
            if ln != len(r):
                raise FormatError()
        return r, rest
    elif g[8]: # Quoted string
        r = _QUOTED_CHAR_RE.sub(_unescape_quoted_char, g[8])
        if g[7]:
            ln = int(g[7])
            if ln != len(r):
                raise FormatError()
        return r, rest
    elif g[9]:
        return 1, rest
    elif g[10]:
        return 2, rest
    else:
        assert s == "["
        hint, rest = _parse_tok(rest)
        if hint in (1,2,None) or isinstance(hint, DisplayHint):
            raise FormatError()
        try:
            idx = rest.find("]")
        except ValueError:
            raise FormatError()
        if rest[:idx-1] and not rest[:idx-1].isspace():
            raise FormatError()
        s, rest = _parse_tok(rest[idx:])
        if s in (1,2,None) or isinstance(hint, DisplayHint):
            raise FormatError()
        return DisplayHint(hint, s), rest

def parse(s):
    cur = top = []
    stack = []
    while 1:
        tok, s = _parse_tok(s)
        if tok == 1:
            next = []
            cur.append(next)
            stack.append(cur)
            cur = next
        elif tok == 2:
            try:
                cur = stack.pop()
            except IndexError:
                raise FormatError()
        elif tok == None:
            if stack or len(top) != 1:
                raise FormatError()
            return top[0]
        else:
            cur.append(tok)

_STR_RE = re.compile(r'''
    ([a-zA-Z0-9\-\.\/\_\:\*\+\=]
     [a-zA-Z0-9\-\.\/\_\:\*\+\=0-9]*) | # Could be a token.
    ([\a\b\t\n\v\f\r\x20-\x7E]+)        # Could be quoted.
  ''', re.X)

_QUOTED_MAP = { '\b' : "\\b",
                '\t' : "\\t",
                '\v' : "\\v",
                '\n' : "\\n",
                '\f' : "\\f",
                '\r' : "\\r",
                '"'  : "\"",
                '\b' : "\\b",
                '\\' : "\\", }
for x in xrange(128):
    if 32 <= x <= 126:
        _QUOTED_MAP[chr(x)] = chr(x)
    elif not _QUOTED_MAP.has_key(chr(x)):
        _QUOTED_MAP[chr(x)] = "\\x%02x"%x
del x

def _writeQuoted(write,s):
    m = _QUOTED_MAP
    write('"')
    for ch in s:
        f.write(m[ch])
    write('"')

def _write_str(write, s, indent, hint=0):
    if not s:
        write('""')
        return
    m = _STR_RE.match(s)
    if m.group(1):
        write(s)
    elif m.group(2):
        _writeQuoted(write,s)
    else:
        ind = " "*indent
        write("\n%s#"%ind)
        for i in xrange(0, len(s), 30):
            write(binascii.b2a_hex(s[i:i+30]))
            if i+30 < len(s):
                write("\n%s "%ind)
        if hint:
            write("#")
        else:
            write("#\n%s"%ind)

def _write_atom(write, s, indent):
    if isinstance(s, types.StringType):
        _write_str(write, s, indent,0)
        return 1
    try:
        getHint = s.getHint
    except AttributeError:
        return 0
    else:
        write("[")
        _write_str(write,getHint(),indent,1)
        write("]")
        _write_str(write,str(s),indent,0)
        return 1


def write_pretty(write, rep, indent_step=1):
    if _write_atom(write, rep, 0):
        return

    stack = []
    idx = 0
    indent = 0
    write("(")
    while 1:
        while idx == len(rep):
            write(")")
            indent -= indent_step
            try:
                rep,idx = stack.pop()
            except IndexError:
                write("\n")
                return
        if _write_atom(write,rep[idx], indent):
            idx += 1
            if idx < len(rep):
                write(" ")
            continue
        stack.append((rep,idx+1))
        rep = rep[idx]
        idx = 0
        indent += indent_step
        write("\n%s("%(" "*indent))

write_pretty(sys.stdout.write, [["abc","d","ef",["1"]]])
