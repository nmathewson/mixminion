# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Config.py,v 1.16 2002/09/10 20:06:25 nickm Exp $

"""Configuration file parsers for Mixminion client and server
   configuration.

   A configuration file consists of one or more Sections.  Each Section
   has a header and optionally a list of Entries.  Each Entry has a key
   and a value.

   A section header is written as an open bracket, an identifier, and a
   close bracket.  An entry is written as a key, followed optionally by
   a colon or an equal sign, followed by a value.  Values may be split
   across multiple lines as in RFC822.

   Empty lines are permitted between entries, and between entries and
   headers.  Comments are permitted on lines beginning with a '#'.

   All identifiers are case-sensitive.

   Example:

   [Section1]

   Key1 value1
   Key2: Value2 value2 value2
        value2 value2
   Key3 = value3
   # A comment
   Key4=value4
   [Section2]
   Key5 value5
      value5 value5 value5

   We also specify a 'restricted' format in which blank lines,
   comments,  line continuations, and entry formats other than 'key: value'
   are forbidden.  Example:

   [Section1]
   Key1: Value1
   Key2: Value2
   Key3: Value3
   [Section2]
   Key4: Value4

   The restricted format is used for server descriptors.   
   """

__all__ = [ 'getConfig', 'loadConfig' ]

import os
import re
import binascii
import socket # for inet_aton and error
from cStringIO import StringIO

import mixminion.Common
from mixminion.Common import MixError, getLog
import mixminion.Packet
import mixminion.Crypto

# String with all characters 0..255; used for str.translate
_ALLCHARS = "".join(map(chr, range(256)))
# String with all printing ascii characters.
_GOODCHARS = "".join(map(chr, range(0x07,0x0e)+range(0x20,0x80)))

class ConfigError(MixError):
    """Thrown when an error is found in a configuration file."""
    pass

def _parseBoolean(boolean):
    """Entry validation function.  Converts a config value to a boolean.
       Raises ConfigError on failure."""
    s = boolean.strip().lower()
    if s in ("1", "yes", "y", "true", "on"):
        return 1
    elif s not in ("0", "no", "n", "false", "off"):
        raise ConfigError("Invalid boolean %r" % (boolean))
    else:
        return 0

def _parseSeverity(severity):
    """Validation function.  Converts a config value to a log severity.
       Raises ConfigError on failure."""
    s = severity.strip().upper()
    if not mixminion.Common._SEVERITIES.has_key(s):
        raise ConfigError("Invalid log level %r" % (severity))
    return s

def _parseServerMode(mode):
    """Validation function.  Converts a config value to a server mode
       (one of 'relay' or 'local'). Raises ConfigError on failure."""
    s = mode.strip().lower()
    if s not in ('relay', 'local'):
        raise ConfigError("Server mode must be 'Relay' or 'Local'")
    return s

# re to match strings of the form '9 seconds', '1 month', etc.
_interval_re = re.compile(r'''(\d+\.?\d*|\.\d+)\s+
                     (sec|second|min|minute|hour|day|week|mon|month|year)s?''',
                          re.X)
_seconds_per_unit = {
    'second': 1,
    'sec':    1,
    'minute': 60,
    'min':    60,
    'hour':   60*60,
    'day':    60*60*24,
    'week':   60*60*24*7,
    'mon':    60*60*24*30,
    'month':  60*60*24*30,    # These last two aren't quite right, but we
    'year':   60*60*24*365,   # don't need exactness.
    }
_abbrev_units = { 'sec' : 'second', 'min': 'minute', 'mon': 'month' }
def _parseInterval(interval):
    """Validation function.  Converts a config value to an interval of time,
       in the format (number of units, name of unit, total number of seconds).
       Raises ConfigError on failure."""
    inter = interval.strip().lower()
    m = _interval_re.match(inter)
    if not m:
        raise ConfigError("Unrecognized interval %r" % inter)
    num, unit = float(m.group(1)), m.group(2)
    unit = _abbrev_units.get(unit, unit)
    nsec = num * _seconds_per_unit[unit]
    return num, unit, nsec

def _parseInt(integer):
    """Validation function.  Converts a config value to an int.
       Raises ConfigError on failure."""
    i = integer.strip()
    try:
        return int(i)
    except ValueError, _:
        raise ConfigError("Expected an integer but got %r" % (integer))

_ip_re = re.compile(r'\d+\.\d+\.\d+\.\d+')

def _parseIP(ip):
    """Validation function.  Converts a config value to an IP address.
       Raises ConfigError on failure."""
    i = ip.strip()

    # inet_aton is a bit more permissive about spaces and incomplete
    # IP's than we want to be.  Thus we use a regex to catch the cases
    # it doesn't.
    if not _ip_re.match(i):
	raise ConfigError("Invalid IP %r" % i)
    try:
        f = socket.inet_aton(i)
    except socket.error, _:
        raise ConfigError("Invalid IP %r" % i)

    return i

_address_set_re = re.compile(r'''(\d+\.\d+\.\d+\.\d+|\*)
                                 \s*
                                 (?:/\s*(\d+\.\d+\.\d+\.\d+))?\s*
                                 (?:(\d+)\s*
                                           (?:-\s*(\d+))?
                                        )?''',re.X)
def _parseAddressSet_allow(s, allowMode=1):
    """Validation function.  Converts an address set string of the form
       IP/mask port-port into a tuple of (IP, Mask, Portmin, Portmax).
       Raises ConfigError on failure."""
    s = s.strip()
    m = _address_set_re.match(s)
    if not m:
        raise ConfigError("Misformatted address rule %r", s)
    ip, mask, port, porthi = m.groups()
    if ip == '*':
        if mask != None:
            raise ConfigError("Misformatted address rule %r", s)
        ip,mask = '0.0.0.0','0.0.0.0'
    else:
        ip = _parseIP(ip)
    if mask:
        mask = _parseIP(mask)
    else:
        mask = "255.255.255.255"
    if port:
        port = _parseInt(port)
        if porthi:
            porthi = _parseInt(porthi)
        else:
            porthi = port
        if not 1 <= port <= porthi <= 65535:
            raise ConfigError("Invalid port range %s-%s" %(port,porthi))
    elif allowMode:
        port = porthi = 48099
    else:
        port, porthi = 0, 65535

    return (ip, mask, port, porthi)

def _parseAddressSet_deny(s):
    return _parseAddressSet_allow(s,0)

def _parseCommand(command):
    """Validation function.  Converts a config value to a shell command of
       the form (fname, optionslist). Raises ConfigError on failure."""
    c = command.strip().split()
    if not c:
        raise ConfigError("Invalid command %r" %command)
    cmd, opts = c[0], c[1:]
    if os.path.isabs(cmd):
        if not os.path.exists(cmd):
            raise ConfigError("Executable file not found: %s" % cmd)
        else:
            return cmd, opts
    else:
        # Path is relative
        for p in os.environ.get('PATH', os.defpath).split(os.pathsep):
            p = os.path.expanduser(p)
            c = os.path.join(p, cmd)
            if os.path.exists(c):
                return c, opts

        raise ConfigError("No match found for command %r" %cmd)

def _parseBase64(s,_hexmode=0):
    """Validation function.  Converts a base-64 encoded config value into
       its original. Raises ConfigError on failure."""
    s = s.translate(_ALLCHARS, " \t\v\n")
    try:
	if _hexmode:
	    return binascii.a2b_hex(s)
	else:
	    return binascii.a2b_base64(s)
    except (TypeError, binascii.Error, binascii.Incomplete), _:
	raise ConfigError("Invalid Base64 data")

def _parseHex(s):
    """Validation function.  Converts a hex-64 encoded config value into
       its original. Raises ConfigError on failure."""
    return _parseBase64(s,1)

def _parsePublicKey(s):
    """Validate function.  Converts a Base-64 encoding of an ASN.1
       represented RSA public key with modulus 65535 into an RSA
       object."""
    asn1 = _parseBase64(s)
    if len(asn1) > 550:
	raise ConfigError("Overlong public key")
    try:
	key = mixminion.Crypto.pk_decode_public_key(asn1)
    except mixminion.Crypto.CryptoError:
	raise ConfigError("Invalid public key")
    if key.get_public_key()[1] != 65537:
	raise ConfigError("Invalid exponent on public key")
    return key

_date_re = re.compile(r"(\d\d)/(\d\d)/(\d\d\d\d)")
_time_re = re.compile(r"(\d\d)/(\d\d)/(\d\d\d\d) (\d\d):(\d\d):(\d\d)")
def _parseDate(s,_timeMode=0):
    """Validation function.  Converts from DD/MM/YYYY format to a (long)
       time value for midnight on that date."""
    s = s.strip()
    r = (_date_re, _time_re)[_timeMode]
    m = r.match(s)
    if not m:
	raise ConfigError("Invalid %s %r" % (("date", "time")[_timeMode],s))
    if _timeMode:
	dd, MM, yyyy, hh, mm, ss = map(int, m.groups())
    else:
	dd, MM, yyyy = map(int, m.groups())
	hh, mm, ss = 0, 0, 0	

    if not ((1 <= dd <= 31) and (1 <= MM <= 12) and
	    (1970 <= yyyy)  and (0 <= hh < 24) and
	    (0 <= mm < 60)  and (0 <= ss <= 61)):
	raise ConfigError("Invalid %s %r" % (("date","time")[_timeMode],s))

    return mixminion.Common.mkgmtime(yyyy, MM, dd, hh, mm, ss)

def _parseTime(s):
    """Validation function.  Converts from DD/MM/YYYY HH:MM:SS format
       to a (float) time value for GMT."""
    return _parseDate(s,1)

#----------------------------------------------------------------------

# Regular expression to match a section header.
_section_re = re.compile(r'\[([^\]]+)\]')
# Regular expression to match the first line of an entry
_entry_re = re.compile(r'([^:= \t]+)(?:\s*[:=]|[ \t])\s*(.*)')
_restricted_entry_re = re.compile(r'([^:= \t]+): (.*)')
def _readConfigLine(line, restrict=0):
    """Helper function.  Given a line of a configuration file, return
       a (TYPE, VALUE) pair, where TYPE is one of the following:

         None: The line is empty or a comment.
         'ERR': The line is incorrectly formatted. VALUE is an error message.
         'SEC': The line is a section header. VALUE is the section's name.
         'ENT': The line is the first line of an entry. VALUE is a (K,V) pair.
         'MORE': The line is a continuation line of an entry. VALUE is the
                 contents of the line.
    """

    if line == '':
        return None, None

    space = line[0] and line[0] in ' \t'
    line = line.strip()
    if line == '' or line[0] == '#':
        return None, None
    elif line[0] == '[':
        m = _section_re.match(line)
        if not m:
            return "ERR", "Bad section declaration"
        return 'SEC', m.group(1).strip()
    elif space:
        return "MORE", line
    else:
	if restrict:
	    m = _restricted_entry_re.match(line)
	else:
	    m = _entry_re.match(line)
        if not m:
            return "ERR", "Bad entry"
        return "ENT", (m.group(1), m.group(2))

def _readConfigFile(contents, restrict=0):
    """Helper function. Given the string contents of a configuration
       file, returns a list of (SECTION-NAME, SECTION) tuples, where
       each SECTION is a list of (KEY, VALUE, LINENO) tuples.

       Throws ConfigError if the file is malformatted.
    """
    sections = []
    curSection = None
    lineno = 0
    lastKey = None

    badchars = contents.translate(_ALLCHARS, _GOODCHARS)
    if badchars:
	raise ConfigError("Invalid characters in file: %r", badchars)

    fileLines = contents.split("\n")
    if fileLines[-1] == '':
	del fileLines[-1]

    for line in fileLines:
        lineno += 1
        type, val = _readConfigLine(line, restrict)
        if type == 'ERR':
            raise ConfigError("%s at line %s" % (val, lineno))
        elif type == 'SEC':
            curSection = [ ]
            sections.append( (val, curSection) )
        elif type == 'ENT':
            key,val = val
            if curSection is None:
                raise ConfigError("Unknown section at line %s" %lineno)
            curSection.append( [key, val, lineno] )
            lastKey = key
        elif type == 'MORE':
	    if restrict:
		raise ConfigError("Continuation not allowed at line %s"%lineno)
            if not lastKey:
                raise ConfigError("Unexpected indentation at line %s" %lineno)
            curSection[-1][1] = "%s %s" % (curSection[-1][1], val)
	else:
	    assert type is None
	    if restrict:
		raise ConfigError("Empty line not allowed at line %s"%lineno)
    return sections

def _formatEntry(key,val,w=79,ind=4):
    """Helper function.  Given a key/value pair, returns a NL-terminated
       entry for inclusion in a configuration file, such that no line is
       avoidably longer than 'w' characters, and with continuation lines
       indented by 'ind' spaces.
    """
    ind_s = " "*(ind-1)
    if len(str(val))+len(key)+2 <= 79:
        return "%s: %s\n" % (key,val)

    lines = [  ]
    linecontents = [ "%s:" % key ]
    linelength = len(linecontents[0])
    for v in val.split(" "):
        if linelength+1+len(v) <= w:
            linecontents.append(v)
	    linelength += 1+len(v)
        else:
	    lines.append(" ".join(linecontents))
	    linecontents = [ ind_s, v ]
	    linelength = ind+len(v)
    lines.append(" ".join(linecontents))
    lines.append("") # so the last line ends with \n
    return "\n".join(lines)

class _ConfigFile:
    """Base class to parse, validate, and represent configuration files.
    """
    ##Fields:
    #  fname: Name of the underlying file.  Used by .reload()
    #  _sections: A map from secname->key->value.
    #  _sectionEntries: A  map from secname->[ (key, value) ] inorder.
    #  _sectionNames: An inorder list of secnames.
    #  _callbacks: A map from section name to a callback function that should 
    #      be invoked with (section,sectionEntries) after each section is
    #      read.  This shouldn't be used for validation; it's for code that
    #      needs to change the semantics of the parser.
    #
    # Fields to be set by a subclass:
    #     _syntax is map from sec->{key:
    #                               (ALLOW/REQUIRE/ALLOW*/REQUIRE*,
    #                                 parseFn,
    #                                 default, ) }
    #     _restrictFormat is 1/0: do we allow full RFC822ness, or do
    #         we insist on a tight data format?

    ## Validation rules:
    # A key without a corresponding entry in _syntax gives an error.
    # A section without a corresponding entry is ignored.
    # ALLOW* and REQUIRE* permit multiple entries with for a given key:
    #   these entries are read into a list.
    # The magic key __SECTION__ describes whether a section is requried.
    # If parseFn is not None, it is invoked on the entry in order to
    #   get a value.  Otherwise, the value is string value of the entry.
    # If the entry is (permissibly) absent, and default is set, then
    #   the entry's value will be set to default.  Otherwise, the value
    #   will be set to None.

    _syntax = None
    _restrictFormat = 0

    def __init__(self, filename=None, string=None, assumeValid=0):
        """Create a new _ConfigFile.  If <filename> is set, read from
           a corresponding file.  If <string> is set, parse its contents.

           If <assumeValid> is true, skip all unnecessary validation
           steps.  (Use this to load a file that's already been checked as
           valid.)"""
        assert filename is None or string is None
        if not hasattr(self, '_callbacks'):
            self._callbacks = {}

        self.assumeValid = assumeValid
        self.fname = filename
        if filename:
            self.reload()
        elif string:
            cs = StringIO(string)
            try:
                self.__reload(cs)
            finally:
                cs.close()
        else:
            self.clear()

    def clear(self):
        """Remove all sections from this _ConfigFile object."""
        self._sections = {}
        self._sectionEntries = {}
        self._sectionNames = []

    def reload(self):
        """Reload this _ConfigFile object from disk.  If the object is no
           longer present and correctly formatted, raise an error, but leave
           the contents of this object unchanged."""
        if not self.fname:
            return
        f = open(self.fname, 'r')
        try:
            self.__reload(f)
        finally:
            f.close()

    def __reload(self, file):
        """As in .reload(), but takes an open file object."""
	fileContents = file.read()
        sections = _readConfigFile(fileContents, self._restrictFormat)

        # These will become self.(_sections,_sectionEntries,_sectionNames)
        # if we are successful.
        self_sections = {}
        self_sectionEntries = {}
        self_sectionNames = []
        sectionEntryLines = {}

        for secName, secEntries in sections:
            self_sectionNames.append(secName)

            if self_sections.has_key(secName):
                raise ConfigError("Duplicate section [%s]" %secName)

            section = {}
            sectionEntries = []
            entryLines = []
            self_sections[secName] = section
            self_sectionEntries[secName] = sectionEntries
            sectionEntryLines[secName] = entryLines

            secConfig = self._syntax.get(secName, None)

            if not secConfig:
                getLog().warn("Skipping unrecognized section %s", secName)
                continue

            # Set entries from the section, searching for bad entries
            # as we go.
            for k,v,line in secEntries:
                rule, parseFn, default = secConfig.get(k, (None,None,None))
                if not rule:
                    raise ConfigError("Unrecognized key %s on line %s" %
                                      (k, line))

                # Parse and validate the value of this entry.
                if parseFn is not None:
                    try:
                        v = parseFn(v)
                    except ConfigError, e:
                        e.args = ("%s at line %s" %(e.args[0],line))
                        raise e

                sectionEntries.append( (k,v) )
                entryLines.append(line)

                # Insert the entry, checking for impermissible duplicates.
                if rule in ('REQUIRE*','ALLOW*'):
                    if section.has_key(k):
                        section[k].append(v)
                    else:
                        section[k] = [v]
                else:
                    assert rule in ('REQUIRE', 'ALLOW')
                    if section.has_key(k):
                        raise ConfigError("Duplicate entry for %s at line %s"
                                          % (k, line))
                    else:
                        section[k] = v

            # Check for missing entries, setting defaults and detecting
            # missing requirements as we go.
            for k, (rule, parseFn, default) in secConfig.items():
                if k == '__SECTION__':
                    continue
                if rule in ('REQUIRE', 'REQUIRE*') and not section.has_key(k):
                    raise ConfigError("Missing entry %s from section %s"
                                      % (k, secName))
                elif not section.has_key(k):
                    if parseFn is None or default is None:
                        if rule == 'ALLOW*':
                            section[k] = []
                        else:
                            section[k] = default
                    elif rule == 'ALLOW':
                        section[k] = parseFn(default)
                    else:
                        assert rule == 'ALLOW*'
                        section[k] = map(parseFn,default)

            cb = self._callbacks.get(secName, None)
            if cb:
                cb(section, sectionEntries)

        # Check for missing required sections, setting any missing
        # allowed sections to {}.
        for secName, secConfig in self._syntax.items():
            secRule = secConfig.get('__SECTION__', ('ALLOW',None,None))
            if (secRule[0] == 'REQUIRE'
                and not self_sections.has_key(secName)):
                raise ConfigError("Section [%s] not found." %secName)
            elif not self_sections.has_key(secName):
                self_sections[secName] = {}
                self_sectionEntries[secName] = {}
                
        if not self.assumeValid:
            # Call our validation hook.
            self.validate(self_sections, self_sectionEntries, 
                          sectionEntryLines, fileContents)

        self._sections = self_sections
        self._sectionEntries = self_sectionEntries
        self._sectionNames = self_sectionNames

    def _addCallback(self, section, cb):
	"""For use by subclasses.  Adds a callback for a section"""
        if not hasattr(self, '_callbacks'):
            self._callbacks = {}
        self._callbacks[section] = cb

    def validate(self, sections, sectionEntries, entryLines,
		 fileContents):
        """Check additional semantic properties of a set of configuration
           data before overwriting old data.  Subclasses should override."""
        pass

    def __getitem__(self, sec):
        """self[section] -> dict

           Return a map from keys to values for a given section.  If the
           section was absent, return an empty map."""
        return self._sections[sec]

    def has_section(self, sec):
        """Return true if this config object allows a section named 'sec'."""
        return self._sections.has_key(sec)

    def getSectionItems(self, sec):
        """Return a list of ordered (key,value) tuples for a given section.
           If the section was absent, return an empty map."""
        return self._sectionEntries[sec]

    def __str__(self):
        """Returns a string configuration file equivalent to this configuration
           file."""
        lines = []
        for s in self._sectionNames:
            lines.append("[%s]\n"%s)
            for k,v in self._sectionEntries[s]:
                lines.append(_formatEntry(k,v))
            lines.append("\n")

        return "".join(lines)

class ClientConfig(_ConfigFile):
    _restrictFormat = 0
    _syntax = {
        'Host' : { '__SECTION__' : ('ALLOW', None, None),
                   'ShredCommand': ('ALLOW', _parseCommand, None),
                   'EntropySource': ('ALLOW', None, "/dev/urandom"),
                   },
        'DirectoryServers' :
                   { '__SECTION__' : ('REQUIRE', None, None),
                     'ServerURL' : ('ALLOW*', None, None),
                     'MaxSkew' : ('ALLOW', _parseInterval, "10 minutes") },
        'User' : { 'UserDir' : ('ALLOW', None, "~/.mixminion" ) },
        'Security' : { 'PathLength' : ('ALLOW', _parseInt, "8"),
                       'SURBAddress' : ('ALLOW', None, None),
                       'SURBPathLength' : ('ALLOW', _parseInt, "8"),
		       'SURBLifetime' : ('ALLOW', _parseInterval, "7 days") },
        }
    def __init__(self, fname=None, string=None):
        _ConfigFile.__init__(self, fname, string)

    def validate(self, sections, entries, lines, contents):
	_validateHostSection(sections.get('Host', {}))

	security = sections.get('Security', {})
	p = security.get('PathLength', 8)
	if not 0 < p <= 16:
	    raise ConfigError("Path length must be between 1 and 16")
	if p < 4:
	    getLog().warn("Your default path length is frighteningly low."
			  "  I'll trust that you know what you're doing.")
	
	    
	    

SERVER_SYNTAX =  {
        'Host' : ClientConfig._syntax['Host'],
        'Server' : { '__SECTION__' : ('REQUIRE', None, None),
                     'Homedir' : ('ALLOW', None, "/var/spool/minion"),
                     'LogFile' : ('ALLOW', None, None),
                     'LogLevel' : ('ALLOW', _parseSeverity, "WARN"),
                     'EchoMessages' : ('ALLOW', _parseBoolean, "no"),
                     'EncryptIdentityKey' : ('REQUIRE', _parseBoolean, "yes"),
		     'IdentityKeyBits': ('ALLOW', _parseInt, "2048"),
                     'PublicKeyLifetime' : ('ALLOW', _parseInterval,
                                            "30 days"),
                     'PublicKeySloppiness': ('ALLOW', _parseInterval,
                                             "5 minutes"),
                     'EncryptPrivateKey' : ('REQUIRE', _parseBoolean, "no"),
                     'Mode' : ('REQUIRE', _parseServerMode, "local"),
                     'Nickname': ('ALLOW', None, None),
                     'Contact-Email': ('ALLOW', None, None),
                     'Comments': ('ALLOW', None, None),
                     'ModulePath': ('ALLOW', None, None),
                     'Module': ('ALLOW*', None, None),
                     },
        'DirectoryServers' : { 'ServerURL' : ('ALLOW*', None, None),
                               'Publish' : ('ALLOW', _parseBoolean, "no"),
                               'MaxSkew' : ('ALLOW', _parseInterval,
                                            "10 minutes",) },
	# FFFF Generic multi-port listen/publish options.
        'Incoming/MMTP' : { 'Enabled' : ('REQUIRE', _parseBoolean, "no"),
			    'IP' : ('ALLOW', _parseIP, None),
                            'Port' : ('ALLOW', _parseInt, "48099"),
                            'Allow' : ('ALLOW*', _parseAddressSet_allow, None),
                            'Deny' : ('ALLOW*', _parseAddressSet_deny, None) },
        'Outgoing/MMTP' : { 'Enabled' : ('REQUIRE', _parseBoolean, "no"),
                            'Allow' : ('ALLOW*', _parseAddressSet_allow, None),
                            'Deny' : ('ALLOW*', _parseAddressSet_deny, None) },
	# FFFF Missing: Queue-Size / Queue config options
	# FFFF         timeout options
	# FFFF         listen timeout??
	# FFFF         Retry options
        }

class ServerConfig(_ConfigFile):
    ##
    # Fields: 
    #   moduleManager
    #
    _restrictFormat = 0
    def __init__(self, fname=None, string=None, moduleManager=None):
	# We use a copy of SERVER_SYNTAX, because the ModuleManager will
	# mess it up.
        self._syntax = SERVER_SYNTAX.copy()

        import mixminion.Modules
	if moduleManager is None:
	    self.moduleManager = mixminion.Modules.ModuleManager()
	else:
	    self.moduleManager = moduleManager
        self._addCallback("Server", self.__loadModules)    

        _ConfigFile.__init__(self, fname, string)

    def validate(self, sections, entries, lines, contents):
	log = getLog()
	_validateHostSection(sections.get('Host', {}))
	# Server section
	server = sections['Server']
	bits = server['IdentityKeyBits']
	if not (2048 <= bits <= 4096):
	    raise ConfigError("IdentityKeyBits must be between 2048 and 4096")
	if server['EncryptIdentityKey']:
	    log.warn("Identity key encryption not yet implemented")
	if server['EncryptPrivateKey']:
	    log.warn("Encrypted private keys not yet implemented")
	if server['PublicKeyLifetime'][2] < 24*60*60:
	    raise ConfigError("PublicKeyLifetime must be at least 1 day.")
	if server['PublicKeySloppiness'][2] > 20*60:
	    raise ConfigError("PublicKeySloppiness must be <= 20 minutes.")
	if [e for e in entries['Server'] if e[0]=='Mode']:
	    log.warn("Mode specification is not yet supported.")

	if not sections['Incoming/MMTP'].get('Enabled'):
	    log.warn("Disabling incoming MMTP is not yet supported.")
	if [e for e in entries['Incoming/MMTP'] if e[0] in ('Allow', 'Deny')]:
	    log.warn("Allow/deny are not yet supported")

	if not sections['Outgoing/MMTP'].get('Enabled'):
	    log.warn("Disabling incoming MMTP is not yet supported.")
	if [e for e in entries['Outgoing/MMTP'] if e[0] in ('Allow', 'Deny')]:
	    log.warn("Allow/deny are not yet supported")

        self.moduleManager.validate(sections, entries, lines, contents)

    def __loadModules(self, section, sectionEntries):
	"""Callback from the [Server] section of a config file.  Parses
	   the module options, and adds new sections to the syntax 
	   accordingly."""
        self.moduleManager.setPath(section.get('ModulePath', None))
        for mod in section.get('Module', []):
	    getLog().info("Loading module %s", mod)
            self.moduleManager.loadExtModule(mod)

        self._syntax.update(self.moduleManager.getConfigSyntax())
    
    def getModuleManager(self):
	"Return the module manager initialized by this server."
	return self.moduleManager

def _validateHostSection(sec):
    #XXXX
    pass

