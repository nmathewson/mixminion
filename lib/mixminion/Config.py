# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Config.py,v 1.4 2002/07/26 15:47:20 nickm Exp $

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
   """

__all__ = [ 'getConfig', 'loadConfig', 'addHook' ]

import os
import re
from cStringIO import StringIO

import mixminion.Common
from mixminion.Common import MixError, getLog
import mixminion.Packet

#----------------------------------------------------------------------

# global variable to hold the configuration object for this process.
_theConfiguration = None

def loadConfig(fname,server=0):
    """Load the configuration file for this process.  Takes a
       filename, and a flag to determine whether we're running as a
       client or a server.

       Registers the configuration object to be reloaded on SIGHUP."""
    global _theConfiguration
    assert _theConfiguration is None

    if server:
        _theConfiguration = ServerConfig(fname)
    else:
        assert fname is not None
        _theConfiguration = ClientConfig(fname)

    mixminion.Common.onReset(_theConfiguration.reload)

def getConfig():
    """Return the configuration object for this process, or None if we haven't
       been configured yet."""
    return _theConfiguration
#----------------------------------------------------------------------

_CONFIG_HOOKS = []
def addHook(hook):
    '''Add 'hook' (a 0-argument function) to the list of configuration
       hooks.  Whenever the configuration file is reloaded (as on a
       SIGHUP), it invokes each of the configuration hooks in the
       order it was added to the list.'''
    # This isn't a method of _Config, since we want to be able to call
    # it before we read the configuration file.
    _CONFIG_HOOKS.append(hook)
    
#----------------------------------------------------------------------

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
    i = integer.strip().lower()
    try:
        return int(i)
    except ValueError, e:
        raise ConfigError("Expected an integer but got %r" % (integer))

def _parseIP(ip):
    """Validation function.  Converts a config value to an IP address.
       Raises ConfigError on failure."""  
    i = ip.strip().lower()
    try:
        f = mixminion.Packet._packIP(i)
    except mixminion.Packet.ParseError, p:
        raise ConfigError("Invalid IP %r" % i)

    return i

def _parseCommand(command):
    """Validation function.  Converts a config value to a shell command of
       the form (fname, optionslist). Raises ConfigError on failure."""  
    c = command.strip().lower().split()
    if not c:
        raise ConfigError("Invalid command %r" %command)
    cmd, opts = c[0], c[1:]
    if os.path.isabs(cmd):
        if not os.path.exists(cmd):
            raise ConfigError("File not found: %s" % cmd)
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

#----------------------------------------------------------------------

# Regular expression to match a section header.
_section_re = re.compile(r'\[([^\]]+)\]')
# Regular expression to match the first line of an entry
_entry_re = re.compile(r'([^:= \t]+)(?:\s*[:=]|[ \t])\s*(.*)')
def _readConfigLine(line):
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
        m = _entry_re.match(line)
        if not m:
            return "ERR", "Bad entry"
        return "ENT", (m.group(1), m.group(2))

def _readConfigFile(file):
    """Helper function. Given an open file object for a configuration
       file, parse it into sections.

       Returns a list of (SECTION-NAME, SECTION) tuples, where each
       SECTION is a list of (KEY, VALUE, LINENO) tuples.

       Throws ConfigError if the file is malformatted.
    """
    sections = []
    curSection = None
    lineno = 0
    lastKey = None
    for line in file.readlines():
        lineno += 1
        type, val = _readConfigLine(line)
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
            if not lastKey:
                raise ConfigError("Unexpected indentation at line %s" %lineno)
            curSection[-1][1] = "%s %s" % (curSection[-1][1], val)
    return sections

def _formatEntry(key,val,w=79,ind=4):
    """Helper function.  Given a key/value pair, returns a NL-terminated
       entry for inclusion in a configuration file, such that no line is
       avoidably longer than 'w' characters, and with continuation lines
       indented by 'ind' spaces.
    """
    ind = " "*ind
    if len(str(val))+len(key)+2 <= 79:
        return "%s: %s\n" % (key,val)

    lines = [ "%s: " %key ]
    #XXXX Bad implementation.
    for v in val.split(" "):
        if len(lines[-1])+1+len(v) <= w:
            lines[-1] = "%s %s" % (lines[-1],v)
        else:
            lines.append(ind+v)
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
    #
    # Set by a subclass:
    #     _syntax is map from sec->{key:
    #                               (ALLOW/REQUIRE/ALLOW*/REQUIRE*,
    #                                 parseFn,
    #                                 default, ) }
    
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

    def __init__(self, fname=None, string=None):
        """Create a new _ConfigFile.  If fname is set, read from
           fname.  If string is set, parse string."""
        assert fname is None or string is None
        self.fname = fname
        if fname:
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
            for hook in _CONFIG_HOOKS:
                hook()
        finally:
            f.close()

    def __reload(self, file):
        """As in .reload(), but takes an open file object."""
        sections = _readConfigFile(file)

        # These will become self.(_sections,_sectionEntries,_sectionNames)
        # if we are successful.
        self_sections = {}
        self_sectionEntries = {}
        self_sectionNames = []
        sectionEntryLines = {}

        for secName, secEntries in  sections:
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

        # Check for missing required sections.
        for secName, secConfig in self._syntax.items():
            secRule = secConfig.get('__SECTION__', ('ALLOW',None,None))
            if (secRule[0] == 'REQUIRE'
                and not self_sections.has_key(secName)):
                raise ConfigError("Section [%s] not found." %secName)
            elif not self_sections.has_key(secName):
                self_sections[secName] = {}
                self_sectionEntries[secName] = {}

        # Make sure that sectionEntries is correct (sanity check)
        for s in self_sectionNames:
            for k,v in self_sectionEntries[s]:
                assert v == self_sections[s][k] or v in self_sections[s][k]

        # Call our validation hook.
        self.validate(self_sections, self_sectionEntries, sectionEntryLines)

        self._sections = self_sections
        self._sectionEntries = self_sectionEntries
        self._sectionNames = self_sectionNames

    def validate(self, sections, sectionEntries, entryLines):
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
    _syntax = {
        'Host' : { '__SECTION__' : ('REQUIRE', None, None),
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
                       'SURBPathLength' : ('ALLOW', None, "8") },
        }
    def __init__(self, fname=None, string=None):
        _ConfigFile.__init__(self, fname, string)

    def validate(self, sections, entries, lines):
        #XXXX Write this
        pass

class ServerConfig(_ConfigFile):
    _syntax = {
        'Host' : ClientConfig._syntax['Host'], 
        'Server' : { '__SECTION__' : ('REQUIRE', None, None),
                     'Homedir' : ('ALLOW', None, "/var/spool/minion"),
                     'LogFile' : ('ALLOW', None, None),
                     'LogLevel' : ('ALLOW', _parseSeverity, "WARN"),
                     'EchoMessages' : ('ALLOW', _parseBoolean, "no"),
                     'EncryptIdentityKey' : ('REQUIRE', _parseBoolean, "yes"),
                     'PublicKeyLifetime' : ('REQUIRE', _parseInterval,
                                            "30 days"),
                     'EncryptPublicKey' : ('REQUIRE', _parseBoolean, "no"),
                     'Mode' : ('REQUIRE', _parseServerMode, "local"),
                     },
        'DirectoryServers' : { 'ServerURL' : ('ALLOW*', None, None),
                               'Publish' : ('ALLOW', _parseBoolean, "no"),
                               'MaxSkew' : ('ALLOW', _parseInterval,
                                            "10 minutes",) }, 
        'Incoming/MMTP' : { 'Enabled' : ('REQUIRE', _parseBoolean, "no"),
                            'IP' : ('ALLOW', _parseIP, None),
                            'Port' : ('ALLOW', _parseInt, "48099"),
                            'Allow' : ('ALLOW*', None, None),
                            'Deny' : ('ALLOW*', None, None) },
        'Outgoing/MMTP' : { 'Enabled' : ('REQUIRE', _parseBoolean, "no"),
                            'Allow' : ('ALLOW*', None, None),
                            'Deny' : ('ALLOW', None, None) },
        'Delivery/MBox' : { 'Enabled' : ('REQUIRE',  _parseBoolean, "no"),
                            'AddressFile' : ('REQUIRE', None, None),
                            'Command' : ('ALLOW', _parseCommand, "sendmail") },
        }
    # XXXX Missing: Queue-Size / Queue config options
    # XXXX         timeout options
    def __init__(self, fname=None, string=None):
        _ConfigFile.__init__(self, fname, string)

    def validate(self, sections, entries, lines):
        #XXXX write this.
        pass
    
## _serverDescriptorSyntax = {
##     'Server' : { 'Descriptor-Version' : 'REQUIRE',
##                  'IP' : 'REQUIRE',
##                  'Nickname' : 'ALLOW',
##                  'Identity' : 'REQUIRE',
##                  'Digest' : 'REQUIRE',
##                  'Signature' : 'REQUIRE',
##                  'Valid-After' : 'REQUIRE',
##                  'Valid-Until' : 'REQUIRE',
##                  'Contact' : 'ALLOW',
##                  'Comments' : 'ALLOW',
##                  'Packet-Key' : 'REQUIRE',  },
##     'Incoming/MMTP' : { 'MMTP-Descriptor-Version' : 'REQUIRE',
##                         'Port' :  'REQUIRE',
##                         'Key-Digest' : 'REQUIRE', },
##     'Modules/MMTP' : { 'MMTP-Descriptor-Version' : 'REQUIRE',
##                        'Allow' : 'ALLOW*',
##                        'Deny' : 'ALLOW*' }
##     }
