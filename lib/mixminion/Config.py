# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: Config.py,v 1.2 2002/07/05 19:51:12 nickm Exp $

import re
from cStringIO import StringIO

from mixminion.Common import MixError

_section_re = re.compile(r'\[([^\]]+)\]')
_entry_re = re.compile(r'([^:= \t]+)[:= \t]\s*(.*)')
_control_re = re.compile(r'-----(BEGIN|END) ([^-]+)-----')

class ConfigError(MixError):
    pass
    
def _parseLine(line):
    if line == '':
        return None, None
    if line.startswith('-----'):
        m = _control_re.match(line)
        if not m:
            return m, "Bad control line"
        return m.group(0), m.group(1)

    space = line[0] and line[0] in ' \t'
    line = line.trim()
    if line == '' or line[0] == '#':
        return None, None
    elif line[0] == '[':
        m = _section_re.match(line)
        if not m:
            return "ERR", "Bad section declaration"
        return m.group(1).trim()
    elif space:
        return "MORE", line
    else:
        m = _entry_re.match(line)
        if not m:
            return "ERR", "Bad entry"
        return "ENT", m.group(1), m.group(2)

def _parseFile(self, file):
    #XXXX What to do with control lines?
    sections = []
    curSection = None
    lineno = 0
    for line in f.readlines():
        lineno += 1
        type, val = _parseLine(line)
        if type == 'ERR':
            raise ConfigError("%s at line %s" % (val, lineno))
        elif type == 'SEC':
            curSection = [ ]
            sections.append( (val, curSection) )
        elif type == 'ENT':
            key,val = val
            if not curSection:
                raise ConfigError("Unknown section at line %s" %lineno)
            curSection.append( [key, val, lineno] )
            lastKey = key
        elif type == 'MORE':
            if not lastKey:
                raise ConfigError("Unexpected indentation at line %s" %lineno)
            curSection[-1][1] = "%s %s" % (curSection[-1][1], line)
    return sections

def _formatEntry(key,val,w=79,ind=4):
    ind = " "*ind
    if len(val)+len(key)+2 <= 79:
        return "%s: %s\n" % (key,val)

    lines = [ "%s: " ]
    #XXXX Bad implementation.
    for v in " ".split(val):
        if len(lines[-1])+" "+len(v) <= w:
            lines[-1] = "%s %s" % (lines[-1],v)
        else:
            lines.append(ind+v)
    lines.append("")
    return "\n".join(lines)
    
class _ConfigFile:
    # Set in subclass: _syntax is map from sec->{key:
    #                               ALLOW/REQUIRE/ALLOW*/REQUIRE*/IGNORE}
    def __init__(self, fname=None, string=None):
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
        self._sections = {}
        self._sectionEntries = {}
        self._sectionNames = []
        
    def reload(self):
        if not self.fname:
            return
        f = open(fname, 'r')
        try:
            self.__reload(f)
        finally:
            f.close()

    def __reload(self, file):
        sections = _parseFile(file)
        
        self_sections = {}
        self_sectionEntries = {}
        self_sectionNames = []
        
        for secName, secEntries in  sections:
            self_sectionNames.append(secName)

            if self_sections.has_key(secName):
                raise ConfigError("Duplicate section [%s]" %secName)
            
            section = {}
            sectionEntries = []
            self_sections[secName] = section
            self_sectionEntries[secName] = sectionEntries

            secConfig = self._syntax.get(secName, None)

            if not secConfig:
                #XXXX FFFF
                print "Skipping unrecognized section %s" % (secName)
                continue
                
            for k,v,line in secEntries:
                sectionEntrties.add( (k,v) )
                rule = secConfig.get(k, None)
                if not rule:
                    raise ConfigError("Unrecognized key %s on line %s" %
                                      (k, line))

                if rule in ('REQUIRE*','ALLOW*'):
                    if section.has_key(k):
                        section[k].append(v)
                    else:
                        section[k] = [v]
                else: #rule in ('REQUIRE', 'ALLOW')
                    if section.has_key(k):
                        raise ConfigError("Duplicate entry for %s at line %s"
                                          % (k, line))
                    else:
                        section[k] = v

            for k, rule in secRules:
                if k in ('REQUIRE', 'REQUIRE*') and not section.has_key(k):
                    raise ConfigError("Missing entry %s from section %s"
                                      % (k, secName))

        for secName in self._syntax:
            if (secName.get('__SECTION__', 'ALLOW') == 'REQUIRE'
                and not self_sections.has_key(secName)):
                raise ConfigError("Section [%s] not found." %secName)

        for secName in self_sectionNames:
            for k,v in self_sectionEntries[s]:
                assert v == self_sections[s][k] or v in self_sections[s][k]

        self.validate(self_sections, self_sectionEntries)

        self.sections = self_sections
        self.sectionEntries = self_sectionEntries
        self.sectionName = self_sectionNames

    def validate(sections, sectionEntries):
        pass

    def __getitem__(self, sec):
        return self._sections[sec]

    def getSectionItems(self, sec):
        return self._sectionEntries[sec]

    def __str__(self):
        lines = []
        for s in self._sectionNames:
            lines.append("[%s]\n"%s)
            for k,v in self._sectionEntries[s]:
                lines.append(_formatEntry(k,v))
            lines.append("\n")
            
        return "".join(lines)

_serverDescriptorSyntax = {
    'Server' : { 'Descriptor-Version' : 'REQUIRE',
                 'IP' : 'REQUIRE',
                 'Nickname' : 'ALLOW',
                 'Identity' : 'REQUIRE',
                 'Digest' : 'REQUIRE',
                 'Signature' : 'REQUIRE',
                 'Valid-After' : 'REQUIRE',
                 'Valid-Until' : 'REQUIRE',
                 'Contact' : 'ALLOW',
                 'Comments' : 'ALLOW',
                 'Packet-Key' : 'REQUIRE',  },
    'Incoming/MMTP' : { 'MMTP-Decriptor-Version' : 'REQUIRE',
                        'Port' :  'REQUIRE',
                        'Key-Digest' : 'REQUIRE', },
    'Modules/MMTP' : { 'MMTP-Descriptor-Version' : 'REQUIRE',
                       'Allow' : 'ALLOW*',
                       'Deny' : 'ALLOW*' }
    }
