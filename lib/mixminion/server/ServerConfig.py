# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerConfig.py,v 1.5 2002/12/21 01:54:23 nickm Exp $

"""Configuration format for server configuration files.

   See Config.py for information about the generic configuration facility."""

__all__ = [ "ServerConfig" ]

import mixminion.Config
import mixminion.server.Modules
from mixminion.Config import ConfigError
from mixminion.Common import LOG

class ServerConfig(mixminion.Config._ConfigFile):
    ##
    # Fields:
    #   moduleManager
    #
    _restrictFormat = 0
    def __init__(self, fname=None, string=None, moduleManager=None):
        # We use a copy of SERVER_SYNTAX, because the ModuleManager will
        # mess it up.
        self._syntax = SERVER_SYNTAX.copy()

        if moduleManager is None:
            self.moduleManager = mixminion.server.Modules.ModuleManager()
        else:
            self.moduleManager = moduleManager
        self._addCallback("Server", self.__loadModules)

        mixminion.Config._ConfigFile.__init__(self, fname, string)

    def validate(self, sections, entries, lines, contents):
        def _haveEntry(entries, section, ent):
            return len([e for e in entries[section] if e[0] == ent]) != 0

        # Pre-emptively configure the log before validation, so we don't
        # write to the terminal if we've been asked not to.
        if not sections['Server'].get("EchoMessages", 0):
            LOG.handlers = []
            # ???? This can't be the best way to do this.

        # Now, validate the host section.
        mixminion.Config._validateHostSection(sections.get('Host', {}))
        # Server section
        server = sections['Server']
        serverents = entries['Server']
        bits = server['IdentityKeyBits']
        if not (2048 <= bits <= 4096):
            raise ConfigError("IdentityKeyBits must be between 2048 and 4096")
        if server['EncryptIdentityKey']:
            LOG.warn("Identity key encryption not yet implemented")
        if server['EncryptPrivateKey']:
            LOG.warn("Encrypted private keys not yet implemented")
        if server['PublicKeyLifetime'][2] < 24*60*60:
            raise ConfigError("PublicKeyLifetime must be at least 1 day.")
        if server['PublicKeySloppiness'][2] > 20*60:
            raise ConfigError("PublicKeySloppiness must be <= 20 minutes.")
        if _haveEntry(entries, 'Server', 'Mode'):
            LOG.warn("Mode specification is not yet supported.")

        if server['MixInterval'][2] < 30*60:
            LOG.warn("Dangerously low MixInterval")
        if server['MixAlgorithm'] == 'TimedMixQueue':
            if _haveEntry(entries, 'Server', 'MixPoolRate'):
                LOG.warn("Option MixPoolRate is not used for Timed mixing.")
            if _haveEntry(entries, 'Server', 'MixPoolMinSize'):
                LOG.warn("Option MixPoolMinSize is not used for Timed mixing.")
        else:
            rate = server['MixPoolRate']
            minSize = server['MixPoolMinSize']
            if rate < 0.05:
                LOG.warn("Unusually low MixPoolRate %s", rate)
            if minSize < 0:
                raise ConfigError("MixPoolMinSize %s must be nonnegative.")

        if not sections['Incoming/MMTP'].get('Enabled'):
            LOG.warn("Disabling incoming MMTP is not yet supported.")
        if [e for e in entries['Incoming/MMTP'] if e[0] in ('Allow', 'Deny')]:
            LOG.warn("Allow/deny are not yet supported")

        if not sections['Outgoing/MMTP'].get('Enabled'):
            LOG.warn("Disabling incoming MMTP is not yet supported.")
        if [e for e in entries['Outgoing/MMTP'] if e[0] in ('Allow', 'Deny')]:
            LOG.warn("Allow/deny are not yet supported")

        self.moduleManager.validate(sections, entries, lines, contents)

    def __loadModules(self, section, sectionEntries):
        """Callback from the [Server] section of a config file.  Parses
           the module options, and adds new sections to the syntax
           accordingly."""
        self.moduleManager.setPath(section.get('ModulePath', None))
        for mod in section.get('Module', []):
            LOG.info("Loading module %s", mod)
            self.moduleManager.loadExtModule(mod)

        self._syntax.update(self.moduleManager.getConfigSyntax())

    def getModuleManager(self):
        "Return the module manager initialized by this server."
        return self.moduleManager

#======================================================================

_MIX_RULE_NAMES = {
    'timed' : "TimedMixQueue",
    'cottrell'     : "CottrellMixQueue",
    'mixmaster'    : "CottrellMixQueue",
    'dynamicpool'  : "CottrellMixQueue",
    'binomial'            : "BinomialCottrellMixQueue",
    'binomialcottrell'    : "BinomialCottrellMixQueue",
    'binomialdynamicpool' : "BinomialCottrellMixQueue",
}

def _parseMixRule(s):
    """Validation function.  Given a string representation of a mixing
       algorithm, return the name of the Mix queue class to be used."""
    name = s.strip().lower()
    v = _MIX_RULE_NAMES.get(name)
    if not v:
        raise ConfigError("Unrecognized mix algorithm %s"%s)
    return v

def _parseFraction(frac):
    """Validation function.  Converts a percentage or a number into a 
       number between 0 and 1."""
    s = frac.strip().lower()
    try:
        if s.endswith("%"):
            ratio = float(s[:-1].strip())/100.0
        else:
            ratio = float(s)
    except ValueError:
        raise ConfigError("%s is not a fraction" %frac)
    if not 0 <= ratio <= 1:
        raise ConfigError("%s is not in range (between 0%% and 100%%)"%frac)
    return ratio

# alias to make the syntax more terse.
C = mixminion.Config

SERVER_SYNTAX =  {
        'Host' : C.ClientConfig._syntax['Host'],
        'Server' : { '__SECTION__' : ('REQUIRE', None, None),
                     'Homedir' : ('ALLOW', None, "/var/spool/minion"),
                     'LogFile' : ('ALLOW', None, None),
                     'LogLevel' : ('ALLOW', C._parseSeverity, "WARN"),
                     'EchoMessages' : ('ALLOW', C._parseBoolean, "no"),
                     'NoDaemon' : ('ALLOW', C._parseBoolean, "no"),
                     'EncryptIdentityKey' : ('REQUIRE', C._parseBoolean, "yes"),
                     'IdentityKeyBits': ('ALLOW', C._parseInt, "2048"),
                     'PublicKeyLifetime' : ('ALLOW', C._parseInterval,
                                            "30 days"),
                     'PublicKeySloppiness': ('ALLOW', C._parseInterval,
                                             "5 minutes"),
                     'EncryptPrivateKey' : ('REQUIRE', C._parseBoolean, "no"),
                     'Mode' : ('REQUIRE', C._parseServerMode, "local"),
                     'Nickname': ('ALLOW', None, None),
                     'Contact-Email': ('ALLOW', None, None),
                     'Comments': ('ALLOW', None, None),
                     'ModulePath': ('ALLOW', None, None),
                     'Module': ('ALLOW*', None, None),
                     'MixAlgorithm' : ('ALLOW', _parseMixRule, "Cottrell"),
                     'MixInterval' : ('ALLOW', C._parseInterval, "30 min"),
                     'MixPoolRate' : ('ALLOW', _parseFraction, "60%"),
                     'MixPoolMinSize' : ('ALLOW', C._parseInt, "5"),
		     'Timeout' : ('ALLOW', C._parseInterval, "5 min"),
                     },
        'DirectoryServers' : { 'ServerURL' : ('ALLOW*', None, None),
                               'Publish' : ('ALLOW', C._parseBoolean, "no"),
                               'MaxSkew' : ('ALLOW', C._parseInterval,
                                            "10 minutes",) },
        # FFFF Generic multi-port listen/publish options.
        'Incoming/MMTP' : { 'Enabled' : ('REQUIRE', C._parseBoolean, "no"),
                            'IP' : ('ALLOW', C._parseIP, "0.0.0.0"),
                            'Port' : ('ALLOW', C._parseInt, "48099"),
			  'Allow' : ('ALLOW*', C._parseAddressSet_allow, None),
                          'Deny' : ('ALLOW*', C._parseAddressSet_deny, None) 
			 },
        'Outgoing/MMTP' : { 'Enabled' : ('REQUIRE', C._parseBoolean, "no"),
                          'Allow' : ('ALLOW*', C._parseAddressSet_allow, None),
                          'Deny' : ('ALLOW*', C._parseAddressSet_deny, None) },
        # FFFF Missing: Queue-Size / Queue config options
        # FFFF         listen timeout??
        # FFFF         Retry options
        # FFFF         pool options
        }
