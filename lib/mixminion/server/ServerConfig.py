# Copyright 2002-2003 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerConfig.py,v 1.27 2003/05/29 01:46:45 nickm Exp $

"""Configuration format for server configuration files.

   See Config.py for information about the generic configuration facility."""

__all__ = [ "ServerConfig" ]

import operator

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

    def validate(self, lines, contents):
        def _haveEntry(self, section, ent):
            entries = self._sectionEntries
            return len([e for e in entries[section] if e[0] == ent]) != 0

        # Pre-emptively configure the log before validation, so we don't
        # write to the terminal if we've been asked not to.
        if not self['Server'].get("EchoMessages", 0):
            LOG.handlers = []
            # ???? This can't be the best way to do this.

        # Now, validate the host section.
        mixminion.Config._validateHostSection(self['Host'])
        # Server section
        server = self['Server']
        bits = server['IdentityKeyBits']
        if not (2048 <= bits <= 4096):
            raise ConfigError("IdentityKeyBits must be between 2048 and 4096")
        if server['EncryptIdentityKey']:
            LOG.warn("Identity key encryption not yet implemented")
        if server['EncryptPrivateKey']:
            LOG.warn("Encrypted private keys not yet implemented")
        if server['PublicKeyLifetime'].getSeconds() < 24*60*60:
            raise ConfigError("PublicKeyLifetime must be at least 1 day.")
        if server['PublicKeyOverlap'].getSeconds() > 6*60*60:
            raise ConfigError("PublicKeyOverlap must be <= 6 hours")

        if _haveEntry(self, 'Server', 'NoDaemon'):
            LOG.warn("The NoDaemon option is obsolete.  Use Daemon instead.")

        if _haveEntry(self, 'Server', 'Mode'):
            LOG.warn("Mode specification is not yet supported.")

        mixInterval = server['MixInterval'].getSeconds()
        if mixInterval < 30*60:
            LOG.warn("Dangerously low MixInterval")
        if server['MixAlgorithm'] == 'TimedMixPool':
            if _haveEntry(self, 'Server', 'MixPoolRate'):
                LOG.warn("Option MixPoolRate is not used for Timed mixing.")
            if _haveEntry(self, 'Server', 'MixPoolMinSize'):
                LOG.warn("Option MixPoolMinSize is not used for Timed mixing.")
        else:
            rate = server['MixPoolRate']
            minSize = server['MixPoolMinSize']
            if rate < 0.05:
                LOG.warn("Unusually low MixPoolRate %s", rate)
            if minSize < 0:
                raise ConfigError("MixPoolMinSize %s must be nonnegative.")

        if not self['Incoming/MMTP'].get('Enabled'):
            LOG.warn("Disabling incoming MMTP is not yet supported.")
        if [e for e in self._sectionEntries['Incoming/MMTP']
            if e[0] in ('Allow', 'Deny')]:
            LOG.warn("Allow/deny are not yet supported")

        if not self['Outgoing/MMTP'].get('Enabled'):
            LOG.warn("Disabling incoming MMTP is not yet supported.")
        if [e for e in self._sectionEntries['Outgoing/MMTP']
            if e[0] in ('Allow', 'Deny')]:
            LOG.warn("Allow/deny are not yet supported")

        self.validateRetrySchedule("Outgoing/MMTP")

        self.moduleManager.validate(self, lines, contents)

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

    def getInsecurities(self):
        """Return false iff this configuration is reasonably secure.
           Otherwise, return a list of reasons why it isn't."""
        reasons = ["Software is alpha"]

        # SERVER
        server = self['Server']
        if server['LogLevel'] in ('TRACE', 'DEBUG'):
            reasons.append("Log is too verbose")
        if server['LogStats'] and server['StatsInterval'].getSeconds() \
               < 24*60*60:
            reasons.append("StatsInterval is too short")
        if not server["EncryptIdentityKey"]:
            reasons.append("Identity key is not encrypted")
        # ???? Pkey lifetime, sloppiness?
        if server["MixAlgorithm"] not in _SECURE_MIX_RULES:
            reasons.append("Mix algorithm is not secure")
        else:
            if server["MixPoolMinSize"] < 5:
                reasons.append("MixPoolMinSize is too small")
            #???? MixPoolRate
        if server["MixInterval"].getSeconds() < 30*60:
            reasons.append("Mix interval under 30 minutes")

        # ???? Incoming/MMTP

        # ???? Outgoing/MMTP

        # ???? Modules

        return reasons

    def validateRetrySchedule(self, sectionName, entryName='Retry'):
        """Check whether the retry schedule in self[sectionName][entryName]
           is reasonable.  Warn or raise ConfigError if it isn't.  Ignore
           the entry if it isn't there.
        """
        entry = self[sectionName].get(entryName,None)
        if not entry:
            return
        mixInterval = self['Server']['MixInterval'].getSeconds()
        _validateRetrySchedule(mixInterval, entry, sectionName)

def _validateRetrySchedule(mixInterval, schedule, sectionName):
    """Backend for ServerConfig.validateRetrySchedule -- separated for testing.

       mixInterval -- our batching interval.
       schedule -- a retry schedule as returned by _parseIntervalList.
       sectionName -- the name of the retrying subsystem: used for messages.
    """
    total = reduce(operator.add, schedule, 0)

    # Warn if we try for less than a day.
    if total < 24*60*60:
        LOG.warn("Dangerously low retry timeout for %s (<1 day)", sectionName)

    # Warn if we try for more than two weeks.
    if total > 2*7*24*60*60:
        LOG.warn("Very high retry timeout for %s (>14 days)", sectionName)

    # Warn if any of our intervals are less than the mix interval...
    if min(schedule) < mixInterval-2:
        LOG.warn("Rounding retry intervals for %s to the nearest mix",
                 sectionName)

    # ... or less than 5 minutes.
    elif min(schedule) < 5*60:
        LOG.warn("Very fast retry intervals for %s (< 5 minutes)", sectionName)

    # Warn if we make fewer than 5 attempts.
    if len(schedule) < 5:
        LOG.warn("Dangerously low number of retries for %s (<5)", sectionName)

    # Warn if we make more than 50 attempts.
    if len(schedule) > 50:
        LOG.warn("Very high number of retries for %s (>50)", sectionName)

#======================================================================

_MIX_RULE_NAMES = {
    'timed' : "TimedMixPool",
    'cottrell'     : "CottrellMixPool",
    'mixmaster'    : "CottrellMixPool",
    'dynamicpool'  : "CottrellMixPool",
    'binomial'            : "BinomialCottrellMixPool",
    'binomialcottrell'    : "BinomialCottrellMixPool",
    'binomialdynamicpool' : "BinomialCottrellMixPool",
}

_SECURE_MIX_RULES = [ "CottrellMixPool", "BinomialCottrellMixPool" ]

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
                     'Daemon' : ('ALLOW', C._parseBoolean, "no"),
                     # Deprecated.
                     'NoDaemon' : ('ALLOW', C._parseBoolean, None),
                     'LogStats' : ('ALLOW', C._parseBoolean, 'yes'),
                     'StatsInterval' : ('ALLOW', C._parseInterval,
                                        "1 day"),
                     'StatsFile' : ('ALLOW', None, None),
                     'EncryptIdentityKey' :('ALLOW', C._parseBoolean, "no"),
                     'IdentityKeyBits': ('ALLOW', C._parseInt, "2048"),
                     'PublicKeyLifetime' : ('ALLOW', C._parseInterval,
                                            "30 days"),
                     'PublicKeyOverlap': ('ALLOW', C._parseInterval,
                                          "5 minutes"),
                     'EncryptPrivateKey' : ('ALLOW', C._parseBoolean, "no"),
                     'Mode' : ('REQUIRE', C._parseServerMode, "local"),
                     'Nickname': ('REQUIRE', C._parseNickname, None),
                     'Contact-Email': ('ALLOW', None, None),
                     'Comments': ('ALLOW', None, None),
                     'ModulePath': ('ALLOW', None, None),
                     'Module': ('ALLOW*', None, None),
                     'MixAlgorithm' : ('ALLOW', _parseMixRule, "Timed"),
                     'MixInterval' : ('ALLOW', C._parseInterval, "30 min"),
                     'MixPoolRate' : ('ALLOW', _parseFraction, "60%"),
                     'MixPoolMinSize' : ('ALLOW', C._parseInt, "5"),
		     'Timeout' : ('ALLOW', C._parseInterval, "5 min"),
                     },
        'DirectoryServers' : { # '__SECTION__' : ('REQUIRE', None, None),
                               'ServerURL' : ('ALLOW*', None, None),
                               'PublishURL' : ('ALLOW*', None, None),
                               'Publish' : ('ALLOW', C._parseBoolean, "no"),
                               'MaxSkew' : ('ALLOW', C._parseInterval,
                                            "10 minutes",) },
        # FFFF Generic multi-port listen/publish options.
        'Incoming/MMTP' : { 'Enabled' : ('REQUIRE', C._parseBoolean, "no"),
                            'IP' : ('ALLOW', C._parseIP, "0.0.0.0"),
                          'Port' : ('ALLOW', C._parseInt, "48099"),
                          'ListenIP' : ('ALLOW', C._parseIP, None),
                          'ListenPort' : ('ALLOW', C._parseInt, None),
  		          'Allow' : ('ALLOW*', C._parseAddressSet_allow, None),
                          'Deny' : ('ALLOW*', C._parseAddressSet_deny, None)
			 },
        'Outgoing/MMTP' : { 'Enabled' : ('REQUIRE', C._parseBoolean, "no"),
                            'Retry' : ('ALLOW', C._parseIntervalList,
                                    ".5 hour for 1 day, 7 hours for 5 days"),
                          'Allow' : ('ALLOW*', C._parseAddressSet_allow, None),
                          'Deny' : ('ALLOW*', C._parseAddressSet_deny, None) },
        # FFFF Missing: Queue-Size / Queue config options
        # FFFF         listen timeout??
        }
