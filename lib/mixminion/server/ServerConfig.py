# Copyright 2002 Nick Mathewson.  See LICENSE for licensing information.
# $Id: ServerConfig.py,v 1.2 2002/12/15 05:55:30 nickm Exp $

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
	# Pre-emptively configure the log before validation, so we don't
	# write to the terminal if we've been asked not to.
	if not sections['Server'].get("EchoMessages", 0):
	    LOG.handlers = []
	    # ???? This can't be the best way to do this.

	# Now, validate the host section.
	mixminion.Config._validateHostSection(sections.get('Host', {}))
	# Server section
	server = sections['Server']
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
	if [e for e in entries['Server'] if e[0]=='Mode']:
	    LOG.warn("Mode specification is not yet supported.")

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
                          'Deny' : ('ALLOW*', C._parseAddressSet_deny, None) },
        'Outgoing/MMTP' : { 'Enabled' : ('REQUIRE', C._parseBoolean, "no"),
                          'Allow' : ('ALLOW*', C._parseAddressSet_allow, None),
                          'Deny' : ('ALLOW*', C._parseAddressSet_deny, None) },
	# FFFF Missing: Queue-Size / Queue config options
	# FFFF         timeout options
	# FFFF         listen timeout??
	# FFFF         Retry options
	# FFFF         pool options
        }
