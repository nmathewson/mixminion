# Copyright 2003-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DirFormats.py,v 1.3 2004/12/13 06:01:59 nickm Exp $

"""mixminion.directory.Directory

   General purpose code for directory servers.
   """

import sys

import mixminion
import mixminion.ServerInfo

from mixminion.Common import formatBase64, formatDate, floorDiv, LOG, \
     MixError, previousMidnight

from mixminion.Config import ConfigError
from mixminion.Crypto import pk_sign, sha1, pk_encode_public_key

def _generateDirectory(identity, status,
                      servers, goodServerNames,
                      voters, validAfter,
                      clientVersions, serverVersions):

    assert status in ("vote", "consensus")
    va = formatDate(previousMidnight(validAfter))
    vu = formatDate(previousMidnight(validAfter)+24*60*60+5)
    rec = goodServerNames[:]
    rec.sort()
    rec = ", ".join(rec)
    v = []
    voters.sort()
    for keyid, urlbase in voters:
        v.append("Voting-Server: %s %s\n"
                 % (keyid, urlbase))
    servers = sortServerList(servers)

    cvers = ", ".join(sortVersionList(clientVersions))
    svers = ", ".join(sortVersionList(serverVersions))
    dirInfo = ("[Directory-Info]\n"
               "Version: 0.3\n"
               "Status: %s\n"
               "Valid-After: %s\n"
               "Valid-Until: %s\n"
               "Recommended-Servers: %s\n%s"
               "[Recommended-Software]\n"
               "MixminionClient: %s\n"
               "MixminionServer: %s\n")%(status, va, vu, rec, "".join(v),
                                         cvers, svers)

    unsigned = "".join([dirInfo]+[s._originalContents for s in servers])
    signature = getDirectorySignature(unsigned, identity)
    return signature+unsigned

def generateVoteDirectory(identity, servers, goodServerNames,
                          voters, validAfter, clientVersions, serverVersions,
                          validatedDigests=None):
    valid = []
    for server in servers:
        try:
            s = mixminion.ServerInfo.ServerInfo(
                string=str(server), validatedDigests=validatedDigests,
                _keepContents=1)
        except ConfigError,e:
            LOG.warn("Rejecting malformed serverinfo: %s",e)
        else:
            valid.append(s)

    val = _generateDirectory(identity, 'vote', valid, goodServerNames,
                             voters, validAfter,
                             clientVersions, serverVersions)

    try:
        directory = mixminion.ServerInfo.SignedDirectory(
            string=val, validatedDigests=validatedDigests)
    except ConfigError,e:
        raise MixError("Generated a vote directory that we cannot parse: %s"%e)

    try:
        checkVoteDirectory(voters, validAfter, directory)
    except BadVote, e:
        raise MixError("Generated unacceptable vote directory: %s"%e)

    return val

def generateConsensusDirectory(identity, voters, validAfter, directories,
                               validatedDigests=None):
    # directories is (source, stringable) list

    # First -- whom shall we vote with?
    goodDirectories = [] # (src, stringable)
    serverMap = {} # digest->server info
    serversByDir = {} # keyid->list of digest
    for src, val in directories:
        LOG.debug("Checking vote directory from %s",src)
        val = str(val)
        try:
            directory = mixminion.ServerInfo.SignedDirectory(string=val,
                                  validatedDigests=validatedDigests,
                                  _keepServerContents=1)
        except ConfigError,e:
            LOG.warn("Rejecting malformed vote directory from %s: %s",src,e)
            continue
        try:
            checkVoteDirectory(voters, validAfter, directory)
        except BadVote, e:
            LOG.warn("Rejecting vote directory from %s: %s", src, e)
            continue
        LOG.info("Accepting vote directory from %s",src)

        # Remember server descs minimally to save room.
        sig = directory.getSignatures()[0]
        ident = sig['Signed-Directory']['Directory-Identity']
        keyid = sha1(pk_encode_public_key(ident))
        serversByDir[keyid] = []
        for s in directory.getAllServers():
            d = s.getDigest()
            serversByDir[keyid].append(d)
            if not serverMap.has_key(d):
                serverMap[d] = s

        del directory.servers[:] # Save RAM
        goodDirectories.append((src, directory))

    # Next -- what is the result of the vote? (easy cases)
    threshold = floorDiv(len(voters)+1, 2)
    includedClientVersions = commonElements(
      [d['Recommended-Software']['MixminionClient'] for _,d in goodDirectories],
      threshold)
    includedServerVersions = commonElements(
      [d['Recommended-Software']['MixminionServer'] for _,d in goodDirectories],
      threshold)
    includedRecommended = commonElements(
      [d['Directory-Info']['Recommended-Servers'] for _,d in goodDirectories],
      threshold)

    # Hard part -- what servers go in?

    # Identities go in if they have a consistant nickname, and most voters
    # include them.
    identNickname = {}
    badIdents = {}
    identsByVoter = []
    digestsByIdent = {}
    for digestList in serversByDir.values():
        idents = {}
        for digest in digestList:
            s = serverMap[digest]
            n = s.getNickname()
            ident = s.getIdentityDigest()
            try:
                if n != identNickname[ident]:
                    LOG.warn("Multiple nicknames for %s",formatBase64(ident))
                    badIdents[ident] = 1
            except KeyError:
                identNickname[ident]=n

            idents[ident] = 1
            digestsByIdent.setdefault(ident,{})[digest]=1
        identsByVoter.append(idents.keys())

    includedIdentities = [ i for i in commonElements(identsByVoter, threshold)
                           if not badIdents.has_key(i) ]

    # okay -- for each identity, what servers do we include?
    includedServers = []
    for ident in includedIdentities:
        servers = [ serverMap[digest] for digest in digestsByIdent[ident].keys()]
        for s in servers:
            if s['Server']['ValidUntil'] < validAfter:
                continue
            elif s['Server']['ValidAfter'] - MAX_WINDOW > validAfter:
                continue
            elif s.isSupersededBy(servers):
                continue
            includedServers.append(s)

    # Generate and sign the result.
    return generateDirectory(identity, "consensus",
                             includedServers, includedRecommended,
                             voters, validAfter,
                             includedClientVersions, includedServerVersions)

MAX_WINDOW = 30*24*60*60

class BadVote(Exception):
    """DOCDOC"""
    pass

def checkVoteDirectory(voters, validAfter, directory):
    # my (sorted, uniqd) list of voters, SignedDirectory instance, URL

    # Is there a single signature?
    sigs = directory.getSignatures()
    if len(sigs) == 0:
        raise BadVote("No signatures")
    elif len(sigs) > 1:
        raise BadVote("Too many signatures")
    sig = sigs[0]

    ident = sig['Signed-Directory']['Directory-Identity']
    keyid = mixminion.Crypto.pk_fingerprint(ident)

    # Do we recognize the signing key?
    for k,_ in voters:
        if k == keyid:
            break
    else:
        raise BadVote("Unknown identity key (%s)"%keyid)

    # Is the signature valid?
    if not sig.checkSignature():
        raise BadVote("Invalid signature")

    # Is the version valid?
    if (directory['Directory-Info']['Version'] !=
        mixminion.ServerInfo._DirectoryInfo.VERSION):
        raise BadVote("Unrecognized version (%s)")

    # Is the directory marked as a vote?
    if directory['Directory-Info']['Status'] != 'vote':
        raise BadVote("Not marked as vote")

    # Do we agree about the voters?
    if not _listIsSorted(directory.dirInfo.voters):
        raise BadVote("Voters not sorted")

    vkeys = {}
    for k,u in directory.dirInfo.voters:
        vkeys[k]=u
    mykeys = {}
    for k,u in voters: mykeys[k]=u

    for k,u in directory.dirInfo.voters:
        try:
            if mykeys[k] != u:
                raise BadVote("Mismatched URL for voter %s (%s vs %s)"%(
                    formatBase64(k), u, mykeys[k]))
        except KeyError:
            raise BadVote("Unkown voter %s at %s"%(k,u))
    for k, u in voters:
        if not vkeys.has_key(k):
            raise BadVote("Missing voter %s at %s"%(k,u))

    assert directory.dirInfo.voters == voters

    # Are the dates right?
    va = directory['Directory-Info']['Valid-After']
    vu = directory['Directory-Info']['Valid-Until']
    if va != validAfter:
        raise BadVote("Validity date is wrong (%s)"%formatDate(va))
    elif vu != previousMidnight(va+24*60*60+60):
        raise BadVote("Validity span is not 1 day long (ends at %s)"%
                      formatDate(vu))

    # Is everything sorted right?
    for vs in ['MixminionClient', 'MixminionServer']:
        versions = directory['Recommended-Software'][vs]
        if not versionListIsSorted(versions):
            raise BadVote("%s:%s is not in correct sorted order"%(vs,versions))
    if not serverListIsSorted(directory.getAllServers()):
        raise BadVote("Server descriptors are not in correct sorted order")

def getDirectorySignature(directory, pkey):
    digest = mixminion.ServerInfo._getMultisignedDirectoryDigest(directory)
    signature = pk_sign(digest, pkey)
    encKey = formatBase64(pk_encode_public_key(pkey))
    encSig = formatBase64(signature)
    encDigest = formatBase64(digest)
    return ("[Signed-Directory]\nDirectory-Identity: %s\n"
            "Directory-Digest: %s\nDirectory-Signature: %s\n")%(
        encKey,encDigest,encSig)

def _versionOrdering(v):
    try:
        return mixminion.parse_version_string(v)
    except ValueError:
        return (sys.maxint, sys.maxint)

def _serverOrdering(s):
    return ( s.getNickname().lower(), s['Server']['Valid-After'],
             s.getDigest() )

def sortServerList(servers):
    return _sortedBy(servers, _serverOrdering)

def sortVersionList(versions):
    return _sortedBy(versions, _versionOrdering)

def serverListIsSorted(servers):
    return _listIsSorted(servers, _serverOrdering)

def versionListIsSorted(versions):
    assert _listIsSorted([4,9,16])
    assert not _listIsSorted([4,91,16])
    assert _listIsSorted([16,9,4], lambda x:-x)
    return _listIsSorted(versions, _versionOrdering)

def _sortedBy(lst, keyFn):
    lst2 = [ (keyFn(item), item) for item in lst ]
    lst2.sort()
    return [ item for _, item in lst2 ]

def _listIsSorted(lst, keyFn=None):
    if keyFn is None:
        lst2 = lst[:]
        lst2.sort()
    else:
        lst2 = _sortedBy(lst, keyFn)
    for a,b in zip(lst,lst2):
        if a is not b:
            return 0
    return 1

def commonElements(lists, threshold):
    counts = {}
    for lst in lists:
        m = {}
        for item in lst:
            m[item]=1
        for item in m.keys():
            try:
                counts[item] += 1
            except KeyError:
                counts[item] = 1

    return [ k for k,c in counts.items() if c >= threshold ]
