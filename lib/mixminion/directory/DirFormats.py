# Copyright 2003-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DirFormats.py,v 1.1 2004/08/24 22:16:09 nickm Exp $

"""mixminion.directory.Directory

   General purpose code for directory servers.
   """

import mixminion
import mixminion.ServerInfo
from mixminion.Common import formatBase64, formatDate, floorDiv, LOG
from mixminion.Crypto import pk_sign, sha1, pk_encode_public_key

def generateDirectory(identity, status,
                      servers, goodServerNames,
                      voters, validAfter,
                      clientVersion, serverVersions):

    assert status in ("vote", "consensus")
    va = formatDate(validAfter)
    vu = formatDate(validAfter+24*60*60+5)
    rec = goodServernames[:]
    rec.sort()
    rec = ", ".join(rec)
    v = []
    voters.sort()
    for keyid, urlbase in voters:
        v.append("Voting-Server: %s %s\n"
                 % (formatBase64(keyid), urlbase))

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
    signature = getDirectorySignature(unsigned, pkey)
    return signature+unsigned

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
        goodDirectories.append(src, directory)

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
        for digest in digestLists:
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

    includedIdenties = [ i for i in commonElements(identsByVoter, threshold)
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
                             includedServers, includedNicknames,
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
    keyid = sha1(pk_encode_public_key(ident))

    # Do we recognize the signing key?
    for k,_ in voters:
        if k == keyid:
            break
    else:
        raise BadVote("Unkown identity key (%s)"%formatBase64(keyid))

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
    dVoters = directory.dirInfo.voters[:]
    dVoters.sort()
    if dVoters != directory.dirInfo.voters:
        raise BadVote("Votes not sorted")

    vkeys = {}
    for k,u in dVoters:
        vkeys[k]=u
    mykeys = {}
    for k,u in voters: mykeys[k]=u

    for k,u in dVoters:
        try:
            if mykeys[k] != u:
                raise BadVote("Mismatched URL for voter %s (%s vs %s)"%(
                    formatBase64(k), u, mykeys[k]))
        except KeyError:
            raise BadVote("Unkown voter %s at %s"%(formatBase64(k),u))
    for k, u in voters:
        if not vkeys.has_key(k):
            raise BadVote("Missing voter %s at %s"%(formatBase64(k),u))

    assert dVoters == voters

    # Are the dates right?
    va = directory['Directory-Info']['Valid-After']
    va = directory['Directory-Info']['Valid-Until']
    if va != validAfter:
        raise BadVote("Validity date is wrong (%s)"%formatDate(va))
    elif vu != previousMidnight(va+24*60*60+60):
        raise BadVote("Validity span is not 1 day long (ends at %s)"%
                      formatDate(vu))

def getDirectorySignature(directory, pkey):
    digest = mixminion.ServerInfo._getMultisignedDirectoryDigest(directory)
    signature = pk_sign(digest, pkey)
    encKey = formatBase64(pk_encode_public_key(pkey))
    encSig = formatBase64(signature)
    encDigest = formatBase64(digest)
    return ("[Signed-Directory]\nDirectory-Identity: %s\n"
            "Directory-Digest: %s\nDirectory-Signature: %s\n")%(
        encKey,encDigest,encSig)

def sortVersionList(versionList):
    """DOCDOC"""
    lst = []
    for v in versionList:
        try:
            t = mixminion.parse_version_string(v)
            lst.append((t,v))
        except ValueError:
            lst.append(((sys.maxint,sys.maxint),v))
    lst.sort()
    return [ v for _,v in lst ]

def sortServerList(servers):
    lst = []
    for s in servers:
        lst.append( (s.getNickname().lower(), s['Server']['Valid-After'],
                     s.getDigest(), s) )
    lst.sort()
    return [ s for _, _, _, s in lst ]

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
