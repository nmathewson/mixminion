#!/usr/bin/env python
#
#  Copyright (c) 2002 Bryce "Zooko" Wilcox-O'Hearn
#  portions Copyright (c) 2001 Autonomous Zone Industries
#  This file is licensed under the
#    GNU Lesser General Public License v2.1.
#    See the file COPYING or visit http://www.gnu.org/ for details.

# Python standard library modules
import exceptions, string, types, zlib

# XXXX (I've added this line since we never seem to import hr.) -NM
hr = repr

true = 1
false = 0

class DecompressError(exceptions.StandardError, zlib.error): pass
class UnsafeDecompressError(DecompressError): pass # This means it would take more memory to decompress than we can spare.
class TooBigError(DecompressError): pass # This means the resulting uncompressed text would exceed the maximum allowed length.
class ZlibError(DecompressError): pass # internal error, probably due to the input not being zlib compressed text

def safe_zlib_decompress_to_retval(zbuf, maxlen=(65 * (2**20)), maxmem=(65 * (2**20))):
    """
    Decompress zbuf so that it decompresses to <= maxlen bytes, while using <= maxmem memory, or else raise an exception.  If `zbuf' contains uncompressed data an exception will be raised.

    This function guards against memory allocation attacks.

    @param maxlen the resulting text must not be greater than this
    @param maxmem the execution of this function must not use more than this amount of memory in bytes;  The higher this number is (optimally 1032 * maxlen, or even greater), the faster this function can complete.  (Actually I don't fully understand the workings of zlib, so this function might use a *little* more than this memory, but not a lot more.)  (Also, this function will raise an exception if the amount of memory required even *approaches* `maxmem'.  Another reason to make it large.)  (Hence the default value which would seem to be exceedingly large until you realize that it means you can decompress 32 KB chunks of compressiontext at a bite.)

    @precondition `maxlen' must be a real maxlen, geez!: ((type(maxlen) == types.IntType) or (type(maxlen) == types.LongType)) and maxlen > 0: "maxlen: %s :: %s" % (hr(maxlen), hr(type(maxlen)))
    @precondition `maxmem' must be at least 1 MB.: maxmem >= 2 ** 20: "maxmem: %s" % hr(maxmem)
    """
    assert ((type(maxlen) == types.IntType) or (type(maxlen) == types.LongType)) and maxlen > 0, "precondition: `maxlen' must be a real maxlen, geez!" + " -- " + "maxlen: %s :: %s" % (hr(maxlen), hr(type(maxlen)))
    assert maxmem >= 2 ** 20, "precondition: `maxmem' must be at least 1 MB." + " -- " + "maxmem: %s" % hr(maxmem)

    lenzbuf = len(zbuf)
    offset = 0
    decomplen = 0
    availmem = maxmem - (76 * 2**10) # zlib can take around 76 KB RAM to do decompression
    availmem = availmem / 2 # generating the result string from the intermediate strings will require using the same amount of memory again, briefly.  If you care about this kind of thing, then let's rewrite this module in C.

    decompstrlist = []

    decomp = zlib.decompressobj()
    while offset < lenzbuf:
        # How much compressedtext can we safely attempt to decompress now without going over `maxmem'?  zlib docs say that theoretical maximum for the zlib format would be 1032:1.
        lencompbite = availmem / 1032 # XXX TODO: The biggest compression ratio zlib can have for whole files is 1032:1.  Unfortunately I don't know if small chunks of compressiontext *within* a file can expand to more than that.  I'll assume not...  --Zooko 2001-05-12
        if lencompbite < 128:
            # If we can't safely attempt even a few bytes of compression text, let us give up.  Either `maxmem' was too small or this compressiontext is actually a decompression bomb.
            raise UnsafeDecompressError, "used up roughly `maxmem' memory. maxmem: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxmem), hr(len(zbuf)), hr(offset), hr(decomplen),)
        # I wish the following were a local function like this:
        # def proc_decomp_bite(tmpstr, lencompbite=0, decomplen=decomplen, maxlen=maxlen, availmem=availmem, decompstrlist=decompstrlist, offset=offset, zbuf=zbuf):
        # ...but until we can depend on Python 2.1 with lexical scoping, we can't update the integers like `offset'.  Oh well.  --Zooko 2001-05-12
        try:
            if (offset == 0) and (lencompbite >= lenzbuf):
                tmpstr = decomp.decompress(zbuf)
            else:
                tmpstr = decomp.decompress(zbuf[offset:offset+lencompbite])
        except zlib.error, le:
            raise ZlibError, (offset, lencompbite, decomplen, hr(le), )

        lentmpstr = len(tmpstr)
        decomplen = decomplen + lentmpstr
        if decomplen > maxlen:
            raise TooBigError, "length of resulting data > `maxlen'. maxlen: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxlen), hr(len(zbuf)), hr(offset), hr(decomplen),)
        availmem = availmem - lentmpstr
        offset = offset + lencompbite
        decompstrlist.append(tmpstr)
        tmpstr = ''

    try:
        tmpstr = decomp.flush()
    except zlib.error, le:
        raise ZlibError, (offset, lencompbite, decomplen, le, )

    lentmpstr = len(tmpstr)
    decomplen = decomplen + lentmpstr
    if decomplen > maxlen:
        raise TooBigError, "length of resulting data > `maxlen'. maxlen: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxlen), hr(len(zbuf)), hr(offset), hr(decomplen),)
    availmem = availmem - lentmpstr
    offset = offset + lencompbite
    if lentmpstr > 0:
        decompstrlist.append(tmpstr)
        tmpstr = ''

    if len(decompstrlist) > 0:
        return string.join(decompstrlist, '')
    else:
        return decompstrlist[0]

def safe_zlib_decompress_to_file(zbuf, fileobj, maxlen=(65 * (2**20)), maxmem=(65 * (2**20))):
    """
    Decompress zbuf so that it decompresses to <= maxlen bytes, while using <= maxmem memory, or else raise an exception.  If `zbuf' contains uncompressed data an exception will be raised.

    This function guards against memory allocation attacks.

    Note that this assumes that data written to `fileobj' continues to take up memory.

    @param maxlen the resulting text must not be greater than this
    @param maxmem the execution of this function must not use more than this amount of memory in bytes;  The higher this number is (optimally 1032 * maxlen, or even greater), the faster this function can complete.  (Actually I don't fully understand the workings of zlib, so this function might use a *little* more than this memory, but not a lot more.)  (Also, this function will raise an exception if the amount of memory required even *approaches* `maxmem'.  Another reason to make it large.)  (Hence the default value which would seem to be exceedingly large until you realize that it means you can decompress 64 KB chunks of compressiontext at a bite.)
    @param fileobj the decompressed text will be written to it

    @precondition `fileobj' must be an IO.: fileobj is not None
    @precondition `maxlen' must be a real maxlen, geez!: ((type(maxlen) == types.IntType) or (type(maxlen) == types.LongType)) and maxlen > 0: "maxlen: %s :: %s" % (hr(maxlen), hr(type(maxlen)))
    @precondition `maxmem' must be at least 1 MB.: maxmem >= 2 ** 20: "maxmem: %s" % hr(maxmem)
    """
    assert fileobj is not None, "precondition: `fileobj' must be an IO."
    assert ((type(maxlen) == types.IntType) or (type(maxlen) == types.LongType)) and maxlen > 0, "precondition: `maxlen' must be a real maxlen, geez!" + " -- " + "maxlen: %s :: %s" % (hr(maxlen), hr(type(maxlen)))
    assert maxmem >= 2 ** 20, "precondition: `maxmem' must be at least 1 MB." + " -- " + "maxmem: %s" % hr(maxmem)

    lenzbuf = len(zbuf)
    offset = 0
    decomplen = 0
    availmem = maxmem - (76 * 2**10) # zlib can take around 76 KB RAM to do decompression

    decomp = zlib.decompressobj()
    while offset < lenzbuf:
        # How much compressedtext can we safely attempt to decompress now without going over `maxmem'?  zlib docs say that theoretical maximum for the zlib format would be 1032:1.
        lencompbite = availmem / 1032 # XXX TODO: The biggest compression ratio zlib can have for whole files is 1032:1.  Unfortunately I don't know if small chunks of compressiontext *within* a file can expand to more than that.  I'll assume not...  --Zooko 2001-05-12
        if lencompbite < 128:
            # If we can't safely attempt even a few bytes of compression text, let us give up.  Either `maxmem' was too small or this compressiontext is actually a decompression bomb.
            raise UnsafeDecompressError, "used up roughly `maxmem' memory. maxmem: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxmem), hr(len(zbuf)), hr(offset), hr(decomplen),)
        # I wish the following were a local function like this:
        # def proc_decomp_bite(tmpstr, lencompbite=0, decomplen=decomplen, maxlen=maxlen, availmem=availmem, decompstrlist=decompstrlist, offset=offset, zbuf=zbuf):
        # ...but until we can use 2.1 lexical scoping we can't update the integers like `offset'.  Oh well.  --Zooko 2001-05-12
        try:
            if (offset == 0) and (lencompbite >= lenzbuf):
                tmpstr = decomp.decompress(zbuf)
            else:
                tmpstr = decomp.decompress(zbuf[offset:offset+lencompbite])
        except zlib.error, le:
            raise ZlibError, (offset, lencompbite, decomplen, le, )
        lentmpstr = len(tmpstr)
        decomplen = decomplen + lentmpstr
        if decomplen > maxlen:
            raise TooBigError, "length of resulting data > `maxlen'. maxlen: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxlen), hr(len(zbuf)), hr(offset), hr(decomplen),)
        availmem = availmem - lentmpstr
        offset = offset + lencompbite
        fileobj.write(tmpstr)
        tmpstr = ''

    try:
        tmpstr = decomp.flush()
    except zlib.error, le:
        raise ZlibError, (offset, lencompbite, decomplen, le, )
    lentmpstr = len(tmpstr)
    decomplen = decomplen + lentmpstr
    if decomplen > maxlen:
        raise TooBigError, "length of resulting data > `maxlen'. maxlen: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxlen), hr(len(zbuf)), hr(offset), hr(decomplen),)
    availmem = availmem - lentmpstr
    offset = offset + lencompbite
    fileobj.write(tmpstr)
    tmpstr = ''

def safe_zlib_decompress_spool_to_file(zbuf, fileobj, maxlen=(65 * (2**20)), maxmem=(65 * (2**20))):
    """
    Decompress zbuf so that it decompresses to <= maxlen bytes, while using <= maxmem memory, or else raise an exception.  If `zbuf' contains uncompressed data an exception will be raised.

    This function guards against memory allocation attacks.

    Note that this assumes that data written to `fileobj' does *not* continue to occupy memory.

    @param maxlen the resulting text must not be greater than this
    @param maxmem the execution of this function must not use more than this amount of memory in bytes;  The higher this number is (optimally 1032 * maxlen, or even greater), the faster this function can complete.  (Actually I don't fully understand the workings of zlib, so this function might use a *little* more than this memory, but not a lot more.)  (Also, this function will raise an exception if the amount of memory required even *approaches* `maxmem'.  Another reason to make it large.)  (Hence the default value which would seem to be exceedingly large until you realize that it means you can decompress 64 KB chunks of compressiontext at a bite.)
    @param fileobj the decompressed text will be written to it

    @precondition `fileobj' must be an IO.: fileobj is not None
    @precondition `maxlen' must be a real maxlen, geez!: ((type(maxlen) == types.IntType) or (type(maxlen) == types.LongType)) and maxlen > 0: "maxlen: %s :: %s" % (hr(maxlen), hr(type(maxlen)))
    @precondition `maxmem' must be at least 1 MB.: maxmem >= 2 ** 20: "maxmem: %s" % hr(maxmem)
    """
    assert fileobj is not None, "precondition: `fileobj' must be an IO."
    assert ((type(maxlen) == types.IntType) or (type(maxlen) == types.LongType)) and maxlen > 0, "precondition: `maxlen' must be a real maxlen, geez!" + " -- " + "maxlen: %s :: %s" % (hr(maxlen), hr(type(maxlen)))
    assert maxmem >= 2 ** 20, "precondition: `maxmem' must be at least 1 MB." + " -- " + "maxmem: %s" % hr(maxmem)

    tmpstr = ''
    lenzbuf = len(zbuf)
    offset = 0
    decomplen = 0
    availmem = maxmem - (76 * 2**10) # zlib can take around 76 KB RAM to do decompression

    decomp = zlib.decompressobj()
    while offset < lenzbuf:
        # How much compressedtext can we safely attempt to decompress now without going over `maxmem'?  zlib docs say that theoretical maximum for the zlib format would be 1032:1.
        lencompbite = availmem / 1032 # XXX TODO: The biggest compression ratio zlib can have for whole files is 1032:1.  Unfortunately I don't know if small chunks of compressiontext *within* a file can expand to more than that.  I'll assume not...  --Zooko 2001-05-12
        if lencompbite < 128:
            # If we can't safely attempt even a few bytes of compression text, let us give up.  Either `maxmem' was too small or this compressiontext is actually a decompression bomb.
            raise UnsafeDecompressError, "used up roughly `maxmem' memory. maxmem: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxmem), hr(len(zbuf)), hr(offset), hr(decomplen),)
        # I wish the following were a local function like this:
        # def proc_decomp_bite(tmpstr, lencompbite=0, decomplen=decomplen, maxlen=maxlen, availmem=availmem, decompstrlist=decompstrlist, offset=offset, zbuf=zbuf):
        # ...but until we can use 2.1 lexical scoping we can't update the integers like `offset'.  Oh well.  --Zooko 2001-05-12
        try:
            if (offset == 0) and (lencompbite >= lenzbuf):
                tmpstr = decomp.decompress(zbuf)
            else:
                tmpstr = decomp.decompress(zbuf[offset:offset+lencompbite])
        except zlib.error, le:
            raise ZlibError, (offset, lencompbite, decomplen, le, )
        lentmpstr = len(tmpstr)
        decomplen = decomplen + lentmpstr
        if decomplen > maxlen:
            raise TooBigError, "length of resulting data > `maxlen'. maxlen: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxlen), hr(len(zbuf)), hr(offset), hr(decomplen),)
        offset = offset + lencompbite
        fileobj.write(tmpstr)
        tmpstr = ''

    try:
        tmpstr = decomp.flush()
    except zlib.error, le:
        raise ZlibError, (offset, lencompbite, decomplen, le, )
    lentmpstr = len(tmpstr)
    decomplen = decomplen + lentmpstr
    if decomplen > maxlen:
        raise TooBigError, "length of resulting data > `maxlen'. maxlen: %s, len(zbuf): %s, offset: %s, decomplen: %s" % (hr(maxlen), hr(len(zbuf)), hr(offset), hr(decomplen),)
    offset = offset + lencompbite
    fileobj.write(tmpstr)
    tmpstr = ''

