/* Copyright (c) 2002 Nick Mathewson.  See LICENSE for licensing information */
/* $Id: aes_ctr.c,v 1.5 2002/08/15 05:26:08 nickm Exp $ */

/* This file reimplements counter mode.  The OpenSSL implementation is
 * unsuitable because 
 *          a) It wants to compute E(x << 64) for E(0),E(1),...
 *          b) It can't begin in the middle of a stream.  (It can resume,
 *             but that's not the same.)
 *          c) It uses some awfully brute-forceish logic to increment
 *             the counter.  Sure, that's not in the critical path,
 *             but it still wrankles.
 *
 * Disclosure: I have seen and played with the OpenSSL implementation for
 *   a while before I decided to abandon it.
 */

#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>

typedef unsigned int u32;
typedef unsigned char u8;

/* ======================================================================
   Endianness is ugly. */

#undef GET_U32
#undef SET_U32

#ifdef MM_B_ENDIAN
#define GET_U32(ptr) (*(u32*)(ptr))
#define SET_U32(ptr,i) (*(u32*)(ptr)) = i 
#define INCR_U32(ptr, i) i = ++(*(u32*)(ptr))
#endif

#if 0  
/* On my Athlon, bswap_32 is actually slower.  Surprisingly,
   the code in glib/gtypes.h _is_ faster; but shaves only 1%
   off encryption.  We seem to be near the point of diminishing
   returns here. */
#ifdef MM_L_ENDIAN
#ifdef MM_HAVE_BYTESWAP_H
#include <byteswap.h>
#define GET_U32(ptr) bswap_32(*(u32*)(ptr))
#define SET_U32(ptr,i) (*(u32*)(ptr)) = bswap_32(i)
#endif
#endif
#endif 


#ifndef GET_U32 
#define GET_U32_cp(ptr) (  (u32)ptr[0] ^         \
                         (((u32)ptr[1]) << 8) ^  \
                         (((u32)ptr[2]) << 16) ^ \
                         (((u32)ptr[3]) << 24))
#define SET_U32_cp(ptr, i) { ptr[0] = (i)     & 0xff; \
                             ptr[1] = (i>>8)  & 0xff; \
                             ptr[2] = (i>>16) & 0xff; \
                             ptr[3] = (i>>24) & 0xff; } 
#define GET_U32(ptr)   GET_U32_cp(((u8*)(ptr)))
#define SET_U32(ptr,i) SET_U32_cp(((u8*)(ptr)), i)
#define INCR_U32(ptr, i) { i = GET_U32(ptr)+1; SET_U32(ptr,i); }
#endif

static inline void
mm_incr(u32 const* ctr32)
{
	u32 i;

	INCR_U32(ctr32+3,i);
	if (i) return;

	INCR_U32(ctr32+2,i);
	if (i) return;

	INCR_U32(ctr32+1,i);
	if (i) return;

	INCR_U32(ctr32,  i);
#if 0
	i = GET_U32(ctr32+3) + 1;
	SET_U32(ctr32+3, i);
	if (i) return;
	
	i = GET_U32(ctr32+2) + 1;
	SET_U32(ctr32+2, i);
	if (i) return;
	
	i = GET_U32(ctr32+1) + 1;
	SET_U32(ctr32+1, i);
	if (i) return;
			
	i = GET_U32(ctr32) + 1;
	SET_U32(ctr32, i);
#endif
}

void
mm_aes_counter128(const char *in, char *out, unsigned int len, AES_KEY *key,
                  unsigned long count) 
{
	unsigned char counter[16];
	unsigned char tmp[16];
	/* making this a variable can hurt register pressure, and we'd
	   really like the compiler to be able to inline mm_incr above. */
	#define CTR32 ((u32*)counter)

	if (!len) return;
	memset(counter, 0, 12);
	SET_U32(CTR32+3, count >> 4);
	count &= 0x0f;

	while (1) {
		AES_encrypt(counter, tmp, key);
		do {
			*(out++) = *(in++) ^ tmp[count];
			if (--len == 0) return; 
		} while (++count != 16);
		mm_incr(CTR32);
		count = 0;
	}
}

/*
  Local Variables:
  mode:c
  c-basic-offset:8
  End:
*/
