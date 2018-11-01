/*------------------------------------------------------------------
 * safe_mem_lib.h - Replacements for Safe C Library Memory Functions
 * 
 * Contains code derived from https://sourceforge.net/projects/safeclib/
 * license reproduced below
 * 
 * October 2008-2018, Bo Berry
 *
 * Copyright (c) 2008-2011 by Cisco Systems, Inc
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *------------------------------------------------------------------
 */
#ifndef __SAFE_MEM_LIB_H__
#define __SAFE_MEM_LIB_H__

#include <stdint.h>
#include "safe_lib_errno.h"

/* Defining the RSIZE_MAX macro */
#ifndef RSIZE_MAX
#define RSIZE_MAX         SIZE_MAX/2
#endif

/**
 *  Maximum memory sizes definitions  based on types 
 */
#ifndef RSIZE_MAX_MEM
#define RSIZE_MAX_MEM       RSIZE_MAX
#endif
#ifndef RSIZE_MAX_MEM16 
#define RSIZE_MAX_MEM16    ( RSIZE_MAX_MEM/2 )
#endif
#ifndef RSIZE_MAX_MEM32 
#define RSIZE_MAX_MEM32    ( RSIZE_MAX_MEM/4 )
#endif


/* copy memory */
extern errno_t memcpy_s(void *dest, rsize_t dmax, const void *src, rsize_t slen);

/* compare memory */
extern errno_t memcmp_s(const void *dest, rsize_t dmax, const void *src, rsize_t slen, int *diff);

/* Set memory */
extern errno_t memset_s (void *s, rsize_t smax, int c, rsize_t n);

/* clear bytes */
extern errno_t memzero_s(void *dest, rsize_t dmax);

/* Move bytes */
extern errno_t memmove_s(void *dest, rsize_t dmax, const void *src, rsize_t smax);

#endif /* __SAFE_MEM_LIB_H__ */
