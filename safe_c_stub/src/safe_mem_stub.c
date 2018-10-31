/*------------------------------------------------------------------
 * safe_mem_stub.c - Replacements for Safe C Library Memory Functions
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
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "safe_lib.h"

/*
 * memset_s()
 *
 * Due to changes in the memset_s api in different versions of safe c,
 * we want to use memzero_s instead.  Do not include memset_s in the
 * stubs!!
 */

/*
 * memzero_s()
 *
 * Emulate subset of the functionality of memzero_s() with bzero()
 */
errno_t memzero_s(void *dest, rsize_t dmax)
{
    if (!dest) return (ESNULLP);
    memset(dest, 0, dmax);
    return (EOK);
}

/*
 * memcpy_s()
 *
 * Emulate subset of the functionality of memcpy_s() with memcpy()
 */
errno_t memcpy_s (void *dest, rsize_t dmax, const void *src, rsize_t slen) {
    if (!src || !dest) return (ESNULLP);
    if (slen > dmax) return (ESLEMAX);
    memcpy(dest, src, slen);
    return (EOK);
}

/*
 * memcmp_s()
 *
 * Emulate subset of the functionality of memcmp_s() with memcmp()
 */
errno_t memcmp_s (const void *dest, rsize_t dmax, const void *src, rsize_t slen, int *diff) {
    if (!src || !dest) return (ESNULLP);
    if (dmax == 0) return (ESZEROL);
    if (slen == 0) return (ESZEROL);
    if (slen > dmax) return (ESLEMAX);
    *diff = memcmp(dest, src, slen);
    return (EOK);
}


/*
 * memmove_s()
 *
 * Emulate memmove_s without constraint handling
 */
errno_t memmove_s (void *dest, rsize_t dmax, const void *src, rsize_t smax)
{

    uint8_t *dp;
    const uint8_t  *sp;

    dp= dest;
    sp = src;

    if (dp == NULL) {
        return (ESNULLP);
    }

    if (dmax == 0) {
        return (ESZEROL);
    }

    if (dmax > RSIZE_MAX_MEM) {
        return (ESLEMAX);
    }

    if (smax == 0) {
        memset(dp, 0, dmax);
        return (ESZEROL);
    }

    if (smax > dmax) {
        memset(dp, 0, dmax);
        return (ESLEMAX);
    }

    if (sp == NULL) {
        memset(dp, 0, dmax);
        return (ESNULLP);
    }

    /*
     * now perform the copy
     */
    
    memmove(dp, sp, smax);


    return (EOK);
}

/*
 * memset_s()
 *
 * Emulate memset_s without constraint handling
 */
errno_t memset_s (void *s, rsize_t smax, int c, rsize_t n)
{
    if (s == NULL) {
        return (ESNULLP);
    }

    if (smax > RSIZE_MAX_MEM) { 
        return (ESLEMAX);
    }
    if (n > RSIZE_MAX_MEM) {
        memset(s, c, smax);
        return (ESLEMAX);
    }
    
    if (n > smax) {
        memset(s, c, smax);
        return (ESLEMAX);
    }

    memset(s, c, n);

    return (EOK);
}
