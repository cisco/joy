/*------------------------------------------------------------------
 * safe_str_stub.c - Replacements for Safe C Library String Functions
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
#include <string.h>
#include <ctype.h>

#include "safe_lib.h"

#define SAFEC_STUB_UNUSED(x) (void)(x)

/*
 * strcmp_s()
 *
 * Emulate subset of the functionality of strcmp_s() with strncmp()
 */
errno_t strcmp_s (const char *dest, rsize_t dmax, const char *src, int *indicator) {
    if (!src || !dest) return (ESNULLP);
    if (dmax == 0) return (ESZEROL);
    *indicator = strncmp(dest, src, dmax);
    return (EOK);
}

/*
 * strcasecmp_s()
 *
 * Emulate subset of the functionality of strcasecmp_s() with strncasecmp()
 */
errno_t strcasecmp_s (const char *dest, rsize_t dmax, const char *src, int *indicator)
{
    const unsigned char *udest = (const unsigned char *) dest;
    const unsigned char *usrc = (const unsigned char *) src;

    if (indicator == NULL) {
        return (ESNULLP);
    }
    *indicator = 0;

    if (dest == NULL) {
        return (ESNULLP);
    }

    if (src == NULL) {
        return (ESNULLP);
    }

    if (dmax == 0) {
        return (ESZEROL);
    }

    if (dmax > RSIZE_MAX_STR) {
        return (ESLEMAX);
    }

    while (*udest && *usrc && dmax) {

        if (toupper(*udest) != toupper(*usrc)) {
            break;
        }

        udest++;
        usrc++;
        dmax--;
    }

    *indicator = (toupper(*udest) - toupper(*usrc));
    return (EOK);
}

errno_t
strncasecmp_s (const char *s1, rsize_t s1max,
               const char *s2, rsize_t n, int *indicator)
{
    if (s1 && s2 && s1max && s2 && n && indicator) {
        return(strcasecmp_s(s1, s1max, s2, indicator));
    } else {
        *indicator = -1;
        return(ESNULLP);  
    }          
}

/*
 * strcat_s()
 *
 * Emulate subset of the functionality of strcat_s() with strcat()
 */
errno_t strcat_s (char *dest, rsize_t dmax, const char *src) {
    if (!src || !dest) return (ESNULLP);
    if (dmax == 0) return (ESZEROL);
    strncat(dest, src, dmax);
    return (EOK);
}

/*
 * strisdigit_s()
 *
 * Emulate strisdigit_s from SafeC without constraint handling
 */
int strisdigit_s (const char *dest, rsize_t dmax)
{
    if (!dest) {
        return (0);
    }

    if (dmax == 0) {
        return (0);
    }

    if (dmax > RSIZE_MAX_STR) {

        return (0);
    }

    if (*dest == '\0') {
        return (0);
    }

    while (*dest) {

        if ((*dest < '0') || (*dest > '9')) {
            return (0);
        }
        dest++;
        dmax--;
    }

    return (1);
}

/*
 * strcspn_s()
 *
 * Emulate strcspn_s from SafeC without constraint handling
 */
errno_t
strcspn_s (const char *dest, rsize_t dmax,
           const char *src,  rsize_t slen, rsize_t *count)
{
    const char *scan2;
    rsize_t smax;

    if (count== NULL) {
        return (ESNULLP);
    }
    *count = 0;

    if (dest == NULL) {
        return (ESNULLP);
    }

    if (src == NULL) {
        return (ESNULLP);
    }

    if (dmax == 0 ) {
        return (ESZEROL);
    }

    if (dmax > RSIZE_MAX_STR) {
        return (ESLEMAX);
    }

    if (slen == 0 ) {
        return (ESZEROL);
    }

    if (slen > RSIZE_MAX_STR) {
        return (ESLEMAX);
    }

    while (*dest && dmax) {

        /*
         * Scanning for exclusions, so if there is a match,
         * we're done!
         */
        smax = slen;
        scan2 = src;
        while (*scan2 && smax) {

             if (*dest == *scan2) {
                 return (EOK);
             }
             scan2++;
             smax--;
        }

        (*count)++;
        dest++;
        dmax--;
    }

    return (EOK);
}

/*
 * strspn_s()
 *
 * Emulate strspn_s from SafeC without constraint handling
 */
errno_t
strspn_s (const char *dest, rsize_t dmax,
          const char *src,  rsize_t slen, rsize_t *count)
{
    const char *scan2;
    rsize_t smax;
    int match_found;

    if (count== NULL) {
        return (ESNULLP);
    }
    *count = 0;

    if (dest == NULL) {
        return (ESNULLP);
    }

    if (src == NULL) {
        return (ESNULLP);
    }

    if (dmax == 0 ) {
        return (ESZEROL);
    }

    if (dmax > RSIZE_MAX_STR) {
        return (ESLEMAX);
    }

    if (slen == 0 ) {
        return (ESZEROL);
    }

    if (slen > RSIZE_MAX_STR) {
        return (ESLEMAX);
    }

    while (*dest && dmax) {

        /*
         * Scan the entire src string for each dest character, counting
         * inclusions.
         */
        match_found = 0;
        smax = slen;
        scan2 = src;
        while (*scan2 && smax) {

            if (*dest == *scan2) {
                match_found = 1;
                break;
            }
            scan2++;
            smax--;
        }

        if (match_found) {
            (*count)++;
        } else {
            break;
        }

        dest++;
        dmax--;
    }

    return (EOK);
}


/*
 * strncat_s()
 *
 * Emulate subset of the functionality of strncat_s() with strncat()
 */
errno_t strncat_s (char *dest, rsize_t dmax, const char *src, rsize_t slen) {
    if (!src || !dest) return (ESNULLP);
    if (dmax == 0) return (ESZEROL);
    strncat(dest, src, slen);
    return (EOK);
}

/*
 * strcpy_s()
 *
 * Emulate subset of the functionality of strcpy_s() with strcpy()
 */
errno_t strcpy_s (char *dest, rsize_t dmax, const char *src) {
    if (!src || !dest) return (ESNULLP);
    if (dmax == 0) return (ESZEROL);
    strncpy(dest, src, dmax);
    return (EOK);
}

/*
 * strncpy_s()
 *
 * Emulate subset of the functionality of strncpy_s() without constraint handling
 */
errno_t strncpy_s (char *dest, rsize_t dmax, const char *src, rsize_t slen)
{
    char *orig_dest;
    const char *overlap_bumper;

    if (dest == NULL) {
        return (ESNULLP);
    }

    if (dmax == 0) {
        return (ESZEROL);
    }

    if (dmax > RSIZE_MAX_STR) {
        return (ESLEMAX);
    }

    /* hold base in case src was not copied */  
    orig_dest = dest;

    if (src == NULL) {
        *orig_dest = '\0';
        return (ESNULLP);
    }

    if (slen > RSIZE_MAX_STR) {
        *orig_dest = '\0';
    }


   if ((uintptr_t)dest < (uintptr_t)src) {
       overlap_bumper = src;

        while (dmax > 0) {
            if (dest == overlap_bumper) {
                *orig_dest = '\0';
                return (ESOVRLP); 
            }

	    if (slen == 0) {
                /*
                 * Copying truncated to n chars.  Note that the C11 says to
                 * copy n chars plus the null char.  
                 */
                *dest = '\0'; 
                return (EOK);
            }

            *dest = *src;
            if (*dest == '\0') {
                return (EOK);
            }

            dmax--;
            slen--;
            dest++;
            src++;
        }

    } else { 
        overlap_bumper = dest;

        while (dmax > 0) {
            if (src == overlap_bumper) {
                *orig_dest = '\0';
                return (ESOVRLP); 
            }

	    if (slen == 0) {
                /*
                 * Copying truncated to n chars.  Note that the C11 says to
                 * copy n chars plus the null char. 
                 */
                *dest = '\0'; 
                return (EOK);
            }

            *dest = *src;
            if (*dest == '\0') {
                return (EOK);
            }

            dmax--;
            slen--;
            dest++;
            src++;
        }
    } 

    /*
     * the entire src was not copied, so zero the string
     */
    *orig_dest = '\0';

    return(ESNOSPC);
}

/*
 * strnlen_s()
 *
 * Emulate subset of the functionality of strnlen_s() with strnlen_s()
 */
rsize_t strnlen_s (const char *s, rsize_t smax) {
    return (strnlen(s, smax));
}

/*
 * strstr_s()
 *
 * Emulate subset of the functionality of strstr_s() with strstr()
 */
errno_t strstr_s (char *dest, rsize_t dmax, 
                  const char *src, rsize_t slen, char **substring) {
    SAFEC_STUB_UNUSED(dmax);
    SAFEC_STUB_UNUSED(slen);
    *substring = strstr(dest, src);
    return (*substring ? EOK : ESNOTFND);
}

/*
 * strtok_s()
 *
 * Emulate subset of the functionality of strtok_s() without constraint handling
 */
char *
strtok_s (char *dest, rsize_t *dmax, const char *src, char **ptr)
{

/*
 * CONFIGURE: The spec does not call out a maximum for the src
 * string, so one is defined here.
 */
#define  STRTOK_DELIM_MAX_LEN   ( 16 )


    const char *pt;
    char *ptoken;
    rsize_t dlen;
    rsize_t slen;

    if (dmax == NULL) {
        return (NULL);
    }

    if (*dmax == 0) {
        return (NULL);
    }

    if (*dmax > RSIZE_MAX_STR) {
        return (NULL);
    }

    if (src == NULL) {
        return (NULL);
    }

    if (ptr == NULL) {
        return (NULL);
    }

    /* if the source was NULL, use the tokenizer context */
    if (dest == NULL) {
        dest = *ptr;
    }

    /*
     * scan dest for a delimiter
     */
    dlen = *dmax;
    ptoken = NULL;
    while (*dest != '\0' && !ptoken) {

        if (dlen == 0) {
            *ptr = NULL;
            return (NULL);
        }

        /*
         * must scan the entire delimiter list
         * ISO should have included a delimiter string limit!!
         */
        slen = STRTOK_DELIM_MAX_LEN;
        pt = src;
        while (*pt != '\0') {

            if (slen == 0) {
                *ptr = NULL;
                return (NULL);
            }
            slen--;

            if (*dest == *pt) {
                ptoken = NULL;
                break;
            } else {
                pt++;
                ptoken = dest;
            }
        }
        dest++;
        dlen--;
    }

    /*
     * if the beginning of a token was not found, then no
     * need to continue the scan.
     */
    if (ptoken == NULL) {
        *dmax = dlen;
        return (ptoken);
    }

    /*
     * Now we need to locate the end of the token
     */
    while (*dest != '\0') {

        if (dlen == 0) {
            *ptr = NULL;
            return (NULL);
        }

        slen = STRTOK_DELIM_MAX_LEN;
        pt = src;
        while (*pt != '\0') {

            if (slen == 0) {
                *ptr = NULL;
                return (NULL);
            }
            slen--;

            if (*dest == *pt) {
                /*
                 * found a delimiter, set to null
                 * and return context ptr to next char
                 */
                *dest = '\0';
                *ptr = (dest + 1);  /* return pointer for next scan */
                *dmax = dlen - 1;   /* account for the nulled delimiter */
                return (ptoken);
            } else {
                /*
                 * simply scanning through the delimiter string
                 */
                pt++;
            }
        }
        dest++;
        dlen--;
    }

    *dmax = dlen;
    return (ptoken);
}
