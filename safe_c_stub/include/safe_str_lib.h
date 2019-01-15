/*------------------------------------------------------------------
 * safe_str_lib.h - Replacements for Safe C Library String Functions
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
#ifndef __SAFE_STR_LIB_H__
#define __SAFE_STR_LIB_H__

#include <stdint.h>
#include <string.h>
#include "safe_lib_errno.h"

/**
 * The shortest string is a null string!! 
 */
#ifndef RSIZE_MIN_STR 
#define RSIZE_MIN_STR      ( 1 )
#endif


/**
 * The maximum sring length
 */
#ifndef RSIZE_MAX_STR 
#define RSIZE_MAX_STR     RSIZE_MAX
#endif



/* string compare */
extern errno_t strcmp_s(const char *dest, rsize_t dmax, const char *src, int *indicator);

/* Case insensitive string compare */
extern errno_t strcasecmp_s (const char *dest, rsize_t dmax, const char *src, int *indicator);

/* string concatenate */
extern errno_t strcat_s(char *dest, rsize_t dmax, const char *src);

/* fitted string concatenate */
extern errno_t strncat_s(char *dest, rsize_t dmax, const char *src, rsize_t slen);

/* string copy */
extern errno_t strcpy_s(char *dest, rsize_t dmax, const char *src);

/* fitted string copy */
extern errno_t strncpy_s (char *dest, rsize_t dmax, const char *src, rsize_t slen);

/* string length */
extern rsize_t strnlen_s(const char *s, rsize_t smax);

/* find a substring */ 
extern errno_t strstr_s(char *dest, rsize_t dmax, const char *src, rsize_t slen, char **substring);

/* string tokenizer */
extern char *strtok_s(char *dest, rsize_t *dmax, const char *src, char **ptr);

/* get span until character in string*/
extern errno_t strcspn_s(const char *dest, rsize_t dmax, const char *src,  rsize_t slen, rsize_t *count);

/* get span of character set in string*/
extern errno_t strspn_s(const char *dest, rsize_t dmax, const char *src,  rsize_t slen, rsize_t *count);

/* determine if character is a digit*/
extern int strisdigit_s(const char *dest, rsize_t dmax);

#endif /* __SAFE_STR_LIB_H__ */
