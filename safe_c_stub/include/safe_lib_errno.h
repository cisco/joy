/*------------------------------------------------------------------
 * safe_lib_errno.h -- Safe C Lib Error codes
 *
 * Octobber 2008, Bo Berry
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

#ifndef __SAFE_LIB_ERRNO_H__
#define __SAFE_LIB_ERRNO_H__
#include <stddef.h>

/*
 * CONFIGURE: If these errno codes are added to errno.h, then 
 * enable this macro
 */ 
/* #define USING_ERRNO_H  */ 

#ifdef USING_ERRNO_H

#include "errno.h"

#else

/* 
 * Safe Lib specific errno codes.  These can be added to the errno.h file
 * if desired. 
 */
#undef  ESNULLP 
#define ESNULLP         ( 400 )       /* null ptr                    */  

#undef  ESZEROL
#define ESZEROL         ( 401 )       /* length is zero              */  

#undef  ESLEMIN  
#define ESLEMIN         ( 402 )       /* length is below min         */  

#undef  ESLEMAX 
#define ESLEMAX         ( 403 )       /* length exceeds max          */  

#undef  ESOVRLP 
#define ESOVRLP         ( 404 )       /* overlap undefined           */ 

#undef  ESEMPTY 
#define ESEMPTY         ( 405 )       /* empty string                */ 

#undef  ESNOSPC 
#define ESNOSPC         ( 406 )       /* not enough space for s2     */  

#undef  ESUNTERM 
#define ESUNTERM        ( 407 )       /* unterminated string         */  

#undef  ESNODIFF 
#define ESNODIFF        ( 408 )       /* no difference               */ 

#undef  ESNOTFND
#define ESNOTFND        ( 409 )       /* not found                   */ 

#endif 


/* errno_t may or may not be defined in errno.h */ 
#ifndef errno_t
typedef int errno_t;
#endif

#ifndef rsize_t
typedef size_t rsize_t;
#endif

/* EOK may or may not be defined in errno.h */ 
#ifndef EOK 
#define EOK   0
#endif


#endif /* __SAFE_LIB_ERRNO_H__ */

