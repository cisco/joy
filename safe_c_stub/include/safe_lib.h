/*------------------------------------------------------------------
 * safe_lib.h -- Stub SafeC library includes
 *
 * June, 2016
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
#ifndef __SAFE_LIB_H__
#define __SAFE_LIB_H__


#ifdef _WIN32
#define __restrict__ 
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "safe_lib_errno.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"


#ifdef __cplusplus
}
#endif
#endif /* __SAFE_LIB_H__ */

