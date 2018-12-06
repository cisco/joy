/*
 *
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*
 * utils.h
 *
 * utilites that can be used by joy feature modules
 */

#ifndef P2FUTILS
#define P2FUTILS

#include <stdio.h>
#include <ctype.h>      /* for isprint()           */
#include <pcap.h>
#include "parson.h"

#define JOY_TIMESTAMP_LEN 64

#define CPU_IS_BIG_ENDIAN (__BYTE_ORDER == __BIG_ENDIAN)

#if CPU_IS_BIG_ENDIAN
# define ntoh64(x) x
# define hton64(x) x
#else
# ifdef WIN32
#   define ntoh64(x) _byteswap_uint64(x)
#   define hton64(x) _byteswap_uint64(x)
# else
#   define ntoh64(x) __builtin_bswap64(x)
#   define hton64(x) __builtin_bswap64(x)
# endif
#endif

#ifdef WIN32
int gettimeofday(struct timeval *tp,
                 struct timezone *tzp);
#endif

unsigned int joy_timer_eq(const struct timeval *a,
                          const struct timeval *b);

unsigned int joy_timer_lt(const struct timeval *a,
                      const struct timeval *b);

void joy_timer_sub(const struct timeval *a,
               const struct timeval *b,
               struct timeval *result);

void joy_timer_clear(struct timeval *a);

unsigned int joy_timeval_to_milliseconds(struct timeval ts);

FILE* joy_utils_open_test_file(const char *filename);

pcap_t* joy_utils_open_test_pcap(const char *filename);

JSON_Value* joy_utils_open_resource_parson(const char *filename);

void joy_utils_convert_to_json_string (char *s, unsigned int len);

void joy_log_timestamp ( char *log_ts);

typedef enum joy_role_ {
  role_unknown   = 0,
  role_client    = 1,
  role_server    = 2,
  role_flow_data = 3
} joy_role_e;

#endif /* P2FUTILS */
