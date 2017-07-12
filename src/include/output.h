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

/**
 * \file output.h
 *
 * \brief this header defines macros for a compile-time option that can
 * automatically compress file output using zlib; it is used for
 * automatic JSON compression (but could be used for other purposes as
 * well)
 *
 */
#ifndef OUTPUT_H
#define OUTPUT_H

#include <zlib.h>

/**
 * \brief Set the variable COMPRESSED_OUTPUT to 1 to use zlib to
 * automatically compress the JSON output, or set it to 0 to have
 * normal output.  When compressed output is used, zless can be used
 * to read the files, and gunzip can be used to convert them to normal
 * files.  
 *
 */
#ifndef COMPRESSED_OUTPUT
#define COMPRESSED_OUTPUT 1
#endif


#if (COMPRESSED_OUTPUT == 0)
/** normal output */
typedef FILE *zfile;

#define zopen(fname, ...)    (fopen(fname, __VA_ARGS__))
#define zattach(fd, ...)     (fd)
#define zprintf(output, ...) (fprintf(output, __VA_ARGS__))
#define zflush(FILEp)        (fflush(FILEp))
#define zclose(output)       (fclose(output))
#define zsuffix(string)      (string)

#else
/** gzip compressed output */
typedef gzFile zfile;

#define zopen(fname, ...)    (gzopen(fname, __VA_ARGS__))

#ifdef WIN32
#define zattach(FILEp, ...)  (gzdopen(_fileno(FILEp), __VA_ARGS__))
#else
#define zattach(FILEp, ...)  (gzdopen(fileno(FILEp), __VA_ARGS__))
#endif

#define zprintf(output, ...) (gzprintf(output, __VA_ARGS__))
#define zflush(FILEp)        (gzflush(FILEp))
#define zclose(output)       (gzclose(output))
#define zsuffix(string)      (string ".gz")

#endif

#endif  /* OUTPUT_H */
