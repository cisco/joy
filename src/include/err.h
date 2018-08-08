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
 * \file err.h
 *
 * \brief error reporting
 *
 */
#ifndef ERR_H
#define ERR_H

#include <stdio.h> 
#include "utils.h"

typedef enum joy_status_ {
    ok = 0,
    failure = 1
} joy_status_e;

typedef enum joy_log_level {
    JOY_LOG_OFF = 0,
    JOY_LOG_DEBUG = 1,
    JOY_LOG_INFO = 2,
    JOY_LOG_WARN = 3,
    JOY_LOG_ERR = 4,
    JOY_LOG_CRIT = 5
} joy_log_level_e;

#define JOY_LOG_DEBUG_STR "DEBUG"
#define JOY_LOG_INFO_STR "INFO"
#define JOY_LOG_WARN_STR "WARN"
#define JOY_LOG_ERR_STR "ERR"
#define JOY_LOG_CRIT_STR "CRIT"

#define joy_log_debug(...) { \
        if (glb_config->verbosity != JOY_LOG_OFF && glb_config->verbosity <= JOY_LOG_DEBUG) { \
            char log_ts[JOY_TIMESTAMP_LEN]; \
            joy_log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", JOY_LOG_DEBUG_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define joy_log_info(...) { \
        if (glb_config->verbosity != JOY_LOG_OFF && glb_config->verbosity <= JOY_LOG_INFO) { \
            char log_ts[JOY_TIMESTAMP_LEN]; \
            joy_log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", JOY_LOG_INFO_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define joy_log_warn(...) { \
        if (glb_config->verbosity != JOY_LOG_OFF && glb_config->verbosity <= JOY_LOG_WARN) { \
            char log_ts[JOY_TIMESTAMP_LEN]; \
            joy_log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", JOY_LOG_WARN_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define joy_log_err(...) { \
        if (glb_config->verbosity != JOY_LOG_OFF && glb_config->verbosity <= JOY_LOG_ERR) { \
            char log_ts[JOY_TIMESTAMP_LEN]; \
            joy_log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", JOY_LOG_ERR_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define joy_log_crit(...) { \
        if (glb_config->verbosity != JOY_LOG_OFF && glb_config->verbosity <= JOY_LOG_CRIT) { \
            char log_ts[JOY_TIMESTAMP_LEN]; \
            joy_log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", JOY_LOG_CRIT_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

/** printf debug macro */
#define zprintf_debug(output, ...) zprintf(output, ",\"DEBUG\": \""  __VA_ARGS__);

/** debug flag */
#define P2F_DEBUG 0

#if P2F_DEBUG
#define debug_printf(...) (fprintf(info, "debug: " __VA_ARGS__)) 
#else
#define debug_printf(...) 
#endif

#endif /* ERR_H */

