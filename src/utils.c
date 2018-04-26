/*
 *
 * Copyright (c) 2017 Cisco Systems, Inc.
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
 * \file utils.c
 *
 * \brief contains helper functionality for the Joy software
 *
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "config.h"
#include "utils.h"
#include "err.h"

#define JOY_UTILS_MAX_FILEPATH 128

/* external definitions from joy.c */
extern struct configuration *glb_config;
extern zfile output;
extern FILE *info;

#ifdef USE_BZIP2

#include <stdarg.h>
#include <bzlib.h>

/* This function is an API glue between zprintf and
 * the subsequent bzwrite to a compressed file. BZ2
 * doesn't have a printf interface, so an equivalent
 * interface needed to be written.
 * Note: this function can only output 4K chars at a time.
 *   if a string comes through bigger than 4K, it will
 *   dynamically allocate a buffer to hold the output and then
 *   print out the data.
 *
 */
#define BZ_MAX_SIZE 4096
char BZ_buff[BZ_MAX_SIZE];
int BZ2_bzprintf(BZFILE *b, const char * format, ...)
{
    int BZ_sz; 
    int BZ_errnum;
    va_list arg;

    va_start(arg, format);
    BZ_sz = vsnprintf(BZ_buff, BZ_MAX_SIZE, format, arg);
    va_end(arg);

    /* check resulting size and perform output accordingly */
    if (BZ_sz >= BZ_MAX_SIZE) {
        char *BZ_dyn_buff = malloc(BZ_sz + 1);
        if (BZ_dyn_buff != NULL) {
            va_start(arg, format);
            BZ_sz = vsnprintf(BZ_dyn_buff, (BZ_sz + 1), format, arg);
            va_end(arg);
            BZ2_bzwrite(b, BZ_dyn_buff, BZ_sz);
            free(BZ_dyn_buff);
        } else {
            /* error scenario, can't print out all the data,
             * let's just print what we can
             */
            BZ2_bzwrite(b, BZ_buff, (BZ_MAX_SIZE-1));
        }
    } else {
        BZ2_bzwrite(b, BZ_buff, BZ_sz);
    }
    BZ2_bzerror(b, &BZ_errnum);
    return BZ_errnum;
}
#endif

/*
 *
 * \brief Use Parson to open a json file from the source resources/ directory.
 *        If aux_resource_path option is given on the command line,
 *        then the file will be searched for in that directory instead.
 *
 * \param filename Name of the json file to be opened.
 *
 * \return JSON_Value pointer, otherwise NULL
 */
JSON_Value* joy_utils_open_resource_parson(const char *filename) {
    JSON_Value *value = NULL;
    char *filepath = NULL;

    /* Allocate memory to store constructed file path */
    filepath = calloc(JOY_UTILS_MAX_FILEPATH, sizeof(char));

    if (glb_config->aux_resource_path) {
        /*
         * Use the path that was given in Joy cli
         */
        strncpy(filepath, glb_config->aux_resource_path, JOY_UTILS_MAX_FILEPATH);
        /* Place "/" before file name in case user left it out */
        strncat(filepath, "/", JOY_UTILS_MAX_FILEPATH - 1);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        value = json_parse_file(filepath);
    } else {
        /* Assume user CWD in root of Joy source package */
        strncpy(filepath, "./resources/", JOY_UTILS_MAX_FILEPATH);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        value = json_parse_file(filepath);
        if (!value) {
            /* Assume user CWD one-level subdir of Joy source package */
            memset(filepath, 0, JOY_UTILS_MAX_FILEPATH);
            strncpy(filepath, "../resources/", JOY_UTILS_MAX_FILEPATH);
            strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
            value = json_parse_file(filepath);
        }
    }

    if (!value) {
        joy_log_err("could not open %s", filename);
    }

    /* Cleanup */
    if (filepath) {
        free(filepath);
    }

    return value;
}

/*
 * \brief Open a file from the source test/misc/ directory.
 *
 * \param filename Name of the file to be opened.
 *
 * \return FILE pointer, otherwise NULL
 */
FILE* joy_utils_open_test_file(const char *filename) {
    FILE *fp = NULL;
    char *filepath = NULL;

    /* Allocate memory to store constructed file path */
    filepath = calloc(JOY_UTILS_MAX_FILEPATH, sizeof(char));

    /* Assume user CWD in root of Joy source package */
    strncpy(filepath, "./test/misc/", JOY_UTILS_MAX_FILEPATH);
    strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
    fp = fopen(filepath, "r");
    if (!fp) {
        /* Assume user CWD one-level subdir of Joy source package */
        memset(filepath, 0, JOY_UTILS_MAX_FILEPATH);
        strncpy(filepath, "../test/misc/", JOY_UTILS_MAX_FILEPATH);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        fp = fopen(filepath, "r");
    }

    if (!fp) {
        joy_log_err("could not open %s", filepath);
    }

    /* Cleanup */
    if (filepath) {
        free(filepath);
    }

    return fp;
}

/*
 *
 * \brief Open a pcap from the source test/pcaps/ directory.
 *
 * \param filename Name of the pcap to be opened.
 *
 * \return pcap_t pointer, otherwise NULL
 */
pcap_t* joy_utils_open_test_pcap(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *filepath = NULL;

    /* Allocate memory to store constructed file path */
    filepath = calloc(JOY_UTILS_MAX_FILEPATH, sizeof(char));

    /* Assume user CWD in root of Joy source package */
    strncpy(filepath, "./test/pcaps/", JOY_UTILS_MAX_FILEPATH);
    strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
    handle = pcap_open_offline(filepath, errbuf);
    if (!handle) {
        /* Assume user CWD one-level subdir of Joy source package */
        memset(filepath, 0, JOY_UTILS_MAX_FILEPATH);
        strncpy(filepath, "../test/pcaps/", JOY_UTILS_MAX_FILEPATH);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        handle = pcap_open_offline(filepath, errbuf);
    }

    if (!handle) {
        joy_log_err("could not open %s", filename);
    }

    /* Cleanup */
    if (filepath) {
        free(filepath);
    }

    return handle;
}

/**
 * \brief Converts the character string into a JSON-safe, NULL-terminated printable string.
 *
 * Non-alphanumeric characters are converted to "." (a period). This
 * function is useful only to ensure that strings that one expects to
 * be printable, such as DNS names, don't cause encoding errors when
 * they are actually not non-printable, non-JSON-safe strings.
 *
 * Stops if a NULL terminator is seen.
 *
 * WARNING: This will NULL terminate the end of string \p s.
 *          i.e. s[len-1] = '0'
 *
 * \param s Pointer to the string
 * \param len Length of the string in bytes
 * \return none
 */
void joy_utils_convert_to_json_string (char *s, unsigned int len) {
    unsigned int i;

    for (i=0; i < len; i++) {
        if (s[i] == 0) {
            /* Encountered termination, no need to go further */
            return;
        } else if (!isprint(s[i])) {
            /* Not a printable character */
            s[i] = '.';
            continue;
        }
        switch (s[i]) {
            case '\n':
            case '\r':
            case '\b':
            case '\f':
            case '\t':
            case '\\':
            case '/':
            case '"':
                s[i] = '.';
            default:
                continue;
        }
    }

    /* NULL terminate */
    s[len-1] = 0;
}

/* *********************************************************************
 * ---------------------------------------------------------------------
 *                      Time functions
 * For portability and static analysis, we define our own timer
 * comparison functions (rather than use non-standard
 * timercmp/timersub macros)
 * ---------------------------------------------------------------------
 * *********************************************************************
 */

/**
 * \brief Compare two times to see if they are equal
 * \param a First time value
 * \param b Second time value
 * \return 1 if equal, 0 otherwise
 */
unsigned int joy_timer_eq(const struct timeval *a,
                          const struct timeval *b) {
    if (a->tv_sec == b->tv_sec && a->tv_usec == b->tv_usec) {
        return 1;
    }

    return 0;
}

unsigned int joy_timer_lt(const struct timeval *a,
                      const struct timeval *b) {
    return (a->tv_sec == b->tv_sec) ? (a->tv_usec < b->tv_usec) : (a->tv_sec < b->tv_sec);
}

/**
 * \brief Calculate the difference betwen two times (result = a - b)
 * \param a First time value
 * \param b Second time value
 * \param result The difference between the two time values
 * \return none
 */
void joy_timer_sub(const struct timeval *a,
               const struct timeval *b,
               struct timeval *result) {
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_usec = a->tv_usec - b->tv_usec;
    if (result->tv_usec < 0) {
        --result->tv_sec;
        result->tv_usec += 1000000;
    }
}

/**
 * \brief Zeroize a timeval.
 * \param a Timeval to zero out
 * \return none
 */
void joy_timer_clear(struct timeval *a) {
    a->tv_sec = a->tv_usec = 0;
}

/**
 * \brief Calculate the milliseconds representation of a timeval.
 * \param ts Timeval
 * \return unsigned int - Milliseconds
 */
unsigned int joy_timeval_to_milliseconds(struct timeval ts) {
    unsigned int result = ts.tv_usec / 1000 + ts.tv_sec * 1000;
    return result;
}

#ifdef WIN32
#include <stdint.h>
int gettimeofday(struct timeval *tp,
                 struct timezone *tzp)
{
	/*
     * NOTE: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
	 * This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
	 * until 00:00:00 January 1, 1970
     */
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}
#endif
