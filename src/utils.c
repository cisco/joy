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
#include "utils.h"

#define JOY_UTILS_MAX_FILEPATH 128

extern char *aux_resource_path;

/*
 * \brief Open a file from the source resources/ directory.
 *        If aux_resource_path option is given on the command line,
 *        then the file will be searched for in that directory instead.
 *
 * \param filename Name of the file to be opened.
 *
 * \return FILE pointer, otherwise NULL
 */
FILE* joy_utils_open_resource_file(const char *filename) {
    FILE *fp = NULL;
    char *filepath = NULL;

    /* Allocate memory to store constructed file path */
    filepath = calloc(JOY_UTILS_MAX_FILEPATH, sizeof(char));

    if (aux_resource_path) {
        /*
         * Use the path that was given in Joy cli
         */
        strncpy(filepath, aux_resource_path, JOY_UTILS_MAX_FILEPATH);
        /* Place "/" before file name in case user left it out */
        strncat(filepath, "/", JOY_UTILS_MAX_FILEPATH - 1);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        fp = fopen(filepath, "r");
    } else {
        /* Assume user CWD in root of Joy source package */
        strncpy(filepath, "./resources/", JOY_UTILS_MAX_FILEPATH);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        fp = fopen(filepath, "r");
        if (!fp) {
            /* Assume user CWD one-level subdir of Joy source package */
            memset(filepath, 0, JOY_UTILS_MAX_FILEPATH);
            strncpy(filepath, "../resources/", JOY_UTILS_MAX_FILEPATH);
            strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
            fp = fopen(filepath, "r");
        }
    }

    if (!fp) {
        fprintf(stderr, "joy_utils_open_resource_file: error: could not open %s\n", filepath);
    }

    /* Cleanup */
    if (filepath) {
        free(filepath);
    }

    return fp;
}

/*
 *
 * \brief Open a pcap from the source resources/ directory.
 *        If aux_resource_path option is given on the command line,
 *        then the pcap will be searched for in that directory instead.
 *
 * \param filename Name of the pcap to be opened.
 *
 * \return pcap_t pointer, otherwise NULL
 */
pcap_t* joy_utils_open_resource_pcap(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *filepath = NULL;

    /* Allocate memory to store constructed file path */
    filepath = calloc(JOY_UTILS_MAX_FILEPATH, sizeof(char));

    if (aux_resource_path) {
        /*
         * Use the path that was given in Joy cli
         */
        strncpy(filepath, aux_resource_path, JOY_UTILS_MAX_FILEPATH);
        /* Place "/" before file name in case user left it out */
        strncat(filepath, "/", JOY_UTILS_MAX_FILEPATH - 1);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        handle = pcap_open_offline(filepath, errbuf);
    } else {
        /* Assume user CWD in root of Joy source package */
        strncpy(filepath, "./resources/", JOY_UTILS_MAX_FILEPATH);
        strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
        handle = pcap_open_offline(filepath, errbuf);
        if (!handle) {
            /* Assume user CWD one-level subdir of Joy source package */
            memset(filepath, 0, JOY_UTILS_MAX_FILEPATH);
            strncpy(filepath, "../resources/", JOY_UTILS_MAX_FILEPATH);
            strncat(filepath, filename, JOY_UTILS_MAX_FILEPATH - 1);
            handle = pcap_open_offline(filepath, errbuf);
        }
    }

    if (!handle) {
        fprintf(stderr, "joy_utils_open_resource_pcap: error: could not open %s\n", filename);
    }

    /* Cleanup */
    if (filepath) {
        free(filepath);
    }

    return handle;
}

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

    if (aux_resource_path) {
        /*
         * Use the path that was given in Joy cli
         */
        strncpy(filepath, aux_resource_path, JOY_UTILS_MAX_FILEPATH);
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
        fprintf(stderr, "joy_utils_open_resource_parson: error: could not open %s\n", filename);
    }

    /* Cleanup */
    if (filepath) {
        free(filepath);
    }

    return value;
}

/*
 *
 * \brief Copy a json-printable string from the source buffer to the
 *        destination buffer.
 *
 * \param buf Destination buffer.
 * \param buflen Maximum length of the destination buffer.
 * \param data Source buffer.
 * \param datalen Length of the source buffer.
 *
 */
void copy_printable_string(char *buf,
			   unsigned int buflen,
			   const void *data,
			   unsigned int datalen) {
    const char *d = data;

    while (buflen-- && datalen--) {
	if (!isprint(*d) || *d == '\"' || *d == '\\' || *d <= 0x1f) { /* json constraints */
	    break;
	}
	*buf++ = *d++;
    }

    *buf = 0; /* null terminate buffer */
}

void vector_init(struct vector *vector) {

    vector->len = 0;
    vector->bytes = NULL;

    return;
}

/* set vector to data, where data may overlap with current vector contents */
void vector_set(struct vector *vector, const void *data, unsigned len) {
    void *tmpptr = NULL;

    tmpptr = malloc(len);
    if (tmpptr == NULL) {
        return;
    }
    memcpy(tmpptr, data, len);
    vector_free(vector); /* does nothing if already empty */
    vector->bytes = tmpptr;
    vector->len = len;

    return;
}

/* append data to current vector contents (even if vector is empty) */
void vector_append(struct vector *vector, const void *data, unsigned len) {

    vector->bytes = realloc(vector->bytes, vector->len + len);
    if (vector->bytes == NULL) {
        return;
    }
    memcpy(vector->bytes + vector->len, data, len);
    vector->len += len;

    return;
}

char *vector_string(struct vector *vector) {
    char *s;

    s = malloc(vector->len+1);
    if (s == NULL) {
        return NULL;
    }
    if (vector->len > 0) {
        copy_printable_string(s, vector->len+1, vector->bytes, vector->len);
    } else {
        s[0] = 0;
    }

    return s;
}

void vector_free(struct vector *vector) {

    if (vector->bytes != NULL) {
        free(vector->bytes);
        vector->bytes = NULL;
    }
    vector->len = 0;

    return;
}
