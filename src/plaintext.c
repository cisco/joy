/*
 *	
 * Copyright (c) 2018 Cisco Systems, Inc.
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
 * \file plaintext.c
 *
 * \brief RAT Plaintext command detection
 */
#include <ctype.h>
#include <string.h> 
#include <stdlib.h>
#include <inttypes.h>
#include "plaintext.h"
#include "p2f.h"
#include "str_match.h"
#include "err.h"

/** user name match structure */
extern str_match_ctx usernames_ctx;

#define PARSE_FAIL (-1)
/*
 * declarations of functions that are internal to this file
 */

static char *strstrn(char *string, char *substring, int depth);

static char plaintext_keywords[][32] = {"shell", "exec", "python", "keydump", "script", "remoteControl", "kill", "passthru", "shell_exec", "system", "phpinfo", "base64_decode", "chmod", "mkdir", "fopen", "fclose", "readfile", "php_uname", "eval", "edoced_46esab", "popen", "include", "create_function", "mysql_execute", "php_uname", "proc_open", "pcntl_exec", "include_once", "require", "require_once", "posix_mkfifo", "posix_getlogin", "posix_ttyname", "getenv", "get_current_user", "proc_get_status", "get_cfg_var", "disk_free_space", "disk_total_space", "diskfreespace", "getcwd", "getlastmo", "getmygid", "getmyinode", "getmypid", "getmyuid", "assert", "extract", "parse_str", "putenv", "ini_set", "pfsockopen", "fsockopen", "apache_child_terminate", "posix_kill", "posix_setpgid", "posix_setsid", "posix_setuid", "tmpfile", "bzopen", "gzopen", "chgrp", "chown", "copy", "file_put_contents", "lchgrp", "lchown", "link", "mkdir", "move_uploaded_file", "symlink", "tempnam", "imagecreatefromgif", "imagecreatefromjpeg", "imagecreatefrompng", "imagecreatefromwbmp", "imagecreatefromxbm", "imagecreatefromxpm", "ftp_put", "ftp_nb_put", "exif_read_data", "read_exif_data", "exif_thumbnail", "exif_imagetype", "hash_file", "hash_hmac_file", "hash_update_file", "md5_file", "sha1_file", "highlight_file", "show_source", "php_strip_whitespace", "get_meta_tags", "str_repeat", "unserialize", "register_tick_function", "register_shutdown_function", "getuid", "uname", "gethostname"};

/**
 *
 * \brief Initialize the memory of plaintext struct.
 *
 * \param plaintext_handle contains plaintext structure to initialize
 *
 * \return none
 */
void plaintext_init (struct plaintext **plaintext_handle) {
    if (*plaintext_handle != NULL) {
        plaintext_delete(plaintext_handle);
    }

    *plaintext_handle = calloc(1, sizeof(struct plaintext));
    if (*plaintext_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
}

/**
 * \brief Parse, process, and record plaintext session \p data.
 *
 * \param plaintext plaintext structure pointer
 * \param header PCAP packet header pointer
 * \param data Beginning of the HTTP / TCP payload data.
 * \param len Length in bytes of the \p data.
 * \param report_plaintext Flag indicating whether this feature should run.
 *                    0 for no, 1 for yes
 *
 * \return none
 */
void plaintext_update(struct plaintext *plaintext,
			     const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_plaintext) {
    
    if (!report_plaintext || plaintext->match_len == MAX_MATCHES)
        return;
    int i;
    for (i = 0; i < PLAINTEXT_KEYWORDS_LENGTH; i++){
        if (strstrn((char *)data, plaintext_keywords[i], (data_len < MAX_SEARCH_LEN ? data_len : MAX_SEARCH_LEN)) != NULL){
            plaintext->detected = 1;
            
            // Fill in matches
            int j = 0;
            for (; j < plaintext->match_len; j++){
                if (i == plaintext->matches[j]){
                    return;
                }
            }
            plaintext->matches[plaintext->match_len++] = i;
            return;
        }
    }
    return;
} 

/**
 * \brief Print the plaintext struct to JSON output file \p f.
 *
 * \param h1 pointer to plaintext structure
 * \param h2 pointer to twin plaintext structure
 * \param f destination file for the output
 *
 * \return none
 */
void plaintext_print_json(const struct plaintext *h1,
                     const struct plaintext *h2,
                     zfile f) {
    /* Sanity check */
    if (h1 == NULL) {
        return;
    }
    
    int detected = h1->detected;
    if (!detected && h2)
        detected = h2->detected;
    
    if (!detected)
        return;
    
    // Find matches
    int matches[2 * MAX_MATCHES] = {0};
    int match_len = 0;
    
    int i = 0;
    int j = 0;
    for (; i < h1->match_len; i++){
        int is_there = 0;
        for (j = 0; j < match_len; j++){
            if (matches[j] == h1->matches[i])
                is_there = 1;
        }
        if (!is_there){
            matches[match_len++] = h1->matches[i];
        }
    }
    if (h2){
        for (i = 0; i < h2->match_len; i++){
            int is_there = 0;
            for (j = 0; j < match_len; j++){
                if (matches[j] == h2->matches[i])
                    is_there = 1;
            }
            if (!is_there){
                matches[match_len++] = h2->matches[i];
            }
        }
    }
    
    
    zprintf(f, ",\"plaintext\":[");
    for (i = 0; i < match_len; i++){
        if (i){
            zprintf(f, ",");
        }
        zprintf(f, "\"%s\"", plaintext_keywords[matches[i]]);
    }
    zprintf(f, "]");
            
    return;
}

/**
 * \fn void plaintext_delete
 * \param data pointer to the plaintext data structure
 * \return none
 */
void plaintext_delete (struct plaintext **plaintext_handle) {
    struct plaintext *plaintext = *plaintext_handle;
    
    free(plaintext);
    *plaintext_handle = 0;
}

/* ************************
 * **********************
 * Internal Functions
 * **********************
 * ************************
 */

static char *strstrn(char *string, char *substring, int depth)
{
    register char *a, *b;

    /* First scan quickly through the two strings looking for a
     * single-character match.  When it's found, then compare the
     * rest of the substring.
     */

    b = substring;
    if (*b == 0) {
	   return string;
    }
    int d;
    for (d = 0; d < depth; d++) {
        if (string[d] != *b) {
            continue;
        }
        a = string+d;
        while (1) {
            if (*b == 0) {
                return string+d;
            }
            if (*a++ != *b++) {
                break;
            }
        }
        b = substring;
    }
    return NULL;
}



void plaintext_unit_test(){
    return;
}