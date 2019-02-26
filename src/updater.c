/*
 *
 * Copyright (c) 2016-2019 Cisco Systems, Inc.
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
 * \file updater.c
 * \brief main code to handle the updating of the resource files
 *        like the labeled subnets, anonization, config and the classifiers.
 *
 ** This file contains the main entry point and all of the subordinate
 *  functions required to handle the updating of the joy program.
 */
#include <unistd.h>
#include "updater.h"
#include "safe_lib.h"
#include "classify.h"
#include "config.h"
#include "radix_trie.h"
#include "openssl/md5.h"

#ifdef WIN32
#include "windows.h"
#define SLEEP Sleep
#else
#define SLEEP sleep
#endif

/* external definitions from joy.c */
extern FILE *info;

pthread_mutex_t work_in_process = PTHREAD_MUTEX_INITIALIZER;

/** radix_trie built from new information and used to replace existing radix_trie */
radix_trie_t updater_trie = NULL;

#if 0
/*
 * Main radix trie updating function.
 *    Reads in new subnet addresses and creates a new radix trie.
 *    Locks the mutex and swaps the pointers on the active radix trie.
 *    Release the mutex and then frees up the old radix trie.
 */
static upd_return_codes_e update_radix_trie (void)
{
    radix_trie_t tmp_rt;
    attr_flags flag_malware;
    const char *configfile = BLACKLIST_FILE_NAME;
    joy_status_e err;

    /* allocate a new radix_trie structure */
    updater_trie = radix_trie_alloc();
    if (updater_trie == NULL) {
        joy_log_err("error: could not allocate memory for radix_trie\n");
        return upd_failure;
    }

    /* initialize */
    err = radix_trie_init(updater_trie);
    if (err != ok) {
        joy_log_err("error: could not initialize radix_trie\n");
        radix_trie_free(updater_trie);
        return upd_failure;
    }

    /* create a malware label */
    flag_malware = radix_trie_add_attr_label(updater_trie, "malware");
    if (flag_malware == 0) {
        joy_log_err("error: count not add label 'malware'\n");
        radix_trie_free(updater_trie);
        return upd_failure;
    }

    /* add subnets from file */
    err = radix_trie_add_subnets_from_file(updater_trie, configfile, flag_malware, info);
    if (err != ok) {
        joy_log_err("error: could not add subnets to radix_trie from file %s\n", configfile);
        radix_trie_free(updater_trie);
        return upd_failure;
    }
 
    /* ok we have fully built new radix trie, let's put it into action */

    /* swap tree pointers */
    pthread_mutex_lock(&radix_trie_lock);
    tmp_rt = glb_config->rt;
    glb_config->rt = updater_trie;
    updater_trie = NULL;
    pthread_mutex_unlock(&radix_trie_lock);

    /* now free up the old radix_trie */
    err = radix_trie_free(tmp_rt);
    if (err != ok) {
        joy_log_err("error: could not free memory for old radix_trie. Potential memory leak.\n");
    }
  
    /* successful update */
    return upd_success;
}
#endif

/**
 * \fn void *updater_main (void *ptr)
 * \brief Runs as a thread off of joy.
 *        Updater is only active during live processing runs.
 *        Updater terminates automatically when joy exits due to the nature of
 *        how pthreads work.
 * \param ptr always a pointer to the config structure
 * \return never return and the thread terminates when joy exits
 */
void *updater_main (void *ptr)
{
    struct configuration *config = (struct configuration*)ptr;

    /* forever loop. Updater will die when the main joy process exits */
    while (1) {
        /* let's only wake up and do work at specified intervals */
        if (config->updater_on) {
            pthread_mutex_lock(&work_in_process);
            pthread_mutex_unlock(&work_in_process);
        }
        SLEEP(UPDATER_WORK_INTERVAL);
    }

    return NULL;
}

