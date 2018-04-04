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
 * \file updater.h
 *
 * \brief Interface to updater code used keep the label subnets up to
 *        date and also re-fresh the classifers.
 *
 */

#ifndef UPD_H
#define UPD_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include "radix_trie.h"

/** maxiumum lengnth of a URL string */
#define MAX_URL_LENGTH 512

/** Work interval defined for the updater main processing loop */
#define UPDATER_WORK_INTERVAL (86400) /* (60*60*24) = 86400 mins, 24 hours */
//#define UPDATER_WORK_INTERVAL (20) /* for testing - 20 second interval */

/** URL for the blacklist malware feed  - default url us Talos feed */
#define BLACKLIST_URL "http://www.talosintelligence.com/feeds/ip-filter.blf"

/** destination file name for the blacklist malware feed */
#define BLACKLIST_FILE_NAME "blacklist-ip-filter.blf"

/** Updater return codes */
typedef enum {
    upd_success = 0,
    upd_failure = 1
} upd_return_codes_t;

/** mutex used to ensure the radix_trie isn't being accessed by another thread */
extern pthread_mutex_t radix_trie_lock;

/** mutex used to let other threads know the updater is currently doing work */
extern pthread_mutex_t work_in_process;

/** Main entry point for the updater thread */
void *updater_main(void* ptr);

#endif /* UPD_H */
