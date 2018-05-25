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
 * \file updater.c
 * \brief main code to handle the download and updating of the
 *        radix_trie for labeled subnets and the classifiers.
 *
 ** This file contains the main entry point and all of the subordinate
 *  functions required to handle the updating of the labeled subnets
 *  and the classifiers for joy.
 */
#include <unistd.h>
#include "updater.h"
#include "string.h"
#include "classify.h"
#include "config.h"
#include "radix_trie.h"
#include "curl/curl.h"
#include "curl/easy.h"
#include "openssl/md5.h"

#ifdef WIN32
#include "windows.h"
#endif

/* external definitions from joy.c */
extern struct configuration *glb_config;
extern FILE *info;

/** select destination for printing out information
 *
 **  TO_SCREEN = 0 for 'info' file
 *
 **  TO_SCREEN = 1 for 'stderr'
 */
#define TO_SCREEN 0

/** used to print out information during the updater run cycle 
 *
 ** print_dest will either be assigned to 'stderr' or 'info' file
 *  depending on the TO_SCREEN setting.
 */
static FILE *print_dest = NULL;

/** sends information to the destination output device */
#define loginfo(...) { \
      if (TO_SCREEN) print_dest = stderr; else print_dest = info; \
      fprintf(print_dest,"%s: ", __FUNCTION__); \
      fprintf(print_dest, __VA_ARGS__); }

pthread_mutex_t work_in_process = PTHREAD_MUTEX_INITIALIZER;

/** radix_trie built from new information and used to replace existing radix_trie */
radix_trie_t updater_trie = NULL;

/** MD5 digest of the blacklist malware feed file */
static unsigned char blacklist_md5[MD5_DIGEST_LENGTH];

/** Classifier digest of the SPLT values */
static unsigned char splt_classifier_md5[MD5_DIGEST_LENGTH];

/** Classifier digest of the BD values */
static unsigned char bd_classifier_md5[MD5_DIGEST_LENGTH];

/** Most recent MD5 digest computed */
static unsigned char md5_digest_result[MD5_DIGEST_LENGTH];

/*
 * Copies a MD5 digest from the source into the destination.
 */
static void save_new_md5 (unsigned char* src, unsigned char *dest)
{
    int i = 0;
    for (i=0; i < MD5_DIGEST_LENGTH; ++i) {
        *(dest+i) = *(src+i);
    }
}

/*
 * Compares to MD5 digests byte by byte to see if they are
 *     the same or not.
 * Returns 0 if they are are different and 1 if they are the same.
 */
static int is_digest_same (unsigned char* d1, unsigned char *d2)
{
    int i = 0;
    for (i=0; i < MD5_DIGEST_LENGTH; ++i) {
        if (*(d1+i) != *(d2+i)) {
            return 0;
        }
    }
    return 1;
}

/* 
 * Computes the MD5 digest of a filename passed in
 *   Opens the file for binary read and performs a
 *   MD5 digest on the contents.
 *   Result is placed in new_md5_hash global variable.
 *   Returns upd_success or upd_failure
 */
static upd_return_codes_t compute_md5_digest (char* filename) {
    int i = 0;
    int bytes = 0;
    MD5_CTX mdContext;
    FILE *new_file = NULL;
    unsigned char c[MD5_DIGEST_LENGTH];
    unsigned char data[1024];

    /* open up the file */
    new_file = fopen(filename, "rb");
    if (new_file == NULL) {
        loginfo("error: couldn't open '%s' file for reading.\n",filename);
        return upd_failure;
    }

    /* compute the MD5 digest */
    MD5_Init (&mdContext);
    while ((bytes = fread(data, 1, 1024, new_file)) != 0)
        MD5_Update(&mdContext, data, bytes);
    MD5_Final (c, &mdContext);

    /* close the file */
    fclose (new_file);

    /* save off the digest */
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        md5_digest_result[i] = c[i];
    }
    return upd_success;
}

/*
 * Function to write out the data received from the curl download
 *    Takes the data from the stream being received by the curl
 *    library call and writes it to an output file.
 */
static size_t upd_write_data (void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = 0;

    written = fwrite(ptr, size, nmemb, stream);
    return written;
}

/*
 * Function performs the main downloading of the blacklist feed file for
 *    known malware domains. Uses curl to download the file from the
 *    blacklist feed and store the file locally.
 */
static upd_return_codes_t dnload_blacklist_file (char* full_url) {
    upd_return_codes_t dnld_rc = upd_failure;
    CURLcode curl_rc = CURLE_OK;
    CURL *handle = NULL;
    FILE *blacklist_file = NULL;
    char errbuf[CURL_ERROR_SIZE];
    
    /* get a curl handle for the download */
    handle = curl_easy_init();
    if (handle == NULL) {
        loginfo("error: curl easy init failed\n");
        return dnld_rc;
    }

    /* open the destination file */
    blacklist_file = fopen(BLACKLIST_FILE_NAME, "wb");
    if (blacklist_file == NULL) {
        loginfo("error: couldn't open destination file for writing.\n");
        curl_easy_cleanup(handle);
        return dnld_rc;
    }

    /* setup the curl URL, output file, callback function and error buffer */
    memset(errbuf, 0x00, CURL_ERROR_SIZE);
#ifdef WIN32
	if (strnicmp(full_url, "default", 7) == 0) {

#else
    if (strncasecmp(full_url, "default", 7) == 0) {
#endif
		/* use default Talos feed black list file */
        curl_easy_setopt(handle, CURLOPT_URL, BLACKLIST_URL);
    } else {
        /* use the url that the user set in the config */
        curl_easy_setopt(handle, CURLOPT_URL, full_url);
    }
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, blacklist_file);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, upd_write_data);
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 40L);

    /* execute the download */
    curl_rc = curl_easy_perform(handle);
    if (curl_rc == CURLE_OK) {
        dnld_rc = upd_success;
    } else {
        size_t len = strlen(errbuf);

        loginfo("error: libcurl: (%d) ", curl_rc);
        if (len) {
            loginfo("%s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
        } else {
            loginfo("%s\n", curl_easy_strerror(curl_rc));
        }
    }

    /* clean up the curl handle and close the output file */
    fclose(blacklist_file);
    curl_easy_cleanup(handle);

    if (dnld_rc == upd_success) {
        return (compute_md5_digest(BLACKLIST_FILE_NAME));
    } else {
        return dnld_rc;
    }
}

/*
 * Function performs the main downloading of the classifier file.
 *    Uses curl to download the file from the feed and store the file locally.
 */
static upd_return_codes_t dnload_classifier_file (char *url, char *filename) {
    upd_return_codes_t dnld_rc = upd_failure;
    CURLcode curl_rc = CURLE_OK;
    CURL *handle = NULL;
    FILE *classifier_file = NULL;
    char full_url[MAX_URL_LENGTH];
    char errbuf[CURL_ERROR_SIZE];
    
    /* get a curl handle for the download */
    handle = curl_easy_init();
    if (handle == NULL) {
        loginfo("error: curl easy init failed\n");
        return dnld_rc;
    }

    /* open the destination file */
    classifier_file = fopen(filename, "wb");
    if (classifier_file == NULL) {
        loginfo("error: couldn't open destination file for writing.\n");
        curl_easy_cleanup(handle);
        return dnld_rc;
    }

    /* setup full URL string */
    snprintf(full_url, MAX_URL_LENGTH, "%s/%s", url, filename);

    /* setup the curl URL, output file, callback function and error buffer */
    memset(errbuf, 0x00, CURL_ERROR_SIZE);
    curl_easy_setopt(handle, CURLOPT_URL, full_url);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, classifier_file);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, upd_write_data);
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 20L);

    /* execute the download */
    curl_rc = curl_easy_perform(handle);
    if (curl_rc == CURLE_OK) {
        dnld_rc = upd_success;
    } else {
        size_t len = strlen(errbuf);

        loginfo("error: libcurl: (%d) ", curl_rc);
        if (len) {
            loginfo("%s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
        } else {
            loginfo("%s\n", curl_easy_strerror(curl_rc));
        }
    }

    /* clean up the curl handle and close the output file */
    fclose(classifier_file);
    curl_easy_cleanup(handle);

    if (dnld_rc == upd_success) {
        return (compute_md5_digest(filename));
    } else {
        return dnld_rc;
    }
}

/*
 * Main radix trie updating function.
 *    Reads in new subnet addresses and creates a new radix trie.
 *    Locks the mutex and swaps the pointers on the active radix trie.
 *    Release the mutex and then frees up the old radix trie.
 */
static upd_return_codes_t update_radix_trie ()
{
    radix_trie_t tmp_rt;
    attr_flags flag_malware;
    char *configfile = BLACKLIST_FILE_NAME;
    enum status err;

    /* allocate a new radix_trie structure */
    updater_trie = radix_trie_alloc();
    if (updater_trie == NULL) {
        loginfo("error: could not allocate memory for radix_trie\n");
        return upd_failure;
    }

    /* initialize */
    err = radix_trie_init(updater_trie);
    if (err != ok) {
        loginfo("error: could not initialize radix_trie\n");
        radix_trie_free(updater_trie);
        return upd_failure;
    }

    /* create a malware label */
    flag_malware = radix_trie_add_attr_label(updater_trie, "malware");
    if (flag_malware == 0) {
        loginfo("error: count not add label 'malware'\n");
        radix_trie_free(updater_trie);
        return upd_failure;
    }

    /* add subnets from file */
    err = radix_trie_add_subnets_from_file(updater_trie, configfile, flag_malware, stderr);
    if (err != ok) {
        loginfo("error: could not add subnets to radix_trie from file %s\n", configfile);
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
        loginfo("error: could not free memory for old radix_trie. Potential memory leak.\n");
    }
  
    /* successful update */
    return upd_success;
}

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
    char params_splt[LINEMAX];
    char params_bd[LINEMAX];
    int num = 0;
    int update_classifiers = 0;
    int update_labels = 0;
    struct configuration *config = ptr;

    /* initialize MD5 digests */
    memset(blacklist_md5, 0x00, MD5_DIGEST_LENGTH);
    memset(splt_classifier_md5, 0x00, MD5_DIGEST_LENGTH);
    memset(bd_classifier_md5, 0x00, MD5_DIGEST_LENGTH);

    /* check for labeling */
    if (config->label_url) {
        loginfo("Labels are configured for continuous updating!\n");
        update_labels = 1;
    } else {
        loginfo("Labels are not configured for continuous updating!\n");
    }

    /* check for remote classifier updates */
    if (config->params_url && config->params_file) {
        num = sscanf(config->params_file, "%[^=:]:%[^=:\n#]", params_splt, params_bd);
        if (num != 2) {
            loginfo("error: could not parse command \"%s\" into form param_splt:param_bd\n", config->params_file);
            loginfo("Classifiers are not configured for continuous updating!\n");
        } else {
            loginfo("Classifiers are configured for continous updating!\n");
            update_classifiers = 1;
        }
    } else {
            loginfo("Classifiers are not configured for continous updating!\n");
    }

    /* initialize the curl library as we need it for downloading updates */
    if (curl_global_init(CURL_GLOBAL_ALL)) {
        loginfo("error: curl init failed\n");
        loginfo("error: updater is not running!\n");
        return NULL;
    }

    /* forever loop. Updater will die when the main joy process exits */
    while (1) {
        /* let's only wake up and do work at specified intervals */
        pthread_mutex_lock(&work_in_process);
      
        /* check for blacklist updates */
        if (update_labels) {
            if (dnload_blacklist_file(config->label_url) == upd_success) {
                if (!is_digest_same(md5_digest_result, blacklist_md5)) {
                   loginfo("Blacklist file is different, updating\n");
                   update_radix_trie();
                   save_new_md5(md5_digest_result, blacklist_md5);
                } else {
                   loginfo("Blacklist file is the same, no work to do\n");
                }
            } else {
                loginfo("error: Blacklist file download failed, no work to do\n");
            }
        }

        /* check for SPLT classifier updates */
        if (update_classifiers) {
            if (dnload_classifier_file(config->params_url,params_splt) == upd_success) {
                if (!is_digest_same(md5_digest_result, splt_classifier_md5)) {
                   loginfo("SPLT classifier is different, updating\n");
                   update_params(SPLT_PARAM_TYPE,params_splt);
                   save_new_md5(md5_digest_result, splt_classifier_md5);
                } else {
                   loginfo("SPLT classifier is the same, no work to do\n");
                }
            } else {
                loginfo("error: SPLT classifier download failed, no work to do\n");
            }

            /* check for BD classifier updates */
            if (dnload_classifier_file(config->params_url,params_bd) == upd_success) {
                if (!is_digest_same(md5_digest_result, bd_classifier_md5)) {
                   loginfo("BD classifier is different, updating\n");
                   update_params(BD_PARAM_TYPE,params_bd);
                   save_new_md5(md5_digest_result, bd_classifier_md5);
                } else {
                   loginfo("BD classifier is the same, no work to do\n");
                }
            } else {
                loginfo("error: BD classifier download failed, no work to do\n");
            }
        }

        pthread_mutex_unlock(&work_in_process);
#ifdef WIN32
		Sleep(UPDATER_WORK_INTERVAL);
#else
        sleep (UPDATER_WORK_INTERVAL);
#endif
    }

    return NULL;
}

