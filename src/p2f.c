/*
 *
 * Copyright (c) 2016-2018 Cisco Systems, Inc.
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
 * \file p2f.c
 *
 * \brief converts pcap files or live packet captures using libpcap into
 * flow/intraflow data in JSON format
 *
 * \brief this file contains the functions relating to flow_records,
 * flow_keys, and the management of the flow cache
 */

#ifdef WIN32
# include "time.h"
#endif

#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include <ctype.h>
#include <float.h>   /* for FLT_EPSILON */
#include "pkt_proc.h" /* packet processing               */
#include "p2f.h"      /* joy data structures       */
#include "err.h"      /* error codes and error reporting */
#include "anon.h"     /* address anonymization           */
#include "classify.h" /* inline classification           */
#include "procwatch.h"  /* process to flow mapping       */
#include "radix_trie.h" /* trie for subnet labels        */
#include "config.h"     /* configuration                 */
#include "output.h"     /* compressed output             */
#include "salt.h"  // Because Windows!
#include "ipfix.h" /* ipfix protocol */
#include "proto_identify.h"
#include "err.h" /* errors and logging */
#include "osdetect.h"
#include "utils.h"
#include "config.h"
#include "joy_api_private.h"

/*
 * The VERSION variable should be set by a compiler directive, based
 * on the file with the same name.  This value is reported in the
 * "metadata" object in JSON output.
 */
#ifndef VERSION
# define VERSION "unknown"
#endif

/*
 * by default, we use a 10-second flow inactivity timeout window
 * and a 20-second activity timeout; the active_timeout represents
 * the difference between those two times
 */
#define T_WINDOW 10
#define T_ACTIVE 20

/* The ETTA Spec says that 4000 octets is suffient for byte distribution */
#define MAX_JOY_BD_OCTETS 4000

static const struct timeval time_window = { T_WINDOW, 0 };

static const struct timeval active_timeout = { T_ACTIVE, 0 };

static const unsigned int active_max = (T_WINDOW + T_ACTIVE);

static const int include_os = 1;

#define expiration_type_reserved 'z'
#define expiration_type_active  'a'
#define expiration_type_inactive 'i'

/*
 * Local prototypes
 */
static void flow_record_delete(joy_ctx_data *ctx, flow_record_t *r);
static void flow_record_print_and_delete(joy_ctx_data *ctx, flow_record_t *record);

/* ***********************************************
 * -----------------------------------------------
 *          Flow monitoring functions
 * -----------------------------------------------
 * ***********************************************
 */

/**
 * \brief Write flow capture stats to the specified file.
 * \param f the output file
 * \return none
 */
void flocap_stats_output (joy_ctx_data *ctx, FILE *f) {
    char time_str[128];
    struct timeval now, tmp;
    float bps, pps, rps, seconds;

#ifdef WIN32
        time_t win_now;
        win_now = time(NULL);
#endif

        gettimeofday(&now, NULL);
        memset(time_str, 0x00, sizeof(time_str));

        joy_timer_sub(&now, &ctx->last_stats_output_time, &tmp);
    seconds = (float) (joy_timeval_to_milliseconds(tmp) / 1000.0);

    bps = (float) (ctx->stats.num_bytes - ctx->last_stats.num_bytes) / seconds;
    pps = (float) (ctx->stats.num_packets - ctx->last_stats.num_packets) / seconds;
    rps = (float) (ctx->stats.num_records_output - ctx->last_stats.num_records_output) / seconds;

#ifdef WIN32
        strftime(time_str, sizeof(time_str) - 1, "%a %b %d %H:%M:%S %Z %Y", localtime(&win_now));
#else
        strftime(time_str, sizeof(time_str) - 1, "%a %b %d %H:%M:%S %Z %Y", localtime(&now.tv_sec));
#endif
    fprintf(f, "%s info: %lu packets, %lu active records, %lu records output, %lu alloc fails, %.4e bytes/sec, %.4e packets/sec, %.4e records/sec\n",
              time_str, ctx->stats.num_packets, ctx->stats.num_records_in_table, ctx->stats.num_records_output, ctx->stats.malloc_fail, bps, pps, rps);
    fflush(f);

    ctx->last_stats_output_time = now;
    ctx->last_stats.num_packets = ctx->stats.num_packets;
    ctx->last_stats.num_bytes = ctx->stats.num_bytes;
    ctx->last_stats.num_records_in_table = ctx->stats.num_records_in_table;
    ctx->last_stats.num_records_output = ctx->stats.num_records_output;
    ctx->last_stats.malloc_fail = ctx->stats.malloc_fail;
}

/**
 * \brief Initialize the flow capture statistics timer.
 * \param none
 * \return none
 */
void flocap_stats_timer_init (joy_ctx_data *ctx) {
    struct timeval now;

    gettimeofday(&now, NULL);
    ctx->last_stats_output_time = now;
}

/**
 * \brief Calculate the hash of a given flow_key.
 * \param f The flow_key to hash
 * \return Hash of \p f
 */
static unsigned int flow_key_hash (const flow_key_t *f) {

    if (glb_config->flow_key_match_method == EXACT_MATCH) {
          return (((unsigned int)f->sa.s_addr * 0xef6e15aa)
            ^ ((unsigned int)f->da.s_addr * 0x65cd52a0)
            ^ ((unsigned int)f->sp * 0x8216)
            ^ ((unsigned int)f->dp * 0xdda37)
            ^ ((unsigned int)f->prot * 0xbc06)) & flow_key_hash_mask;

    } else {  /* flow_key_match_method == NEAR_MATCH */
        /*
         * To make it possible to identify NAT'ed twins, the hash of the
         * flows (sa, da, sp, dp, pr) and (*, *, dp, sp, pr) are identical.
         * This is done by omitting addresses and sorting the ports into
         * order before hashing.
         */
        unsigned int hi, lo;

        if (f->sp > f->dp) {
            hi = f->sp;
            lo = f->dp;
        } else {
            hi = f->dp;
            lo = f->sp;
        }

        return ((hi * 0x8216) ^ (lo * 0xdda37)
            ^ ((unsigned int)f->prot * 0xbc06)) & flow_key_hash_mask;
    }
}

/**
 * \brief Initialize the flow_record_list.
 * \param none
 * \param return
 */
void flow_record_list_init (joy_ctx_data *ctx) {
    unsigned int i;

    ctx->flow_record_chrono_first = ctx->flow_record_chrono_last = NULL;
    for (i=0; i<FLOW_RECORD_LIST_LEN; i++) {
        ctx->flow_record_list_array[i] = NULL;
    }
}

/**
 * \brief Free up all flow_records within the flow_record_list.
 * \param none
 * \return none
 */
void flow_record_list_free (joy_ctx_data *ctx) {
    flow_record_t *record, *tmp;
    unsigned int i, count = 0;

    for (i=0; i<FLOW_RECORD_LIST_LEN; i++) {
        record = ctx->flow_record_list_array[i];
        while (record != NULL) {
            tmp = record->next;
            flow_record_delete(ctx, record);
            record = tmp;
            count++;
        }
        ctx->flow_record_list_array[i] = NULL;
    }
    ctx->flow_record_chrono_first = NULL;
    ctx->flow_record_chrono_last = NULL;
}

/**
 * \brief Compare two flow_keys to see if they are equal.
 * \param a The first flow_key
 * \param b The second flow_key
 * \return 0 for equality, 1 for not
 */
static int flow_key_is_eq (const flow_key_t *a,
                           const flow_key_t *b) {
    if (a->sa.s_addr != b->sa.s_addr) {
        return 1;
    }
    if (a->da.s_addr != b->da.s_addr) {
        return 1;
    }
    if (a->sp != b->sp) {
        return 1;
    }
    if (a->dp != b->dp) {
        return 1;
    }
    if (a->prot != b->prot) {
        return 1;
    }

    /* Match was found */
    return 0;
}

/**
 * \brief Check if two flow_keys are twins.
 * \param a The first flow_key
 * \param b The second flow_key
 * \return 0 if they are twins, 1 for not
 */
static int flow_key_is_twin (const flow_key_t *a,
                             const flow_key_t *b) {
    if (glb_config->flow_key_match_method == NEAR_MATCH) {
        /*
         * Require that only one address match, so that we can find twins
         * even in the presence of NAT; that is, (sa, da) equals either
         * (*, sa) or (da, *).
         *
         * Note that this scheme works only with Network Address
         * Translation (NAT), and not Port Address Translation (PAT).  NAT
         * is commonly done with and without PAT.
         */
        if (a->sa.s_addr != b->da.s_addr && a->da.s_addr != b->sa.s_addr) {
            return 1;
        }
    } else {
        /*
         * Require that both addresses match, that is, (sa, da) == (da, sa)
         */
        if (a->sa.s_addr != b->da.s_addr) {
            return 1;
        }
        if (a->da.s_addr != b->sa.s_addr) {
            return 1;
        }
    }
    if (a->sp != b->dp) {
        return 1;
    }
    if (a->dp != b->sp) {
        return 1;
    }
    if (a->prot != b->prot) {
        return 1;
    }

    /* Match was found */
    return 0;
}

/**
 * \brief Copy a flow_key.
 * \param dst The destination flow_key that will be copied into
 * \param b The source flow_key that will be copied from
 * \return none
 */
static void flow_key_copy (flow_key_t *dst, const flow_key_t *src) {
    dst->sa.s_addr = src->sa.s_addr;
    dst->da.s_addr = src->da.s_addr;
    dst->sp = src->sp;
    dst->dp = src->dp;
    dst->prot = src->prot;
}

#define MAX_TTL 255

flow_record_t *flow_key_get_twin(joy_ctx_data *ctx, const flow_key_t *key);

/**
 * \brief Initialize a flow_record.
 * \param[out] record Flow record
 * \param[in] Flow key to be used for identifiying the record
 * \return none
 */
static void flow_record_init (joy_ctx_data *ctx,
                              flow_record_t *record,
                              const flow_key_t *key) {

    /* Increment the stats flow record count */
    flocap_stats_incr_records_in_table(ctx);

    /* Zero out the flow_record structure */
    memset(record, 0, sizeof(flow_record_t));

    /* Set the flow_key and TTL */
    flow_key_copy(&record->key, key);
    record->ip.ttl = MAX_TTL;
}

/**
 * \brief Check if the flow record is in chrono list.
 * \param record Flow_record
 * \return Valid pointer if in list, NULL otherwise
 */
static inline unsigned int flow_record_is_in_chrono_list (joy_ctx_data *ctx, const flow_record_t *record) {
    if (record->time_next || record->time_prev) {
        return 1;
    }
    if (record == ctx->flow_record_chrono_first) {
        /* Corner case when there is a single record in the list */
        return 1;
    }
    return 0;
}

/**
 * \brief Find the flow record in list, if it exists.
 * \param list The list of flow_records to search
 * \param key The flow_key used to identify the flow_record
 * \return Valid flow_record or NULL
 */
static flow_record_t *flow_record_list_find_record_by_key (const flow_record_list *list,
                                                                const flow_key_t *key) {
    flow_record_t *record = *list;

    /* Find a record matching the flow key, if it exists */
    while (record != NULL) {
        if (flow_key_is_eq(key, &record->key) == 0) {
            debug_printf("LIST (head location: %p) record %p found\n", list, record);
            return record;
        }
        record = record->next;
    }
    debug_printf("LIST (head location: %p) did not find record\n", list);

    return NULL;
}

/**
 * \brief Find the twin of the flow_key in the flow_record_list.
 * \param list The list of flow_records to search
 * \param key The flow_key of the record whose twin we will search for.
 * \return The twin flow_record or NULL
 */
static flow_record_t *flow_record_list_find_twin_by_key (const flow_record_list *list,
                                                              const flow_key_t *key) {
    flow_record_t *record = *list;

    /* find a record matching the flow key, if it exists */
    while (record != NULL) {
        if (flow_key_is_twin(key, &record->key) == 0) {
            debug_printf("LIST (head location: %p) record %p found\n", list, record);
            return record;
        }
        record = record->next;
    }
    debug_printf("LIST (head location: %p) did not find record\n", list);

    return NULL;
}

/**
 * \brief Set the \p head a flow_record_list to the given \p record.
 * \param list The list of flow records
 * \param record The flow_record that will be prepended to the \p list
 * \return none
 */
static void flow_record_list_prepend (flow_record_list *head,
                                      flow_record_t *record) {
    flow_record_t *tmp;

    tmp = *head;
    if (tmp == record) {
        printf("setting record->next to record! (%p)\n", record);
    }
    if (tmp != NULL) {
        tmp->prev = record;
        record->next = tmp;
    }
    *head = record;
    debug_printf("LIST (head location %p) head set to %p (prev: %p, next: %p)\n",
                     head, *head, record->prev, record->next);
}

/**
 * \brief Remove a flow record from the list.
 * \param head The list of records
 * \param r The flow_record that will be removed from the \p list
 * \return none
 */
static unsigned int flow_record_list_remove (flow_record_list *head,
                                             flow_record_t *r) {

    if (r == NULL) {
        return 1;    /* don't process NULL pointers; probably an error to get here */
    }

    debug_printf("LIST (head location %p) removing record at %p (prev: %p, next: %p)\n",
                   head, r, r->prev, r->next);

    if (r->prev == NULL) {
        /*
         * r is the first (or only) record within its flow_record_list, so
         * the head of the list must be set
         */
        if (*head != r) {
            printf("error: frla[hk] != r\n");
            exit(1);
        }
        *head = r->next;
        if (*head != NULL) {
            /*
             * the list is not empty, so we need to set the prev pointer in
             * the first record to indicate that it is the head of the list
             */
          (*head)->prev = NULL;
        }
    } else {
        /*
         * r needs to be stitched out of its flow_record_list, by setting
         * its previous entry to point to its next entry
         */
        r->prev->next = r->next;
        debug_printf("LIST (head location %p) now prev->next: %p\n", head, r->prev->next);
        if (r->next != NULL) {
            /*
             * the next entry's previous pointer must be made to point to
             * the previous entry
             */
            r->next->prev = r->prev;
            debug_printf("LIST (head location %p) now next->prev: %p\n", head, r->next->prev);
        }
    }

    return 0; /* indicate success */
}

/**
 * \brief Append a flow record to the chrono list.
 * \param record The flow_record that will be appended to the list
 * \return none
 */
static void flow_record_chrono_list_append (joy_ctx_data *ctx, flow_record_t *record) {
    if (ctx->flow_record_chrono_first == NULL) {
        ctx->flow_record_chrono_first = record;
        ctx->flow_record_chrono_last = record;
    } else {
        ctx->flow_record_chrono_last->time_next = record;
        record->time_prev = ctx->flow_record_chrono_last;
        ctx->flow_record_chrono_last = record;
    }
}

/**
 * \brief Remove a flow record from the chrono list.
 * \param record The flow_record that will be removed from the list
 * \return none
 */
static void flow_record_chrono_list_remove (joy_ctx_data *ctx, flow_record_t *record) {
    if (record == NULL) {
        return;
    }

    if (record == ctx->flow_record_chrono_first) {
        ctx->flow_record_chrono_first = record->time_next;
    }
    if (record == ctx->flow_record_chrono_last) {
        ctx->flow_record_chrono_last = record->time_prev;
    }

    if (record->time_prev != NULL) {
        record->time_prev->time_next = record->time_next;
    }
    if (record->time_next != NULL) {
        record->time_next->time_prev = record->time_prev;
    }
}

/**
 *
 * \brief Check if an active flow_record is expired.
 *
 * This function operates in one of two modes:
 * 1. Use the incoming packet information within \p header to determine if
 *    the current flow \p record is expired. I.e. should the incoming packet
 *    be placed in a new record.
 * 2. If there is not a new packet \p header, then use the timestamps
 *    of the \p record to determine if it is expired.
 *
 * \param record - The current flow record that matches the incoming packet
 * \param header - this is the incoming packet header which contains timestamps
 * \return int - 1 if expired, 0 otherwise
 */
static int flow_record_is_active_expired(flow_record_t *record,
                                         const struct pcap_pkthdr *header) {
    if (header) {
        /*
         * Preemptive Timeout
         * Check the new incoming packet to see if it will expire the record
         */
        if (header->ts.tv_sec > (record->start.tv_sec + active_max) && glb_config->preemptive_timeout) {
            if ((record->twin == NULL) || (header->ts.tv_sec > (record->twin->start.tv_sec + active_max))) {
                return 1;
            }
        }
    } else {
        /* Check the record only to see if it's expired (no new packet) */
        if (record->end.tv_sec > (record->start.tv_sec + active_max)) {
            if ((record->twin == NULL) || (record->end.tv_sec > (record->twin->start.tv_sec + active_max))) {
                return 1;
            }
        }
    }

    return 0;
}

/**
 *
 * \brief Check if a flow_record is expired.
 *
 * The global Joy time is the most recent packet that has been seen.
 * All of the cutoffs are calculated relative to each other because
 * it enables usage in situations where we cannot use real-time,
 * i.e. IPFIX collection.
 *
 * \param record - A flow_record
 * \return int - 1 if expired, 0 otherwise
 */
unsigned int flow_record_is_expired(joy_ctx_data *ctx, flow_record_t *record) {
    struct timeval inactive_cutoff;
    struct timeval active_cutoff;

    joy_timer_sub(&ctx->global_time, &time_window, &inactive_cutoff);
    joy_timer_sub(&inactive_cutoff, &active_timeout, &active_cutoff);

    /*
     * Check for active timeout
     */
    if (joy_timer_lt(&record->start, &active_cutoff)) {
        if (record->twin) {
            if (joy_timer_lt(&record->twin->start, &active_cutoff)) {
                      record->exp_type = expiration_type_active;
                      return 1;
            }
        } else {
            record->exp_type = expiration_type_active;
            return 1;
        }
    }

    /*
     * Check for inactive timeout
     */
    if (joy_timer_lt(&record->end, &inactive_cutoff)) {
        if (record->twin) {
            if (joy_timer_lt(&record->twin->end, &inactive_cutoff)) {
                    record->exp_type = expiration_type_inactive;
                    return 1;
            }
        } else {
            record->exp_type = expiration_type_inactive;
            return 1;
        }
    }

    return 0;
}

/**
 * \brief Retrieve a flow record using a \p key to find it.
 * \param key The flow_key to use for lookup of flow record
 * \param create_new_records Flag for whether a new record should be created
 * \return pointer to the flow record structure
 * \return NULL if expired or could not create or retrieve record
 */
flow_record_t *flow_key_get_record (joy_ctx_data *ctx,
                                         const flow_key_t *key,
                                         unsigned int create_new_records,
                                         const struct pcap_pkthdr *header) {
    flow_record_t *record;
    unsigned int hash_key;

    /* Find a record matching the flow key, if it exists */
    hash_key = flow_key_hash(key);
    record = flow_record_list_find_record_by_key(&ctx->flow_record_list_array[hash_key], key);

    if (record != NULL) {
       if (create_new_records && flow_record_is_in_chrono_list(ctx, record)
           && flow_record_is_active_expired(record, header)) {
            /*
             *  Active-timeout exceeded for this flow_record; print and delete
             *  it, then set record = NULL to cause the creation of a new
             *  flow_record to be used in further packet processing
             */
           flow_record_print_and_delete(ctx, record);
           record = NULL;
       } else {
           return record;
       }
    }

    /* if we get here, then record == NULL  */

    if (create_new_records) {

        /* allocate and initialize a new flow record */
        record = calloc(1, sizeof(flow_record_t));
        debug_printf("LIST record %p allocated\n", record);

        if (record == NULL) {
            joy_log_warn("could not allocate memory for flow_record");
            flocap_stats_incr_malloc_fail(ctx);
            return NULL;
        }

        flow_record_init(ctx, record, key);

        /* enter record into flow_record_list */
        flow_record_list_prepend(&ctx->flow_record_list_array[hash_key], record);

        /*
         * if we are tracking bidirectional flows, and if record has a
         * twin, then set both twin pointers; otherwise, enter the
         * record into the chronological list
         */
        if (glb_config->bidir) {
            record->twin = flow_key_get_twin(ctx, key);
            debug_printf("LIST record %p is twin of %p\n", record, record->twin);
        }
        if (record->twin != NULL) {
            if (record->twin->twin != NULL) {
                fprintf(info, "warning: found twin that already has a twin; not setting twin pointer\n");
                debug_printf("\trecord:    (hash key %x)(addr: %p)\n", flow_key_hash(&record->key), record);
                debug_printf("\ttwin:      (hash key %x)(addr: %p)\n", flow_key_hash(&record->twin->key), &record->twin);
                debug_printf("\ttwin twin: (hash key %x)(addr: %p)\n", flow_key_hash(&record->twin->twin->key), &record->twin->key);
                /*
                 * experimental - consider this record an orphan, add it to chrono list, but without its twin pointer set
                 */
                record->twin = NULL;
                flow_record_chrono_list_append(ctx, record);
            } else {
                record->twin->twin = record;
            }
        } else {

            /* this flow has no twin, so add it to chronological list */
            flow_record_chrono_list_append(ctx, record);
        }
    }

    return record;
}

/**
 * \brief Delete a flow record.
 * \param r The flow_record to delete
 * \return none
 */
static void flow_record_delete (joy_ctx_data *ctx, flow_record_t *r) {

    if (flow_record_list_remove(&ctx->flow_record_list_array[flow_key_hash(&r->key)], r) != 0) {
        joy_log_err("problem removing flow record %p from list", r);
        return;
    }

    flocap_stats_decr_records_in_table(ctx);

    /*
     * free the memory allocated inside of flow record
     */
    if (r->idp) {
        free(r->idp);
    }

    if (r->exe_name) {
        free(r->exe_name);
    }

        if (r->full_path) {
                free(r->full_path);
        }

        if (r->file_version) {
                free(r->file_version);
        }

        if (r->file_hash) {
                free(r->file_hash);
        }

    delete_all_features(feature_list);

    /*
     * zeroize memory (this is defensive coding; pointers to deleted
     * records will result in crashes rather than silent errors)
     */
    memset(r, 0, sizeof(flow_record_t));
    free(r);
    r = NULL;
}

/**
* \fn int flow_key_set_process_info (const flow_key_t *key, const host_flow_t *data)
* \param key flow key structure
* \param data process flow information
* \return failure
* \return ok
*/
int flow_key_set_process_info(joy_ctx_data *ctx, const flow_key_t *key, const host_flow_t *data) {
        flow_record_t *r;

        if (data->exe_name == NULL) {
                return failure;   /* no point in looking for flow_record */
        }
        r = flow_key_get_record(ctx, key, DONT_CREATE_RECORDS, NULL);
        // flow_key_print(key);
        if (r) {
                if (r->exe_name == NULL) {
                        r->exe_name = strdup(data->exe_name);
                }
                if (r->full_path == NULL) {
                    if (data->full_path)
                        r->full_path = strdup(data->full_path);
                }
                if (r->file_version == NULL) {
                    if (data->file_version)
                        r->file_version = strdup(data->file_version);
                }
                if (r->file_hash == NULL) {
                    if (data->hash)
                        r->file_hash = strdup(data->hash);
                }
                r->uptime_seconds = data->uptime_seconds;
                return ok;
        }
        return failure;
}

/**
 * \brief Update the byte count for the flow record.
 * \param f Flow record
 * \param x Data to use for update
 * \param len Length of the data (in bytes)
 * \return none
 */
void flow_record_update_byte_count (flow_record_t *f, const void *x, unsigned int len) {
    const unsigned char *data = x;
    unsigned int i;

    /*
     * implementation note: The spec says that 4000 octets is enough of a
     * sample size to accurately reflect the byte distribution. Also, to avoid
     * wrapping of the byte count at the 16-bit boundry, we stop counting once
     * the 4000th octet has been seen for a flow.
     */

    if (glb_config->byte_distribution || glb_config->report_entropy) {
        if (f->ob < MAX_JOY_BD_OCTETS) {
            for (i=0; i<len; i++) {
                f->byte_count[data[i]]++;
            }
        }
    }
}

/**
 * \brief Update the compact byte count for the flow record.
 * \param f Flow record
 * \param x Data to use for update
 * \param len Length of the data (in bytes)
 * \return none
 */
void flow_record_update_compact_byte_count (flow_record_t *f, const void *x, unsigned int len) {
    const unsigned char *data = x;
    unsigned int i;

    if (glb_config->compact_byte_distribution) {
        for (i=0; i<len; i++) {
            f->compact_byte_count[glb_config->compact_bd_mapping[data[i]]]++;
        }
    }
}

/**
 * \brief Update the byte distribution mean for the flow record.
 * \param f Flow record
 * \param x Data to use for update
 * \param len Length of the data (in bytes)
 * \return none
 */
void flow_record_update_byte_dist_mean_var (flow_record_t *f, const void *x, unsigned int len) {
    const unsigned char *data = x;
    double delta;
    unsigned int i;

    if (glb_config->byte_distribution || glb_config->report_entropy) {
        for (i=0; i<len; i++) {
            f->num_bytes += 1;
            delta = ((double)data[i] - f->bd_mean);
            f->bd_mean += delta/((double)f->num_bytes);
            f->bd_variance += delta*((double)data[i] - f->bd_mean);
        }
    }
}

static float flow_record_get_byte_count_entropy (const unsigned int byte_count[256],
    unsigned int num_bytes) {
    int i;
    float tmp, sum = 0.0;

    for (i=0; i<256; i++) {
        tmp = (float) byte_count[i] / (float) num_bytes;
        if (tmp > FLT_EPSILON) {
            sum -= tmp * logf(tmp);
        }
        // fprintf(output, "tmp: %f\tsum: %f\n", tmp, sum);
    }
    return sum / logf(2.0);
}

static void print_bytes_dir_time (joy_ctx_data *ctx,
                                  unsigned short int pkt_len,
                                  const char *dir,
                                  struct timeval ts,
                                  const char *term) {
    if (pkt_len < 32768) {
        zprintf(ctx->output, "{\"b\":%u,\"dir\":\"%s\",\"ipt\":%u}%s",
                    pkt_len, dir, joy_timeval_to_milliseconds(ts), term);
    } else {
        zprintf(ctx->output, "{\"rep\":%u,\"dir\":\"%s\",\"ipt\":%u}%s",
                    65536-pkt_len, dir, joy_timeval_to_milliseconds(ts), term);
    }
}

/**
 * \brief Print out raw values as hex to the output file.
 * \param f Output file
 * \param data The data to print out
 * \param len Length of the data to print (in bytes)
 * \return none
 */
void zprintf_raw_as_hex (zfile f,
                         const unsigned char *data,
                         unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    zprintf(f, "\"");   /* quotes needed for JSON */
    while (x < end) {
        zprintf(f, "%02x", *x++);
    }
    zprintf(f, "\"");
}

static void reduce_bd_bits (unsigned int *bd,
                            unsigned int len) {
    int mask = 0;
    int shift = 0;
    unsigned int i = 0;

    for (i = 0; i < len; i++) {
        mask = mask | bd[i];
    }

    mask = mask >> 8;
    for (i = 0; i < 24 && mask; i++) {
        mask = mask >> 1;
        if (mask == 0) {
            shift = i+1;
            break;
        }
    }

    for (i = 0; i < len; i++) {
        bd[i] = bd[i] >> shift;
    }
}

/**
 * \brief Print the host executable information tied to this flow.
 *
 * \param f Output file
 * \param rec Flow record
 *
 * \return none
 */
static void print_executable_json (zfile f, const flow_record_t *rec) {
    uint8_t comma = 0;

    if (rec->exe_name || rec->full_path ||
        rec->file_version || rec->file_hash) {

        zprintf(f, ",\"exe\":{");
        if (rec->exe_name) {
            zprintf(f, "\"name\":\"%s\"", rec->exe_name);
            comma = 1;
        }
        if (rec->full_path) {
            if (comma) {
                zprintf(f, ",\"path\":\"%s\"", rec->full_path);
            } else {
                zprintf(f, "\"path\":\"%s\"", rec->full_path);
                comma = 1;
            }
        }
        if (rec->file_version) {
            if (comma) {
                zprintf(f, ",\"version\":\"%s\"", rec->file_version);
            } else {
                zprintf(f, "\"version\":\"%s\"", rec->file_version);
                comma = 1;
            }
        }
        if (rec->file_hash) {
            if (comma) {
                zprintf(f, ",\"hash\":\"%s\"", rec->file_hash);
            } else {
                zprintf(f, "\"hash\":\"%s\"", rec->file_hash);
                comma = 1;
            }
        }
        if (rec->uptime_seconds > 0) {
            if (comma) {
                zprintf(f, ",\"uptime\":%lu", rec->uptime_seconds);
            } else {
                zprintf(f, "\"uptime\":%lu", rec->uptime_seconds);
                comma = 1;
            }
        }
        zprintf(f, "}");
    }
}

static void print_tcp_json (zfile f, const flow_record_t *rec) {
    int top_com = 0;
    int com = 0;
    int empty = 1;
    int out_empty = 1;
    int in_empty = 1;

    /*
     * Check what TCP data is avilable (if any).
     */
    if (rec->tcp.first_seq) {
        empty = 0;
    } else if (rec->twin && rec->twin->tcp.first_seq) {
        empty = 0;
    }

#define not_empty(rec) (rec->tcp.flags || rec->tcp.first_window_size || rec->tcp.opt_len)

    if (not_empty(rec)) {
        empty = 0; out_empty = 0;
    }
    if (rec->twin && not_empty(rec->twin)) {
        empty = 0; in_empty = 0;
    }

    if (empty) {
        /* No data to print */
        return;
    }

    zprintf(f, ",\"tcp\":{");

    if (rec->tcp.first_seq) {
        zprintf(f, "\"first_seq\":%u", rec->tcp.first_seq);
        top_com = 1;
    } else if (rec->twin != NULL && rec->twin->tcp.first_seq) {
        zprintf(f, "\"first_seq\":%u", rec->twin->tcp.first_seq);
        top_com = 1;
    }

    if (!out_empty) {
        char out_flags_string[9] = {0};

        if (top_com) {
            zprintf(f, ",\"out\":{");
        } else {
            zprintf(f, "\"out\":{");
            top_com = 1;
        }

        if (rec->tcp.flags) {
            tcp_flags_to_string(rec->tcp.flags, out_flags_string);
            zprintf(f, "\"flags\":\"%s\"", out_flags_string);
            com = 1;
        }

        if (rec->tcp.first_window_size) {
            if (com) {
                zprintf(f, ",\"first_window_size\":%u", rec->tcp.first_window_size);
            } else {
                zprintf(f, "\"first_window_size\":%u", rec->tcp.first_window_size);
                com = 1;
            }
        }

        if (rec->tcp.opt_len) {
            if (com) {
                zprintf(f, ",\"opt_len\":%u", rec->tcp.opt_len);
            } else {
                zprintf(f, "\"opt_len\":%u", rec->tcp.opt_len);
            }
            tcp_opt_print_json(f, rec->tcp.opts, rec->tcp.opt_len);
        }

        /* End out object */
        zprintf(f, "}");
    }

    if (!in_empty) {
        char in_flags_string[9] = {0};
        com = 0;

        if (top_com) {
            zprintf(f, ",\"in\":{");
        } else {
            zprintf(f, "\"in\":{");
        }

        if (rec->twin->tcp.flags) {
            tcp_flags_to_string(rec->twin->tcp.flags, in_flags_string);
            zprintf(f, "\"flags\":\"%s\"", in_flags_string);
            com = 1;
        }

        if (rec->twin->tcp.first_window_size) {
            if (com) {
                zprintf(f, ",\"first_window_size\":%u", rec->twin->tcp.first_window_size);
            } else {
                zprintf(f, "\"first_window_size\":%u", rec->twin->tcp.first_window_size);
                com = 1;
            }
        }

        if (rec->twin->tcp.opt_len) {
            if (com) {
                zprintf(f, ",\"opt_len\":%u", rec->twin->tcp.opt_len);
            } else {
                zprintf(f, "\"opt_len\":%u", rec->twin->tcp.opt_len);
            }
            tcp_opt_print_json(f, rec->twin->tcp.opts, rec->twin->tcp.opt_len);
        }

        /* End in object */
        zprintf(f, "}");
    }

    /* End tcp object */
    zprintf(f, "}");
}

static void print_ip_json (zfile f, const flow_record_t *rec) {
    int k = 0;

    zprintf(f, ",\"ip\":{");

    zprintf(f, "\"out\":{");
    zprintf(f, "\"ttl\":%u", rec->ip.ttl);
    if (rec->ip.num_id) {
        zprintf(f, ",\"id\":[");
        for (k = 0; k < rec->ip.num_id - 1; k++) {
            zprintf(f, "%u,", rec->ip.id[k]);
        }
        zprintf(f, "%u]", rec->ip.id[k]);
    }
    /* End out object */
    zprintf(f, "}");

    if (rec->twin) {
        zprintf(f, ",\"in\":{");
        zprintf(f, "\"ttl\":%u", rec->twin->ip.ttl);
        if (rec->twin->ip.num_id) {
            zprintf(f, ",\"id\":[");
            for (k = 0; k < rec->twin->ip.num_id - 1; k++) {
                zprintf(f, "%u,", rec->twin->ip.id[k]);
            }
            zprintf(f, "%u]", rec->twin->ip.id[k]);
        }
        /* End in object */
        zprintf(f, "}");
    }

    /* End IP object */
    zprintf(f, "}");
}

static const flow_record_t *tcp_client_flow(const flow_record_t *a,
                                                 const flow_record_t *b) {
    if (!a->tcp.flags && !b->tcp.flags) {
        /* No flags to compare */
        return NULL;
    }

    if (a->tcp.flags == 2 && b->tcp.flags == 2) {
        /* Cannot determine, both have SYN */
        return NULL;
    }

    /* SYN */
    if (a->tcp.flags == 2) {
        return a;
    } else if (b->tcp.flags == 2) {
        return b;
    }

    if (a->tcp.flags == 18 && b->tcp.flags == 18) {
        /* Cannot determine, both have SYN/ACK */
        return NULL;
    }

    /*
     * SYN/ACK
     * If detected, then return the twin.
     */
    if (a->tcp.flags == 18) {
        return b;
    } else if (b->tcp.flags == 18) {
        return a;
    }

    return NULL;
}

static const flow_record_t *get_client_flow(const flow_record_t *a,
                                                 const flow_record_t *b) {
    /* See if either is client */
    if (a->dir == DIR_CLIENT) {
        return a;
    } else if (b->dir == DIR_CLIENT) {
        return b;
    }

    /* See if either is server, then the twin is client */
    if (a->dir == DIR_SERVER) {
        return b;
    } else if (b->dir == DIR_SERVER) {
        return a;
    }

    /*
     * Try identifying by tcp flags.
     */
    return tcp_client_flow(a, b);
}

#define OUT "<"
#define IN  ">"

/**
 * \brief Print a flow record to the JSON output.
 *
 * \param record Flow record to print
 *
 * \return none
 */
static void flow_record_print_json
 (joy_ctx_data *ctx, const flow_record_t *record) {
    unsigned int i, j, imax, jmax;
    struct timeval ts, ts_last, ts_start, ts_end, ts_tmp;
    const flow_record_t *rec = NULL;
    unsigned int pkt_len;
    const char *dir;
    char ipv4_addr[INET_ADDRSTRLEN];

    flocap_stats_incr_records_output(ctx);
    ctx->records_in_file++;

    if (record->twin != NULL) {
        /*
         * The flow is bidirectional.
         * Need to figure client/server order.
         */
        int compare_start_times = 1;

        if (joy_timer_eq(&record->start, &record->twin->start)) {
            /*
             * The start times are equal.
             * Try to resolve direction.
             */
            rec = get_client_flow(record, record->twin);
            if (rec != NULL) {
                compare_start_times = 0;
                ts_start = rec->start;
            }
        }

        if (compare_start_times) {
            /*
             * Get start time.
             * Use the smaller of the 2 time values.
             */
            if (joy_timer_lt(&record->start, &record->twin->start)) {
                ts_start = record->start;
                rec = record;
            } else {
                ts_start = record->twin->start;
                rec = record->twin;
            }
        }

        /*
         * Get end time.
         * Use the larger of the 2 time values.
         */
        if (joy_timer_lt(&record->end, &record->twin->end)) {
            ts_end = record->twin->end;
        } else {
            ts_end = record->end;
        }
    } else {
        /*
         * The flow is unidirectional. Easy enough.
         */
        ts_start = record->start;
        ts_end = record->end;
        rec = record;
    }

    /*****************************************************************
     * ---------------------------------------------------------------
     * Flow Record object start
     * ---------------------------------------------------------------
     *****************************************************************
     */
    zprintf(ctx->output, "{");

    if (ipv4_addr_needs_anonymization(&rec->key.sa)) {
        zprintf(ctx->output, "\"sa\":\"%s\",", addr_get_anon_hexstring(&rec->key.sa));
    } else {
        inet_ntop(AF_INET, &rec->key.sa, ipv4_addr, INET_ADDRSTRLEN);
        zprintf(ctx->output, "\"sa\":\"%s\",", ipv4_addr);
    }
    if (ipv4_addr_needs_anonymization(&rec->key.da)) {
        zprintf(ctx->output, "\"da\":\"%s\",", addr_get_anon_hexstring(&rec->key.da));
    } else {
        inet_ntop(AF_INET, &rec->key.da, ipv4_addr, INET_ADDRSTRLEN);
        zprintf(ctx->output, "\"da\":\"%s\",", ipv4_addr);
    }
    zprintf(ctx->output, "\"pr\":%u,", rec->key.prot);

    if (rec->key.prot == 6 || rec->key.prot == 17) {
        zprintf(ctx->output, "\"sp\":%u,", rec->key.sp);
        zprintf(ctx->output, "\"dp\":%u,", rec->key.dp);
    } else {
        /* Make dp/sp null so that they can still be compared */
        zprintf(ctx->output, "\"sp\":null,");
        zprintf(ctx->output, "\"dp\":null,");
    }

    /*
     * if src or dst address matches a subnets associated with labels,
     * then print out those labels
     */
    if (glb_config->num_subnets) {
        attr_flags flag;

        flag = radix_trie_lookup_addr(glb_config->rt, rec->key.sa);
        attr_flags_json_print_labels(glb_config->rt, flag, "sa_labels", ctx->output);
        flag = radix_trie_lookup_addr(glb_config->rt, rec->key.da);
        attr_flags_json_print_labels(glb_config->rt, flag, "da_labels", ctx->output);
    }

    /*
     * Flow stats
     */
    zprintf(ctx->output, "\"bytes_out\":%u,", rec->ob);
    zprintf(ctx->output, "\"num_pkts_out\":%u,", rec->np); /* not just packets with data */
    if (rec->twin != NULL) {
        zprintf(ctx->output, "\"bytes_in\":%u,", rec->twin->ob);
        zprintf(ctx->output, "\"num_pkts_in\":%u,", rec->twin->np);
    }
#ifdef WIN32
        zprintf(ctx->output, "\"time_start\":%i.%06i,", ts_start.tv_sec, ts_start.tv_usec);
        zprintf(ctx->output, "\"time_end\":%i.%06i,", ts_end.tv_sec, ts_end.tv_usec);
#else
    zprintf(ctx->output, "\"time_start\":%zd.%06zd,", ts_start.tv_sec, (long)ts_start.tv_usec);
    zprintf(ctx->output, "\"time_end\":%zd.%06zd,", ts_end.tv_sec, (long)ts_end.tv_usec);
#endif

    /*****************************************************************
     * Packet length and time array
     *****************************************************************
     */
    zprintf(ctx->output, "\"packets\":[");

    if (rec->twin == NULL) {

        imax = rec->op > NUM_PKT_LEN ? NUM_PKT_LEN : rec->op;
        if (imax == 0) {
            ; /* no packets had data, so we print out nothing */
        } else {
            for (i = 0; i < imax-1; i++) {
                if (i > 0) {
                    joy_timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
                } else {
                    joy_timer_clear(&ts);
                }
                print_bytes_dir_time(ctx, rec->pkt_len[i], OUT, ts, ",");
            }
            if (i == 0) {        /* TODO this code could be simplified */
                joy_timer_clear(&ts);
            } else {
                joy_timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
            }
            print_bytes_dir_time(ctx, rec->pkt_len[i], OUT, ts, "");
        }
        zprintf(ctx->output, "]");
    } else {
        imax = rec->op > NUM_PKT_LEN ? NUM_PKT_LEN : rec->op;
        jmax = rec->twin->op > NUM_PKT_LEN ? NUM_PKT_LEN : rec->twin->op;
        i = j = 0;
        ts_last = ts_start;

        while ((i < imax) || (j < jmax)) {
            if (i >= imax) {
                /* record list is exhausted, so use twin */
                    dir = OUT;
                    ts = rec->twin->pkt_time[j];
                    pkt_len = rec->twin->pkt_len[j];
                    j++;
            } else if (j >= jmax) {
                /* twin list is exhausted, so use record */
                dir = IN;
                ts = rec->pkt_time[i];
                pkt_len = rec->pkt_len[i];
                i++;
            } else {
                /* Neither list is exhausted, so use list with lowest time */
                if (joy_timer_lt(&rec->pkt_time[i], &rec->twin->pkt_time[j])) {
                    ts = rec->pkt_time[i];
                    pkt_len = rec->pkt_len[i];
                    dir = IN;
                    if (i < imax) i++;
                } else {
                    ts = rec->twin->pkt_time[j];
                    pkt_len = rec->twin->pkt_len[j];
                    dir = OUT;
                    if (j < jmax) j++;
                }
            }

            joy_timer_sub(&ts, &ts_last, &ts_tmp);
            print_bytes_dir_time(ctx, pkt_len, dir, ts_tmp, "");
            ts_last = ts;

            if (!((i == imax) & (j == jmax))) {
                /* Done */
                zprintf(ctx->output, ",");
            }
        }
        zprintf(ctx->output, "]");
    }

    if (glb_config->byte_distribution || glb_config->report_entropy || glb_config->compact_byte_distribution) {
        const unsigned int *array = NULL;
        const unsigned int *compact_array = NULL;
        unsigned int tmp[256];
        unsigned int compact_tmp[16];
        unsigned int num_bytes;
        double mean = 0.0, variance = 0.0;

        /*
         * Sum up the byte_count array for outbound and inbound flows,
         * if this flow is bidirectional
         */
        if (rec->twin == NULL) {
            array = rec->byte_count;
            //compact_array = rec->compact_byte_count; //overwritten below fixme
            num_bytes = rec->ob;

            for (i=0; i<256; i++) {
                      tmp[i] = rec->byte_count[i];
            }
            for (i=0; i<16; i++) {
                      compact_tmp[i] = rec->compact_byte_count[i];
            }

            if (rec->num_bytes != 0) {
                mean = rec->bd_mean;
                variance = rec->bd_variance/(rec->num_bytes - 1);
                variance = sqrt(variance);

                if (rec->num_bytes == 1) {
                    variance = 0.0;
                }
            }
        } else {
            for (i=0; i<256; i++) {
                      tmp[i] = rec->byte_count[i] + rec->twin->byte_count[i];
            }
            for (i=0; i<16; i++) {
                      compact_tmp[i] = rec->compact_byte_count[i] + rec->twin->compact_byte_count[i];
            }
            array = tmp;
            compact_array = compact_tmp;
            num_bytes = rec->ob + rec->twin->ob;

            if (rec->num_bytes + rec->twin->num_bytes != 0) {
                mean = ((double)rec->num_bytes)/((double)(rec->num_bytes+rec->twin->num_bytes))*rec->bd_mean +
                           ((double)rec->twin->num_bytes)/((double)(rec->num_bytes+rec->twin->num_bytes))*rec->twin->bd_mean;

                    variance = ((double)rec->num_bytes)/((double)(rec->num_bytes+rec->twin->num_bytes))*rec->bd_variance +
                               ((double)rec->twin->num_bytes)/((double)(rec->num_bytes+rec->twin->num_bytes))*rec->twin->bd_variance;

                    variance = variance/((double)(rec->num_bytes + rec->twin->num_bytes - 1));
                    variance = sqrt(variance);
                    if (rec->num_bytes + rec->twin->num_bytes == 1) {
                        variance = 0.0;
                    }
            }
        }

        if (glb_config->byte_distribution) {
            reduce_bd_bits(tmp, 256);
            array = tmp;

            zprintf(ctx->output, ",\"byte_dist\":[");
            for (i = 0; i < 255; i++) {
                zprintf(ctx->output, "%u,", (unsigned char)array[i]);
            }
            zprintf(ctx->output, "%u]", (unsigned char)array[i]);

            /* Output the mean */
            if (num_bytes != 0) {
                zprintf(ctx->output, ",\"byte_dist_mean\":%f", mean);
                zprintf(ctx->output, ",\"byte_dist_std\":%f", variance);
            }

        }

        if (glb_config->compact_byte_distribution) {
            reduce_bd_bits(compact_tmp, 16);
            compact_array = compact_tmp;

            zprintf(ctx->output, ",\"compact_byte_dist\":[");
            for (i = 0; i < 15; i++) {
                zprintf(ctx->output, "%u,", (unsigned char)compact_array[i]);
            }
            zprintf(ctx->output, "%u]", (unsigned char)compact_array[i]);
        }

        if (glb_config->report_entropy) {
            if (num_bytes != 0) {
                double entropy = flow_record_get_byte_count_entropy(array, num_bytes);

                zprintf(ctx->output, ",\"entropy\":%f", entropy);
                zprintf(ctx->output, ",\"total_entropy\":%f", entropy * num_bytes);
            }
        }
    }

    /*
     * Inline classification of flows
     */
    if (glb_config->include_classifier) {
        float score = 0.0;

        if (rec->twin) {
            score = classify(rec->pkt_len, rec->pkt_time, rec->twin->pkt_len, rec->twin->pkt_time,
                                     rec->start, rec->twin->start,
                                     NUM_PKT_LEN, rec->key.sp, rec->key.dp, rec->np, rec->twin->np, rec->op, rec->twin->op,
                                     rec->ob, rec->twin->ob, glb_config->byte_distribution,
                                     rec->byte_count, rec->twin->byte_count);
        } else {
            score = classify(rec->pkt_len, rec->pkt_time, NULL, NULL,   rec->start, rec->start,
                                     NUM_PKT_LEN, rec->key.sp, rec->key.dp, rec->np, 0, rec->op, 0,
                                     rec->ob, 0, glb_config->byte_distribution,
                                     rec->byte_count, NULL);
        }

        zprintf(ctx->output, ",\"p_malware\":%f", score);
    }

    /* IP object */
    print_ip_json(ctx->output, rec);

    if (rec->key.prot == 6) {
        /* TCP object */
        print_tcp_json(ctx->output, rec);
    }

    /*
     * All of the feature modules
     */
    print_all_features(feature_list);

    /*
     * Host executable
     */
    print_executable_json(ctx->output, rec);

    if (glb_config->report_hd) {
        /*
         * TODO: this should be bidirectional, but it is not!  This will
         * be changed sometime soon, but for now, this will give some
         * experience with this type of data
         */
        header_description_printf(&rec->hd, ctx->output, glb_config->report_hd);
    }

    /*
     * Operating system
     */
    if (include_os) {
        if (rec->twin) {
            os_printf(ctx->output, rec->ip.ttl, rec->tcp.first_window_size, rec->twin->ip.ttl, rec->twin->tcp.first_window_size);
        } else {
            os_printf(ctx->output, rec->ip.ttl, rec->tcp.first_window_size, 0, 0);
        }
    }

    /*
     * Initial data packet (IDP)
     */
    if (glb_config->idp) {
        if (rec->idp != NULL) {
            zprintf(ctx->output, ",\"idp_out\":");
            zprintf_raw_as_hex(ctx->output, rec->idp, rec->idp_len);
            zprintf(ctx->output, ",\"idp_len_out\":%u", rec->idp_len);
        }
        if (rec->twin && (rec->twin->idp != NULL)) {
            zprintf(ctx->output, ",\"idp_in\":");
            zprintf_raw_as_hex(ctx->output, rec->twin->idp, rec->twin->idp_len);
            zprintf(ctx->output, ",\"idp_len_in\":%u", rec->twin->idp_len);
        }
    }

    {
        unsigned int retrans, invalid;

        retrans = rec->tcp.retrans;
        invalid = rec->invalid;
        if (rec->twin) {
            retrans += rec->twin->tcp.retrans;
            invalid += rec->twin->invalid;
        }

        if (retrans || invalid) {
            uint8_t comma = 0;
            zprintf(ctx->output, ",\"debug\":{");
            if (retrans) {
                zprintf(ctx->output, "\"tcp_retrans\":%u", retrans);
                comma = 1;
            }
            if (invalid) {
                if (comma) {
                    zprintf(ctx->output, ",\"invalid\":%u", invalid);
                } else {
                    zprintf(ctx->output, "\"invalid\":%u", invalid);
                }
            }
            zprintf(ctx->output, "}");
        }

    }

    if (rec->exp_type) {
        zprintf(ctx->output, ",\"expire_type\":\"%c\"", rec->exp_type);
    }

    /*****************************************************************
     * Flow Record object end
     *****************************************************************
     */
    zprintf(ctx->output, "}\n");
}



/**
 * \brief Print a flow record to output and delete.
 *
 * After printing the flow \p record, it will first be removed
 * from the chrono list and then deleted. If IPFIX export is enabled,
 * the record will be exported before deletion.
 *
 * \param record Flow record to print and delete 
 *
 * \return none
 */
static void flow_record_print_and_delete (joy_ctx_data *ctx, flow_record_t *record) {
    /*
     * Print the record to JSON output
     */
    flow_record_print_json(ctx, record);

#ifndef JOY_LIB_API
    /*
     * Export this record before deletion if running in
     * IPFIX exporter mode.
     */
    if (glb_config->ipfix_export_port) {
        ipfix_export_main(ctx, record);
    }
#endif
    /*
     * Delete twin, if there is one
     */
    if (record->twin != NULL) {
        debug_printf("LIST deleting twin\n");
        flow_record_delete(ctx, record->twin);
    }

    /* Remove record from chrono list, then delete from flow_record_list_array */
    flow_record_chrono_list_remove(ctx, record);
    flow_record_delete(ctx, record);
}

/**
 * \brief Does IPFix sending of flow record data.
 *
 * \param export_all Flag whether to indiscriminately print all flow_records.
 *                  JOY_EXPIRED_FLOWS - perform expiration check
 *                  JOY_ALL_FLOWS - print all of them
 *
 * \return none
 */
void flow_record_export_as_ipfix (joy_ctx_data *ctx, unsigned int export_type) {
    flow_record_t *record = NULL;

    /* The head of chrono record list */
    record = ctx->flow_record_chrono_first;

    while (record != NULL) {
        if (export_type == JOY_EXPIRED_FLOWS) {
            /* Avoid printing flows that might still be active */
            if (!flow_record_is_expired(ctx,record)) {
                break;
            }
        }

        /*
         * Export this record before deletion if running in
         * IPFIX exporter mode.
         */
        if (glb_config->ipfix_export_port) {
            ipfix_export_main(ctx,record);
        }

        /*
         * Delete twin, if there is one
         */
        if (record->twin != NULL) {
            debug_printf("LIST deleting twin\n");
            flow_record_delete(ctx, record->twin);
        }

        /* Remove record from chrono list, then delete from flow_record_list_array */
        flow_record_chrono_list_remove(ctx, record);
        flow_record_delete(ctx, record);

        /* Advance to next record on chrono list */
        record = ctx->flow_record_chrono_first;
    }
}

/**
 * \brief Prints out the flow record list in JSON format.
 *
 * \param export_all Flag whether to indiscriminately print all flow_records.
 *                  JOY_EXPIRED_FLOWS - perform expiration check
 *                  JOY_ALL_FLOWS - print all of them
 *
 * \return none
 */
void flow_record_list_print_json (joy_ctx_data *ctx, unsigned int print_type) {
    flow_record_t *record = NULL;

    /* The head of chrono record list */
    record = ctx->flow_record_chrono_first;

    while (record != NULL) {
        if (print_type == JOY_EXPIRED_FLOWS) {
            /* Avoid printing flows that might still be active */
            if (!flow_record_is_expired(ctx,record)) {
                break;
            }
        }

        /* print and remove the record */
        flow_record_print_and_delete(ctx, record);

        /* Advance to next record on chrono list */
        record = ctx->flow_record_chrono_first;
    }

    // note: we might need to call flush in the future
    // zflush(ctx->output);
}

/**
 * \brief Removes the record and its twin from the list and the flow records
 *     structure.
 *
 * \param ctx - the joy context to process with
 * \param rec - the rec we are deleting
 *
 * \return none.
 */
void remove_record_and_update_list(joy_ctx_data *ctx, flow_record_t *rec)
{
    /* sanity check */
    if ((ctx == NULL) || (rec == NULL)) {
        return;
    }

    /* Delete twin, if there is one */
    if (rec->twin != NULL) {
        flow_record_delete(ctx, rec->twin);
    }

    /* Remove from chrono list, then delete from flow_record_list_array */
    flow_record_chrono_list_remove(ctx, rec);
    flow_record_delete(ctx, rec);
}


/**
 * \brief Get the twin of a flow_key.
 *
 * \param key A flow_key that we will try to find it's twin
 *
 * \return The twin flow_key, or NULL
 */
flow_record_t *flow_key_get_twin (joy_ctx_data *ctx, const flow_key_t *key) {
    if (glb_config->flow_key_match_method == EXACT_MATCH) {
        flow_key_t twin;

        /*
         * we use find_record_by_key() instead of find_twin_by_key(),
         * because we are using a flow_key_hash() that depends on the
         * entire flow key, and that hash won't work with
         * find_twin_by_key() function because it does not map near twins
         * to the same flow_record_list
         */
        twin.sa.s_addr = key->da.s_addr;
        twin.da.s_addr = key->sa.s_addr;
        twin.sp = key->dp;
        twin.dp = key->sp;
        twin.prot = key->prot;

        return flow_record_list_find_record_by_key(&ctx->flow_record_list_array[flow_key_hash(&twin)], &twin);

    } else {
        return flow_record_list_find_twin_by_key(&ctx->flow_record_list_array[flow_key_hash(key)], key);
    }
}

/**
 * \brief Unit test for the flow_record list functionality.
 *
 * \param none
 *
 * \return Number of failures
 */
static int p2f_test_flow_record_list(joy_ctx_data *ctx) {
    flow_record_list list = NULL;
    flow_record_t a, b, c, d;
    flow_record_t *rp;
    flow_key_t k1 = { { 0xcafe }, { 0xbabe }, 0xfa, 0xce, 0xdd };
    flow_key_t k2 = { { 0xdead }, { 0xbeef }, 0xfa, 0xce, 0xdd };
    int num_fails = 0;

    flow_record_init(ctx, &a, &k1);
    flow_record_init(ctx, &b, &k2);
    flow_record_init(ctx, &c, &k1);
    flow_record_init(ctx, &d, &k1);

    flow_record_list_prepend(&list, &a);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (!rp) {
        joy_log_err("did not find a");
        num_fails++;
    }

    flow_record_list_remove(&list, &a);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (rp) {
        joy_log_err("found a, but should not have");
        num_fails++;
    }

    flow_record_list_prepend(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (!rp) {
        joy_log_err("did not find b");
        num_fails++;
    }

    flow_record_list_remove(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (rp) {
        joy_log_err("found b, but should not have");
        num_fails++;
    }

    flow_record_list_prepend(&list, &a);
    flow_record_list_prepend(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (!rp) {
        joy_log_err("did not find a");
        num_fails++;
    }

    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (!rp) {
        joy_log_err("did not find b");
        num_fails++;
    }

    flow_record_list_remove(&list, &a);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (rp) {
        joy_log_err("found a, but should not have");
        num_fails++;
    }

    flow_record_list_remove(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (rp) {
        joy_log_err("found a, but should not have");
        num_fails++;
    }

    flow_record_list_prepend(&list, &a);
    flow_record_list_prepend(&list, &c);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (!rp) {
        joy_log_err("did not find a");
        num_fails++;
    }

    return num_fails;
}

void p2f_unit_test() {
    int num_fails = 0;
    joy_ctx_data *main_ctx = NULL;
    
    main_ctx = calloc(1, sizeof(joy_ctx_data));
    if (!main_ctx) {
        fprintf(info, "Out of memory\n");
        return;
    }

    fprintf(info, "\n******************************\n");
    fprintf(info, "P2F Unit Test starting...\n");

    num_fails += p2f_test_flow_record_list(main_ctx);

    if (num_fails) {
        fprintf(info, "Finished - failures: %d\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
    free(main_ctx);
    main_ctx = NULL;
}

/*********************************************************
 * -------------------------------------------------------
 * Uploader functions
 * -------------------------------------------------------
 *********************************************************
 */

/** maxiumum lengnth of the upload URL string */
#define MAX_UPLOAD_CMD_LENGTH 512

/** maximum length of the upload file name */
#define MAX_FILENAME_LENGTH 1024

/** thread mutex for locking */
pthread_mutex_t upload_in_process = PTHREAD_MUTEX_INITIALIZER;

/** thread condition to wait for */
pthread_cond_t upload_run_cond = PTHREAD_COND_INITIALIZER;

/** thread signal for execution */
int upload_can_run = 0;

/** filename to be uploaded */
char upload_filename[MAX_FILENAME_LENGTH];

static int uploader_send_file (char *filename, const char *servername,
                               const char *key, unsigned int retain) {
    int rc = 0;
    char cmd[MAX_UPLOAD_CMD_LENGTH];

    snprintf(cmd,MAX_UPLOAD_CMD_LENGTH,"scp -q -C -i %s %s %s",key,filename,servername);
    rc = system(cmd);

    /* see if the command was successful */
    if (rc == 0) {
       joy_log_info("transfer of file [%s] successful!", filename);
       /* see if we are allowed to delete the file after upload */
       if (retain == 0) {
            snprintf(cmd, MAX_UPLOAD_CMD_LENGTH, "rm %s", filename);
            joy_log_info("removing file [%s]", filename);
 	    rc = remove(filename);
            if (rc != 0) {
                joy_log_err("removing file [%s] failed!", filename);
            }
        }
    } else {
        joy_log_warn("transfer of file [%s] failed!", filename);
    }

    return 0;
}

/**
 * \fn void *uploader_main (void *ptr)
 * \brief Runs as a thread off of joy.
 *        Uploader is only active during live processing runs.
 *        Uploader terminates automatically when joy exits due to the nature of
 *        how pthreads work.
 * \param ptr always a pointer to the config structure
 * \return never return and the thread terminates when joy exits
 */
#ifdef WIN32
__declspec(noreturn) void *uploader_main(void *ptr)
#else
__attribute__((__noreturn__)) void *uploader_main(void *ptr)
#endif
{
    struct configuration *config = ptr;

    /* initialize the uploader filename container */
    memset(upload_filename, 0x00, MAX_FILENAME_LENGTH);

    /* uploader stays alive until joy exists */
    while (1) {

        /* wait until we are signaled to do work */
        pthread_mutex_lock(&upload_in_process);
        while (!upload_can_run) {
            joy_log_info("waiting on signal...");
            pthread_cond_wait(&upload_run_cond, &upload_in_process);
        }

        /* upload file now */
        if (strlen(upload_filename) > 0) {
            joy_log_info("uploading file [%s] ...", upload_filename);
            uploader_send_file(upload_filename, config->upload_servername,
                               config->upload_key, config->retain_local);
        }

        /* we are done uploading the file, go back to sleep */
        memset(upload_filename, 0x00, MAX_FILENAME_LENGTH);
        upload_can_run = 0;
        pthread_mutex_unlock(&upload_in_process);
    }
}

/*
 * file uploading after rotation
 */
/**
 * \fn int upload_file (char *filename
 * \brief upload file to the storage server
 * \param filename file to upload
 * \return failure/EXIT_FAILURE
 * \return 0 success
 */
int upload_file (char *filename) {

    /* sanity check we were passed in a file to upload */
    if (filename == NULL) {
        joy_log_err("could not upload file (output file not set)");
        return failure;
    }

    /* wake up the uploader thread so it can do its work */
    pthread_mutex_lock(&upload_in_process);
    memcpy(upload_filename, filename, (MAX_FILENAME_LENGTH-1));
    upload_can_run = 1;
    pthread_cond_signal(&upload_run_cond);
    pthread_mutex_unlock(&upload_in_process);

    return 0;
}

