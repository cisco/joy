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
#include "ip_id.h" // Because Windows!
#include "ipfix.h" /* ipfix protocol */
#include "err.h" /* errors and logging */
#include "osdetect.h"
#include "utils.h"

/*
 *  global variables
 */

/*
 * The VERSION variable should be set by a compiler directive, based
 * on the file with the same name.  This value is reported in the
 * "metadata" object in JSON output.
 */
#ifndef VERSION
# define VERSION "unknown"
#endif

/*
 * configuration state
 */
define_all_features_config_uint(feature_list);

unsigned int bidir = 0;

unsigned int include_zeroes = 0;

unsigned int include_retrans = 0;

unsigned int byte_distribution = 0;

char *compact_byte_distribution = NULL;

unsigned int report_entropy = 0;

unsigned int report_idp = 0;

unsigned int report_hd = 0;

unsigned int include_classifier = 0;

unsigned int nfv9_capture_port = 0;

unsigned int ipfix_collect_port = 0;

unsigned int ipfix_collect_online = 0;

unsigned int ipfix_export_port = 0;

unsigned int ipfix_export_remote_port = 0;

unsigned int preemptive_timeout = 0;

char *ipfix_export_remote_host = NULL;

char *ipfix_export_template = NULL;

char *aux_resource_path = NULL;

zfile output = NULL;

FILE *info = NULL;

unsigned int records_in_file = 0;

unsigned int verbosity = 0;

unsigned short compact_bd_mapping[16];

radix_trie_t rt = NULL;

enum SALT_algorithm salt_algo = raw;

/*
 * config is the global configuration
 */
struct configuration config = { 0, };

/*
 * by default, we use a 10-second flow inactivity timeout window
 * and a 20-second activity timeout; the active_timeout represents
 * the difference between those two times
 */
#define T_WINDOW 10
#define T_ACTIVE 20

struct timeval global_time = {0, 0};

struct timeval time_window = { T_WINDOW, 0 };

struct timeval active_timeout = { T_ACTIVE, 0 };

unsigned int active_max = (T_WINDOW + T_ACTIVE);

int include_os = 1;

#define expiration_type_reserved 'z'
#define expiration_type_active  'a'
#define expiration_type_inactive 'i'

#define flow_key_hash_mask 0x000fffff

#define FLOW_RECORD_LIST_LEN (flow_key_hash_mask + 1)

flow_record_list flow_record_list_array[FLOW_RECORD_LIST_LEN] = { 0, };

enum twins_match {
    exact = 0,
    near_match = 1,
};

struct flocap_stats stats = {  0, 0, 0, 0 };
struct flocap_stats last_stats = { 0, 0, 0, 0 };
struct timeval last_stats_output_time;

unsigned int num_pkt_len = NUM_PKT_LEN;

/*
 * Local prototypes
 */
static void flow_record_delete(struct flow_record *r);
static void flow_record_print_and_delete(struct flow_record *record);

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
void flocap_stats_output (FILE *f) {
    char time_str[128];
    struct timeval now, tmp;
    float bps, pps, rps, seconds;

#ifdef WIN32
	time_t win_now;
	win_now = time(NULL);
#endif

	gettimeofday(&now, NULL);
	memset(time_str, 0x00, sizeof(time_str));

	joy_timer_sub(&now, &last_stats_output_time, &tmp);
    seconds = (float) joy_timeval_to_milliseconds(tmp) / 1000.0;

    bps = (float) (stats.num_bytes - last_stats.num_bytes) / seconds;
    pps = (float) (stats.num_packets - last_stats.num_packets) / seconds;
    rps = (float) (stats.num_records_output - last_stats.num_records_output) / seconds;

#ifdef WIN32
	strftime(time_str, sizeof(time_str) - 1, "%a %b %d %H:%M:%S %Z %Y", localtime(&win_now));
#else
	strftime(time_str, sizeof(time_str) - 1, "%a %b %d %H:%M:%S %Z %Y", localtime(&now.tv_sec));
#endif
    fprintf(f, "%s info: %lu packets, %lu active records, %lu records output, %lu alloc fails, %.4e bytes/sec, %.4e packets/sec, %.4e records/sec\n",
	      time_str, stats.num_packets, stats.num_records_in_table, stats.num_records_output, stats.malloc_fail, bps, pps, rps);
    fflush(f);

    last_stats_output_time = now;
    last_stats = stats;
}

/**
 * \brief Initialize the flow capture statistics timer.
 * \param none
 * \return none
 */
void flocap_stats_timer_init () {
    struct timeval now;

#ifdef WIN32
	DWORD t;
	t = timeGetTime();
	now.tv_sec = t / 1000;
	now.tv_usec = t % 1000;
#else
	gettimeofday(&now, NULL);
#endif
    last_stats_output_time = now;
}

/**
 * \brief Calculate the hash of a given flow_key.
 * \param f The flow_key to hash
 * \return Hash of \p f
 */
static unsigned int flow_key_hash (const struct flow_key *f) {

    if (config.flow_key_match_method == exact) {
          return (((unsigned int)f->sa.s_addr * 0xef6e15aa)
	    ^ ((unsigned int)f->da.s_addr * 0x65cd52a0)
	    ^ ((unsigned int)f->sp * 0x8216)
	    ^ ((unsigned int)f->dp * 0xdda37)
	    ^ ((unsigned int)f->prot * 0xbc06)) & flow_key_hash_mask;

    } else {  /* flow_key_match_method == near_match */
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

/* Flow record list chronological head and tail */
static struct flow_record *flow_record_chrono_first = NULL;
static struct flow_record *flow_record_chrono_last = NULL;

/**
 * \brief Initialize the flow_record_list.
 * \param none
 * \param return
 */
void flow_record_list_init () {
    unsigned int i;

    flow_record_chrono_first = flow_record_chrono_last = NULL;
    for (i=0; i<FLOW_RECORD_LIST_LEN; i++) {
        flow_record_list_array[i] = NULL;
    }
}

/**
 * \brief Free up all flow_records within the flow_record_list.
 * \param none
 * \return none
 */
void flow_record_list_free () {
    struct flow_record *record, *tmp;
    unsigned int i, count = 0;

    for (i=0; i<FLOW_RECORD_LIST_LEN; i++) {
        record = flow_record_list_array[i];
        while (record != NULL) {
            tmp = record->next;
            flow_record_delete(record);
            record = tmp;
            count++;
        }
        flow_record_list_array[i] = NULL;
    }
    flow_record_chrono_first = NULL;
    flow_record_chrono_last = NULL;
}

/**
 * \brief Compare two flow_keys to see if they are equal.
 * \param a The first flow_key
 * \param b The second flow_key
 * \return 0 for equality, 1 for not
 */
static int flow_key_is_eq (const struct flow_key *a,
                           const struct flow_key *b) {
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
static int flow_key_is_twin (const struct flow_key *a,
                             const struct flow_key *b) {
    if (config.flow_key_match_method == near_match) {
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
static void flow_key_copy (struct flow_key *dst, const struct flow_key *src) {
    dst->sa.s_addr = src->sa.s_addr;
    dst->da.s_addr = src->da.s_addr;
    dst->sp = src->sp;
    dst->dp = src->dp;
    dst->prot = src->prot;
}

#define MAX_TTL 255

struct flow_record *flow_key_get_twin(const struct flow_key *key);

/**
 * \brief Initialize a flow_record.
 * \param[out] record Flow record
 * \param[in] Flow key to be used for identifiying the record
 * \return none
 */
static void flow_record_init (struct flow_record *record,
                              const struct flow_key *key) {

    /* Increment the stats flow record count */
    flocap_stats_incr_records_in_table();

    /* Zero out the flow_record structure */
    memset(record, 0, sizeof(struct flow_record));

    /* Set the flow_key and TTL */
    flow_key_copy(&record->key, key);
    record->ttl = MAX_TTL;
}

/**
 * \brief Check if the flow record is in chrono list.
 * \param record Flow_record
 * \return Valid pointer if in list, NULL otherwise
 */
static inline unsigned int flow_record_is_in_chrono_list (const struct flow_record *record) {
    return record->time_next || record->time_prev;
}

/**
 * \brief Find the flow record in list, if it exists.
 * \param list The list of flow_records to search
 * \param key The flow_key used to identify the flow_record
 * \return Valid flow_record or NULL
 */
static struct flow_record *flow_record_list_find_record_by_key (const flow_record_list *list,
                                                                const struct flow_key *key) {
    struct flow_record *record = *list;

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
static struct flow_record *flow_record_list_find_twin_by_key (const flow_record_list *list,
                                                              const struct flow_key *key) {
    struct flow_record *record = *list;

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
                                      struct flow_record *record) {
    struct flow_record *tmp;

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
                                             struct flow_record *r) {

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
static void flow_record_chrono_list_append (struct flow_record *record) {
    extern struct flow_record *flow_record_chrono_first;
    extern struct flow_record *flow_record_chrono_last;

    if (flow_record_chrono_first == NULL) {
        flow_record_chrono_first = record;
        flow_record_chrono_last = record;
    } else {
        flow_record_chrono_last->time_next = record;
        record->time_prev = flow_record_chrono_last;
        flow_record_chrono_last = record;
    }
}

/**
 * \brief Remove a flow record from the chrono list.
 * \param record The flow_record that will be removed from the list
 * \return none
 */
static void flow_record_chrono_list_remove (struct flow_record *record) {
    extern struct flow_record *flow_record_chrono_first;
    extern struct flow_record *flow_record_chrono_last;

    if (record == NULL) {
        return;
    }

    if (record == flow_record_chrono_first) {
        flow_record_chrono_first = record->time_next;
    }
    if (record == flow_record_chrono_last) {
        flow_record_chrono_last = record->time_prev;
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
static int flow_record_is_active_expired(struct flow_record *record,
                                         const struct pcap_pkthdr *header) {
    if (header) {
        /*
         * Preemptive Timeout
         * Check the new incoming packet to see if it will expire the record
         */
        if (header->ts.tv_sec > (record->start.tv_sec + active_max) && preemptive_timeout) {
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
static unsigned int flow_record_is_expired(struct flow_record *record) {
    struct timeval inactive_cutoff;
    struct timeval active_cutoff;

    joy_timer_sub(&global_time, &time_window, &inactive_cutoff);
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
struct flow_record *flow_key_get_record (const struct flow_key *key,
                                         unsigned int create_new_records,
                                         const struct pcap_pkthdr *header) {
    struct flow_record *record;
    unsigned int hash_key;

    /* Find a record matching the flow key, if it exists */
    hash_key = flow_key_hash(key);
    record = flow_record_list_find_record_by_key(&flow_record_list_array[hash_key], key);

    if (record != NULL) {
       if (create_new_records && flow_record_is_in_chrono_list(record)
           && flow_record_is_active_expired(record, header)) {
            /*
             *  Active-timeout exceeded for this flow_record; print and delete
             *  it, then set record = NULL to cause the creation of a new
             *  flow_record to be used in further packet processing
             */
           flow_record_print_and_delete(record);
           record = NULL;
       } else {
           return record;
       }
    }

    /* if we get here, then record == NULL  */

    if (create_new_records) {

        /* allocate and initialize a new flow record */
        record = malloc(sizeof(struct flow_record));
        debug_printf("LIST record %p allocated\n", record);

        if (record == NULL) {
            joy_log_warn("could not allocate memory for flow_record");
            flocap_stats_incr_malloc_fail();
            return NULL;
        }

        flow_record_init(record, key);

        /* enter record into flow_record_list */
        flow_record_list_prepend(&flow_record_list_array[hash_key], record);

        /*
         * if we are tracking bidirectional flows, and if record has a
         * twin, then set both twin pointers; otherwise, enter the
         * record into the chronological list
         */
        if (bidir) {
            record->twin = flow_key_get_twin(key);
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
	        flow_record_chrono_list_append(record);
            } else {
	        record->twin->twin = record;
            }
        } else {

            /* this flow has no twin, so add it to chronological list */
            flow_record_chrono_list_append(record);
        }
    }

    return record;
}

/**
 * \brief Delete a flow record.
 * \param r The flow_record to delete
 * \return none
 */
static void flow_record_delete (struct flow_record *r) {

    if (flow_record_list_remove(&flow_record_list_array[flow_key_hash(&r->key)], r) != 0) {
        joy_log_err("problem removing flow record %p from list", r);
        return;
    }

    flocap_stats_decr_records_in_table();

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
    memset(r, 0, sizeof(struct flow_record));
    free(r);
}

/**
* \fn int flow_key_set_process_info (const struct flow_key *key, const struct host_flow *data)
* \param key flow key structure
* \param data process flow information
* \return failure
* \return ok
*/
int flow_key_set_process_info(const struct flow_key *key, const struct host_flow *data) {
	struct flow_record *r;

	if (data->exe_name == NULL) {
		return failure;   /* no point in looking for flow_record */
	}
	r = flow_key_get_record(key, DONT_CREATE_RECORDS, NULL);
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
void flow_record_update_byte_count (struct flow_record *f, const void *x, unsigned int len) {
    const unsigned char *data = x;
    int i;

    if (byte_distribution || report_entropy) {
        for (i=0; i<len; i++) {
            f->byte_count[data[i]]++;
        }
    }

    /*
     * implementation note: overflow might occur in the byte_count
     * array; if the integer type for that array is small, then we
     * should check for overflow and rebalance the array as needed
     */

}

/**
 * \brief Update the compact byte count for the flow record.
 * \param f Flow record
 * \param x Data to use for update
 * \param len Length of the data (in bytes)
 * \return none
 */
void flow_record_update_compact_byte_count (struct flow_record *f, const void *x, unsigned int len) {
    const unsigned char *data = x;
    int i;

    if (compact_byte_distribution) {
        for (i=0; i<len; i++) {
            f->compact_byte_count[compact_bd_mapping[data[i]]]++;
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
void flow_record_update_byte_dist_mean_var (struct flow_record *f, const void *x, unsigned int len) {
    const unsigned char *data = x;
    double delta;
    int i;

    if (byte_distribution || report_entropy) {
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

static void print_bytes_dir_time (unsigned short int pkt_len,
                                  char *dir,
                                  struct timeval ts,
                                  char *term) {
    if (pkt_len < 32768) {
        zprintf(output, "{\"b\":%u,\"dir\":\"%s\",\"ipt\":%u}%s",
	            pkt_len, dir, joy_timeval_to_milliseconds(ts), term);
    } else {
        zprintf(output, "{\"rep\":%u,\"dir\":\"%s\",\"ipt\":%u}%s",
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
    int i = 0;

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

#define OUT "<"
#define IN  ">"

/**
 * \brief Print a flow record to the JSON output.
 *
 * \param record Flow record to print
 *
 * \return none
 */
static void flow_record_print_json (const struct flow_record *record) {
    unsigned int i, j, imax, jmax;
    struct timeval ts, ts_last, ts_start, ts_end, tmp;
    const struct flow_record *rec;
    unsigned int pkt_len;
    char *dir;

    flocap_stats_incr_records_output();
    records_in_file++;

    if (record->twin != NULL) {
        // Use the smaller of the 2 time values
        if (joy_timer_lt(&record->start, &record->twin->start)) {
            ts_start = record->start;
            rec = record;
        } else {
            ts_start = record->twin->start;
            rec = record->twin;
        }
        // Use the larger of the 2 time values
        if (joy_timer_lt(&record->end, &record->twin->end)) {
            ts_end = record->twin->end;
        } else {
            ts_end = record->end;
        }
    } else {
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
    zprintf(output, "{");

    /*****************************************************************
     * IP object start
     *****************************************************************
     */
    zprintf(output, "\"ip\":{");
    if (ipv4_addr_needs_anonymization(&rec->key.sa)) {
        zprintf(output, "\"sa\":\"%s\"", addr_get_anon_hexstring(&rec->key.sa));
    } else {
        zprintf(output, "\"sa\":\"%s\"", inet_ntoa(rec->key.sa));
    }
    if (ipv4_addr_needs_anonymization(&rec->key.da)) {
        zprintf(output, ",\"da\":\"%s\"", addr_get_anon_hexstring(&rec->key.da));
    } else {
        zprintf(output, ",\"da\":\"%s\"", inet_ntoa(rec->key.da));
    }
    zprintf(output, ",\"pr\":%u", rec->key.prot);
    zprintf(output, ",\"sp\":%u", rec->key.sp);
    zprintf(output, ",\"dp\":%u", rec->key.dp);
    zprintf(output, "},");
    /*****************************************************************
     * IP object end
     *****************************************************************
     */

    /*
     * if src or dst address matches a subnets associated with labels,
     * then print out those labels
     */
    if (config.num_subnets) {
        attr_flags flag;

        flag = radix_trie_lookup_addr(rt, rec->key.sa);
        attr_flags_json_print_labels(rt, flag, "sa_labels", output);
        flag = radix_trie_lookup_addr(rt, rec->key.da);
        attr_flags_json_print_labels(rt, flag, "da_labels", output);
    }

    /*
     * Flow stats
     */
    zprintf(output, "\"ob\":%u,", rec->ob);
    zprintf(output, "\"opk\":%u,", rec->np); /* not just packets with data */
    if (rec->twin != NULL) {
        zprintf(output, "\"ib\":%u,", rec->twin->ob);
        zprintf(output, "\"ipk\":%u,", rec->twin->np);
    }
#ifdef WIN32
	zprintf(output, "\"ts\":%i.%06i,", ts_start.tv_sec, ts_start.tv_usec);
	zprintf(output, "\"te\":%i.%06i,", ts_end.tv_sec, ts_end.tv_usec);
#else
    zprintf(output, "\"ts\":%zd.%06zd,", ts_start.tv_sec, ts_start.tv_usec);
    zprintf(output, "\"te\":%zd.%06zd,", ts_end.tv_sec, ts_end.tv_usec);
#endif
	zprintf(output, "\"ottl\":%u,", rec->ttl);
    if (rec->twin != NULL) {
        zprintf(output, "\"ittl\":%u,", rec->twin->ttl);
    }

    if (rec->initial_seq) {
        zprintf(output, "\"initial_seq\":%u,", rec->initial_seq);
    }
    if (rec->twin != NULL) {
        if (!rec->initial_seq && rec->twin->initial_seq) {
            zprintf(output, "\"initial_seq\":%u,", rec->twin->initial_seq);
        }
    }

    if (rec->tcp_initial_window_size) {
        zprintf(output, "\"otcp_win\":%u,", rec->tcp_initial_window_size);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_initial_window_size) {
            zprintf(output, "\"itcp_win\":%u,", rec->twin->tcp_initial_window_size);
        }
    }

    if (rec->tcp_syn_size) {
        zprintf(output, "\"otcp_syn\":%u,", rec->tcp_syn_size);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_syn_size) {
            zprintf(output, "\"itcp_syn\":%u,", rec->twin->tcp_syn_size);
        }
    }

    /*****************************************************************
     * Packet length and time array
     *****************************************************************
     */
    zprintf(output, "\"packets\":[");

    if (rec->twin == NULL) {

        imax = rec->op > num_pkt_len ? num_pkt_len : rec->op;
        if (imax == 0) {
            ; /* no packets had data, so we print out nothing */
        } else {
            for (i = 0; i < imax-1; i++) {
                if (i > 0) {
                    joy_timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
                } else {
                    joy_timer_clear(&ts);
                }
                print_bytes_dir_time(rec->pkt_len[i], OUT, ts, ",");
            }
            if (i == 0) {        /* TODO this code could be simplified */
                joy_timer_clear(&ts);
            } else {
                joy_timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
            }
            print_bytes_dir_time(rec->pkt_len[i], OUT, ts, "");
        }
        zprintf(output, "]");
    } else {
        imax = rec->op > num_pkt_len ? num_pkt_len : rec->op;
        jmax = rec->twin->op > num_pkt_len ? num_pkt_len : rec->twin->op;
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

            joy_timer_sub(&ts, &ts_last, &tmp);
            print_bytes_dir_time(pkt_len, dir, tmp, "");
            ts_last = ts;

            if (!((i == imax) & (j == jmax))) {
                /* Done */
                zprintf(output, ",");
            }
        }
        zprintf(output, "]");
    }

    if (byte_distribution || report_entropy || compact_byte_distribution) {
        const unsigned int *array;
        const unsigned int *compact_array;
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
            compact_array = rec->compact_byte_count;
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

        if (byte_distribution) {
            reduce_bd_bits(tmp, 256);
            array = tmp;

            zprintf(output, ",\"bd\":[");
            for (i = 0; i < 255; i++) {
                zprintf(output, "%u,", (unsigned char)array[i]);
            }
            zprintf(output, "%u]", (unsigned char)array[i]);

            /* Output the mean */
            if (num_bytes != 0) {
                zprintf(output, ",\"bd_mean\":%f", mean);
                zprintf(output, ",\"bd_std\":%f", variance);
            }

        }

        if (compact_byte_distribution) {
            reduce_bd_bits(compact_tmp, 16);
            compact_array = compact_tmp;

            zprintf(output, ",\"compact_bd\":[");
            for (i = 0; i < 15; i++) {
                zprintf(output, "%u,", (unsigned char)compact_array[i]);
            }
            zprintf(output, "%u]", (unsigned char)compact_array[i]);
        }

        if (report_entropy) {
            if (num_bytes != 0) {
                double entropy = flow_record_get_byte_count_entropy(array, num_bytes);

                zprintf(output, ",\"be\":%f", entropy);
                zprintf(output, ",\"tbe\":%f", entropy * num_bytes);
            }
        }
    }

    /*
     * Inline classification of flows
     */
    if (include_classifier) {
        float score = 0.0;

        if (rec->twin) {
            score = classify(rec->pkt_len, rec->pkt_time, rec->twin->pkt_len, rec->twin->pkt_time,
		                     rec->start, rec->twin->start,
		                     NUM_PKT_LEN, rec->key.sp, rec->key.dp, rec->np, rec->twin->np, rec->op, rec->twin->op,
		                     rec->ob, rec->twin->ob, byte_distribution,
		                     rec->byte_count, rec->twin->byte_count);
        } else {
            score = classify(rec->pkt_len, rec->pkt_time, NULL, NULL,	rec->start, rec->start,
		                     NUM_PKT_LEN, rec->key.sp, rec->key.dp, rec->np, 0, rec->op, 0,
		                     rec->ob, 0, byte_distribution,
		                     rec->byte_count, NULL);
        }

        zprintf(output, ",\"p_malware\":%f", score);
    }

    /*
     * All of the feature modules
     */
    print_all_features(feature_list);

    if (report_hd) {
        /*
         * TODO: this should be bidirectional, but it is not!  This will
         * be changed sometime soon, but for now, this will give some
         * experience with this type of data
         */
        header_description_printf(&rec->hd, output, report_hd);
    }

    /*
     * Operating system
     */
    if (include_os) {

        if (rec->twin) {
            os_printf(output, rec->ttl, rec->tcp_initial_window_size, rec->twin->ttl, rec->twin->tcp_initial_window_size);
        } else {
            os_printf(output, rec->ttl, rec->tcp_initial_window_size, 0, 0);
        }
    }

    /*
     * Initial data packet (IDP)
     */
    if (report_idp) {
        if (rec->idp != NULL) {
            zprintf(output, ",\"oidp\":");
            zprintf_raw_as_hex(output, rec->idp, rec->idp_len);
            zprintf(output, ",\"oidp_len\":%u", rec->idp_len);
        }
        if (rec->twin && (rec->twin->idp != NULL)) {
            zprintf(output, ",\"iidp\":");
            zprintf_raw_as_hex(output, rec->twin->idp, rec->twin->idp_len);
            zprintf(output, ",\"iidp_len\":%u", rec->twin->idp_len);
        }
    }

    {
        unsigned int retrans, invalid;

        retrans = rec->retrans;
        invalid = rec->invalid;
        if (rec->twin) {
            retrans += rec->twin->retrans;
            invalid += rec->twin->invalid;
        }
        if (retrans) {
            zprintf(output, ",\"rtn\":%u", retrans);
        }
        if (invalid) {
            zprintf(output, ",\"inv\":%u", invalid);
        }

    }

    if (rec->exe_name) {
        zprintf(output, ",\"exe\":\"%s\"", rec->exe_name);
    }

    if (rec->full_path) {
        zprintf(output, ",\"path\":\"%s\"", rec->full_path);
    }

    if (rec->file_version) {
        zprintf(output, ",\"fileVer\":\"%s\"", rec->file_version);
    }

    if (rec->file_hash) {
        zprintf(output, ",\"fileHash\":\"%s\"", rec->file_hash);
    }

    if (rec->exp_type) {
        zprintf(output, ",\"x\":\"%c\"", rec->exp_type);
    }

    /*****************************************************************
     * Flow Record object end
     *****************************************************************
     */
    zprintf(output, "}\n");
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
static void flow_record_print_and_delete (struct flow_record *record) {
    /*
     * Print the record to JSON output
     */
    flow_record_print_json(record);

    /*
     * Export this record before deletion if running in
     * IPFIX exporter mode.
     */
    if (ipfix_export_port) {
        ipfix_export_main(record);
    }

    /* 
     * Delete twin, if there is one
     */
    if (record->twin != NULL) {
        debug_printf("LIST deleting twin\n");
        flow_record_delete(record->twin);
    }

    /* Remove record from chrono list, then delete from flow_record_list_array */
    flow_record_chrono_list_remove(record);
    flow_record_delete(record);
}

/**
 * \brief Prints out the flow record list in JSON format.
 *
 * \param print_all Flag whether to indiscriminately print all flow_records.
 *                  1 to print all of them, 0 to perform expiration check
 *
 * \return none
 */
void flow_record_list_print_json (unsigned int print_all) {
    struct flow_record *record = NULL;

    /* The head of chrono record list */
    record = flow_record_chrono_first;

    while (record != NULL) {
        if (!print_all) {
            /* Avoid printing flows that might still be active */
            if (!flow_record_is_expired(record)) {
                break;
            }
        }

        flow_record_print_and_delete(record);

        /* Advance to next record on chrono list */
        record = flow_record_chrono_first;
    }

    // note: we might need to call flush in the future
    // zflush(output);
}

/**
 * \brief Get the twin of a flow_key.
 *
 * \param key A flow_key that we will try to find it's twin
 *
 * \return The twin flow_key, or NULL
 */
struct flow_record *flow_key_get_twin (const struct flow_key *key) {
    if (config.flow_key_match_method == exact) {
        struct flow_key twin;

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

        return flow_record_list_find_record_by_key(&flow_record_list_array[flow_key_hash(&twin)], &twin);

    } else {
        return flow_record_list_find_twin_by_key(&flow_record_list_array[flow_key_hash(key)], key);
    }
}

/**
 * \brief Unit test for the flow_record list functionality.
 *
 * \param none
 *
 * \return Number of failures
 */
static int p2f_test_flow_record_list() {
    flow_record_list list = NULL;
    struct flow_record a, b, c, d;
    struct flow_record *rp;
    struct flow_key k1 = { { 0xcafe }, { 0xbabe }, 0xfa, 0xce, 0xdd };
    struct flow_key k2 = { { 0xdead }, { 0xbeef }, 0xfa, 0xce, 0xdd };
    int num_fails = 0;

    flow_record_init(&a, &k1);
    flow_record_init(&b, &k2);
    flow_record_init(&c, &k1);
    flow_record_init(&d, &k1);

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

    fprintf(info, "\n******************************\n");
    fprintf(info, "P2F Unit Test starting...\n");

    num_fails += p2f_test_flow_record_list();

    if (num_fails) {
        fprintf(info, "Finished - failures: %d\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
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

static int uploader_send_file (char *filename, char *servername,
                               char *key, unsigned int retain) {
    int rc = 0;
    char cmd[MAX_UPLOAD_CMD_LENGTH];

    snprintf(cmd,MAX_UPLOAD_CMD_LENGTH,"scp -q -C -i %s %s %s",key,filename,servername);
    rc = system(cmd);

    /* see if the command was successful */
    if (rc == 0) {
       joy_log_info("transfer of file [%s] successful!", filename);
       /* see if we are allowed to delete the file after upload */
       if (retain == 0) {
            snprintf(cmd, MAX_UPLOAD_CMD_LENGTH, "rm %s", "config.vars");
            joy_log_info("removing file [%s]", "config.vars");
            rc = system(cmd);
            if (rc != 0) {
                fprintf(info,"uploader: removing file [%s] failed!", "config.vars");
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
void *uploader_main(void *ptr)
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
    return NULL;
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

