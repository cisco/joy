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

#include <stdlib.h>   
#include <pthread.h>   
#include "pkt_proc.h" /* packet processing               */
#include "p2f.h"      /* pcap2flow data structures       */
#include "err.h"      /* error codes and error reporting */
#include "anon.h"     /* address anonymization           */
#include "tls.h"      /* TLS awareness                   */
#include "dns.h"      /* DNS awareness                   */
#include "classify.h" /* inline classification           */
#include "http.h"     /* http header data                */
#include "procwatch.h"  /* process to flow mapping       */
#include "radix_trie.h" /* trie for subnet labels        */
#include "config.h"     /* configuration                 */
#include "output.h"     /* compressed output             */


/* local prototypes */
static void flow_record_delete(struct flow_record *r);
static void flow_record_print_and_delete(struct flow_record *record);

#if 0
static void flow_key_print(const struct flow_key *key);
#endif


static inline unsigned int flow_record_is_in_chrono_list (const struct flow_record *record) {
    return record->time_next || record->time_prev;
}

#if 0
/*
 * for portability and static analysis, we define our own timer
 * comparison functions (rather than use non-standard
 * timercmp/timersub macros)
 */
static inline unsigned int timer_gt (const struct timeval *a, const struct timeval *b) {
    return (a->tv_sec == b->tv_sec) ? (a->tv_usec > b->tv_usec) : (a->tv_sec > b->tv_sec);
}
#endif

static inline unsigned int timer_lt (const struct timeval *a, const struct timeval *b) {
    return (a->tv_sec == b->tv_sec) ? (a->tv_usec < b->tv_usec) : (a->tv_sec < b->tv_sec);
}

/**
 * \fn void timer_sub (const struct timeval *a, const struct timeval *b, struct timeval *result)
 * \brief calculate the difference betwen two times (result = a - b)
 * \param a first time value
 * \param b second time value
 * \param result the result of the difference between the two time values
 * \return none
 */
void timer_sub (const struct timeval *a, const struct timeval *b, struct timeval *result)  {  
    result->tv_sec = a->tv_sec - b->tv_sec;        
    result->tv_usec = a->tv_usec - b->tv_usec;     
    if (result->tv_usec < 0) {                         
        --result->tv_sec;                                
        result->tv_usec += 1000000;                      
    }                                                    
}

static inline void timer_clear (struct timeval *a) { 
    a->tv_sec = a->tv_usec = 0; 
}


/*
 * The VERSION variable should be set by a compiler directive, based
 * on the file with the same name.  This value is reported in the
 * "metadata" object in JSON output.
 */

#ifndef VERSION
#define VERSION "unknown"
#endif

/*
 *  global variables
 */

radix_trie_t rt = NULL;

enum SALT_algorithm salt_algo = raw;

enum print_level output_level = none;

struct flocap_stats stats = {  0, 0, 0, 0 };
struct flocap_stats last_stats = { 0, 0, 0, 0 };
struct timeval last_stats_output_time;

unsigned int num_pkt_len = NUM_PKT_LEN;

#include "osdetect.h"


/* START flow monitoring */


static unsigned int timeval_to_milliseconds (struct timeval ts) {
    unsigned int result = ts.tv_usec / 1000 + ts.tv_sec * 1000;
    return result;
}

/**
 * \fn void flocap_stats_output (FILE *f)
 * \brief output the stats to the specified file
 * \param f the output file
 * \return none
 */
void flocap_stats_output (FILE *f) {
    char time_str[128];
    // time_t now = time(NULL);
    struct timeval now, tmp;
    float bps, pps, rps, seconds;

    gettimeofday(&now, NULL);
    timer_sub(&now, &last_stats_output_time, &tmp);
    seconds = (float) timeval_to_milliseconds(tmp) / 1000.0;
    bps = (float) (stats.num_bytes - last_stats.num_bytes) / seconds;
    pps = (float) (stats.num_packets - last_stats.num_packets) / seconds;
    rps = (float) (stats.num_records_output - last_stats.num_records_output) / seconds;

    strftime(time_str, sizeof(time_str)-1, "%a %b %2d %H:%M:%S %Z %Y", localtime(&now.tv_sec));
    fprintf(f, "%s info: %lu packets, %lu active records, %lu records output, %lu alloc fails, %.4e bytes/sec, %.4e packets/sec, %.4e records/sec\n", 
	      time_str, stats.num_packets, stats.num_records_in_table, stats.num_records_output, stats.malloc_fail, bps, pps, rps);
    fflush(f);

    last_stats_output_time = now;
    last_stats = stats;
}

/**
 * \fn void flocap_stats_timer_init ()
 * \brief initialize the statistics timer
 * \param none
 * \retrun none
 */
void flocap_stats_timer_init () {
    struct timeval now;

    gettimeofday(&now, NULL);
    last_stats_output_time = now;
}


/* configuration state */

define_all_features_config_uint(feature_list);

unsigned int bidir = 0;

unsigned int include_zeroes = 0;

unsigned int byte_distribution = 0;

char *compact_byte_distribution = NULL;

unsigned int report_entropy = 0;

unsigned int report_idp = 0;

unsigned int report_hd = 0;

// unsigned int report_dns = 0;

unsigned int include_tls = 0;

unsigned int include_classifier = 0;

unsigned int nfv9_capture_port = 0;

unsigned int ipfix_collect_port = 0;

unsigned int ipfix_collect_online = 0;

unsigned int ipfix_export_port = 0;

unsigned int ipfix_export_remote_port = 0;

char *ipfix_export_remote_host = NULL;

zfile output = NULL;

FILE *info = NULL;

unsigned int records_in_file = 0;

unsigned short compact_bd_mapping[16];

/*
 * config is the global configuration 
 */
struct configuration config = { 0, };


/*
 * by default, we use a 10-second flow inactivity timeout window
 * and a 30-second activity timeout; the active_timeout represents
 * the difference between those two times
 */
#define T_WINDOW 10
#define T_ACTIVE 20

struct timeval time_window = { T_WINDOW, 0 };

struct timeval active_timeout = { T_ACTIVE, 0 };

unsigned int active_max = (T_WINDOW + T_ACTIVE);

int include_os = 1;

#define expiration_type_reserved 'z'
#define expiration_type_active  'a'
#define expiration_type_inactive 'i'


#define flow_key_hash_mask 0x000fffff
// #define flow_key_hash_mask 0xff

#define FLOW_RECORD_LIST_LEN (flow_key_hash_mask + 1)

flow_record_list flow_record_list_array[FLOW_RECORD_LIST_LEN] = { 0, };

enum twins_match { exact = 0, near = 1 };

// enum twins_match flow_key_match_method = exact;

static unsigned int flow_key_hash (const struct flow_key *f) {

    if (config.flow_key_match_method == exact) {
          return (((unsigned int)f->sa.s_addr * 0xef6e15aa) 
	    ^ ((unsigned int)f->da.s_addr * 0x65cd52a0) 
	    ^ ((unsigned int)f->sp * 0x8216) 
	    ^ ((unsigned int)f->dp * 0xdda37) 
	    ^ ((unsigned int)f->prot * 0xbc06)) & flow_key_hash_mask;

    } else {  /* flow_key_match_method == near */
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

struct flow_record *flow_record_chrono_first = NULL;
struct flow_record *flow_record_chrono_last = NULL;

/**
 * \fn void flow_record_list_init ()
 * \brief initialize a flow record list
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
 * \fn void flow_record_list_free ()
 * \brief free up the flow records
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
            // fprintf(stderr, "freeing record %p\n", record);
            flow_record_delete(record);
            record = tmp;
            count++;
        }
        flow_record_list_array[i] = NULL;
    }
    flow_record_chrono_first = NULL;
    flow_record_chrono_last = NULL;

    // fprintf(output, "freed %u flow records\n", count);
}


static int flow_key_is_eq (const struct flow_key *a, const struct flow_key *b) {
    //return (memcmp(a, b, sizeof(struct flow_key)));
    // more robust way of checking keys are equal
    //   0: flow keys are equal
    //   1: flow keys are not equal
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

    // match was found
    return 0;
}

static int flow_key_is_twin (const struct flow_key *a, const struct flow_key *b) {
    //return (memcmp(a, b, sizeof(struct flow_key)));
    // more robust way of checking keys are equal
    //   0: flow keys are equal
    //   1: flow keys are not equal
    if (config.flow_key_match_method == near) {
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
         * require that both addresses match, that is, (sa, da) == (da, sa)
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

    // match was found
    return 0;
}

static void flow_key_copy (struct flow_key *dst, const struct flow_key *src) {
    dst->sa.s_addr = src->sa.s_addr;
    dst->da.s_addr = src->da.s_addr;
    dst->sp = src->sp;
    dst->dp = src->dp;
    dst->prot = src->prot;
}

#define MAX_TTL 255

struct flow_record *flow_key_get_twin(const struct flow_key *key);

/** flow record initialization routine */
static void flow_record_init (/* @out@ */ struct flow_record *record, 
		              /* @in@  */ const struct flow_key *key) {

    flocap_stats_incr_records_in_table();
 
    flow_key_copy(&record->key, key); 
    record->np = 0;
    record->op = 0;
    record->ob = 0;
    record->num_bytes = 0;
    record->bd_mean = 0.0;
    record->bd_variance = 0.0;
    record->initial_seq = 0;
    record->seq = 0;
    record->ack = 0;
    record->invalid = 0;
    record->retrans = 0;
    record->ttl = MAX_TTL;
    timer_clear(&record->start);
    timer_clear(&record->end);
    record->last_pkt_len = 0;
    memset(record->byte_count, 0, sizeof(record->byte_count));
    memset(record->compact_byte_count, 0, sizeof(record->compact_byte_count));
    memset(record->pkt_len, 0, sizeof(record->pkt_len));
    memset(record->pkt_time, 0, sizeof(record->pkt_time));
    memset(record->pkt_flags, 0, sizeof(record->pkt_flags));
    record->exe_name = NULL;
    record->tcp_option_nop = 0;
    record->tcp_option_mss = 0;
    record->tcp_option_wscale = 0;
    record->tcp_option_sack = 0;
    record->tcp_option_fastopen = 0;
    record->tcp_option_tstamp = 0;
    record->tcp_initial_window_size = 0;
    record->tcp_syn_size = 0;
    //  memset(record->dns.dns_name, 0, sizeof(record->dns.dns_name));
    // dns_init(&record->dns);
    record->idp = NULL;
    record->idp_len = 0;
    record->exp_type = 0;
    record->first_switched_found = 0;
    record->next = NULL;
    record->prev = NULL;
    record->time_prev = NULL;
    record->time_next = NULL;
    record->twin = NULL;

    /* initialize TLS data */
    //tls_record_init(&record->tls_info);
    record->tls_info = NULL;

    http_init(&record->http_data);
    init_all_features(feature_list);

    header_description_init(&record->hd);

#ifdef END_TIME
    record->end_time_next = NULL;
    record->end_time_prev = NULL;
#endif
}

static struct flow_record *flow_record_list_find_record_by_key (const flow_record_list *list, 
    const struct flow_key *key) {
    struct flow_record *record = *list;

    /* find a record matching the flow key, if it exists */
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

static void flow_record_list_prepend (flow_record_list *head, struct flow_record *record) {
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


static unsigned int flow_record_list_remove (flow_record_list *head, struct flow_record *r) {
  
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

void flow_record_list_unit_test () {
    flow_record_list list;
    struct flow_record a, b, c, d;
    struct flow_record *rp;
    struct flow_key k1 = { { 0xcafe }, { 0xbabe }, 0xfa, 0xce, 0xdd };
    struct flow_key k2 = { { 0xdead }, { 0xbeef }, 0xfa, 0xce, 0xdd };

    flow_record_init(&a, &k1);
    flow_record_init(&b, &k2);
    flow_record_init(&c, &k1);
    flow_record_init(&d, &k1);

    list = NULL;  /* initialization */
    flow_record_list_prepend(&list, &a);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (rp) {
        printf("found a\n");
    } else {
        printf("error: did not find a\n");
    }
    flow_record_list_remove(&list, &a);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (!rp) {
        printf("didn't find a\n");
    } else {
        printf("error: found a, but should not have\n");
    }
    flow_record_list_prepend(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (rp) {
        printf("found b\n");
    } else {
        printf("error: did not find b\n");
    }
    flow_record_list_remove(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (!rp) {
        printf("didn't find b\n");
    } else {
        printf("error: found b, but should not have\n");
    }

    flow_record_list_prepend(&list, &a);
    flow_record_list_prepend(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (rp) {
        printf("found a\n");
    } else {
        printf("error: did not find a\n");
    }
    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (rp) {
        printf("found b\n");
    } else {
        printf("error: did not find b\n");
    }
    flow_record_list_remove(&list, &a);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (!rp) {
        printf("didn't find a\n");
    } else {
        printf("error: found a, but should not have\n");
    }
    flow_record_list_remove(&list, &b);
    rp = flow_record_list_find_record_by_key(&list, &k2);
    if (!rp) {
        printf("didn't find b\n");
    } else {
        printf("error: found a, but should not have\n");
    }

    flow_record_list_prepend(&list, &a);
    flow_record_list_prepend(&list, &c);
    rp = flow_record_list_find_record_by_key(&list, &k1);
    if (rp) {
        printf("found a\n");
    } else {
      printf("error: did not find a\n");
    }
  
}

static void flow_record_chrono_list_append (struct flow_record *record) {
    extern struct flow_record *flow_record_chrono_first;
    extern struct flow_record *flow_record_chrono_last;

    if (flow_record_chrono_first == NULL) {
        // fprintf(info, "CHRONO flow_record_chrono_first == NULL, setting to %p ------------------\n", record);
        flow_record_chrono_first = record;
        flow_record_chrono_last = record;
    } else {
        // fprintf(info, "CHRONO last == %p, setting to %p\n", flow_record_chrono_last, record);
        // fprintf(info, "CHRONO last->time_next == %p, setting to %p\n", flow_record_chrono_last->time_next, record);
        flow_record_chrono_last->time_next = record;
        record->time_prev = flow_record_chrono_last;
        flow_record_chrono_last = record;
        // fprintf(info, "CHRONO last->time_next == %p\n", flow_record_chrono_last->time_next);
    }
}

static void flow_record_chrono_list_remove (struct flow_record *record) {
    extern struct flow_record *flow_record_chrono_first;
    extern struct flow_record *flow_record_chrono_last;

    if (record == NULL) {
        return;   /* sanity check - don't ever go here */
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

static struct flow_record *flow_record_chrono_list_get_first () {
    return flow_record_chrono_first;
}

/*
 * flow_record_is_past_active_expiration(record) returns 1 if the age
 * of the flow record is greater than active_max, and returns 0 otherwise
 */
static unsigned int flow_record_is_past_active_expiration (const struct flow_record *record) {
    if (record->end.tv_sec > (record->start.tv_sec + active_max)) { 
        if ((record->twin == NULL) || (record->end.tv_sec > (record->twin->start.tv_sec + active_max))) {
            return 1;
        }
    }
    return 0;
}

/**
 * \fn struct flow_record *flow_key_get_record (const struct flow_key *key,       
    unsigned int create_new_records)
 * \param key
 * \param create_new_records
 * \return pointer to the flow record structure
 * \return NULL if expired or could not create or retireve record
 */
struct flow_record *flow_key_get_record (const struct flow_key *key, 
    unsigned int create_new_records) {
    struct flow_record *record;
    unsigned int hash_key;

    /* find a record matching the flow key, if it exists */
    hash_key = flow_key_hash(key);
    record = flow_record_list_find_record_by_key(&flow_record_list_array[hash_key], key);
    if (record != NULL) {
        if (create_new_records && flow_record_is_in_chrono_list(record) && flow_record_is_past_active_expiration(record)) {
            /* 
             *  active-timeout exceeded for this flow_record; print and delete
             *  it, then set record = NULL to cause the creation of a new
             *  flow_record to be used in further packet processing
             */
            // fprintf(output, "deleting active-expired record\n");
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
            fprintf(info, "warning: could not allocate memory for flow_record\n");
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

static void flow_record_delete (struct flow_record *r) {

    //  hash_key = flow_key_hash(&r->key);
    if (flow_record_list_remove(&flow_record_list_array[flow_key_hash(&r->key)], r) != 0) {
        fprintf(info, "warning: error removing flow record %p from list\n", r);
        return;
    }

    flocap_stats_decr_records_in_table();

    /*
     * free the memory allocated inside of flow record
     */
    // dns_delete(&r->dns);
    if (r->idp) {
        free(r->idp);
    }

    /* cleanup TLS info structure */
    if (r->tls_info != NULL) {
        tls_record_delete(r->tls_info);
        free(r->tls_info);
        r->tls_info = NULL;
    }

    http_delete(&r->http_data);

    if (r->exe_name) {
        free(r->exe_name);
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
 * \fn int flow_key_set_exe_name (const struct flow_key *key, const char *name)
 * \param key flow key structure
 * \param name executable name
 * \return failure
 * \return ok
 */
int flow_key_set_exe_name (const struct flow_key *key, const char *name) {
    struct flow_record *r;

    if (name == NULL) {
        return failure;   /* no point in looking for flow_record */
    }
    r = flow_key_get_record(key, DONT_CREATE_RECORDS);
    // flow_key_print(key);
    if (r) {
        if (r->exe_name == NULL) {
            r->exe_name = strdup(name);
            return ok;
        }
    }
    return failure;
}

/**
 * \fn void flow_record_update_byte_count (struct flow_record *f, const void *x, unsigned int len)
 * \brief update the byte count for the flow record
 * \param f flow record
 * \param x data to use for update
 * \param len length of the data
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
 * \fn void flow_record_update_compact_byte_count (struct flow_record *f, const void *x, unsigned int len)
 * \brief update the compact byte count for the flow record
 * \param f flow record
 * \param x data to use for update
 * \param len length of the data
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
 * \fn void flow_record_update_byte_dist_mean_var (struct flow_record *f, const void *x, unsigned int len)
 * \brief update the byte distribution mean for the flow record
 * \param f flow record
 * \param x data to use for update
 * \param len length of the data
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

#include <math.h>
#include <float.h>   /* for FLT_EPSILON */

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

#if 0
static void mem_print (const void *mem, unsigned int len) {
    const unsigned char *x = mem;

    while (len-- > 0) {
        zprintf(output, "%02x", *x++);
    }
    zprintf(output, "\n");
}
#endif

#if 0
static void flow_key_print (const struct flow_key *key) {
    debug_printf("flow key:\n");
    debug_printf("\tsa: %s\n", inet_ntoa(key->sa));
    debug_printf("\tda: %s\n", inet_ntoa(key->da));
    debug_printf("\tsp: %u\n", key->sp);
    debug_printf("\tdp: %u\n", key->dp);
    debug_printf("\tpr: %u\n", key->prot);
    mem_print(key, sizeof(struct flow_key));
}
#endif

#if 0
static void flow_record_print (const struct flow_record *record) {
    unsigned int i, imax;
    char addr_string[INET6_ADDRSTRLEN];

    zprintf(output, "flow record:\n");
    if (ipv4_addr_needs_anonymization(&record->key.sa)) {
        zprintf(output, "\tsa: %s\n", addr_get_anon_hexstring(&record->key.sa));
    } else {
        inet_ntop(AF_INET, &record->key.sa, addr_string, INET6_ADDRSTRLEN);
        zprintf(output, "\tsa: %s\n", addr_string);
    }
    if (ipv4_addr_needs_anonymization(&record->key.da)) {
        zprintf(output, "\tda: %s\n", addr_get_anon_hexstring(&record->key.da));
    } else {
        zprintf(output, "\tda: %s\n", inet_ntoa(record->key.da));
    }
    zprintf(output, "\tsp: %u\n", record->key.sp);
    zprintf(output, "\tdp: %u\n", record->key.dp);
    zprintf(output, "\tpr: %u\n", record->key.prot);
    zprintf(output, "\tob: %u\n", record->ob);
    zprintf(output, "\top: %u\n", record->np);  /* not just packets with data */
    zprintf(output, "\tttl: %u\n", record->ttl);  
    zprintf(output, "\tpkt_len: [ ");
    imax = record->op > num_pkt_len ? num_pkt_len : record->op;
    if (imax != 0) {
        for (i = 1; i < imax; i++) {
            zprintf(output, "%u, ", record->pkt_len[i-1]);
        }
        zprintf(output, "%u ", record->pkt_len[i-1]);
    }
    zprintf(output, "]\n");
    if (byte_distribution) {
        if (record->ob != 0) {
            zprintf(output, "\tbd: [ ");
            for (i = 0; i < 255; i++) {
	        zprintf(output, "%u, ", record->byte_count[i]);
            }
            zprintf(output, "%u ]\n", record->byte_count[i]);
        }
    }
    if (compact_byte_distribution) {
      if (record->ob != 0) {
          zprintf(output, "\tcompact_bd: [ ");
          for (i = 0; i < 15; i++) {
	      zprintf(output, "%u, ", record->compact_byte_count[i]);
          }
          zprintf(output, "%u ]\n", record->compact_byte_count[i]);
      }
    }
    if (report_entropy) {
        if (record->ob != 0) {
            zprintf(output, "\tbe: %f\n", 
               flow_record_get_byte_count_entropy(record->byte_count, record->ob));
        }
    }
}
#endif

static void print_bytes_dir_time (unsigned short int pkt_len, char *dir, struct timeval ts, char *term) {
    if (pkt_len < 32768) {
        zprintf(output, "{\"b\":%u,\"dir\":\"%s\",\"ipt\":%u}%s", 
	            pkt_len, dir, timeval_to_milliseconds(ts), term);
    } else {
        zprintf(output, "{\"rep\":%u,\"dir\":\"%s\",\"ipt\":%u}%s", 
	            65536-pkt_len, dir, timeval_to_milliseconds(ts), term);    
    }
}

#if 0
static void print_bytes_dir_time_type (unsigned short int pkt_len, 
    char *dir, struct timeval ts, struct tls_type_code type, char *term) {

    zprintf(output, "{\"b\":%u,\"dir\":\"%s\",\"ipt\":%u,\"tp\":\"%u:%u\"}%s", 
	        pkt_len, dir, timeval_to_milliseconds(ts), type.content, type.handshake, term);
}
#endif

#define OUT "<"
#define IN  ">"

#if 0
static void len_time_print_interleaved (unsigned int op, const unsigned short *len,
    const struct timeval *time, const struct tls_type_code *type,
    unsigned int op2, const unsigned short *len2, 
    const struct timeval *time2, const struct tls_type_code *type2) {

    unsigned int i, j, imax, jmax;
    struct timeval ts, ts_last, ts_start, tmp;
    unsigned int pkt_len;
    char *dir;
    struct tls_type_code typecode;

    //  zprintf(output, ",\n\t\t\t\"tls\": [\n");

    if (len2 == NULL) {
    
        ts_start = *time;

        imax = op > num_pkt_len ? num_pkt_len : op;
        if (imax == 0) { 
            ; /* no packets had data, so we print out nothing */
        } else {
            for (i = 0; i < imax-1; i++) {
	              if (i > 0) {
	                  timer_sub(&time[i], &time[i-1], &ts);
	              } else {
	                  timer_clear(&ts);
	              }
	              print_bytes_dir_time_type(len[i], OUT, ts, type[i], ",");
	              // zprintf(output, "\t\t\t\t{ \"b\": %u, \"dir\": \">\", \"ipt\": %u },\n", 
	              //    len[i], timeval_to_milliseconds(ts));
            }
            if (i == 0) {        /* this code could be simplified */ 	
	              timer_clear(&ts);  
            } else {
	              timer_sub(&time[i], &time[i-1], &ts);
            }
            print_bytes_dir_time_type(len[i], OUT, ts, type[i], "");
            // zprintf(output, "\t\t\t\t{ \"b\": %u, \"dir\": \">\", \"ipt\": %u }\n", 
            //    len[i], timeval_to_milliseconds(ts));
        }
        //    zprintf(output, "\t\t\t]"); 
    } else {

        if (timer_lt(time, time2)) {
            ts_start = *time;
        } else {
            ts_start = *time2;
        }

        imax = op > num_pkt_len ? num_pkt_len : op;
        jmax = op2 > num_pkt_len ? num_pkt_len : op2;
        i = j = 0;
        ts_last = ts_start;
        while ((i < imax) || (j < jmax)) {      

            if (i >= imax) {  /* record list is exhausted, so use twin */
	              dir = OUT;
	              ts = time2[j];
	              pkt_len = len2[j];
	              typecode = type2[j];
	              j++;
            } else if (j >= jmax) {  /* twin list is exhausted, so use record */
	              dir = IN;
	              ts = time[i];
	              pkt_len = len[i];
	              typecode = type[i];
	              i++;
          } else { /* neither list is exhausted, so use list with lowest time */     

	            if (timer_lt(&time[i], &time2[j])) {
	                ts = time[i];
	                pkt_len = len[i];
	                typecode = type[i];
	                dir = IN;
	                if (i < imax) {
	                    i++;
	                }
	            } else {
	                ts = time2[j];
	                pkt_len = len2[j];
	                typecode = type2[j];
	                dir = OUT;
	                if (j < jmax) {
	                    j++;
	                }
	            }
          }
          // zprintf(output, "i: %d\tj: %d\timax: %d\t jmax: %d", i, j, imax, jmax);
          timer_sub(&ts, &ts_last, &tmp);
          //      zprintf(output, "\t\t\t\t{ \"b\": %u, \"dir\": \"%s\", \"ipt\": %u }", 
          //     pkt_len, dir, timeval_to_milliseconds(tmp));
          print_bytes_dir_time_type(pkt_len, dir, tmp, typecode, "");
          ts_last = ts;
          if (!((i == imax) & (j == jmax))) { /* we are done */
	            zprintf(output, ",");
          }
      }
      //    zprintf(output, "\t\t\t]");
    }
}
#endif

/**
 * \fn void zprintf_raw_as_hex (zfile f, const void *data, unsigned int len)
 * \brief print out raw values as hex to the output file
 * \param f output file
 * \param data the data to print out 
 * \param len length of the data to print
 * \return none
 */
void zprintf_raw_as_hex (zfile f, const void *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;
  
    zprintf(f, "\"");   /* quotes needed for JSON */
    while (x < end) {
        zprintf(f, "%02x", *x++);
    }
    zprintf(f, "\"");
}

static void reduce_bd_bits (unsigned int *bd, unsigned int len) {
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

/* output flow record in JSON format */
static void flow_record_print_json (const struct flow_record *record) {
    unsigned int i, j, imax, jmax;
    struct timeval ts, ts_last, ts_start, ts_end, tmp;
    const struct flow_record *rec;
    unsigned int pkt_len;
    char *dir;

    //if (records_in_file != 0) {
    //    zprintf(output, ",\n");
    //}
 
    flocap_stats_incr_records_output();
    records_in_file++;

    if (record->twin != NULL) {
        if (timer_lt(&record->start, &record->twin->start)) {
            ts_start = record->start;
            rec = record;
        } else {
            ts_start = record->twin->start;
            rec = record->twin;
        }
        if (timer_lt(&record->end, &record->twin->end)) {
            ts_end = record->end;
        } else {
            ts_end = record->twin->end;
        }
    } else {
        ts_start = record->start;
        ts_end = record->end;
        rec = record;
    }

    zprintf(output, "{");

    /* print flow key */
    if (ipv4_addr_needs_anonymization(&rec->key.sa)) {
        zprintf(output, "\"sa\":\"%s\",", addr_get_anon_hexstring(&rec->key.sa));
    } else {
        zprintf(output, "\"sa\":\"%s\",", inet_ntoa(rec->key.sa));
    }
    if (ipv4_addr_needs_anonymization(&rec->key.da)) {
        zprintf(output, "\"da\":\"%s\",", addr_get_anon_hexstring(&rec->key.da));
    } else {
        zprintf(output, "\"da\":\"%s\",", inet_ntoa(rec->key.da));
    }
    zprintf(output, "\"pr\":%u,", rec->key.prot);
    if (1 || rec->key.prot == 6 || rec->key.prot == 17) {
        zprintf(output, "\"sp\":%u,", rec->key.sp);
        zprintf(output, "\"dp\":%u,", rec->key.dp);
    }

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

    /* print flow stats */
    zprintf(output, "\"ob\":%u,", rec->ob);
    zprintf(output, "\"op\":%u,", rec->np); /* not just packets with data */
    if (rec->twin != NULL) {
        zprintf(output, "\"ib\":%u,", rec->twin->ob);
        zprintf(output, "\"ip\":%u,", rec->twin->np);
    }
    zprintf(output, "\"ts\":%zd.%06zd,", ts_start.tv_sec, ts_start.tv_usec);
    zprintf(output, "\"te\":%zd.%06zd,", ts_end.tv_sec, ts_end.tv_usec);
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

    if (rec->tcp_option_nop) {
        zprintf(output, "\"otcp_nop\":%u,", rec->tcp_option_nop);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_option_nop) {
            zprintf(output, "\"itcp_nop\":%u,", rec->twin->tcp_option_nop);
        }
    }

    if (rec->tcp_option_mss) {
        zprintf(output, "\"otcp_mss\":%u,", rec->tcp_option_mss);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_option_mss) {
            zprintf(output, "\"itcp_mss\":%u,", rec->twin->tcp_option_mss);
        }
    }

    if (rec->tcp_option_wscale) {
        zprintf(output, "\"otcp_wscale\":%u,", rec->tcp_option_wscale);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_option_wscale) {
            zprintf(output, "\"itcp_wscale\":%u,", rec->twin->tcp_option_wscale);
        }
    }

    if (rec->tcp_option_sack) {
        zprintf(output, "\"otcp_sack\":%u,", rec->tcp_option_sack);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_option_sack) {
            zprintf(output, "\"itcp_sack\":%u,", rec->twin->tcp_option_sack);
        }
    }

    if (rec->tcp_option_fastopen) {
        zprintf(output, "\"otcp_fastopen\":%u,", rec->tcp_option_fastopen);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_option_fastopen) {
            zprintf(output, "\"itcp_fastopen\":%u,", rec->twin->tcp_option_fastopen);
        }
    }

    if (rec->tcp_option_tstamp) {
        zprintf(output, "\"otcp_tstamp\":%u,", rec->tcp_option_tstamp);
    }
    if (rec->twin != NULL) {
        if (rec->twin->tcp_option_tstamp) {
            zprintf(output, "\"itcp_tstamp\":%u,", rec->twin->tcp_option_tstamp);
        }
    }

#if 0

    len_time_print_interleaved(rec->op, rec->pkt_len, rec->pkt_time,
			     rec->twin->op, rec->twin->pkt_len, rec->twin->pkt_time);
#else
    /* print length and time arrays */
    zprintf(output, "\"packets\":[");

    if (rec->twin == NULL) {
    
        imax = rec->op > num_pkt_len ? num_pkt_len : rec->op;
        if (imax == 0) { 
            ; /* no packets had data, so we print out nothing */
        } else {
            for (i = 0; i < imax-1; i++) {
	              if (i > 0) {
	                  timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
	              } else {
	                  timer_clear(&ts);
	              }
	              print_bytes_dir_time(rec->pkt_len[i], OUT, ts, ",");
	              // zprintf(output, "\t\t\t\t{ \"b\": %u, \"dir\": \">\", \"ipt\": %u },\n", 
	              //    record->pkt_len[i], timeval_to_milliseconds(ts));
            }
            if (i == 0) {        /* this code could be simplified */ 	
	              timer_clear(&ts);  
            } else {
	              timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
            }
            print_bytes_dir_time(rec->pkt_len[i], OUT, ts, "");
            // zprintf(output, "\t\t\t\t{ \"b\": %u, \"dir\": \">\", \"ipt\": %u }\n", 
            //    record->pkt_len[i], timeval_to_milliseconds(ts));
        }
        zprintf(output, "]"); 
    } else {

        imax = rec->op > num_pkt_len ? num_pkt_len : rec->op;
        jmax = rec->twin->op > num_pkt_len ? num_pkt_len : rec->twin->op;
        i = j = 0;
        ts_last = ts_start;
        while ((i < imax) || (j < jmax)) {      

            if (i >= imax) {  /* record list is exhausted, so use twin */
	              dir = OUT;
	              ts = rec->twin->pkt_time[j];
	              pkt_len = rec->twin->pkt_len[j];
	              j++;
            } else if (j >= jmax) {  /* twin list is exhausted, so use record */
	              dir = IN;
	              ts = rec->pkt_time[i];
	              pkt_len = rec->pkt_len[i];
	              i++;
            } else { /* neither list is exhausted, so use list with lowest time */     

	              if (timer_lt(&rec->pkt_time[i], &rec->twin->pkt_time[j])) {
	                    ts = rec->pkt_time[i];
	                    pkt_len = rec->pkt_len[i];
	                    dir = IN;
	                    if (i < imax) {
	                        i++;
	                    }
	              } else {
	                  ts = rec->twin->pkt_time[j];
	                  pkt_len = rec->twin->pkt_len[j];
	                  dir = OUT;
	                  if (j < jmax) {
	                      j++;
	                  }
	              }
            }
            // zprintf(output, "i: %d\tj: %d\timax: %d\t jmax: %d", i, j, imax, jmax);
            timer_sub(&ts, &ts_last, &tmp);
            //      zprintf(output, "\t\t\t\t{ \"b\": %u, \"dir\": \"%s\", \"ipt\": %u }", 
            //     pkt_len, dir, timeval_to_milliseconds(tmp));
            print_bytes_dir_time(pkt_len, dir, tmp, "");
            ts_last = ts;
            if (!((i == imax) & (j == jmax))) { /* we are done */
	              zprintf(output, ",");
            }
            /*if ((i == imax) & (j == jmax)) {
      	        zprintf(output, ""); 
            } else {
	              zprintf(output, ",");
            }*/
        }
        zprintf(output, "]");
    }
#endif /* 0 */

    if (byte_distribution || report_entropy || compact_byte_distribution) {
        const unsigned int *array;
        const unsigned int *compact_array;
        unsigned int tmp[256];
        unsigned int compact_tmp[16];
        unsigned int num_bytes;
        double mean = 0.0, variance = 0.0;

        /* 
         * sum up the byte_count array for outbound and inbound flows, if
         * this flow is bidirectional
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
	              //if ((i % 16) == 0) {
	              //  zprintf(output, "");	    
	              //}
	              zprintf(output, "%u,", (unsigned char)array[i]);
            }
            zprintf(output, "%u]", (unsigned char)array[i]);

            // output the mean
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
	              //if ((i % 16) == 0) {
	              //  zprintf(output, "");	    
	              //}
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

    // inline classification of flows
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

    print_all_features(feature_list);

    if (report_hd) {
        /*
         * note: this should be bidirectional, but it is not!  This will
         * be changed sometime soon, but for now, this will give some
         * experience with this type of data
         */
        header_description_printf(&rec->hd, output, report_hd);
    }

    if (include_os) { 

        if (rec->twin) {
            os_printf(output, rec->ttl, rec->tcp_initial_window_size, rec->twin->ttl, rec->twin->tcp_initial_window_size);
        } else {
            os_printf(output, rec->ttl, rec->tcp_initial_window_size, 0, 0);
        }
    }

    if (include_tls) { 
        if (rec->twin) {
            tls_printf(rec->tls_info, rec->twin->tls_info, output);
        } else {
            tls_printf(rec->tls_info, NULL, output);
        }
    }

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

    if (config.http) {
        http_printf(&rec->http_data, "ohttp", output);
        if (rec->twin) { 
            http_printf(&rec->twin->http_data, "ihttp", output);
        }
    }

    if (report_dns && (rec->key.sp == 53 || rec->key.dp == 53)) {
        //    unsigned int count;
        //    char **twin_dns_name = NULL;
        //unsigned short *twin_pkt_len = NULL;
        //
        //count = rec->op > MAX_NUM_PKT_LEN ? MAX_NUM_PKT_LEN : rec->op;
        //if (rec->twin) {
        //  count = rec->twin->op > count ? rec->twin->op : count;
        //  twin_dns_name = rec->twin->dns.dns_name;
        //  twin_pkt_len = rec->twin->pkt_len;
        // }
        //
        //    dns_printf(rec->dns.dns_name, rec->pkt_len, twin_dns_name, twin_pkt_len, count, output);

        dns_print_json(&rec->dns, rec->twin ? &rec->twin->dns : NULL, output);

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

    if (rec->exp_type) {
        zprintf(output, ",\"x\":\"%c\"", rec->exp_type);
    }

    zprintf(output, "}\n");

}

#if 0
static void flow_record_print_time_to_expiration (const struct flow_record *r, 
    const struct timeval *inactive_cutoff) {
    struct timeval tte_active, tte_inactive, active_expiration;

    timer_sub(&r->end, inactive_cutoff, &tte_inactive);
    timer_sub(inactive_cutoff, &active_timeout, &active_expiration);
    timer_sub(&r->start, &active_expiration, &tte_active); 
    fprintf(info, "seconds to expiration - active: %f inactive %f\n", 
	        ((float) timeval_to_milliseconds(tte_active)) / 1000.0,
	        ((float) timeval_to_milliseconds(tte_inactive) / 1000.0));
}
#endif

/*
 * a unidirectional flow_record is inactive-expired when it end time is after
 * the expiration time
 *
 * a bidirectional flow_record (i.e. one with twin != NULL) is expired
 * when both the record end time and the twin end time are after the
 * expiration time
 *
 */
static unsigned int flow_record_is_inactive (struct flow_record *record,
    const struct timeval *expiration) {

    if (timer_lt(&record->end, expiration)) {
          if (record->twin) {
              if (timer_lt(&record->twin->end, expiration)) {
	                //  fprintf(info, "bidir flow past inactive cutoff\n");
	                record->exp_type = expiration_type_inactive;
	                return 1;
              }
          } else {
              // fprintf(info, "undir flow past inactive cutoff\n");
              record->exp_type = expiration_type_inactive;
              return 1;
          }
    }
    // fprintf(info, "no inactive cutoff\n");
    return 0;
}

static unsigned int flow_record_is_expired (struct flow_record *record,
    const struct timeval *inactive_cutoff) {
    struct timeval active_expiration;

    /*
     * check for active timeout
     */ 
    timer_sub(inactive_cutoff, &active_timeout, &active_expiration);

    if (timer_lt(&record->start, &active_expiration)) {
        if (record->twin) {
            if (timer_lt(&record->twin->start, &active_expiration)) {
	              record->exp_type = expiration_type_active;
	              // fprintf(info, "bidir flow past active cutoff\n");
	              return 1;
            }
        } else {
            record->exp_type = expiration_type_active;
            // fprintf(info, "unidir flow past active cutoff\n");
            return 1;
        }
    }
    // fprintf(info, "no active cutoff\t");
    return flow_record_is_inactive(record, inactive_cutoff);
}

static void flow_record_print_and_delete (struct flow_record *record) {
  
    flow_record_print_json(record);
  
    /* delete twin, if there is one */
    if (record->twin != NULL) {
        debug_printf("LIST deleting twin\n");
        flow_record_delete(record->twin);
        //      fprintf(info, "DELETING TWIN: %p\n", record->twin);
    }
  
    /* remove record from chrono list, then delete from flow_record_list_array */
    flow_record_chrono_list_remove(record);
    flow_record_delete(record);    
  
}

/**
 * \fn void flow_record_list_print_json (const struct timeval *inactive_cutoff)
 * \brief prints out the flow record list in JSON format
 * \param instactive_cutoff cutoff time for inactive flows
 * \return none
 */
void flow_record_list_print_json (const struct timeval *inactive_cutoff) {
    struct flow_record *record;
    // unsigned int num_printed = 0;

    record = flow_record_chrono_list_get_first();
    while (record != NULL) {
        /*
         * avoid printing flows that might still be active, if a non-NULL
         * expiration time was passed into this function
         */
        if (inactive_cutoff && !flow_record_is_expired(record, inactive_cutoff)) {
            // fprintf(info, "BREAK: "); 
            // flow_record_print_time_to_expiration(record, inactive_cutoff);
            // flocap_stats_output(info);
            break;
        } 
    
        flow_record_print_and_delete(record);

        /* advance to next record on chrono list */  
        record = flow_record_chrono_list_get_first();
    }
    // zprintf(output, "] }\n");
    // fprintf(info, "printed %u records\n", num_printed);
  
    // note: we might need to call flush in the future
    // zflush(output);
}

#if 0
static void flow_record_list_print (const struct timeval *expiration) {
    struct flow_record *record;
    unsigned int count = 0;

    record = flow_record_chrono_first;
    while (record != NULL) {
        /*
         * avoid printing flows that might still be active, if a non-NULL
         * expiration time was passed into this function
         */
        if (expiration && timer_gt(&record->end, expiration)) {
            break;
        }
        flow_record_print(record);
        count++;
        record = record->time_next;
    }
    zprintf(output, "printed %u flow records\n", count);
}
#endif

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


#if 0
/*
 * The function flow_record_list_find_twins() is DEPRECATED, since
 * flow_key_get_record() now finds a twin for a newly created flow, if
 * that flow exists, and sets the twin pointer at that point.
 */
static void flow_record_list_find_twins (const struct timeval *expiration) {
    struct flow_record *record, *twin, *parent;
    struct flow_key key;

    parent = record = flow_record_chrono_first;
    while (record != NULL) {
        /*
         * process only older, inactive flows, if a non-NULL expiration
         * time was passed into this function
         */
        if (expiration && timer_gt(&record->end, expiration)) {
            // zprintf(output, "record:     %u\n", timeval_to_milliseconds(record->end));
            // zprintf(output, "expiration: %u\n", timeval_to_milliseconds(*expiration));
            // zprintf(output, "find_twins reached end of expired flows\n");
            break;
        }

        key.sa = record->key.da;
        key.da = record->key.sa;
        key.sp = record->key.dp;
        key.dp = record->key.sp;
        key.prot = record->key.prot;
    
        twin = flow_key_get_record(&key, DONT_CREATE_RECORDS);
        if (twin != NULL) {
            /* sanity check */
            if (twin == record) {
	              debug_printf("error: flow should not be its own twin\n");
            } else {
	              // zprintf(output, "found twins\n");
	              // flow_key_print(&key);
	              // flow_key_print(&record->key);
	              twin->twin = record;
	              record->twin = twin;
	              parent->time_next = record->time_next; /* remove record from chrono list */ 
            } 
        }
        if (parent != record) {
            parent = parent->time_next;
        }
        record = record->time_next;
    }
}
#endif

/* END flow monitoring */


/** maxiumum lengnth of the upload URL string */
#define MAX_UPLOAD_CMD_LENGTH 512

/** thread mutex for locking */
pthread_mutex_t upload_in_process = PTHREAD_MUTEX_INITIALIZER;

/** thread condition to wait for */
pthread_cond_t upload_run_cond = PTHREAD_COND_INITIALIZER;

/** thread signal for execution */
int upload_can_run = 0;

/** filename to be uploaded */
char *upload_filename = NULL;

static int uploader_send_file (char *filename, char *servername, 
                               char *key, unsigned int retain) {
    int rc = 0;
    char cmd[MAX_UPLOAD_CMD_LENGTH];

    snprintf(cmd,MAX_UPLOAD_CMD_LENGTH,"scp -q -C -i %s %s %s",key,filename,servername);
    rc = system(cmd);

    /* see if the command was successful */
    if (rc == 0) { 
       fprintf(info,"transfer of file [%s] successful!\n",filename);
       /* see if we are allowed to delete the file after upload */
       if (retain == 0) {
            snprintf(cmd,MAX_UPLOAD_CMD_LENGTH,"rm %s","config.vars");
            fprintf(info,"removing file [%s]\n","config.vars");
            system(cmd);
        }
    } else {
        fprintf(info,"transfer of file [%s] failed!\n",filename);
    }
    
    return 0;
}

/**
 * \fn void *uploader_main (void *ptr)
 * \brief Runs as a thread off of pcap2flow.
 *        Uploader is only active during live processing runs.
 *        Uploader terminates automatically when pcap2flow exits due to the nature of
 *        how pthreads work.
 * \param ptr always a pointer to the config structure
 * \return never return and the thread terminates when pcap2flow exits
 */
void *uploader_main(void *ptr)
{
    struct configuration *config = ptr;
 
    /* uploader stays alive until pcap2flow exists */
    while (1) {

        /* wait until we are signaled to do work */
        pthread_mutex_lock(&upload_in_process);
        while (!upload_can_run) {
            fprintf(info,"uploader: waiting on signal...\n");
            pthread_cond_wait(&upload_run_cond, &upload_in_process);
        }

        /* upload file now */
        if (upload_filename != NULL) {
            fprintf(info,"uploader: uploading file [%s] ...\n", upload_filename);
            uploader_send_file(upload_filename, config->upload_servername, 
                               config->upload_key, config->retain_local);
        }
    
        /* we are done uploading the file, go back to sleep */
        upload_filename = NULL;
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
        fprintf(info, "error: could not upload file (output file not set\n");
        return failure;
    }

    /* wake up the uploader thread so it can do its work */
    pthread_mutex_lock(&upload_in_process);
    upload_can_run = 1;
    upload_filename = filename;
    pthread_cond_signal(&upload_run_cond);
    pthread_mutex_unlock(&upload_in_process);

    return 0;
}



#include <ctype.h>
/**
 * \fn void *convert_string_to_printable (char *s, unsigned int len)
 * \brief  convert_string_to_printable(s, len) convers the character string 
 * into a JSON-safe, NULL-terminated printable string.
 * Non-alphanumeric characters are converted to "." (a period).  This
 * function is useful only to ensure that strings that one expects to
 * be printable, such as DNS names, don't cause encoding errors when
 * they are actually not non-printable, non-JSON-safe strings.
 *
 * \param s pointer to the string
 * \param len length of the string
 * \return none
 */ 
void *convert_string_to_printable (char *s, unsigned int len) {
    unsigned int i;

    for (i=0; i<len; i++) {
        if (s[i] == 0) {
            return s + i + 1;
        } else if (!isprint(s[i])) {
            s[i] = '.';
        }
    }
    s[len-1] = 0;  /* NULL termination */
    return s + i;
}
