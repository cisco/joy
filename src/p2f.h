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

/*
 * p2f.h
 *
 * header file for pcap2flow
 */

#ifndef P2F_H
#define P2F_H

#include <sys/socket.h>   /* for struct in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

#include "tls.h"          /* provides TLS awareness        */
#include "pkt_proc.h"     /* for struct tls_type_code      */
#include "hdr_dsc.h"      /* header description (proto id) */
#include "wht.h"          /* walsh-hadamard transform      */

enum print_level { 
  none = 0, 
  packet_summary = 1, 
  all_data =2 
};


struct flow_key {
  struct in_addr sa;
  struct in_addr da;
  unsigned short int sp;
  unsigned short int dp;
  unsigned short int prot;
};

/*
 * default and maximum number of packets on which to report
 * lengths/times (actual value configurable on command line)
 */
#define NUM_PKT_LEN 50
#define MAX_NUM_PKT_LEN 200
#define MAX_IDP 1500

struct flow_record {
  struct flow_key key;                  /* identifies flow by 5-tuple          */
  unsigned int np;                      /* number of packets                   */
  unsigned int op;                      /* number of packets (w/nonzero data)  */
  unsigned int ob;                      /* number of bytes of application data */
  unsigned char ttl;                    /* smallest IP TTL in flow             */
  struct timeval start;                 /* start time                          */ 
  struct timeval end;                   /* end time                            */
  unsigned int last_pkt_len;            /* last observed appdata length        */
  unsigned short pkt_len[MAX_NUM_PKT_LEN];  /* array of packet appdata lengths */  
  struct timeval pkt_time[MAX_NUM_PKT_LEN]; /* array of arrival times          */
  unsigned char pkt_flags[MAX_NUM_PKT_LEN]; /* array of packet flags           */
  unsigned int byte_count[256];         /* number of occurences of each byte   */
  unsigned long int num_bytes;
  double bd_mean;
  double bd_variance;
  struct wht wht;                       /* walsh hadamard transform            */
  struct header_description hd;         /* header description (proto ident)    */
  struct tls_information tls_info;      /* TLS awareness                       */
  char *dns_name[MAX_NUM_PKT_LEN];       /* array of DNS names                 */
  void *idp;
  unsigned int idp_len;
  unsigned int ack;
  unsigned int seq;
  unsigned int invalid;
  unsigned int retrans;
  char *exe_name;                       /* executable associated with flow    */ 
  unsigned char tcp_option_nop;
  unsigned int tcp_option_mss;
  unsigned int tcp_option_wscale;
  unsigned char tcp_option_sack;
  unsigned char tcp_option_tstamp;
  unsigned short tcp_initial_window_size;
  unsigned int tcp_syn_size;
  unsigned char exp_type;
  unsigned char first_switched_found;   /* hack to make sure we only correct once */
  struct flow_record *twin;             /* other half of bidirectional flow    */
  struct flow_record *next;             /* next record in flow_record_list     */
  struct flow_record *prev;             /* previous record in flow_record_list */
  struct flow_record *time_prev;        /* previous record in chronological list */
  struct flow_record *time_next;        /* next record in chronological list     */
};


/*
 * flow_records can be accessed in either of two ways: 
 *
 *   - An individual record can be looked up by its flow key, which
 *     uses the flow_record_list_array[], which is indexed by the
 *     flow_key_hash() function; this is a doubly linked list.
 *
 *   - All records can be listed in chronological order, using the
 *     time_next pointer's linked list.  (That list will actually be
 *     ordered based on when each flow record is allocated and
 *     initialized, which in most cases is the order in which new
 *     flows are observed.)  The head and tail of that list are
 *     flow_record_chrono_first and flow_record_chrono_last,
 *     respectively.
 *
 * Flows are allocated and initialized by the flow_key_get_record()
 * function when the CREATE_RECORDS flag is set in the arguments to
 * that function.  
 *
 * Each flow_record describes a single unidirectional flow.  The twin
 * pointer contains the address to the flow record of the twin (that
 * is, the flow with source and destination addresses and ports
 * reversed), if there is a twin; otherwise, the twin pointer is NULL.
 * The twin pointer is set in flow_key_get_record(), and that function
 * adds a newly created flow_record to the chronological list only if
 * it has no twin.
 *
 * The function flow_record_list_free() frees *all* flow records in
 * the flow_record_list_array[].  This function should only be used
 * after all processing of all of the associated flows is done.
 * 
 */


/*
 * A flow_record_list is a handle for a linked list of flow_records;
 * an array of such lists is used as a flow cache
 */

typedef struct flow_record *flow_record_list;

/*
 * The function flow_key_get_record(k, flag) returns a pointer to a
 * flow_record structure that has flow_key k.  If such a record
 * existed before the invocation, then it returns a pointer to that
 * record.  If no matching flow_record exists before invocation, then
 * if flag=CREATE_RECORDS, a flow_record will be allocated and
 * initialized, but if flag=DONT_CREATE_RECORDS, then a NULL pointer
 * will be returned.  If flag=CREATE_RECORDS, a NULL pointer will be
 * returned if the malloc() call that attempts to allocate memory for
 * a new flow_record structure itself returns NULL.
 *
 * If the pointer returned by flow_key_get_record() is not NULL, then
 * it points to a flow_record structure that is fully initialized (if
 * it is newly created) and potentially already populated with some
 * flow data (if not newly created).  
 * 
 * The twin of a flow_key (src, dst, srcp, dstp, pr) is the flow_key
 * (dst, src, dstp, srcp, pr) with addresses and ports swapped.  If a
 * flow_record that is the twin of the flow_key k exists before the
 * invocation of flow_key_get_records(k, flag), then the pointer
 * "struct flow_record *twin" of both that record and its twin are set
 * to point to each other.  That is, this function performs the
 * stitching of unidirectional flows into bidirectional flows as
 * appropriate.  The function flow_record_print_json() recognizes when
 * a flow_record is part of a bidirectional flow by checking the
 * "twin" pointer, and prints out bidirectional information.
 *
 */
#define CREATE_RECORDS      1
#define DONT_CREATE_RECORDS 0
struct flow_record *flow_key_get_record(const struct flow_key *key, 
					unsigned int create_new_records);


void flow_record_init(/*@out@*/ struct flow_record *record, 
		      /*@in@*/ const struct flow_key *key);

void flow_record_print_json(const struct flow_record *record);

void flow_record_update_byte_count(struct flow_record *f, const void *x, unsigned int len);

void flow_record_update_byte_dist_mean_var(struct flow_record *f, const void *x, unsigned int len);

void flow_record_delete(struct flow_record *r);

void flow_record_print_and_delete(struct flow_record *record);

inline unsigned int flow_record_is_in_chrono_list(const struct flow_record *record);

void flow_record_list_init();

void flow_record_list_free(); 

void flow_record_list_print_json(const struct timeval *inactive_cutoff);

/*
 * flow_record_is_past_active_expiration(record) returns 1 if the age
 * of the flow record is greater than active_max, and returns 0 otherwise
 */
unsigned int flow_record_is_past_active_expiration(const struct flow_record *record);

int process_pcap_file(char *file_name, char *filter_exp, bpf_u_int32 *net, struct bpf_program *fp);


/* flocap_stats holds high-level statistics about packets and flow
 * records, for use in accounting and troubleshooting
 * 
 * num_packets is the total number of packets that have been observed
 * and processed by the system; note that this count includes only the
 * packets that have been processed by the BPF filter, if one is used
 * 
 * num_records_in_table is the total number of records that are
 * currently in the flow record table
 * 
 * num_records_output is the total number of flow records that have been 
 * written to output
 *
 */
struct flocap_stats {
  unsigned long int num_packets;
  unsigned long int num_bytes;
  unsigned long int num_records_in_table;
  unsigned long int num_records_output;
  unsigned long int malloc_fail;
};

#define flocap_stats_init() struct flocap_stats stats = {  0, 0, 0, 0 };

#define flocap_stats_get_num_packets() (stats.num_packets)

#define flocap_stats_incr_num_packets() (stats.num_packets++)

#define flocap_stats_incr_num_bytes(x) (stats.num_bytes += (x))

#define flocap_stats_add_packets(x) (stats.num_packets += (x))

#define flocap_stats_incr_records_output() (stats.num_records_output++)

#define flocap_stats_incr_records_in_table() (stats.num_records_in_table++)

#define flocap_stats_decr_records_in_table() (stats.num_records_in_table--)

#define flocap_stats_incr_malloc_fail() (stats.malloc_fail++)

#define flocap_stats_format "packets: %lu\tcurrent records: %lu\toutput records: %lu"


void flocap_stats_output(FILE *f);

void flocap_stats_timer_init();

/*
 * the function flow_key_set_exe_name(key, name) finds the flow record
 * associated with key, if there is one, and then sets the exe_name of
 * that record to the provided name
 */
int flow_key_set_exe_name(const struct flow_key *key, const char *exe_name);

enum SALT_algorithm { 
  reserved = 0,
  raw = 1,
  aggregated = 2,
  defragmented = 3,
  rle = 4
};

/*
 * for portability and static analysis, we define our own timer
 * comparison functions (rather than use non-standard
 * timercmp/timersub macros)
 */
unsigned int timer_gt(const struct timeval *a, const struct timeval *b);

unsigned int timer_lt(const struct timeval *a, const struct timeval *b);

void timer_sub(const struct timeval *a, const struct timeval *b, struct timeval *result);

void timer_clear(struct timeval *a);

int upload_file(const char *filename, const char *servername, const char *key, unsigned int retain); 


void flow_record_list_unit_test();

/* 
 * convert_string_to_printable(s, len) convers the character string s
 * into a JSON-safe, NULL-terminated printable string.
 * Non-alphanumeric characters are converted to "." (a period).  This
 * function is useful only to ensure that strings that one expects to
 * be printable, such as DNS names, don't cause encoding errors when
 * they are actually not non-printable, non-JSON-safe strings.
 */ 

void convert_string_to_printable(char *s, unsigned int len);

#endif /* P2F_H */
