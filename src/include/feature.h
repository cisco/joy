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
 * \file feature.h
 *
 * \brief joy internal interface for data feature modules
 *
 * \remarks
 * \verbatim
 * Overview: this interface provides a way to implement a new feature
 * (that is, a new network data feature that will be captured and
 * reported on by the Joy package) without altering any of the core
 * files of the joy program.  This extensibility is achieved by
 * using preprocessor macros in a generic programming style, using the
 * MAP() define from map.h.  In essence, there are macros inside
 * joy that provide hooks that will define the feature and call
 * the functions at the appropriate time; by adding a feature to the
 * feature_list, it is hooked into the system without any need to
 * modify any of the core joy source code files.
 *
 *  A new feature with the name of "F" * is added by:
 * 
 *   1) defining a structure named "F" that holds all of the data
 *      context for that feature, for a single unidirecitonal flow,
 *      and a typedef defining F_t to be equivalent to "struct F", in
 *      a separate C header file (preferably one named F.h),
 * 
 *   2) implenting functions that match the function declarations made
 *      by the declare_feature(F) macro below, in a separate C file
 *      (preferably one named F.c),
 * 
 *   3) define the macro F_usage to be a constant, printable C string
 *      that describes the usage of the feature, in the header file,
 *
 *   4) define the macro F_filter(key), in the header file, to be a C
 *      expression that operates on the struct flow_key (in p2f.h) and
 *      evaluates to true for flows on which the data feature should
 *      be collecting information, 
 *
 *   5) add the C header file to the files included in modules.h, and
 *
 *   6) add F to the comma-separated list, in the #define for
 *   feature_list below.
 *
 * The files example.c and example.h provide a simple example of a
 * (trivial) feature module.  The dns.c and dns.h files provide a
 * slightly more complex example of a non-trivial module; the macro
 * dns_filter() provides a good example of how a feature can filter on
 * protocols and ports.
 *
 * This interface has been designed to provide extensibility and
 * modularity, and it achieves these goals reasonably well.  It may be
 * altered in the future to improve performance and/or ease of use.
 * 
 * NOTE: the only configuration option supported so far is a boolean;
 * other types may need to be supported in the future.
 *
 * \endverbatim
 */

#ifndef FEATURE_H
#define FEATURE_H

#ifdef WIN32
#include "win_types.h"
#endif

#include <stdio.h> 
#include <pcap.h>
#include "err.h"
#include "output.h"
#include "map.h"


/** The feature_list macro defines all of the features that will be
 * included in the flow_record.  To include/exclude a feature in a
 * build of joy, add/remove it from this list.
 */
#define ip_feature_list ip_id
#define tcp_feature_list salt, ppi
#define payload_feature_list wht, example, dns, ssh, tls, dhcp, http
#define feature_list payload_feature_list, ip_feature_list, tcp_feature_list

#define define_feature_config_uint(f) unsigned int report_##f = 0;
#define define_all_features_config_uint(flist) MAP(define_feature_config_uint, flist)

#define define_feature_config_extern_uint(f) extern unsigned int report_##f;
#define define_all_features_config_extern_uint(flist) MAP(define_feature_config_extern_uint, flist)

#define declare_feature_config_uint(f) unsigned int report_##f;
#define declare_all_features_config_uint(flist)  MAP(declare_feature_config_uint, flist)

#define set_config_feature(F) report_##F = config.report_##F;
#define set_config_all_features(flist) MAP(set_config_feature, flist)


/** The function feature_init(ptr) is invoked on a pointer to a data
 * feature, it initializes an instance of the feature, possibly 
 * performing memory allocation as a side effect
 * This function is called in flow_record_init() in p2f.c.
 */
#define declare_init(F) void F##_init(F##_t **f)

/** \brief \verbatim
 * The function feature_update(feature, header, data, data_len, report_feature)
 * updates the data feature context "feature" stored in a flow_record, based on
 * the packet located at "data", which has length "len", whenever "report_feature" is nonzero.
 *
 * return value: 
 *     no_more_packets_needed  (if enough packets in flow have been seen)
 *     more_packets_needed     (otherwise)
 * 
 * This function is called in process_tcp(), process_udp(),
 * process_ip(), and process_icmp(), in the file pkt_proc.c.
 * \endverbatim
 */
#define declare_update(F)                         \
void F##_update(F##_t *f,	                  \
                const struct pcap_pkthdr *header, \
                const void *data,                 \
	        unsigned int len,                 \
		unsigned int report_F); 


/** \brief \verbatim
 * The function feature_print_json_func(feature, twin_feature, file)
 * prints out a JSON representation of the data feature.  The
 * twin_feature pointer MUST be set to NULL if a record is
 * unidirectional, and set to the flow's twin's data feature
 * otherwise.
 * 
 * 
 * This function is called in flow_record_print_json() in the file
 * p2f.c.
 * \endverbatim
 */
#define declare_print_json(F)            \
void F##_print_json(const F##_t *F,      \
		    const F##_t *twin_F, \
		    zfile f);


/** \brief \verbatim
 * The function feature_delete_func(ptr), when invoked on a feature_ptr,
 * frees any and all memory that is allocated by feature_init().  It
 * may also zeroize that memory.
 * 
 * This function is called in flow_record_delete(), in the file p2f.c
 * \endverbatim
 */
#define declare_delete(F) void F##_delete(F##_t **F);


/** \brief \verbatim
 * The feature_unit_test function() performs a test of the feature
 * module.  It is meant to be called by the unit_test() function,
 * which appears in a test-specific program; it is not intended to be
 * used in any production code, and it may rely on the presence of
 * external files that are only available in the source code package.
 *
 * This function is invoked by the unit_test program
 * (src/unit_test.c).
 * \endverbatim
 */
#define declare_unit_test(F) void F##_unit_test();

/** The macro declare_feature(F) declares all of the functions
 * associated with the feature F_t
 */
#define declare_feature(F)    \
  declare_init(F);            \
  declare_update(F);          \
  declare_print_json(F);      \
  declare_delete(F);          \
  declare_unit_test(F); 

/* delete, print, etc. are missing for now */

/** The macro define_feature(f) instantiates a structure of type f_t
 * and name f.
 */
#define define_feature(f) f##_t *f;

/** The macro init_feature(f) initializes the element f in the
 * structure record
 */
#define init_feature(f) record->f=NULL;

/** The macro update_feature(f) processes a single packet and updates
 * the feature context
 */
#define update_feature(f) \
    if (f##_filter(key) && (report_##f)) { \
        if (record->f == NULL) f##_init(&record->f); \
        f##_update(record->f, header, payload, size_payload, report_##f); \
    }

/** The macro update_ip_feature(f) processes a single packet, given
 * a pointer to the IP header, and updates the feature context
 */
#define update_ip_feature(f) \
    if (f##_filter(key) && (report_##f)) { \
        if (record->f == NULL) f##_init(&record->f); \
        f##_update(record->f, header, ip, ip_hdr_len, report_##f); \
    }

/** The macro update_tcp_feature(f) processes a single packet, given
 * a pointer to the TCP header, and updates the feature context
 */
#define update_tcp_feature(f) \
    if (f##_filter(key) && (report_##f)) { \
        if (record->f == NULL) f##_init(&record->f); \
        f##_update(record->f, header, transport_start, transport_len, report_##f); \
    }

/** The macro print_feature(f) prints the feature as JSON 
 */
#define print_feature(f) if (rec->f != NULL) f##_print_json(rec->f, (rec->twin ? rec->twin->f : NULL), output);


/** The macro init_feature(f) initializes the element f in the
 * structure record
 */
#define delete_feature(f) if (r->f != NULL) f##_delete(&r->f);

#define unit_test_feature(F) F##_unit_test();

#define define_config_all_features(feature_list) MAP(define_config_feature, feature_list)

#define parse_check_feature_bool(f) if (match(command, #f)) { \
    parse_check(parse_bool(&config->report_##f, arg, num));   \
     }

#define config_all_features_bool(feature_list) MAP(parse_check_feature_bool, feature_list)

#define config_print_feature_bool(F) fprintf(f, #F " = %u\n", c->report_##F);

#define config_print_all_features_bool(feature_list) MAP(config_print_feature_bool, feature_list)

#define config_print_json_feature_bool(F) zprintf(f, "\"" #F "\":%u,", c->report_##F);

#define config_print_json_all_features_bool(feature_list) MAP(config_print_json_feature_bool, feature_list)


/** The macro declare_all_features(list) invokes init_feature() for each
 * feature in list
 */
#define declare_all_features(feature_list) MAP(init_feature, feature_list)

/** The macro init_all_features(list) invokes init_feature() for each
 * feature in list
 */
#define init_all_features(feature_list) MAP(init_feature, feature_list)

/** The macro define_all_features(list) invokes define_feature() for each
 * feature in list
 */
#define define_all_features(feature_list) MAP(define_feature, feature_list)

/** The macro update_all_features(list) invokes update_feature() for each
 * feature in list
 */
#define update_all_features(feature_list) MAP(update_feature, feature_list)

/** The macro update_all_features(list) invokes update_feature() for each
 * feature in list
 */
#define update_all_ip_features(feature_list) MAP(update_ip_feature, feature_list)

/** The macro update_all_features(list) invokes update_feature() for each
 * feature in list
 */
#define update_all_tcp_features(feature_list) MAP(update_tcp_feature, feature_list)

/** The macro print_all_features(list) invokes print_feature() for each
 * feature in list
 */
#define print_all_features(feature_list) MAP(print_feature, feature_list)

/** The macro delete_all_features(list) invokes feature_print_json() for each
 * feature in list
 */
#define delete_all_features(feature_list) MAP(delete_feature, feature_list)


/** The macro unit_test_all_features(list) invokes feature_unit_test() for each
 * feature in list
 */
#define unit_test_all_features(feature_list) MAP(unit_test_feature, feature_list)


#define get_usage(F) F##_usage 

#define get_usage_all_features(feature_list) MAP(get_usage, feature_list)


#endif /* FEATURE_H */
