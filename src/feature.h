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
 * feature.h
 *
 * Proposed pcap2flow internal interface for data features 
 *
 * Overview: this interface provides a way to implement a new feature
 * (that is, a new network data feature that will be captured and
 * reported on by the Joy package) without altering any of the core
 * files of the pcap2flow program.  A new feature is added by:
 * 
 *   1) implenting functions that match the typedefs below, 
 * 
 *   2) populating a feature_class structure with those function
 *   pointers, 
 *     
 *   3) registering the feature_class, using the
 *   feature_class_register() function
 * 
 *  This interface is *not* yet functional, and is intended for review
 *  purposes only.
 * 
 */

#ifndef FEATURE_H
#define FEATURE_H

#include <stdio.h>   /* for FILE*       */
#include "err.h"
#include "output.h"
#include "map.h"

/* 
 * interface to data feature structures and functions
 *
 *
 * This interface makes pcap2flow extensible, so that it is easy to
 * add new data features.  This extensibility is achieved by using
 * preprocessor macros in generic programming style.  In essence,
 * there are macros inside pcap2flow that provide hooks that will
 * define the feature and call the functions at the appropriate time;
 * by adding a feature to the feature_list, it is hooked into the
 * system without any need to modify any of the core pcap2flow source
 * code files.  
 *
 * To add a new data feature:
 *
 *   1. Define the struct or typedef for that feature, and give it a
 *      name like feature_t (where "feature" is replaced with a short
 *      descriptive name).  The trailing "_t" is mandatory.  Below, we
 *      use "feature" as a symbol representing this string.
 *
 *   2. Declare the function prototypes for your feature by invoking
 *      the macro declare_feature(feature), with "feature" replaced by
 *      the name of your new feature.
 *
 *   3. Define the functions for those prototypes: feature_init,
 *      feature_update, feature_print, feature_delete; example
 *      function prototypes are given below.  (The core code invokes
 *      these functions at the appropriate time via the macros
 *      init_all_features, update_all_features, print_all_features,
 *      delete_all_features.)
 *
 *   4. Add the string "feature" (not feature_t, just feature!) to the
 *      end of the comma-separated list in the feature_list macro
 *      below.
 * 
 * 
 */


/*
 * The feature_list macro defines all of the features that will be
 * included in the flow_record.  To include/exclude a feature in a
 * build of pcap2flow, add/remove it from this list.
 */
#define feature_list wht, example

#define define_feature_config_uint(f) unsigned int report_##f = 0;
#define define_all_features_config_uint(flist) MAP(define_feature_config_uint, flist)

#define define_feature_config_extern_uint(f) extern unsigned int report_##f;
#define define_all_features_config_extern_uint(flist) MAP(define_feature_config_extern_uint, flist)

#define declare_feature_config_uint(f) unsigned int report_##f;
#define declare_all_features_config_uint(flist) MAP(declare_feature_config_uint, flist)

#define set_config_feature(F) report_##F = config.report_##F;
#define set_config_all_features(flist) MAP(set_config_feature, flist)

#define declare_init(F) void F##_init(F##_t *f)

#define declare_update(F)               \
void F##_update(F##_t *f,	        \
                const void *data,       \
	        unsigned int len,       \
		unsigned int report_f); 

#define declare_print_json(F)            \
void F##_print_json(const F##_t *F,      \
		    const F##_t *twin_F, \
		    zfile f);

#define declare_delete(F) void F##_delete(F##_t *F);

#define declare_unit_test(F) void F##_unit_test();

/*
 * The macro declare_feature(F) declares all of the functions
 * associated with the feature F_t
 */
#define declare_feature(F)    \
  declare_init(F);            \
  declare_update(F);          \
  declare_print_json(F);      \
  declare_delete(F);          \
  declare_unit_test(F); 

/* delete, print, etc. are missing for now */

/*
 * The macro define_feature(f) instantiates a structure of type f_t
 * and name f.
 */
#define define_feature(f) f##_t f;

/*
 * The macro init_feature(f) initializes the element f in the
 * structure record
 */
#define init_feature(f) f##_init(&(record->f));

/*
 * The macro update_feature(f) processes a single packet and updates
 * the feature context
 */
#define update_feature(f) f##_update(&((record)->f), payload, size_payload, report_##f);

/*
 * The macro print_feature(f) prints the feature as JSON 
 */
//#define print_feature(f, r, t, output) f##_print_json(&((r)->f), (t ? &((t)->f) : NULL), (output));
#define print_feature(f) f##_print_json(&((rec)->f), (rec->twin ? &(rec->twin->f) : NULL), output);


/*
 * The macro init_feature(f) initializes the element f in the
 * structure record
 */
#define delete_feature(f) f##_delete(&(r->f));

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


/*
 * The macro declare_all_features(list) invokes init_feature() for each
 * feature in list
 */
#define declare_all_features(feature_list) MAP(init_feature, feature_list)

/*
 * The macro init_all_features(list) invokes init_feature() for each
 * feature in list
 */
#define init_all_features(feature_list) MAP(init_feature, feature_list)

/*
 * The macro define_all_features(list) invokes define_feature() for each
 * feature in list
 */
#define define_all_features(feature_list) MAP(define_feature, feature_list)

/*
 * The macro update_all_features(list) invokes update_feature() for each
 * feature in list
 */
#define update_all_features(feature_list) MAP(update_feature, feature_list)

/*
 * The macro print_all_features(list) invokes print_feature() for each
 * feature in list
 */
#define print_all_features(feature_list) MAP(print_feature, feature_list)

/*
 * The macro delete_all_features(list) invokes feature_print_json() for each
 * feature in list
 */
#define delete_all_features(feature_list) MAP(delete_feature, feature_list)


/*
 * The macro unit_test_all_features(list) invokes feature_unit_test() for each
 * feature in list
 */
#define unit_test_all_features(feature_list) MAP(unit_test_feature, feature_list)

//typedef struct { int x; } wht2_t;
//typedef struct { int x; } wht3_t;
//declare_feature(wht);
//declare_feature(wht3);


// declare_all_features(feature_list);

#define get_usage(F) F##_usage 

#define get_usage_all_features(feature_list) MAP(get_usage, feature_list)


/*
 * START OF OLD STUFF
 */
#include <stdio.h>   /* for FILE* */
#include "output.h"

/*
 * feature_ptr is a pointer to the memory location of the
 * feature specific context for a particular flow
 *
 * if information for the feature is being gathered for a
 * particular flow, then the flow_record for that flow will contain a
 * feature_ptr for that record
 */
//typedef void *feature_ptr;

/*
 * when feature_init_func(ptr) is invoked on a pointer to a
 * pointer to the data feature, it allocates and initializes an
 * instance of the feature, and then sets the memory at the
 * location pointed to by ptr to point to that location
 *
 * return value: ok if no problem; return code otherwise (see err.h)
 * 
 * this function is called in flow_record_init()
 */
//typedef enum status (*feature_init_func)(feature_ptr *ptr);


/*
 * enum packet_status indicates whether or not more packets in the
 * flow are needed by a particular feature; some features are done
 * after the initial data packet, or after the first few packets,
 * while others may need all packets
 */
enum packet_status { 
  no_more_packets_needed = 0,  
  more_packets_needed = 1
};

/*
 * feature_update_func(feature, data, len) updates the data
 * feature stored in a flow_record, based on the packet located at
 * "data", which has length "len"
 * 
 * return value: 
 *     no_more_packets_needed  (if enough packets in flow have been seen)
 *     more_packets_needed     (otherwise)
 * 
 * this function is called in flow_record_update()
 */
//typedef enum packet_status (*feature_update_func)(feature_ptr feature, 
//						  const void *data, 
//						  unsigned int len);


/*
 * feature_print_json_func(feature, record, twin_feature,
 * twin_record) prints out a JSON representation of the data feature.
 * The twin_feature and twin_record pointers should be set to NULL if
 * a record is unidirectional, and set to the flow's twin otherwise.
 * 
 * The record and twin_record pointers are present in order to make it
 * possible for a data record to make use of the basic flow record
 * information, e.g. addresses and byte count.
 * 
 * return value: void
 * 
 * this function is called in flow_record_print_json()
 */
//typedef void (*feature_print_json_func)(const feature_ptr feature, 
//					const struct flow_record *record,
//					const feature_ptr twin_feature, 
//					const struct flow_record *twin_record, 
//					zfile f);

/*
 * nfv9_t is a handle to an Netflow v9 context
 */
//typedef void *nfv9_t;

/*
 * feature_encode_nfv9_func(feature, record, twin_feature,
 * twin_record) creates a NFv9 representation of the data feature.
 * The twin_feature and twin_record pointers should be set to NULL if
 * a record is unidirectional, and set to the flow's twin otherwise.
 * 
 * The record and twin_record pointers are present in order to make it
 * possible for a data record to make use of the basic flow record
 * information, e.g. addresses and byte count.
 * 
 * return value: void
 * 
 * this function is called in flow_record_print_json()
 */
//typedef void (*feature_encode_nfv9_json_func)(const feature_ptr feature, 
//					      const struct flow_record *record,
//					      const feature_ptr twin_feature, 
//					      const struct flow_record *twin_record, 
//					      nfv9_t nfv9_handle);

/*
 * feature_decode_nfv9_func(feature, record, twin_feature,
 * twin_record) creates a NFv9 representation of the data feature.
 * The twin_feature and twin_record pointers should be set to NULL if
 * a record is unidirectional, and set to the flow's twin otherwise.
 * 
 * The record and twin_record pointers are present in order to make it
 * possible for a data record to make use of the basic flow record
 * information, e.g. addresses and byte count.
 * 
 * return value: void
 * 
 * this function is called in nfv9_process_flow_record()
 */
//typedef void (*feature_decode_nfv9_json_func)(const feature_ptr feature, 
//					      const struct flow_record *record,
//					      nfv9_template template,
//					      const void *nfv9_data, 
//					      int record_num);


/*
 * when feature_delete_func(ptr) is invoked on a feature_ptr, it frees all
 * memory that is allocated by feature_init()
 *
 * return value: void
 * 
 * this function is called in flow_record_delete()
 */
//typedef void (*feature_delete_func)(feature_ptr *ptr);


/*
 * struct feature_class is the metaobject for the class of objects
 * pointed to by feature_ptr, in object-oriented terms
 *
 * init_func, update_func, and delete_func MUST NOT be NULL
 *
 * print_json_func, encode_nfv9_func, and decode_nfv9_func MAY be NULL
 * 
 */
//struct feature_class {
//  feature_init_func        init_func;
//  feature_update_func      update_func;
//  feature_print_json_func  print_json_func;
//  feature_delete_func      delete_func;
//  feature_encode_nfv9_func encode_nfv9_func;
//  feature_decode_nfv9_func decode_nfv9_func;
//};

/*
 * The function feature_register() registers a feature_class with the
 * main pcap2flow program, making it accessible to that program
 * 
 * return value: ok if no problem; return code otherwise (see err.h)
 *
 */
//enum status feature_register(const struct feature_class *fc);


/*
 * TBD: there needs to be an interface into the configuration
 * function, which can set and read (or print) configuration variables
 */

//typedef void (*feature_print_config_func)(FILE *f); 

/*
 * The feature_unit_test function is called by the unit_test()
 * function, which appears in a test-specific program - it is not
 * intended to be used in any production code, and it may rely on the
 * presence of external files that are only available in the source
 * code package.
 *
 * This function is invoked by the unit_test program
 * (src/unit_test.c).
 *
 */
//typedef void (*feature_unit_test)();

/*
 * The function register_feature_unit_test(feature_unit_test ft)
 * registers feature_unit_test() with the test program
 *
 */
//enum status register_feature_unit_test(feature_unit_test fut); 

/*
 * The internals behind the interface
 * 
 * The flow_record data structure has an array of feature structures,
 * as defined below.  
 *
 */
//struct feature {
//  feature_ptr ptr;
//  feature_update_func update_func;
//};



#endif /* FEATURE_H */
