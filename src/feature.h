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
 * files of the pcap2flow program.  A new feature is added by
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

#include <stdio.h>   /* for FILE* */
#include "output.h"
#include "err.h"


/*
 * feature_ptr is a pointer to the memory location of the
 * feature specific context for a particular flow
 *
 * if information for the feature is being gathered for a
 * particular flow, then the flow_record for that flow will contain a
 * feature_ptr for that record
 */
typedef void *feature_ptr;

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
typedef enum status (*feature_init_func)(feature_ptr *ptr);


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
typedef enum packet_status (*feature_update_func)(feature_ptr feature_ptr, 
						       const void *data, 
						       unsigned int len);


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
typedef void (*feature_print_json_func)(const feature_ptr feature_ptr, 
					const struct flow_record *record,
					const feature_ptr twin_feature_ptr, 
					const struct flow_record *twin_record, 
					zfile f);


typedef void (*feature_print_config_func)(FILE *f); 

/*
 * struct feature_class is the metaobject for the class of objects
 * pointed to by feature_ptr, in object-oriented terms
 */

struct feature_class {
  feature_init_func init_func;
  feature_update_func update_func;
  feature_print_json_func print_json_func;
};

/*
 * The function feature_register() registers a feature_class with the
 * main pcap2flow program, making it accessible to that program
 * 
 * return value: ok if no problem; return code otherwise (see err.h)
 *
 */
enum status feature_register(const struct feature_class *fc);


/*
 * TBD: there needs to be an interface into the configuration
 * function, which can set and read (or print) configuration variables
 */

/*
 * The feature_unit_test function is called by the unit_test()
 * function, which appears in a test-specific program - it is not
 * intended to be used in any production code, and it may rely on the
 * presence of external files that are only available in the source
 * code package.
 *
 */
typedef void (*feature_unit_test)();

/*
 * The function register_feature_unit_test(feature_unit_test ft)
 * registers feature_unit_test() with the test program
 *
 */
enum status register_feature_unit_test(feature_unit_test fut); 

/*
 * The internals behind the interface
 * 
 * The flow_record data structure has an array of feature structures,
 * as defined below.  
 *
 */
  
struct feature {
  feature_ptr ptr;
  feature_update_func update_func;
};



#endif /* FEATURE_H */
