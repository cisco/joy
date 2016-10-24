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

/**********************************************************
 * @file ipfix.c
 *
 * @brief Source code to perform IPFIX protocol operations.
 **********************************************************/

#include <string.h>   /* for memcpy() */
#include <stdlib.h>
#include <time.h>
#include "ipfix.h"
#include "pkt.h"
#include "http.h"
#include "tls.h"
#include "config.h"

/********************************************
 *********
 * LOGGING
 *********
 ********************************************/
/** select destination for printing out information
 *
 ** TO_SCREEN = 0 for 'info' file
 *
 **  TO_SCREEN = 1 for 'stderr'
 */
#define TO_SCREEN 0

/** used to print out information during ipfix execution
 *
 ** print_dest will either be assigned to 'stderr' or 'info' file
 *  depending on the TO_SCREEN setting.
 */
static FILE *print_dest = NULL;

/** sends information to the destination output device */
#define loginfo(...) { \
        if (TO_SCREEN) print_dest = stderr; else print_dest = info; \
        fprintf(print_dest,"%s: ", __FUNCTION__); \
        fprintf(print_dest, __VA_ARGS__); \
        fprintf(print_dest, "\n"); }


#define CTS_MONITOR_INTERVAL (30)
#define CTS_EXPIRE_TIME (1800) /* 30 minutes */
//static pthread_mutex_t cts_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Doubly linked list for collector template store (cts).
 */
#define MAX_IPFIX_TEMPLATES 100
struct ipfix_template *collect_template_store_head = NULL;
struct ipfix_template *collect_template_store_tail = NULL;
uint16_t cts_count = 0;


/*
 * External objects, defined in pcap2flow
 */
extern unsigned int include_tls;
extern struct configuration config;
define_all_features_config_extern_uint(feature_list);


/*
 * Local ipfix.c prototypes
 */
static int ipfix_cts_search(struct ipfix_template_key needle,
                            struct ipfix_template **dest_template,
                            int flag_renew);


static inline struct ipfix_template *ipfix_template_malloc(size_t field_list_size);


static int ipfix_cts_append(struct ipfix_template tmp);


static int ipfix_loop_data_fields(const unsigned char *data_ptr,
                                  struct ipfix_template *cur_template,
                                  uint16_t *min_record_len);


static void ipfix_flow_key_init(struct flow_key *key,
                                const struct ipfix_template *cur_template,
                                const void *flow_data);


static void ipfix_template_key_init(struct ipfix_template_key *k,
                                    uint32_t addr,
                                    uint32_t id,
                                    uint16_t template_id);


static int ipfix_process_flow_sys_up_time(const void *flow_data,
                                          struct flow_record *ix_record,
                                          int flag_end);


static int ipfix_skip_idp_header(struct flow_record *nf_record,
                                 const unsigned char **payload,
                                 unsigned int *size_payload);

static void ipfix_process_flow_record(struct flow_record *ix_record,
                               const struct ipfix_template *cur_template,
                               const void *flow_data,
                               int record_num);


/*
 * @brief Free an allocated template structure.
 *
 * First free the attached fields memory. Then free the template memory.
 *
 * @param template IPFIX template that will have it's heap memory freed.
 */
static inline void ipfix_delete_template(struct ipfix_template *template) {
  if (template == NULL) {
    loginfo("api-error: template is null");
    return;
  }

  if (template->fields) {
    uint16_t field_count = template->hdr.field_count;
    size_t field_list_size = sizeof(struct ipfix_template_field) * field_count;
    memset(template->fields, 0, field_list_size);
    free(template->fields);
  }

  memset(template, 0, sizeof(struct ipfix_template));
  free(template);
}


/*
 * @brief Delete a template from the collector template store (cts).
 *
 * The heap memory that was allocated for the fields will first be freed,
 * and then the template itself will be destroyed.
 *
 * WARNING: the mutex lock (cts_lock) for the collector template store
 * MUST be aquired before invoking this function.
 *
 * @param template IPFIX template that will be deleted from the cts.
 */
static void ipfix_cts_delete(struct ipfix_template *template) {
  struct ipfix_template *prev_template = NULL;
  struct ipfix_template *next_template = NULL;

  prev_template = template->prev;
  next_template = template->next;

  /*
   * Update neighbor template pointers.
   */
  if (prev_template && next_template) {
    /* Both previous and next template exists */
    prev_template->next = next_template;
    next_template->prev = prev_template;
  } else if (prev_template) {
    /* Looking at tail of list */
    prev_template->next = NULL;
    collect_template_store_tail = prev_template;
  } else if (next_template) {
    /* Looking at head of list */
    next_template->prev = NULL;
    collect_template_store_head = next_template;
  } else {
    /* Only 1 template in list, need to set head and tail to NULL */
    collect_template_store_tail = NULL;
    collect_template_store_head = NULL;
  }

  ipfix_delete_template(template); 

  /* Decrement the store count */
  cts_count -= 1;
}


/*
 * @brief Scan IPFIX collector template store (cts) for expired.
 *
 * Go through the cts looking for any templates that have not
 * been refreshed within the configured expire time.
 *
 * WARNING: the mutex lock (cts_lock) for the collector template store
 * MUST be aquired before invoking this function.
 *
 * @return >0 for number of records expired, 0 for none
 */
static int ipfix_cts_scan_expired(void) {
  time_t current_time = time(NULL);
  struct ipfix_template *cur_template;
  struct ipfix_template *next_template;
  int rc = 0;

  //pthread_mutex_lock(&cts_lock);
  if (collect_template_store_head == NULL) {
    //pthread_mutex_unlock(&cts_lock);
    return rc;
  }

  cur_template = collect_template_store_head;
  next_template = cur_template->next;
  if ((current_time - cur_template->last_seen) > CTS_EXPIRE_TIME) {
    /* The template is expired, remove from store */
    ipfix_cts_delete(cur_template);
    rc += 1;
  }

  while (next_template) {
    cur_template = next_template;
    next_template = cur_template->next;
    if ((current_time - cur_template->last_seen) > CTS_EXPIRE_TIME) {
      /* The template is expired, remove from store */
      ipfix_cts_delete(cur_template);
      rc += 1;
    }
  }
  //pthread_mutex_unlock(&cts_lock);

  return rc;
}


/*
 * @brief Monitor the collector template store (cts) running
 *        as a thread off of pcap2flow.
 *
 * Monitoring is only active during live processing runs.
 * Monitor terminates automatically when pcap2flow exits due
 * to the nature of how pthreads work.
 *
 * @param ptr Always NULL and not used, part of function
 *            prototype for pthread_create.
 *
 * @return Never return and the thread terminates when pcap2flow exits.
 */
void *ipfix_cts_monitor(void *ptr) {
  uint16_t num_expired;
  while (1) {
    /* let's only wake up and do work at specific intervals */
    num_expired = ipfix_cts_scan_expired();
    if (!num_expired) {
      loginfo("No templates were expired.");
    } else {
      loginfo("%d templates were expired.", num_expired);
    }

    sleep(CTS_MONITOR_INTERVAL);
  }
}


/*
 * @brief Compare a pair of ipfix template keys.
 *
 * @param a First IPFIX template key.
 * @param b Second IPFIX template key.
 *
 * @return 1 if match, 0 if not match
 */
static inline int ipfix_template_key_cmp(const struct ipfix_template_key a,
                                         const struct ipfix_template_key b) {
  if (a.observe_dom_id == b.observe_dom_id &&
      a.template_id == b.template_id &&
      a.exporter_addr.s_addr == b.exporter_addr.s_addr) {
    return 1;
  } else {
    return 0;
  }
}


/*
 * @brief Renew a template.
 *
 * Set the last_seen field within the /p template to the current time.
 *
 * @param template IPFIX template that will be renewed.
 */
static inline void ipfix_cts_template_renewal(struct ipfix_template *template) {
  template->last_seen = time(NULL);
}


/*
 * @brief Free all templates that exist in the collector template store (cts).
 *
 * Any ipfix_template structures that currently remain within the CTS will
 * be zeroized and have their heap memory freed.
 *
 * NOTE: The collector template store (cts) mutex lock (cts_lock) will be
 * acquired while this cleanup function executes.
 */
void ipfix_cts_cleanup(void) {
  struct ipfix_template *this_template;
  struct ipfix_template *next_template;

  //pthread_mutex_lock(&cts_lock);
  if (collect_template_store_head == NULL) {
    //pthread_mutex_unlock(&cts_lock);
    return;
  }

  this_template = collect_template_store_head;
  next_template = this_template->next;

  /* Free the first stored template */
  ipfix_cts_delete(this_template);

  while (next_template) {
    this_template = next_template;
    next_template = this_template->next;

    ipfix_cts_delete(this_template);
  }
  //pthread_mutex_unlock(&cts_lock);
}


/*
 * @brief Copy a template from the store list into a new template.
 *
 * Using /p as the template from the store, copy it's contents
 * into a newly allocated template that is totally independent.
 * The user of the new template can modify it however they wish,
 * with no impact to the original store template.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 */
static void ipfix_cts_copy(struct ipfix_template **dest_template,
                           struct ipfix_template *src_template) {
  uint16_t field_count = src_template->hdr.field_count;
  size_t field_list_size = sizeof(struct ipfix_template_field) * field_count;
  struct ipfix_template_field *new_fields = NULL;
  struct ipfix_template *new_template = NULL;

  if (dest_template == NULL || src_template == NULL) {
    loginfo("api-error: dest or src template is null");
    return;
  }

  /* Allocate heap memory for new_template */
  new_template = ipfix_template_malloc(field_list_size);

  /* Save pointer to new_template field memory */
  new_fields = new_template->fields;

  memcpy(new_template, src_template, sizeof(struct ipfix_template));

  /* Reattach new_fields */
  new_template->fields = new_fields;

  /* New template is a copy, so it isn't part of the store */
  new_template->next = NULL;
  new_template->prev = NULL;

  /* Copy the fields data */
  if (src_template->fields && new_template->fields) {
    memcpy(new_template->fields, src_template->fields, field_list_size);
  }

  /* Assign dest_template handle to newly allocated template */
  *dest_template = new_template;
}


/*
 * @brief Search the IPFIX collector template store (cts) for a match.
 *
 * Using the /p needle template, search through the store list
 * to find whether an identical template exists in the store
 * already.
 *
 * @param needle IPFIX template that will be searched for.
 * @param dest_template IPFIX template that will have match contents
 *                      copied into.
 * @param flag_renew Controls whether a matched template should have it's
 *                   last_seen time refreshed. Use 1 to enable renewal.
 *
 * @return 1 for match, 0 for not match
 */
static int ipfix_cts_search(struct ipfix_template_key needle,
                            struct ipfix_template **dest_template,
                            int flag_renew) {
  struct ipfix_template *cur_template;

  //pthread_mutex_lock(&cts_lock);
  if (collect_template_store_head == NULL) {
    //pthread_mutex_unlock(&cts_lock);
    return 0;
  }

  cur_template = collect_template_store_head;
  if (ipfix_template_key_cmp(cur_template->template_key, needle)) {
    /* Found match */
    if (flag_renew == 1) {
      ipfix_cts_template_renewal(cur_template);
    }
    if (dest_template != NULL) {
      ipfix_cts_copy(dest_template, cur_template);
    }
    //pthread_mutex_unlock(&cts_lock);
    return 1;
  }

  while (cur_template->next) {
    cur_template = cur_template->next;
    if (ipfix_template_key_cmp(cur_template->template_key, needle)) {
      /* Found match */
      if (flag_renew == 1) {
        ipfix_cts_template_renewal(cur_template);
      }
      if (dest_template != NULL) {
        ipfix_cts_copy(dest_template, cur_template);
      }
      //pthread_mutex_unlock(&cts_lock);
      return 1;
    }
  }
  //pthread_mutex_unlock(&cts_lock);

  return 0;
}


/*
 * @brief Allocate heap memory for a sequence of fields.
 *
 * @param template IPFIX template which will have allocated memory
 *                 attached to it via pointer.
 */
static inline void ipfix_template_fields_malloc(struct ipfix_template *template,
                                                size_t field_list_size) {
  template->fields = malloc(field_list_size);
  memset(template->fields, 0, field_list_size);
}


static inline struct ipfix_template *ipfix_template_malloc(size_t field_list_size) {
  /* Init a new template on the heap */
  struct ipfix_template *template = malloc(sizeof(struct ipfix_template));
  memset(template, 0, sizeof(struct ipfix_template));

  /* Allocate memory for the fields */
  ipfix_template_fields_malloc(template, field_list_size);

  return template;
}


/*
 * @brief Append to the collector template store (cts).
 *
 * Create a new template on the heap, and copy the key, hdr, and fields
 * from the template /p tmp. The timestamp of last_seen will be calculated
 * and attached to the newly allocated template.
 *
 * @return 0 if templates was added, 1 if template was not added.
 */
static int ipfix_cts_append(struct ipfix_template tmp) {
  uint16_t field_count = tmp.hdr.field_count;
  size_t field_list_size = sizeof(struct ipfix_template_field) * field_count;
  struct ipfix_template *template = NULL;

  if (cts_count >= (MAX_IPFIX_TEMPLATES - 1)) {
    loginfo("warning: ipfix template lost, already at maximum storage threshold");
    return 1;
  }

  /* Init a new template on the heap */
  template = ipfix_template_malloc(field_list_size);

  /* Copy the atrribute data */
  template->template_key = tmp.template_key;
  template->hdr = tmp.hdr;
  memcpy(template->fields, tmp.fields, field_list_size);
  template->payload_length = tmp.payload_length;

  /* Write the current time */
  template->last_seen = time(NULL);

  //pthread_mutex_lock(&cts_lock);
  if (collect_template_store_head == NULL) {
    /* This is the first template in store list */
    collect_template_store_head = template;
  } else {
    /* Append to the end of store list */
    collect_template_store_tail->next = template;
    template->prev = collect_template_store_tail;
  }

  /* Update the tail */
  collect_template_store_tail = template;

  /* Increment the store count */
  cts_count += 1;
  //pthread_mutex_unlock(&cts_lock);

  return 0;
}


/*
 * @brief Construct a flow key corresponding to an IPFIX data record.
 *
 * Create a flow key that can be used to either lookup an existing
 * flow record, or in the process of making a new flow record for
 * storage of the IPFIX data. Note, usage of the function assumes
 * that the \p cur_template contains variable lengths related to
 * fields where necessary.
 *
 * @param key Flow key to be filled in with 5-tuple identifier.
 * @param cur_template IPFIX template that corresponds to data record.
 * @param flow_data IPFIX data record being parsed.
 */
static void ipfix_flow_key_init(struct flow_key *key,
                         const struct ipfix_template *cur_template,
                         const void *flow_data) {
  int i;
  for (i = 0; i < cur_template->hdr.field_count; i++) {
    uint16_t field_length = 0;

    if (cur_template->fields[i].variable_length) {
      field_length = cur_template->fields[i].variable_length;
    } else {
      field_length = cur_template->fields[i].fixed_length;
    }

    switch (cur_template->fields[i].info_elem_id) {
      case IPFIX_SOURCE_IPV4_ADDRESS:
        key->sa.s_addr = *(const uint32_t *)flow_data;
        flow_data += field_length;
        break;
      case IPFIX_DESTINATION_IPV4_ADDRESS:
        key->da.s_addr = *(const uint32_t *)flow_data;
        flow_data += field_length;
        break;
      case IPFIX_SOURCE_TRANSPORT_PORT:
        key->sp = ntohs(*(const uint16_t *)flow_data);
        flow_data += field_length;
        break;
      case IPFIX_DESTINATION_TRANSPORT_PORT:
        key->dp = ntohs(*(const uint16_t *)flow_data);
        flow_data += field_length;
        break;
      case IPFIX_PROTOCOL_IDENTIFIER:
        key->prot = *(const uint8_t *)flow_data;
        flow_data += field_length;
        break;
      default:
        flow_data += field_length;
        break;
    }
  }
}


/*
 * @brief Initialize an IPFIX template key.
 *
 * Initialize a template key for use by the IPFIX Collector to uniquely
 * identify templates that it encounters.
 *
 * @param k IPFIX template key structure that will be initialized.
 * @param addr Exporter IP address.
 * @param id Exporter observation domain id.
 * @param template_id Template id contained in the template header.
 */
static void ipfix_template_key_init(struct ipfix_template_key *k,
                                    uint32_t addr,
                                    uint32_t id,
                                    uint16_t template_id) {
  memset(k, 0, sizeof(struct ipfix_template_key));
  k->exporter_addr.s_addr = addr;
  k->observe_dom_id = id;
  k->template_id = template_id;
}


/*
 * @brief Parse through the contents of an IPFIX Template Set.
 *
 * @param ipfix The IPFIX message header.
 * @param template_start Beginning of the template set.
 * @param set_len Total length of the template set measured in octets. 
 * @param rec_key Flow key generated upstream in process_packet()
 *                corresponding to the packet capture.
 *
 * @return 0 for success, 1 for failure
 */
int ipfix_parse_template_set(const struct ipfix_hdr *ipfix,
                             const void *template_start,
                             uint16_t set_len,
                             const struct flow_key rec_key) {

  const void *template_ptr = template_start;
  uint16_t template_set_len = set_len;

  while (template_set_len > 0) {
    const struct ipfix_template_hdr *template_hdr = template_ptr;
    template_ptr += 4; /* Move past template header */
    template_set_len -= 4;
    uint16_t template_id = ntohs(template_hdr->template_id);
    uint16_t field_count = ntohs(template_hdr->field_count);
    struct ipfix_template cur_template = {0};
    struct ipfix_template_key template_key;
    int cur_template_pld_len = 0;
    struct ipfix_template *redundant_template = NULL;
    struct ipfix_template_field stack_fields[field_count];
    int i;

    /*
     * Define Template Set key:
     * {source IP + observation domain ID + template ID}
     */
    ipfix_template_key_init(&template_key, rec_key.sa.s_addr,
                            ntohl(ipfix->observe_dom_id), template_id);

    /* Check to see if template already exists, if so, continue */
    if (ipfix_cts_search(template_key, &redundant_template, 1)) {
      template_ptr += redundant_template->payload_length;
      template_set_len -= redundant_template->payload_length;
      /* Need to free the allocated temporary template */
      ipfix_delete_template(redundant_template);
      continue;
    }

    /* Assign the stack fields array to current template for
     * automatic cleanup */
    cur_template.fields = stack_fields;

    /*
     * The enterprise field may or may not exist for certain fields
     * within the payload, so we need to walk the entire template.
     */
    for (i = 0; i < field_count; i++) {
      int fld_size = 4;
      const struct ipfix_template_field *tmp_field = template_ptr;
      const unsigned short host_info_elem_id = ntohs(tmp_field->info_elem_id);
      const unsigned short host_fixed_length = ntohs(tmp_field->fixed_length);

      if (ipfix_field_enterprise_bit(host_info_elem_id)) {
        /* The enterprise bit is set, remove from element id */
        cur_template.fields[i].info_elem_id = host_info_elem_id ^ 0x8000;
        cur_template.fields[i].enterprise_num = ntohl(tmp_field->enterprise_num);
        fld_size = 8;
      } else {
        cur_template.fields[i].info_elem_id = host_info_elem_id;
      }

      cur_template.fields[i].fixed_length = host_fixed_length;

      template_ptr += fld_size;
      template_set_len -= fld_size;
      cur_template_pld_len += fld_size;
    }

    /* The template is new, so save info */
    cur_template.hdr.template_id = template_id;
    cur_template.hdr.field_count = field_count;
    cur_template.payload_length = cur_template_pld_len;
    cur_template.template_key = template_key;

    /* Save template */
    ipfix_cts_append(cur_template);
  }

  return 0;
}


/*
 * @brief Loop through the info fields in a single data record.
 *
 * Calculate the size of the data record that \p data_ptr is pointing to.
 * The \p cur_template dictates how many information fields exist, and
 * it is also used to strore any variable lengths. Note, any existing
 * value in the variable length field will be overwritten by the new value
 * that corresponds to this particular data record.
 *
 * Additionally, if the value of /p min_record_len is 0, it will be filled
 * in (by reference) with the minimum valid data record size.
 *
 * @param data_ptr Pointer to the IPFIX data record.
 * @param cur_template IPFIX template used for data record interpretation.
 * @param min_record_len Used to hold minimum size of a valid data record.
 *
 * @return 0 for failure, >0 for success
 */
static int ipfix_loop_data_fields(const unsigned char *data_ptr,
                                  struct ipfix_template *cur_template,
                                  uint16_t *min_record_len) {
  int i;
  int flag_min_record = 0;
  int data_record_size = 0;
  uint16_t data_field_count = cur_template->hdr.field_count;

  if (*min_record_len == 0) {
    flag_min_record = 1;
  }

  for (i = 0; i < data_field_count; i++) {
    int variable_length_hdr = 0;
    uint16_t actual_fld_len = 0;
    uint16_t min_field_len = 0;
    uint16_t cur_fld_len = cur_template->fields[i].fixed_length;
    if (cur_fld_len == 65535) {
      /* The current field is of variable length */
      unsigned char fld_len_flag = (unsigned char)*data_ptr;
      if (fld_len_flag < 255) {
        actual_fld_len = (unsigned short)fld_len_flag;
        /* Fill in the variable length field in global template list */
        cur_template->fields[i].variable_length = actual_fld_len;
        /* RFC 7011 section 7, Figure R. */
        cur_template->fields[i].var_hdr_length = 1;
        variable_length_hdr += 1;
        min_field_len = 1;
      } else if (fld_len_flag == 255) {
        actual_fld_len = ntohs(*(unsigned short *)(data_ptr + 1));
        /* Fill in the variable length field in global template list */
        cur_template->fields[i].variable_length = actual_fld_len;
        /* RFC 7011 section 7, Figure S. */
        cur_template->fields[i].var_hdr_length = 3;
        variable_length_hdr += 3;
        min_field_len = 3;
      } else {
        /* Error, invalid variable length */
        loginfo("error: bad variable length");
        return 0;
      }
    } else {
      /* Fixed length field */
      actual_fld_len = cur_fld_len;
      min_field_len = actual_fld_len;
    }

    if (flag_min_record) {
      *min_record_len += min_field_len;
    }
    data_ptr += actual_fld_len + variable_length_hdr;
    data_record_size += actual_fld_len + variable_length_hdr;
  }
  return data_record_size;
}


/*
 * @brief Parse through the contents of an IPFIX Data Set.
 *
 * @param ipfix The IPFIX message header.
 * @param template_start Beginning of the data set.
 * @param set_len Total length of the data set measured in octets.
 * @param set_id I.d. of Template to be used for interpreting data set.
 * @param rec_key Flow key generated upstream in process_packet()
 *                corresponding to the packet capture.
 * @param prev_data_key Previous flow key that was created for preceding
 *                      data record. This is a handle to the variable
 *                      sitting on process_ipfix() stack memory.
 *
 * @param 0 for success, 1 for failure
 */
int ipfix_parse_data_set(const struct ipfix_hdr *ipfix,
                         const void *data_start,
                         uint16_t set_len,
                         uint16_t set_id,
                         const struct flow_key rec_key,
                         struct flow_key *prev_data_key) {

  const unsigned char *data_ptr = data_start;
  uint16_t data_set_len = set_len;
  uint16_t template_id = set_id;
  struct ipfix_template_key template_key;
  struct ipfix_template *cur_template = NULL;
  uint16_t min_record_len = 0;
  int rc = 1;

  /* Define data template key:
   * {source IP + observation domain ID + template ID}
   */
  ipfix_template_key_init(&template_key, rec_key.sa.s_addr,
                          ntohl(ipfix->observe_dom_id), template_id);

  /* Look for template match */
  ipfix_cts_search(template_key, &cur_template, 0);

  /* Process data if we know the template */
  if (cur_template->hdr.template_id != 0) {
    struct flow_key key;
    struct flow_record *ix_record;

    /* Process all data records in set */
    while (data_set_len > min_record_len){
      int data_record_size = 0;
      /*
       * Get the size of this data record, and store field variable lengths
       * in the current template.
       */
      if(!(data_record_size = ipfix_loop_data_fields(data_ptr, cur_template,
                                                     &min_record_len))){
        goto cleanup;
      }

      /* Init flow key */
      ipfix_flow_key_init(&key, cur_template, data_ptr);

      /* Get a flow record related to ipfix data */
      ix_record = flow_key_get_record(&key, CREATE_RECORDS);

      /* Fill out record */
      if (memcmp(&key, prev_data_key, sizeof(struct flow_key)) != 0) {
        ipfix_process_flow_record(ix_record, cur_template, data_ptr, 0);
      } else {
        ipfix_process_flow_record(ix_record, cur_template, data_ptr, 1);
      }
      memcpy(prev_data_key, &key, sizeof(struct flow_key));

      data_ptr += data_record_size;
      data_set_len -= data_record_size;
    }
  } else {
    /* FIXME hold onto the data set for a certain amount of time since
     * the template may come later... */
    loginfo("error: current template is null, cannot parse the data set");
  }

  rc = 0;

  /* Cleanup */
cleanup:
  if (cur_template) {
    ipfix_delete_template(cur_template);
  }

  return rc;
}


/*
 * @brief Skip past L3/L4 header contained within the IDP flow data.
 *
 * @param ix_record IPFIX flow record being encoded, contains total IDP flow
 *        data originating from exporter.
 * @param payload Will be assigned address of payload data that comes
 *        immediately after protocol headers.
 * @param size_payload Handle for external unsigned integer
 *        that will store length of the payload data.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_skip_idp_header(struct flow_record *ix_record,
                                 const unsigned char **payload,
                                 unsigned int *size_payload) {
  unsigned char proto = 0;
  const struct ip_hdr *ip;
  unsigned int ip_hdr_len;
  const void *flow_data = ix_record->idp;
  unsigned int flow_len = ix_record->idp_len;

  /* define/compute ip header offset */
  ip = (struct ip_hdr*)(flow_data);
  ip_hdr_len = ip_hdr_length(ip);
  if (ip_hdr_len < 20) {
    /*
     * FIXME Does not handle packets with all 0s.
     */
    loginfo("error: invalid ip header of len %d", ip_hdr_len);
    return 1;
  }

  if (ntohs(ip->ip_len) < sizeof(struct ip_hdr)) {
    /* IP packet is malformed (shorter than a complete IP header) */
    loginfo("error: ip packet malformed, ip_len: %d", ntohs(ip->ip_len));
    return 1;
  }

  proto = ix_record->key.prot;

  if (proto == IPPROTO_ICMP) {
    unsigned int icmp_hdr_len = 8;

    if (icmp_hdr_len > (flow_len - ip_hdr_len)) {
      loginfo("error: not enough space in payload for icmp hdr");
      return 1;
    }
    /* define/compute icmp payload (segment) offset */
    *payload = (unsigned char *)(flow_data + ip_hdr_len + icmp_hdr_len);

    /* compute icmp payload (segment) size */
    *size_payload = flow_len - ip_hdr_len - icmp_hdr_len;
  } else if (proto == IPPROTO_TCP) {
    unsigned int tcp_hdr_len;
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(flow_data + ip_hdr_len);
    tcp_hdr_len = tcp_hdr_length(tcp);

    if (tcp_hdr_len < 20 || tcp_hdr_len > (flow_len - ip_hdr_len)) {
      loginfo("error: invalid tcp hdr length");
      return 1;
    }
    /* define/compute tcp payload (segment) offset */
    *payload = (unsigned char *)(flow_data + ip_hdr_len + tcp_hdr_len);

    /* compute tcp payload (segment) size */
    *size_payload = flow_len - ip_hdr_len - tcp_hdr_len;
  } else if (proto == IPPROTO_UDP) {
    unsigned int udp_hdr_len = 8;

    /* define/compute udp payload (segment) offset */
    *payload = (unsigned char *)(flow_data + ip_hdr_len + udp_hdr_len);

    /* compute udp payload (segment) size */
    *size_payload = flow_len - ip_hdr_len - udp_hdr_len;
  } else {
    loginfo("error: transport protocol not supported");
    return 1;
  }

  return 0;
}


/*
 * @brief Process the flow's start or ending system up time.
 *
 * @param flow_data Contains the exported start/end system up time.
 * @param ix_record IPFIX flow record being encoded.
 * @param flag_end Signals whether the end or start time is being encoded.
 *        0 for start, 1 for end, anything else is invalid.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_process_flow_sys_up_time(const void *flow_data,
                                          struct flow_record *ix_record,
                                          int flag_end) {
  struct timeval *time;
  switch (flag_end) {
    case 0:
      time = &ix_record->start;
      break;
    case 1:
      time = &ix_record->end;
      break;
    default:
      loginfo("api-error: invalid value for flag_end, must be 0 or 1");
      return 1;
  }
  if (time->tv_sec + time->tv_usec == 0) {
    time->tv_sec =
      (time_t)((uint32_t)(ntohl(*(const uint32_t *)flow_data) / 1000));

    time->tv_usec =
      (time_t)((uint32_t)ntohl(*(const uint32_t *)flow_data) % 1000)*1000;
  }
  return 0;
}


static void ipfix_process_flow_record(struct flow_record *ix_record,
                               const struct ipfix_template *cur_template,
                               const void *flow_data,
                               int record_num) {
  //struct timeval old_val_time;
  //unsigned int total_ms;
  const void *flow_ptr = flow_data;
  const unsigned char *payload = NULL;
  unsigned int size_payload = 0;
  struct flow_record *record = ix_record;
  struct flow_key *key = &ix_record->key;
  int i, j;

  for (i = 0; i < cur_template->hdr.field_count; i++) {
    uint16_t field_length = 0;
    flow_data = flow_ptr;

    if (cur_template->fields[i].variable_length) {
      /* Get variable length and move just beyond it */
      field_length = cur_template->fields[i].variable_length;
      flow_data += cur_template->fields[i].var_hdr_length;
    } else {
      /* Field length is fixed */
      field_length = cur_template->fields[i].fixed_length;
    }

    switch (cur_template->fields[i].info_elem_id) {
      case IPFIX_PACKET_DELTA_COUNT:
        if (record_num == 0) {
          if (cur_template->fields[i].fixed_length == 4) {
            ix_record->np += ntohl(*(const uint32_t *)(flow_data));
          } else {
            ix_record->np +=
              __builtin_bswap64(*(const uint64_t *)(flow_data)); /*FIXME*/
          }
        }

        flow_ptr += field_length;
        break;

      case IPFIX_FLOW_START_SYS_UP_TIME:
        ipfix_process_flow_sys_up_time(flow_data, ix_record, 0);

        flow_ptr += field_length;
        break;

      case IPFIX_FLOW_END_SYS_UP_TIME:
        ipfix_process_flow_sys_up_time(flow_data, ix_record, 1);

        flow_ptr += field_length;
        break;
#if 0
      case TLS_SRLT:
        total_ms = 0;
        for (j = 0; j < 20; j++) {
          if (htons(*(const short *)(flow_data+j*2)) == 0) {
            break;
          }

          ix_record->tls_info.tls_len[j] = ntohs(*(const unsigned short *)(flow_data+j*2));

          ix_record->tls_info.tls_time[j].tv_sec =
            (total_ms+ntohs(*(const unsigned short *)(flow_data+40+j*2))
            +ix_record->start.tv_sec*1000+ix_record->start.tv_usec/1000)/1000;

          ix_record->tls_info.tls_time[j].tv_usec =
            ((total_ms+ntohs(*(const unsigned short *)(flow_data+40+j*2))
            +ix_record->start.tv_sec*1000+ix_record->start.tv_usec/1000)%1000)*1000;

          total_ms += htons(*(const unsigned short *)(flow_data+40+j*2));

          ix_record->tls_info.tls_type[j].content = *(const unsigned char *)(flow_data+80+j);
          ix_record->tls_info.tls_type[j].handshake = *(const unsigned char *)(flow_data+100+j);
          ix_record->tls_info.tls_op += 1;
        }

        flow_data += field_length;
        break;

      case TLS_CS:
        for (j = 0; j < 125; j++) {
          if (ntohs(*(const uint16_t *)(flow_data+j*2)) == 65535) {
            break;
          }
          ix_record->tls_info.ciphersuites[j] = ntohs(*(const uint16_t *)(flow_data+j*2));
          ix_record->tls_info.num_ciphersuites += 1;
        }

        flow_data += field_length;
        break;

      case TLS_EXT:
        for (j = 0; j < 35; j++) {
          if (htons(*(const short *)(flow_data+j*2)) == 0) {
            break;
          }
          ix_record->tls_info.tls_extensions[j].length = ntohs(*(const unsigned short *)(flow_data+j*2));
          ix_record->tls_info.tls_extensions[j].type = ntohs(*(const unsigned short *)(flow_data+70+j*2));
          ix_record->tls_info.tls_extensions[j].data = NULL;
          ix_record->tls_info.num_tls_extensions += 1;
        }

        flow_data += field_length;
        break;

      case TLS_VERSION:
        ix_record->tls_info.tls_v = *(const uint8_t *)flow_data;
        flow_data += field_length;
        break;

      case TLS_CLIENT_KEY_LENGTH:
        ix_record->tls_info.tls_client_key_length = ntohs(*(const uint16_t *)flow_data);
        flow_data += field_length;
        break;

      case TLS_SESSION_ID:
        ix_record->tls_info.tls_sid_len = ntohs(*(const uint16_t *)flow_data);
        ix_record->tls_info.tls_sid_len = min(ix_record->tls_info.tls_sid_len,256);
        memcpy(ix_record->tls_info.tls_sid, flow_data+2, ix_record->tls_info.tls_sid_len);
        flow_data += field_length;
        break;

      case TLS_HELLO_RANDOM:
        memcpy(ix_record->tls_info.tls_random, flow_data, 32);
        flow_data += field_length;
        break;
#endif
      case IPFIX_IDP:
        ix_record->idp_len = field_length;
        ix_record->idp = malloc(ix_record->idp_len);
        memcpy(ix_record->idp, flow_data, ix_record->idp_len);

        /* Get the start of IDP packet payload */
        if (ipfix_skip_idp_header(ix_record, &payload, &size_payload)) {
          /* Error skipping idp header */
          flow_ptr += field_length;
          break;
        }

        /* If packet has port 443 and nonzero data length, process it as TLS */
        if (include_tls && size_payload && (key->sp == 443 || key->dp == 443)) {
          struct timeval ts = {0}; /* Zeroize temporary timestamp */
          process_tls(ts, payload, size_payload, &record->tls_info);
        }

        /* If packet has port 80 and nonzero data length, process it as HTTP */
        if (config.http && size_payload && (key->sp == 80 || key->dp == 80)) {
          http_update(&record->http_data, payload, size_payload, config.http);
        }

        /* Update all enabled feature modules */
        update_all_features(feature_list);
        flow_ptr += field_length;
        break;
#if 0
      case SPLT:
      case SPLT_NGA: ;
        int max_length_array = (int)ntohs(cur_template->fields[i].FieldLength)/2;
        const void *length_data = flow_data;
        const void *time_data = flow_data + max_length_array;

        int pkt_len_index = ix_record->op;
        int pkt_time_index = ix_record->op;

        /* Process the lengths array in the SPLT data */
        nfv9_process_lengths(ix_record, length_data,
                             max_length_array, pkt_len_index);

        /* Initialize the time <- this is where we should use the ipfix timestamp */
        if (pkt_time_index > 0) {
          old_val_time.tv_sec = ix_record->pkt_time[pkt_time_index-1].tv_sec;
          old_val_time.tv_usec = ix_record->pkt_time[pkt_time_index-1].tv_usec;
        } else {
          old_val_time.tv_sec = ix_record->start.tv_sec;
          old_val_time.tv_usec = ix_record->start.tv_usec;
        }

        // process the times array in the SPLT data
        nfv9_process_times(ix_record, time_data, &old_val_time,
                           max_length_array, pkt_time_index);

        flow_data += field_length;
        break;
#endif
      case IPFIX_BYTE_DISTRIBUTION: ;
        int bytes_per_val = field_length/256;
        for (j = 0; j < 256; j++) {
          /* 1 byte vals */
          if (bytes_per_val == 1) {
            ix_record->byte_count[j] = (int)*(const uint8_t *)(flow_data+j*bytes_per_val);
          }
          /* 2 byte vals */
          else if (bytes_per_val == 2) {
            ix_record->byte_count[j] = ntohs(*(const uint16_t *)(flow_data+j*bytes_per_val));
          }
          /* 4 byte vals */
          else {
            ix_record->byte_count[j] = ntohl(*(const uint32_t *)(flow_data+j*bytes_per_val));
          }
        }

        flow_ptr += field_length;
        break;

      default:
        flow_ptr += field_length;
        break;
    }
  }
}

