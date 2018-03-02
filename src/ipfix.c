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
#include <unistd.h>
#include <string.h>   /* for memcpy() */
#include <stdlib.h>
#include <time.h>

#ifdef WIN32
#include <unistd.h>
#include "Ws2tcpip.h"
#else
#include <netdb.h>
#endif

#include <openssl/rand.h>
#include "ipfix.h"
#include "pkt.h"
#include "http.h"
#include "tls.h"
#include "pkt_proc.h"
#include "p2f.h"
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
#define TO_SCREEN 1

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
static pthread_mutex_t cts_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Doubly linked list for collector template store (cts).
 */
#define MAX_IPFIX_TEMPLATES 100
static struct ipfix_template *collect_template_store_head = NULL;
static struct ipfix_template *collect_template_store_tail = NULL;
static uint16_t cts_count = 0;


#define XTS_RESEND_TIME (600) /* 10 minutes */
#define XTS_EXPIRE_TIME (1800) /* 10 minutes */
/*
 * Doubly linked list for exporter template store (xts).
 */
static struct ipfix_exporter_template *export_template_store_head = NULL;
static struct ipfix_exporter_template *export_template_store_tail = NULL;
static uint16_t xts_count = 0;


/* Related to SPLT */
static unsigned int splt_pkt_index = 0;

/* Exporter object to send messages, alive until process termination */
#ifdef DARWIN
static struct ipfix_exporter gateway_export = {
  {0,0,0,{'0'}},
  {0,0,0,{'0'}},
  0,0
};
#else
static struct ipfix_exporter gateway_export = {
  {0,0,{0},{'0','0','0','0','0','0','0','0'}},
  {0,0,{0},{'0','0','0','0','0','0','0','0'}},
  0,0
};
#endif


/* Collector object to receive messages, alive until process termination */
#ifdef DARWIN
static struct ipfix_collector gateway_collect = {
  {0,0,0,{'0'}},
  0,0
};
#else
static struct ipfix_collector gateway_collect = {
  {0,0,{0},{'0','0','0','0','0','0','0','0'}},
  0,0
};
#endif

/* Used for exporting formatted IPFIX messages */
static struct ipfix_raw_message raw_message;

/* Used for storing IPFIX messages before transmission */
static struct ipfix_message *export_message = NULL;

enum ipfix_template_type export_template_type;


/*
 * External objects, defined in joy
 */
extern unsigned int ipfix_collect_port;
extern unsigned int ipfix_export_port;
extern unsigned int ipfix_export_remote_port;
extern char *ipfix_export_remote_host;
extern char *ipfix_export_template;
extern struct configuration config;
define_all_features_config_extern_uint(feature_list);


/*
 * Local ipfix.c prototypes
 */
static int ipfix_cts_search(struct ipfix_template_key needle,
                            struct ipfix_template **dest_template,
                            int flag_renew);


static inline struct ipfix_template *ipfix_template_malloc(size_t field_list_size);


static int ipfix_cts_append(struct ipfix_template *tmp);


static int ipfix_loop_data_fields(const unsigned char *data_ptr,
                                  struct ipfix_template *cur_template,
                                  uint16_t *min_record_len);


static void ipfix_flow_key_init(struct flow_key *key,
                                const struct ipfix_template *cur_template,
                                const char *flow_data);


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
                               const char *flow_data,
                               int record_num);

/*
 * @brief Initialize an IPFIX collector object.
 *
 * Startup a collector object that keeps track of the number
 * of messages received, and configures it with a transport socket
 * for receiving messages.
 *
 * @param c Pointer to the ipfix_collector that will be initialized.
 */
static int ipfix_collector_init(struct ipfix_collector *c) {
  /* Initialize the collector structures */
  memset(c, 0, sizeof(struct ipfix_collector));

  /* Get a socket for the collector */
  c->socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (c->socket < 0) {
    loginfo("error: cannot create socket");
    return 1;
  }

  /* Set local (collector) address */
  c->clctr_addr.sin_family = AF_INET;
  c->clctr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  c->clctr_addr.sin_port = htons(ipfix_collect_port);

  /* Bind the socket */
  if (bind(c->socket, (struct sockaddr *)&c->clctr_addr,
           sizeof(c->clctr_addr)) < 0) {
    loginfo("error: bind address failed");
    return 1;
  }

  loginfo("IPFIX collector configured...");
  loginfo("Host Port: %u", ipfix_collect_port);
  loginfo("Ready!\n");

  return 0;
}


static int ipfix_collect_process_socket(unsigned char *data,
                                        unsigned int data_len,
                                        struct sockaddr_in *remote_addr) {
  struct flow_key key;
  struct flow_record *record = NULL;

  /* Create a flow_key and flow_record to use */
  memset(&key, 0, sizeof(struct flow_key));

  key.sa = remote_addr->sin_addr;
  key.sp = ntohs(remote_addr->sin_port);
  key.da = gateway_collect.clctr_addr.sin_addr;
  key.dp = ntohs(gateway_collect.clctr_addr.sin_port);
  key.prot = IPPROTO_UDP;

  record = flow_key_get_record(&key, CREATE_RECORDS,NULL);

  process_ipfix((char*)data, data_len, record);

  return 0;
}


static void ipfix_collect_socket_loop(struct ipfix_collector *c) {
  struct sockaddr_in remote_addr;
  socklen_t remote_addrlen = 0;
  int recvlen = 0;
  unsigned char buf[TRANSPORT_MTU];
  //int i = 0;

  /* Initialize stuff for receiving data */
  memset(&remote_addr, 0, sizeof(struct sockaddr_in));
  remote_addrlen = sizeof(remote_addr);
  memset(buf, 0, sizeof(TRANSPORT_MTU));

  /*
   * Loop waiting to receive data.
   * Infinite loop, ends with process termination.
   */
  while(1) {
    recvlen = recvfrom(c->socket, buf, TRANSPORT_MTU, 0,
                       (struct sockaddr *)&remote_addr, &remote_addrlen);
    if (recvlen > 0) {
      ipfix_collect_process_socket(buf, recvlen, &remote_addr);
    }
    loginfo("received %d bytes", recvlen);
#if 0
    if (recvlen > 0) {
      buf[recvlen] = '\0';
      printf("received message: ");
      for (i=0; i < recvlen; i++) {
        printf("0x%08x", buf[i]);
      }
      printf("\n");
    }
#endif
  }
}


int ipfix_collect_main(void) {
  /* Init the collector for use, if not done already */
  if (gateway_collect.socket == 0) {
    if (ipfix_collector_init(&gateway_collect)) {
      loginfo("error: could not init ipfix_collector \"gateway_collect\"");
      return 1;
    }
  }

  /* Loop on the socket waiting for data to process */
  ipfix_collect_socket_loop(&gateway_collect);
  /* Never returns from here */

  return 0;
}


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

  pthread_mutex_lock(&cts_lock);
  if (collect_template_store_head == NULL) {
    pthread_mutex_unlock(&cts_lock);
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
  pthread_mutex_unlock(&cts_lock);

  return rc;
}


/*
 * @brief Monitor the collector template store (cts) running
 *        as a thread off of joy.
 *
 * Monitoring is only active during live processing runs.
 * Monitor terminates automatically when joy exits due
 * to the nature of how pthreads work.
 *
 * @param ptr Always NULL and not used, part of function
 *            prototype for pthread_create.
 *
 * @return Never return and the thread terminates when joy exits.
 */
void *ipfix_cts_monitor(void *ptr) {
  uint16_t num_expired;
  while (1) {
    /* let's only wake up and do work at specific intervals */
    num_expired = ipfix_cts_scan_expired();
    if (num_expired) {
      loginfo("%d templates were expired.", num_expired);
    }

#ifdef WIN32
	Sleep(CTS_MONITOR_INTERVAL);
#else
	sleep(CTS_MONITOR_INTERVAL);
#endif
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
 * Set the last_seen field within the \p template to the current time.
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

  pthread_mutex_lock(&cts_lock);
  if (collect_template_store_head == NULL) {
    pthread_mutex_unlock(&cts_lock);
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
  pthread_mutex_unlock(&cts_lock);
}


/*
 * @brief Copy a template from the store list into a new template.
 *
 * Using \p as the template from the store, copy it's contents
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
 * Using the \p needle template, search through the store list
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

  pthread_mutex_lock(&cts_lock);
  if (collect_template_store_head == NULL) {
    pthread_mutex_unlock(&cts_lock);
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
    pthread_mutex_unlock(&cts_lock);
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
      pthread_mutex_unlock(&cts_lock);
      return 1;
    }
  }
  pthread_mutex_unlock(&cts_lock);

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
  if (template->fields != NULL) {
    free(template->fields);
  }

  template->fields = malloc(field_list_size);

  if (template->fields == NULL) {
    loginfo("error: could not allocate memory for field list");
  } else {
    memset(template->fields, 0, field_list_size);
  }
}


static inline struct ipfix_template *ipfix_template_malloc(size_t field_list_size) {
  /* Init a new template on the heap */
  struct ipfix_template *template = malloc(sizeof(struct ipfix_template));

  if (template != NULL){
    memset(template, 0, sizeof(struct ipfix_template));

    /* Allocate memory for the fields */
    ipfix_template_fields_malloc(template, field_list_size);
  }

  return template;
}


/*
 * @brief Append to the collector template store (cts).
 *
 * Create a new template on the heap, and copy the key, hdr, and fields
 * from the template \p tmp. The timestamp of last_seen will be calculated
 * and attached to the newly allocated template.
 *
 * @return 0 if templates was added, 1 if template was not added.
 */
static int ipfix_cts_append(struct ipfix_template *tmp) {
  uint16_t field_count = tmp->hdr.field_count;
  size_t field_list_size = sizeof(struct ipfix_template_field) * field_count;
  struct ipfix_template *template = NULL;

  if (cts_count >= (MAX_IPFIX_TEMPLATES - 1)) {
    loginfo("warning: ipfix template lost, already at maximum storage threshold");
    return 1;
  }

  /* Init a new template on the heap */
  template = ipfix_template_malloc(field_list_size);

  /* Copy the atrribute data */
  template->template_key = tmp->template_key;
  template->hdr = tmp->hdr;
  memcpy(template->fields, tmp->fields, field_list_size);
  template->payload_length = tmp->payload_length;

  /* Write the current time */
  template->last_seen = time(NULL);

  pthread_mutex_lock(&cts_lock);
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
  pthread_mutex_unlock(&cts_lock);

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
                         const char *flow_data) {
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
                             const char *template_start,
                             uint16_t set_len,
                             const struct flow_key rec_key) {

  const char *template_ptr = template_start;
  uint16_t template_set_len = set_len;

  while (template_set_len > 0) {
    const struct ipfix_template_hdr *template_hdr = (const struct ipfix_template_hdr*)template_ptr;
    template_ptr += 4; /* Move past template header */
    template_set_len -= 4;
    uint16_t template_id = ntohs(template_hdr->template_id);
    uint16_t field_count = ntohs(template_hdr->field_count);
    struct ipfix_template *cur_template = NULL;
    struct ipfix_template_key template_key;
    int cur_template_fld_len = 0;
    struct ipfix_template *redundant_template = NULL;
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

    /* Allocate temporary template */
    cur_template = ipfix_template_malloc(field_count * sizeof(struct ipfix_template_field));

    /*
     * The enterprise field may or may not exist for certain fields
     * within the payload, so we need to walk the entire template.
     */
    for (i = 0; i < field_count; i++) {
      int fld_size = 4;
      const struct ipfix_template_field *tmp_field = (const struct ipfix_template_field*)template_ptr;
      const unsigned short host_info_elem_id = ntohs(tmp_field->info_elem_id);
      const unsigned short host_fixed_length = ntohs(tmp_field->fixed_length);

      if (ipfix_field_enterprise_bit(host_info_elem_id)) {
        /* The enterprise bit is set, remove from element id */
        cur_template->fields[i].info_elem_id = host_info_elem_id ^ 0x8000;
        cur_template->fields[i].enterprise_num = ntohl(tmp_field->enterprise_num);
        fld_size = 8;
      } else {
        cur_template->fields[i].info_elem_id = host_info_elem_id;
      }

      cur_template->fields[i].fixed_length = host_fixed_length;

      template_ptr += fld_size;
      template_set_len -= fld_size;
      cur_template_fld_len += fld_size;
    }

    /* The template is new, so save info */
    cur_template->hdr.template_id = template_id;
    cur_template->hdr.field_count = field_count;
    cur_template->payload_length = cur_template_fld_len;
    cur_template->template_key = template_key;

    /* Save template */
    ipfix_cts_append(cur_template);

    /* Cleanup the temporary template */
    if (cur_template) {
      ipfix_delete_template(cur_template);
    }
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
 * Additionally, if the value of \p min_record_len is 0, it will be filled
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
  if (!ipfix_cts_search(template_key, &cur_template, 0)) {
    loginfo("error: no template for data set found");
    goto cleanup;
  }

  /* Process data if we know the template */
  if (cur_template->hdr.template_id != 0) {
    struct flow_key key;
    struct flow_record *ix_record;

    memset(&key, 0, sizeof(struct flow_key));

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
      ipfix_flow_key_init(&key, cur_template, (const char*)data_ptr);

      /* Get a flow record related to ipfix data */
      ix_record = flow_key_get_record(&key, CREATE_RECORDS,NULL);


      /* Fill out record */
      if (memcmp(&key, prev_data_key, sizeof(struct flow_key)) != 0) {
        ipfix_process_flow_record(ix_record, cur_template, (const char*)data_ptr, 0);
      } else {
        ipfix_process_flow_record(ix_record, cur_template, (const char*)data_ptr, 1);
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
  const struct ip_hdr *ip = NULL;
  unsigned int ip_hdr_len;
  const char *flow_data = ix_record->idp;
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

  proto = (unsigned char)ix_record->key.prot;

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


/*
 * @brief Process the flow's absolute start or ending time in milliseconds.
 *
 * @param flow_data Contains the exported start/end flow time.
 * @param ix_record IPFIX flow record being encoded.
 * @param flag_end Signals whether the end or start time is being encoded.
 *        0 for start, 1 for end, anything else is invalid.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_process_flow_time_milli(const void *flow_data,
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
      (time_t)((uint32_t)(ntoh64(*(const uint64_t *)flow_data) / 1000));

    time->tv_usec =
      (time_t)((uint64_t)ntoh64(*(const uint64_t *)flow_data) % 1000)*1000;
  }
  return 0;
}


/*
 * @brief Process the flow's absolute start or ending time in microseconds.
 *
 * @param flow_data Contains the exported start/end flow time.
 * @param ix_record IPFIX flow record being encoded.
 * @param flag_end Signals whether the end or start time is being encoded.
 *        0 for start, 1 for end, anything else is invalid.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_process_flow_time_micro(const void *flow_data,
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
      (time_t)((uint32_t)(ntoh64(*(const uint64_t *)flow_data) >> 32));

    time->tv_usec =
      (time_t)((uint64_t)ntoh64(*(const uint64_t *)flow_data) & 0x00000000FFFFFFFF);
  }
  return 0;
}


/*
 * @brief Process byte distribution related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the byte distribution data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_byte_distribution(struct flow_record *ix_record,
                                            const char *data,
                                            uint16_t data_length,
                                            uint16_t element_length) {
  int i = 0;

  if (element_length != 2) {
    loginfo("api-error: expecting element_length == 2");
    return;
  }

  while (data_length > 0) {
    ix_record->byte_count[i] = (uint16_t)ntohs(*(const uint16_t *)data);

    data += element_length;
    data_length -= element_length;
    i += 1;
  }
}


/*
 * @brief Process sequence packet lengths related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the sequence packet lengths data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_spl(struct flow_record *ix_record,
                              const char *data,
                              uint16_t data_length,
                              uint16_t element_length) {
  int16_t old_value = 0;
  int16_t repeated_length = 0;
  unsigned int pkt_len_index = 0;

  if (element_length != 2) {
    loginfo("api-error: expecting element_length == 2");
    return;
  }

  /*
   * Set the global splt packet index variable,
   * for use in subsequent sequence packet times.
   */
  splt_pkt_index = ix_record->op;
  pkt_len_index = splt_pkt_index;

  while (data_length > 0) {
    int16_t packet_length = (int16_t)ntohs(*(const int16_t *)data);

    if (packet_length >= 0) {
      old_value = packet_length;
      if (packet_length > 0) {
        ix_record->op += 1;
      }
      if (pkt_len_index < MAX_NUM_PKT_LEN) {
        ix_record->pkt_len[pkt_len_index] = packet_length;
        ix_record->ob += packet_length;
        pkt_len_index++;
      } else {
        break;
      }
    } else {
      /*
       * Packet length value represents the number of packets that were
       * observed that had a length equal to the last observed packet length.
       */
      int i = 0;
      repeated_length = packet_length * -1;
      ix_record->op += repeated_length;
      for (i = 0; i < repeated_length; i++) {
        if (pkt_len_index < MAX_NUM_PKT_LEN) {
          ix_record->pkt_len[pkt_len_index] = old_value;
          ix_record->ob += old_value;
          pkt_len_index++;
        } else {
          break;
        }
      }
    }

    data += element_length;
    data_length -= element_length;
  }
}


/*
 * @brief Process sequence packet times related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the sequence packet times data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 * @param hdr_length Length in octets of the basicList header.
 */
static void ipfix_process_spt(struct flow_record *ix_record,
                              const char *data,
                              uint16_t data_length,
                              uint16_t element_length,
                              uint16_t hdr_length) {
  struct timeval previous_time;
  uint16_t packet_time = 0;
  int repeated_times = 0;
  unsigned int pkt_time_index = 0;
  int i = 0;

  memset(&previous_time, 0, sizeof(struct timeval));

  pkt_time_index = splt_pkt_index;

  /* Initialize the most recent previous time */
  if (pkt_time_index > 0) {
    previous_time.tv_sec = ix_record->pkt_time[pkt_time_index-1].tv_sec;
    previous_time.tv_usec = ix_record->pkt_time[pkt_time_index-1].tv_usec;
  } else {
    previous_time.tv_sec = ix_record->start.tv_sec;
    previous_time.tv_usec = ix_record->start.tv_usec;
  }

  while (data_length > 0) {
    int16_t packet_length =
      ntohs(*(const int16_t *)((data + i) - (data_length + hdr_length)));
    packet_time = ntohs(*(const uint16_t *)data);

    /* Look for run length encoding */
    if (packet_length < 0) {
      int16_t repeated_length = packet_length * -1;
      while (repeated_length > 0) {
        if (pkt_time_index < MAX_NUM_PKT_LEN) {
          ix_record->pkt_time[pkt_time_index] = previous_time;
          pkt_time_index++;
        } else {
          break;
        }
        repeated_length -= 1;
      }
    }

    if (packet_time >= 0) {
      /*
       * Packet_time value represents the positive time delta between
       * the previous packet and the current packet.
       */
      if (pkt_time_index < MAX_NUM_PKT_LEN) {
        previous_time.tv_sec += (time_t)(packet_time/1000);
        previous_time.tv_usec +=
          (uint32_t)(packet_time - ((int)(packet_time/1000.0))*1000)*1000;

        /*
         * Make sure to check for wrap around,
         * weirdness happens when usec >= 1000000
         */
        if (previous_time.tv_usec >= 1000000) {
          previous_time.tv_sec +=
            (time_t)((int)(previous_time.tv_usec / 1000000));
          previous_time.tv_usec %= 1000000;
        }

        ix_record->pkt_time[pkt_time_index] = previous_time;
        pkt_time_index++;
      } else {
        break;
      }
    } else {
      /*
       * Packet_time value represents the number of packets that were
       * observed that had an arrival time equal to the last observed
       * arrival time
       */
      int k;
      repeated_times = packet_time * -1;
      for (k = 0; k < repeated_times; k++) {
        if (pkt_time_index < MAX_NUM_PKT_LEN) {
          ix_record->pkt_time[pkt_time_index] = previous_time;
          pkt_time_index++;
        } else {
          break;
        }
      }
    }

    data += element_length;
    data_length -= element_length;
    i += 2;
  }
}


/*
 * @brief Process TLS record lengths related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the TLS record lengths data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_tls_record_lengths(struct flow_record *ix_record,
                                             const char *data,
                                             uint16_t data_length,
                                             uint16_t element_length) {
  int i = 0;

  if (element_length != 2) {
    loginfo("api-error: expecting element_length == 2");
    return;
  }

  while (data_length > 0) {
    ix_record->tls->lengths[i] = ntohs(*((const uint16_t *)data));

    data += element_length;
    data_length -= element_length;
    i++;
  }
}


/*
 * @brief Process TLS record times related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the TLS record times data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_tls_record_times(struct flow_record *ix_record,
                                           const char *data,
                                           uint16_t data_length,
                                           uint16_t element_length) {
  uint32_t total_ms = 0;
  int i = 0;

  if (element_length != 2) {
    loginfo("api-error: expecting element_length == 2");
    return;
  }

  while (data_length > 0) {
    uint16_t value_time = ntohs(*((const uint16_t *)data));
    ix_record->tls->times[i].tv_sec =
      ((total_ms + value_time) + (ix_record->start.tv_sec * 1000)
      + (ix_record->start.tv_usec / 1000)) / 1000;

    ix_record->tls->times[i].tv_usec =
      (((total_ms + value_time) + (ix_record->start.tv_sec * 1000)
        + (ix_record->start.tv_usec/1000)) % 1000) * 1000;

    total_ms += value_time;

    data += element_length;
    data_length -= element_length;
    i++;
  }
}


/*
 * @brief Process TLS content types related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the TLS content types data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_tls_content_types(struct flow_record *ix_record,
                                            const char *data,
                                            uint16_t data_length,
                                            uint16_t element_length) {
  int i = 0;

  if (element_length != 1) {
    loginfo("api-error: expecting element_length == 1");
    return;
  }

  while (data_length > 0) {
    ix_record->tls->msg_stats[i].content_type = *((const uint8_t *)data);

    data += element_length;
    data_length -= element_length;
    i++;
  }
}


/*
 * @brief Process TLS handshake types related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the TLS handshake types data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_tls_handshake_types(struct flow_record *ix_record,
                                              const char *data,
                                              uint16_t data_length,
                                              uint16_t element_length) {
  int i = 0;

  if (element_length != 1) {
    loginfo("api-error: expecting element_length == 1");
    return;
  }

  while (data_length > 0) {
    ix_record->tls->msg_stats[i].handshake_types[0] = *((const uint8_t *)data);
    ix_record->tls->msg_stats[i].num_handshakes = 1;
    ix_record->tls->op += 1;

    data += element_length;
    data_length -= element_length;
    i++;
  }
}


/*
 * @brief Process TLS cipher suites related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the TLS cipher suites data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_tls_cipher_suites(struct flow_record *ix_record,
                                            const char *data,
                                            uint16_t data_length,
                                            uint16_t element_length) {
  int i = 0;

  if (element_length != 2) {
    loginfo("api-error: expecting element_length == 2");
    return;
  }

  while (data_length > 0) {
    ix_record->tls->ciphersuites[i] = ntohs(*((const uint16_t *)data));
    ix_record->tls->num_ciphersuites += 1;

    data += element_length;
    data_length -= element_length;
    i++;
  }
}


/*
 * @brief Process TLS extension lengths related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the TLS extension lengths data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_tls_ext_lengths(struct flow_record *ix_record,
                                          const char *data,
                                          uint16_t data_length,
                                          uint16_t element_length) {
  int i = 0;

  if (element_length != 2) {
    loginfo("api-error: expecting element_length == 2");
    return;
  }

  while (data_length > 0) {
    ix_record->tls->extensions[i].length = ntohs(*((const uint16_t *)data));

    data += element_length;
    data_length -= element_length;
    i++;
  }
}


/*
 * @brief Process TLS extension types related data.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the TLS extension lengths data.
 * @param data_length Length in octets of the data.
 * @param element_length Length in octets of each element.
 */
static void ipfix_process_tls_ext_types(struct flow_record *ix_record,
                                          const char *data,
                                          uint16_t data_length,
                                          uint16_t element_length) {
  int i = 0;

  if (element_length != 2) {
    loginfo("api-error: expecting element_length == 2");
    return;
  }

  while (data_length > 0) {
    ix_record->tls->extensions[i].type = ntohs(*((const uint16_t *)data));
    ix_record->tls->extensions[i].data = NULL;
    ix_record->tls->num_extensions += 1;

    data += element_length;
    data_length -= element_length;
    i++;
  }
}


/*
 * @brief Parse through the contents of an IPFIX basicList.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param data Contains the basicList.
 * @param data_length Length in octets of the basicList.
 */
static void ipfix_parse_basic_list(struct flow_record *ix_record,
                                   const void *data,
                                   uint16_t data_length) {
  const char *ptr = data;
  const struct ipfix_basic_list_hdr *bl_hdr = (const struct ipfix_basic_list_hdr*)ptr;
  //uint8_t semantic = bl_hdr->semantic;
  uint16_t field_id = ntohs(bl_hdr->field_id);
  uint16_t element_length = ntohs(bl_hdr->element_length);
  //uint32_t enterprise_num = 0;
  uint8_t hdr_length = 5; /* default 5 bytes */
  uint16_t remaining_length = data_length;

  if ipfix_field_enterprise_bit(field_id) {
    /* Enterprise bit is set,  */
    //enterprise_num = ntohl(bl_hdr->enterprise_num);
    /* Remove the bit from field_id */
    field_id = field_id ^ 0x8000;
    hdr_length += 4;
  }

  remaining_length -= hdr_length;
  ptr += hdr_length;

  switch (field_id) {
    case IPFIX_BYTE_DISTRIBUTION:
      ipfix_process_byte_distribution(ix_record, ptr, remaining_length,
                                      element_length);
      break;

    case IPFIX_SEQUENCE_PACKET_LENGTHS:
      ipfix_process_spl(ix_record, ptr, remaining_length,
                        element_length);
      break;

    case IPFIX_SEQUENCE_PACKET_TIMES:
      ipfix_process_spt(ix_record, ptr, remaining_length,
                        element_length, hdr_length);
      break;

    case IPFIX_TLS_RECORD_LENGTHS:
      ipfix_process_tls_record_lengths(ix_record, ptr, remaining_length,
                                       element_length);
      break;

    case IPFIX_TLS_RECORD_TIMES:
      ipfix_process_tls_record_times(ix_record, ptr, remaining_length,
                                     element_length);
      break;

    case IPFIX_TLS_CONTENT_TYPES:
      ipfix_process_tls_content_types(ix_record, ptr, remaining_length,
                                      element_length);
      break;

    case IPFIX_TLS_HANDSHAKE_TYPES:
      ipfix_process_tls_handshake_types(ix_record, ptr, remaining_length,
                                        element_length);
      break;

    case IPFIX_TLS_CIPHER_SUITES:
      ipfix_process_tls_cipher_suites(ix_record, ptr, remaining_length,
                                      element_length);
      break;

    case IPFIX_TLS_EXTENSION_LENGTHS:
      ipfix_process_tls_ext_lengths(ix_record, ptr, remaining_length,
                                    element_length);
      break;

    case IPFIX_TLS_EXTENSION_TYPES:
      ipfix_process_tls_ext_types(ix_record, ptr, remaining_length,
                                  element_length);
      break;

    default:
      break;
  }
}


/*
 * @brief Parse through the contents of an IPFIX Data Set.
 *
 * @param ix_record IPFIX flow record being encoded.
 * @param cur_template IPFIX template used to interpret the data.
 * @param flow_data Flow data representing an IPFIX data record.
 * @param record_num Flag indicating whether to record the packet delta.
 *                   Use 0 for yes, otherwise no
 *
 */
static void ipfix_process_flow_record(struct flow_record *ix_record,
                               const struct ipfix_template *cur_template,
                               const char *flow_data,
                               int record_num) {
  //uint16_t bd_format = 1;
  const struct pcap_pkthdr *header = NULL;   /* dummy */
  const char *flow_ptr = flow_data;
  const unsigned char *payload = NULL;
  unsigned int size_payload = 0;
  struct flow_record *record = ix_record;
  //struct flow_key *key = &ix_record->key;
  int i;

  for (i = 0; i < cur_template->hdr.field_count; i++) {
    uint16_t field_length = 0;
    uint8_t flag_var_field = 0;
    flow_data = flow_ptr;

    if (cur_template->fields[i].fixed_length == 65535) {
      /*
       * This is a variable length field
       */
      flag_var_field = 1;

      if (cur_template->fields[i].variable_length) {
        /* Variable length is greater than 0 */
        field_length = cur_template->fields[i].variable_length;
      }
      /* Move just beyond the var header */
      flow_data += cur_template->fields[i].var_hdr_length;
      flow_ptr += cur_template->fields[i].var_hdr_length;
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
              ntoh64(*(const uint64_t *)(flow_data));
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

      case IPFIX_FLOW_START_MILLISECONDS:
        ipfix_process_flow_time_milli(flow_data, ix_record, 0);

        flow_ptr += field_length;
        break;

      case IPFIX_FLOW_END_MILLISECONDS:
        ipfix_process_flow_time_milli(flow_data, ix_record, 1);

        flow_ptr += field_length;
        break;

      case IPFIX_FLOW_START_MICROSECONDS:
        ipfix_process_flow_time_micro(flow_data, ix_record, 0);

        flow_ptr += field_length;
        break;

      case IPFIX_FLOW_END_MICROSECONDS:
        ipfix_process_flow_time_micro(flow_data, ix_record, 1);

        flow_ptr += field_length;
        break;

      case IPFIX_TLS_VERSION:
        ix_record->tls->version = *(const uint8_t *)flow_data;
        flow_data += field_length;
        break;

      case IPFIX_TLS_KEY_LENGTH:
        ix_record->tls->client_key_length = ntohs(*(const uint16_t *)flow_data);
        flow_data += field_length;
        break;

      case IPFIX_TLS_SESSION_ID:
        ix_record->tls->sid_len = min(field_length, 256);
        memcpy(ix_record->tls->sid, flow_data, ix_record->tls->sid_len);
        flow_data += field_length;
        break;

      case IPFIX_TLS_RANDOM:
        memcpy(ix_record->tls->random, flow_data, 32);
        flow_data += field_length;
        break;

      case IPFIX_COLLECT_IDP:
        if (flag_var_field && (field_length != 0)) {
          /*
           * We have actual IDP data to process
           */
          if (ix_record->idp != NULL) {
            free(ix_record->idp);
          }
          ix_record->idp_len = field_length;
          ix_record->idp = malloc(ix_record->idp_len);
          if (ix_record->idp != NULL) {
            memcpy(ix_record->idp, flow_data, ix_record->idp_len);
          }

          /* Get the start of IDP packet payload */
          payload = NULL;
          size_payload = 0;
          if (ipfix_skip_idp_header(ix_record, &payload, &size_payload)) {
            /* Error skipping idp header */
            flow_ptr += field_length;
            break;
          }

          /* Update all enabled feature modules */
          update_all_features(feature_list);
          flow_ptr += field_length;
          break;
        }
#if 0
      case IPFIX_BYTE_DISTRIBUTION_FORMAT:
        bd_format = (uint16_t)*((const uint16_t *)flow_data);
        flow_ptr += field_length;
        break;
#endif

      case IPFIX_BASIC_LIST:
        ipfix_parse_basic_list(ix_record, flow_data, field_length);
        flow_ptr += field_length;
        break;

      default:
        flow_ptr += field_length;
        break;
    }
  }
}


/******************************************
 * \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
 *                                        |
 *          IPFIX EXPORTING               |
 *                                        |
 * ////////////////////////////////////////
 *****************************************/


/*
 * Exporting process observation domain id.
 * Will be generated upon creation of the first ipfix_exporter object.
 */
static uint32_t exporter_obs_dom_id = 0;

#define IPFIX_COLLECTOR_DEFAULT_PORT 4739
#define HOST_NAME_MAX_SIZE 50
#define TEMPLATE_NAME_MAX_SIZE 50

static uint16_t exporter_template_id = 256;

#define ipfix_exp_template_field_macro(a, b) \
  ((struct ipfix_exporter_template_field) {a, b, 0})

#define ipfix_exp_template_ent_field_macro(a, b) \
  ((struct ipfix_exporter_template_field) {a, b, 9})


/*
 * @brief Allocate heap memory for a sequence of fields.
 *
 * @param template IPFIX exporter template which will have allocated memory
 *                 attached to it via pointer.
 */
static void ipfix_exp_template_fields_malloc(struct ipfix_exporter_template *template,
                                             uint16_t field_count) {
  size_t field_list_size = field_count * sizeof(struct ipfix_exporter_template_field);

  template->fields = malloc(field_list_size);
  memset(template->fields, 0, field_list_size);
}


/*
 * @brief Allocate heap memory for a sequence of fields.
 *
 * @param template IPFIX exporter template which will have allocated memory
 *                 attached to it via pointer.
 */
static void ipfix_delete_exp_template_fields(struct ipfix_exporter_template *template) {
  uint16_t field_count = 0;

  if (template == NULL) {
    loginfo("api-error: template is null");
  }

  field_count = template->hdr.field_count;

  size_t field_list_size = field_count * sizeof(struct ipfix_exporter_template_field);
  if (template->fields) {
    memset(template->fields, 0, field_list_size);
    free(template->fields);
  } else {
    loginfo("warning: fields were already null");
  }
}


/*
 * @brief Allocate heap memory for an exporter template.
 *
 * @param num_fields Number of fields the template will be able to hold.
 *
 * @return A newly allocated ipfix_exporter_template
 */
static struct ipfix_exporter_template *ipfix_exp_template_malloc(uint16_t field_count) {
  /* Init a new exporter template on the heap */
  struct ipfix_exporter_template *template = malloc(sizeof(struct ipfix_exporter_template));

  if (template != NULL) {
    memset(template, 0, sizeof(struct ipfix_exporter_template));
    /* Allocate memory for the fields */
    ipfix_exp_template_fields_malloc(template, field_count);
  } else {
    loginfo("error: malloc failed");
  }

  template->length = 4;

  return template;
}


/*
 * @brief Free an allocated exporter template structure.
 *
 * First free the attached fields memory. Then free the template memory.
 *
 * @param template IPFIX exporter template that will have it's heap memory freed.
 */
static inline void ipfix_delete_exp_template(struct ipfix_exporter_template *template) {
  if (template == NULL) {
    loginfo("api-error: template is null");
    return;
  }

  if (template->fields) {
    /* Free the attached fields memory */
    ipfix_delete_exp_template_fields(template);
  }

  /* Free the template */
  memset(template, 0, sizeof(struct ipfix_exporter_template));
  free(template);
}


/*
 * @brief Allocate heap memory for an exporter data record.
 *
 * @return A newly allocated ipfix_exporter_data
 */
static struct ipfix_exporter_data *ipfix_exp_data_record_malloc(void) {
  struct ipfix_exporter_data *data_record = NULL;

  /* Init a new exporter data record on the heap */
  data_record = malloc(sizeof(struct ipfix_exporter_data));

  if (data_record != NULL) {
    memset(data_record, 0, sizeof(struct ipfix_exporter_data));
  } else {
    loginfo("error: malloc failed, data record is null");
  }

  return data_record;
}


/*
 * @brief Free an allocated exporter data record.
 *
 * @param template IPFIX exporter data record that will have it's heap memory freed.
 */
static inline void ipfix_delete_exp_data_record(struct ipfix_exporter_data *data_record) {
  enum ipfix_template_type template_type = 0;
  uint16_t variable_len = 0;

  if (data_record == NULL) {
    loginfo("api-error: data record is null");
    return;
  }

  template_type = data_record->type;
  switch (template_type) {
    case IPFIX_IDP_TEMPLATE:
      variable_len = data_record->record.idp_record.idp_field.length;
      if (variable_len != 0) {
        /* Deallocate the IDP memory buffer */
        memset(data_record->record.idp_record.idp_field.info, 0,
               variable_len);
        free(data_record->record.idp_record.idp_field.info);
      }
      break;

    default:
      break;
  }

  /* Free the data record */
  memset(data_record, 0, sizeof(struct ipfix_exporter_data));
  free(data_record);
}


/*
 * @brief Append to the exporter template store (xts).
 *
 * Add a given template to the end of the exporter template store
 * linked list.
 *
 * @param template IPFIX exporter template that will be appended.
 *
 * @return 0 if templates was added, 1 if template was not added.
 */
static int ipfix_xts_append(struct ipfix_exporter_template *template) {
  if (xts_count >= (MAX_IPFIX_TEMPLATES - 1)) {
    loginfo("warning: ipfix template cannot be added to xts, already at maximum storage threshold");
    return 1;
  }

  /* Write the current time */
  //template->last_seen = time(NULL);

  if (export_template_store_head == NULL) {
    /* This is the first template in store list */
    export_template_store_head = template;
  } else {
    /* Append to the end of store list */
    export_template_store_tail->next = template;
    template->prev = export_template_store_tail;
  }

  /* Update the tail */
  export_template_store_tail = template;

  /* Increment the store count */
  xts_count += 1;

  return 0;
}


/*
 * @brief Copy a template from the export store list into a new template.
 *
 * Using \p as the template from the store, copy it's contents
 * into a newly allocated template that is totally independent.
 * The user of the new template can modify it however they wish,
 * with no impact to the original export store template.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @return 0 for success, 1 for failure.
 */
static int ipfix_xts_copy(struct ipfix_exporter_template **dest_template,
                           struct ipfix_exporter_template *src_template) {
  uint16_t field_count = src_template->hdr.field_count;
  struct ipfix_exporter_template_field *new_fields = NULL;
  struct ipfix_exporter_template *new_template = NULL;
  size_t field_list_size = field_count * sizeof(struct ipfix_exporter_template_field);

  if (dest_template == NULL || src_template == NULL) {
    loginfo("api-error: dest or src template is null");
    return 1;
  }

  /* Allocate heap memory for new_template */
  new_template = ipfix_exp_template_malloc(field_count);

  if (new_template == NULL) {
    loginfo("error: template is null");
    return 1;
  }

  /* Save pointer to new_template field memory */
  new_fields = new_template->fields;

  memcpy(new_template, src_template, sizeof(struct ipfix_exporter_template));

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

  return 0;
}


/*
 * @brief Search the IPFIX exporter template store (xts) for a match.
 *
 * Using the \p type of the template, search through the store list
 * to find whether an identical template exists in the store
 * already.
 *
 * @param type IPFIX exporter template type that will be searched for.
 * @param dest_template IPFIX exporter template that will have match contents
 *                      copied into.
 *
 * @return 1 for match, 0 for not match
 */
static struct ipfix_exporter_template *ipfix_xts_search
(enum ipfix_template_type type, struct ipfix_exporter_template **dest_template) {
  struct ipfix_exporter_template *cur_template;

  if (export_template_store_head == NULL) {
    return NULL;
  }

  cur_template = export_template_store_head;
  if (cur_template->type == type) {
    /* Found match */
    if (dest_template != NULL) {
      ipfix_xts_copy(dest_template, cur_template);
    }
    return cur_template;
  }

  while (cur_template->next) {
    cur_template = cur_template->next;
    if (cur_template->type == type) {
      /* Found match */
      if (dest_template != NULL) {
        ipfix_xts_copy(dest_template, cur_template);
      }
      return cur_template;
    }
  }

  return NULL;
}


/*
 * @brief Free all templates that exist in the exporter template store (xts).
 *
 * Any ipfix_exporter_template structures that currently remain within the XTS will
 * be zeroized and have their heap memory freed.
 */
void ipfix_xts_cleanup(void) {
  struct ipfix_exporter_template *this_template;
  struct ipfix_exporter_template *next_template;

  if (export_template_store_head == NULL) {
    return;
  }

  this_template = export_template_store_head;
  next_template = this_template->next;

  /* Free the first stored template */
  ipfix_delete_exp_template(this_template);

  while (next_template) {
    /* Free any remainders */
    this_template = next_template;
    next_template = this_template->next;

    ipfix_delete_exp_template(this_template);
  }
}


/////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Template Set
/////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX template set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the necessary set id and length.
 *
 * @param set Pointer to an ipfix_exporter_template_set in memory.
 */
static void ipfix_exp_template_set_init(struct ipfix_exporter_template_set *set) {
  if (set == NULL) {
    loginfo("api-error: set is null");
    return;
  }

  memset(set, 0, sizeof(struct ipfix_exporter_template_set));
  set->set_hdr.set_id = IPFIX_TEMPLATE_SET;
  set->set_hdr.length = 4; /* size of the header */
}


/*
 * @brief Allocate heap memory for a template set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the necessary set id and length.
 *
 * @return An allocated IPFIX template set, or NULL
 */
static struct ipfix_exporter_template_set *ipfix_exp_template_set_malloc(void) {
  struct ipfix_exporter_template_set *template_set = NULL;

  template_set = malloc(sizeof(struct ipfix_exporter_template_set));

  if (template_set != NULL) {
    ipfix_exp_template_set_init(template_set);
  } else {
    loginfo("error: template set malloc failed");
  }

  return template_set;
}


/*
 * @brief Append to the list of templates attached to the set.
 *
 * The \p set contains the head/tail of a list of related templates.
 * Here, \p template will be added to that list.
 *
 * @param set Pointer to an ipfix_exporter_template_set in memory.
 * @param template IPFIX exporter template that will be appended.
 */
static void ipfix_exp_template_set_add(struct ipfix_exporter_template_set *set,
                                       struct ipfix_exporter_template *template) {

  /*
   * Add the template to the list attached to set.
   */
  if (set->records_head == NULL) {
    /* This is the first template in set list*/
    set->records_head = template;
  } else {
    /* Append to the end of set list */
    set->records_tail->next = template;
    template->prev = set->records_tail;
  }

  /* Update the tail */
  set->records_tail = template;

  /* Update the set length with total size of template */
  set->set_hdr.length += template->length;
  if (set->parent_message) {
    /*
     * The template set has already been attached to a message,
     * so update the length of that as well.
     */
    set->parent_message->hdr.length += template->length;
  }
}


/*
 * @brief Cleanup a template set by freeing any allocated memory that's been attached.
 *
 * A template \p set contains a list of templates that have been allocated on
 * the heap. This function takes care of freeing up that list.
 *
 * @param set Pointer to an ipfix_exporter_template_set in memory.
 */
static void ipfix_exp_template_set_cleanup(struct ipfix_exporter_template_set *set) {
  struct ipfix_exporter_template *this_template;
  struct ipfix_exporter_template *next_template;

  if (set->records_head == NULL) {
    return;
  }

  this_template = set->records_head;
  next_template = this_template->next;

  /* Free the first stored template */
  ipfix_delete_exp_template(this_template);

  while (next_template) {
    this_template = next_template;
    next_template = this_template->next;

    ipfix_delete_exp_template(this_template);
  }
}


/*
 * @brief Free an allocated template set.
 *
 * First free the any attached memory to the template \p set.
 * Then free the template \p set itself.
 *
 * @param set Pointer to an ipfix_exporter_template_set in memory.
 */
static void ipfix_delete_exp_template_set(struct ipfix_exporter_template_set *set) {
  if (set == NULL) {
    return;
  }

  ipfix_exp_template_set_cleanup(set);

  memset(set, 0, sizeof(struct ipfix_exporter_template_set));
  free(set);
}


/////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Data Set
/////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX data set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the associated template and initial length.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 */
static void ipfix_exp_data_set_init(struct ipfix_exporter_data_set *set,
                                    uint16_t rel_template_id) {
  if (set == NULL) {
    loginfo("api-error: set is null");
    return;
  }

  memset(set, 0, sizeof(struct ipfix_exporter_data_set));
  set->set_hdr.set_id = rel_template_id;
  set->set_hdr.length = 4; /* size of the header */
}


/*
 * @brief Allocate heap memory for a template set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the necessary set id and length.
 *
 * @param rel_template_id The associated template id that collector
 *                        uses to interpret the data set.
 *
 * @return An allocated IPFIX data set, or NULL
 */
static struct ipfix_exporter_data_set *ipfix_exp_data_set_malloc(uint16_t rel_template_id) {
  struct ipfix_exporter_data_set *data_set = NULL;

  data_set = malloc(sizeof(struct ipfix_exporter_data_set));

  if (data_set != NULL) {
    ipfix_exp_data_set_init(data_set, rel_template_id);
  } else {
    loginfo("error: data set malloc failed");
  }

  return data_set;
}


/*
 * @brief Append to the list of data records attached to the set.
 *
 * The \p set contains the head/tail of a list of related data_record.
 * Here, \p data_record will be added to that list.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 * @param data_record IPFIX exporter data record that will be appended.
 */
static void ipfix_exp_data_set_add(struct ipfix_exporter_data_set *set,
                                   struct ipfix_exporter_data *data_record) {

  /*
   * Add the template to the list attached to set.
   */
  if (set->records_head == NULL) {
    /* This is the first data record in set list*/
    set->records_head = data_record;
  } else {
    /* Append to the end of set list */
    set->records_tail->next = data_record;
    data_record->prev = set->records_tail;
  }

  /* Update the tail */
  set->records_tail = data_record;

  /* Update the set length with total size of data record */
  set->set_hdr.length += data_record->length;
  if (set->parent_message) {
    /*
     * The data set has already been attached to a message,
     * so update the length of that as well.
     */
    set->parent_message->hdr.length += data_record->length;
  }
}


/*
 * @brief Cleanup a data set by freeing any allocated memory that's been attached.
 *
 * A data \p set contains a list of data records that have been allocated on
 * the heap. This function takes care of freeing up that list.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 */
static void ipfix_exp_data_set_cleanup(struct ipfix_exporter_data_set *set) {
  struct ipfix_exporter_data *this_data_record;
  struct ipfix_exporter_data *next_data_record;

  if (set->records_head == NULL) {
    return;
  }

  this_data_record = set->records_head;
  next_data_record = this_data_record->next;

  /* Free the first data record */
  ipfix_delete_exp_data_record(this_data_record);

  while (next_data_record) {
    this_data_record = next_data_record;
    next_data_record = this_data_record->next;

    ipfix_delete_exp_data_record(this_data_record);
  }
}


/*
 * @brief Free an allocated data set.
 *
 * First free the any attached memory to the data \p set.
 * Then free the data \p set itself.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 */
static void ipfix_delete_exp_data_set(struct ipfix_exporter_data_set *set) {
  if (set == NULL) {
    return;
  }

  ipfix_exp_data_set_cleanup(set);

  memset(set, 0, sizeof(struct ipfix_exporter_data_set));
  free(set);
}


////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Set Node
////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX set node.
 *
 * The set \p node will have it's memory zeroized, and then a set
 * will be allocated and attached to the \p node.
 *
 * WARNING: The \p node must be cleaned up before process exit
 * because of the downstream allocated memory.
 *
 * @param node Pointer to an ipfix_exporter_set_node in memory.
 * @param set_id set_id 2 for template set, 3 for option set, >= 256 for data set,
 *        otherwise invalid
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_set_node_init(struct ipfix_exporter_set_node *node,
                                   uint16_t set_id) {
  struct ipfix_exporter_template_set *template_set = NULL;
  struct ipfix_exporter_option_set *option_set = NULL;
  struct ipfix_exporter_data_set *data_set = NULL;

  if (node == NULL) {
    loginfo("api-error: set is null");
    return 1;
  }

  memset(node, 0, sizeof(struct ipfix_exporter_set_node));

  if (set_id == IPFIX_TEMPLATE_SET) {
    /* Create and attach a template set */
    template_set = ipfix_exp_template_set_malloc();
    node->set.template_set = template_set;
    //node->length = template_set->set_hdr.length;
  } else if (set_id == IPFIX_OPTION_SET) {
    /* Create and attached an option set */
    // TODO change to use option_set api when it has been made
    option_set = malloc(sizeof(struct ipfix_exporter_option_set));
    node->set.option_set = option_set;
    //node->length = option_set->set_hdr.length;
  } else if (set_id >= 256) {
    /* Create and attach a data set */
    data_set = ipfix_exp_data_set_malloc(set_id);
    node->set.data_set = data_set;
    //node->length = option_set->set_hdr.length;
  } else {
    loginfo("api-error: invalid set_id");
    return 1;
  }

  node->set_type = set_id;

  return 0;
}


/*
 * @brief Allocate heap memory for a set node.
 *
 * The set node is used as a container to encapsulate any 1 of the valid IPFIX set
 * types, i.e. template set, option set, or data set. Use \p set_id as an indicator
 * for which type of IPFIX set should be allocated and attached to the new set node
 * container.
 *
 * @param set_id 2 for template set, 3 for option set, >= 256 for data set,
 *        otherwise invalid
 *
 * @return An allocated set node container
 */
static struct ipfix_exporter_set_node *ipfix_exp_set_node_malloc(uint16_t set_id) {
  struct ipfix_exporter_set_node *node = NULL;

  node = malloc(sizeof(struct ipfix_exporter_set_node));

  if (node != NULL) {
    if (ipfix_exp_set_node_init(node, set_id)) {
      loginfo("error: could not init the set_node");
    }
  } else {
    loginfo("error: set_node malloc failed");
  }

  return node;
}


/*
 * @brief Cleanup a set node by freeing any allocated memory that's been attached.
 *
 * A set \p node contains an attached IPFIX set that exists on the heap.
 * This function takes care of freeing up that set and any other necessary cleanup
 * steps.
 *
 * @param set Pointer to an ipfix_exporter_set_node in memory.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_set_node_cleanup(struct ipfix_exporter_set_node *node) {
  uint16_t set_type = 0;

  if (node == NULL) {
    loginfo("api-error: node is null");
    return 1;
  }

  set_type = node->set_type;

  if (set_type == IPFIX_TEMPLATE_SET) {
    /* Cleanup and delete the template set */
    ipfix_delete_exp_template_set(node->set.template_set);
  } else if (set_type == IPFIX_OPTION_SET) {
    /* Cleanup and delete the option set */
    // TODO change to use option_set api when it has been made
    free(node->set.option_set);
  } else if (set_type >= 256) {
    /* Cleanup and delete the data set */
    ipfix_delete_exp_data_set(node->set.data_set);
  } else {
    loginfo("error: invalid set type");
    return 1;
  }

  return 0;
}


/*
 * @brief Free an allocated set node.
 *
 * First free the any attached memory to the set \p node.
 * Then free the set \p node itself.
 *
 * @param set Pointer to an ipfix_exporter_set_node in memory.
 */
static void ipfix_delete_exp_set_node(struct ipfix_exporter_set_node *node) {
  if (node == NULL) {
    loginfo("warning: node parameter is null");
    return;
  }

  ipfix_exp_set_node_cleanup(node);

  memset(node, 0, sizeof(struct ipfix_exporter_set_node));
  free(node);
}


////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Message
////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX message.
 *
 * @param set Pointer to an ipfix_exporter_template_set in memory.
 * @param template IPFIX exporter template that will be appended.
 */
static void ipfix_exp_message_init(struct ipfix_message *message) {

    memset(message, 0, sizeof(struct ipfix_message));

    /* IPFIX version = 10 */
    message->hdr.version_number = htons(10);
    /* Must be converted to network-byte order before message send */
    message->hdr.length = 16;
    /* Set the observation domain id */
    message->hdr.observe_dom_id = htonl(exporter_obs_dom_id);
}


/*
 * @brief Allocate heap memory for an IPFIX message.
 *
 * @return An allocated IPFIX message, or NULL
 */
static struct ipfix_message *ipfix_exp_message_malloc(void) {
  struct ipfix_message *message = NULL;

  message = malloc(sizeof(struct ipfix_message));

  if (message != NULL) {
    ipfix_exp_message_init(message);
  } else {
    loginfo("error: data set malloc failed");
  }

  return message;
}


/*
 * @brief Find the an IPFIX template set in a message.
 *
 * Look for a valid template set which is attached to the \p message.
 * It is not necessary to provide a set id, because templates sets
 * will always have a set id equal to 2.
 *
 * @param message Pointer to an ipfix_message in memory.
 *
 * @return The desired data set, or NULL
 */
static struct ipfix_exporter_template_set *ipfix_exp_message_find_template_set
(struct ipfix_message *message) {
  struct ipfix_exporter_set_node *set_node = NULL;
  struct ipfix_exporter_template_set *template_set = NULL;
  uint16_t set_id = 2;

  if (message->sets_head == NULL) {
    return NULL;
  }

  set_node = message->sets_head;
  if (set_node->set_type == set_id) {
    template_set = set_node->set.template_set;
    /* Found match */
    if (template_set != NULL) {
      return template_set;
    }
  }

  while (set_node->next) {
    set_node = set_node->next;
    if (set_node->set_type == set_id) {
      template_set = set_node->set.template_set;
      /* Found match */
      if (template_set != NULL) {
        return template_set;
      }
    }
  }

  return NULL;
}


/*
 * @brief Find the requested IPFIX data set in a message.
 *
 * Look for a data set which matches the \p set_id and which
 * is attached to the \p message.
 *
 * @param message Pointer to an ipfix_message in memory.
 * @param set_id The set id of the data set, used to identify it.
 *
 * @return The desired data set, or NULL
 */
static struct ipfix_exporter_data_set *ipfix_exp_message_find_data_set
(struct ipfix_message *message,
 uint16_t set_id) {
  struct ipfix_exporter_set_node *set_node = NULL;
  struct ipfix_exporter_data_set *data_set = NULL;

  if (message->sets_head == NULL) {
    return NULL;
  }

  set_node = message->sets_head;
  if (set_node->set_type == set_id) {
    data_set = set_node->set.data_set;
    /* Found match */
    if (data_set != NULL) {
      return data_set;
    }
  }

  while (set_node->next) {
    set_node = set_node->next;
    if (set_node->set_type == set_id) {
      data_set = set_node->set.data_set;
      /* Found match */
      if (data_set != NULL) {
        return data_set;
      }
    }
  }

  return NULL;
}


/*
 * @brief Add to the list of set nodes attached to the IPFIX message.
 *
 * The \p message contains the head/tail of a list of related set_nodes.
 * Here \p node will be added to that list.
 *
 * @param message Pointer to an ipfix_message in memory.
 * @param node IPFIX exporter set node that will be appended.
 *
 * return 0 for success, 1 for failure, 2 if message full
 */
static int ipfix_exp_message_add(struct ipfix_message *message,
                                 struct ipfix_exporter_set_node *node) {
  uint16_t set_type = 0;

  if (message == NULL) {
    loginfo("api-error: message is null");
    return 1;
  }

  if (node == NULL) {
    loginfo("api-error: node is null");
    return 1;
  }

  /*
   * Get the set type
   */
  set_type = node->set_type;

  if (set_type == IPFIX_TEMPLATE_SET) {
    /* Add the template set length */
    if (message->hdr.length + node->set.template_set->set_hdr.length > IPFIX_MTU) {
      loginfo("info: message is full, please attach to another message");
      return 2;
    }
    node->set.template_set->parent_message = message;
    message->hdr.length += node->set.template_set->set_hdr.length;
  } else if (set_type == IPFIX_OPTION_SET) {
    /* Add the option set length */
    if (message->hdr.length + node->set.template_set->set_hdr.length > IPFIX_MTU) {
      loginfo("info: message is full, please attach to another message");
      return 2;
    }
    // TODO add parent message here for option set
    message->hdr.length += node->set.option_set->set_hdr.length;
  } else if (set_type >= 256) {
    /* Add the data set length */
    if (message->hdr.length + node->set.template_set->set_hdr.length > IPFIX_MTU) {
      loginfo("info: message is full, please attach to another message");
      return 2;
    }
    node->set.data_set->parent_message = message;
    message->hdr.length += node->set.data_set->set_hdr.length;
  } else {
    loginfo("error: invalid set type");
    return 1;
  }

  /*
   * Add the template to the list attached to set.
   */
  if (message->sets_head == NULL) {
    /* This is the first template in set list*/
    message->sets_head = node;
  } else {
    /* Append to the end of set list */
    message->sets_tail->next = node;
    node->prev = message->sets_tail;
  }

  /* Update the tail */
  message->sets_tail = node;

  return 0;
}


/*
 * @brief Cleanup an IPFIX message by freeing any allocated memory that's been attached.
 *
 * A \p message contains a list of set nodes that have been allocated on
 * the heap. This function takes care of freeing up that list.
 *
 * @param set Pointer to an ipfix_message in memory.
 */
static void ipfix_exp_message_cleanup(struct ipfix_message *message) {
  struct ipfix_exporter_set_node *this_set_node;
  struct ipfix_exporter_set_node *next_set_node;

  if (message->sets_head == NULL) {
    return;
  }

  this_set_node = message->sets_head;
  next_set_node = this_set_node->next;

  /* Free the first set node */
  ipfix_delete_exp_set_node(this_set_node);

  while (next_set_node) {
    this_set_node = next_set_node;
    next_set_node = this_set_node->next;

    ipfix_delete_exp_set_node(this_set_node);
  }
}


/*
 * @brief Free an allocated IPFIX message.
 *
 * First free the any attached memory to the \p message.
 * Then free the \p message itself.
 *
 * @param set Pointer to an ipfix_message in memory.
 */
static void ipfix_delete_exp_message(struct ipfix_message *message) {
  if (message == NULL) {
    return;
  }

  ipfix_exp_message_cleanup(message);

  memset(message, 0, sizeof(struct ipfix_message));
  free(message);
}


/*
 * @brief Initialize an IPFIX exporter object.
 *
 * Startup an exporter object that keeps track of the number
 * of messages sent, and configures it with a transport socket
 * for sending messages. If \p host_name is NULL, the localhost
 * is used as the server (collector) target.
 *
 * @param e Pointer to the ipfix_exporter that will be initialized.
 * @param host_name Host name of the server, a.k.a collector.
 */
static int ipfix_exporter_init(struct ipfix_exporter *e,
                               const char *host_name) {
  struct hostent *host = NULL;
  char host_desc [HOST_NAME_MAX_SIZE];
  unsigned long localhost = 0;
  unsigned int remote_port = 0;

  memset(e, 0, sizeof(struct ipfix_exporter));

  if (host_name != NULL) {
    strncpy(host_desc, host_name, HOST_NAME_MAX_SIZE);
  }

  e->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (e->socket < 0) {
    loginfo("error: cannot create socket");
    return 1;
  }

  /* Set local (exporter) address */
  e->exprt_addr.sin_family = AF_INET;
  e->exprt_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  e->exprt_addr.sin_port = htons(ipfix_export_port);
  if (bind(e->socket, (struct sockaddr *)&e->exprt_addr,
           sizeof(e->exprt_addr)) < 0) {
    loginfo("error: bind address failed");
    return 1;
  }

  /* Set remote (collector) address */
  e->clctr_addr.sin_family = AF_INET;
  if (ipfix_export_remote_port) {
    remote_port = ipfix_export_remote_port;
    e->clctr_addr.sin_port = htons(remote_port);
  } else {
    remote_port = IPFIX_COLLECTOR_DEFAULT_PORT;
    e->clctr_addr.sin_port = htons(remote_port);
  }

  if (host_name != NULL) {
    host = gethostbyname(host_desc);
    if (!host) {
      loginfo("error: could not find address for collector %s", host_desc);
      return 1;
    }
    memcpy((void *)&e->clctr_addr.sin_addr, host->h_addr_list[0], host->h_length);
  } else {
    strncpy(host_desc, "127.0.0.1", HOST_NAME_MAX_SIZE);
    localhost = inet_addr(host_desc);
    e->clctr_addr.sin_addr.s_addr = localhost;
  }

  /* Generate the global observation domain id if not done already */
  if (!exporter_obs_dom_id) {
    uint8_t rand_buf[4];
    if (!RAND_pseudo_bytes(rand_buf, sizeof(rand_buf))) {
      loginfo("error: observation domain id prng failure");
    }
    exporter_obs_dom_id = bytes_to_u32(rand_buf);
  }

  loginfo("IPFIX exporter configured...");
  loginfo("Observation Domain ID: %u", exporter_obs_dom_id);
  loginfo("Host Port: %u", ipfix_export_port);
  loginfo("Remote IP Address: %s", host_desc);
  loginfo("Remote Port: %u", remote_port);

  /* Set the template type to use */
  if (ipfix_export_template) {
      if (!strncmp(ipfix_export_template, "simple", TEMPLATE_NAME_MAX_SIZE)) {
          export_template_type = IPFIX_SIMPLE_TEMPLATE;
          loginfo("Template Type: %s", "simple");
      } else if (!strncmp(ipfix_export_template, "idp", TEMPLATE_NAME_MAX_SIZE)) {
          export_template_type = IPFIX_IDP_TEMPLATE;
          loginfo("Template Type: %s", "idp");
      } else {
          loginfo("warning: template type invalid, defaulting to \"simple\"");
          export_template_type = IPFIX_SIMPLE_TEMPLATE;
          loginfo("Template Type: %s", "simple");
      }
  } else {
      export_template_type = IPFIX_SIMPLE_TEMPLATE;
      loginfo("Template Type: %s", "simple");
  }

  loginfo("Ready!\n");

  return 0;
}


/*
 * @brief Pack a timeval into a uint64_t (8 bytes).
 *
 * The 4 most significant bytes of the uint64_t will contain the tv_sec value,
 * and the 4 least significant bytes will contain the tv_usec value.
 *
 * @param timeval The timeval that will be packed.
 *
 * @return uint64_t - Packed timeval
 */
static uint64_t timeval_pack_uint64_t(const struct timeval *timeval) {
    uint64_t packed = 0;

    /* Shift to the 4 most significant bytes of the packed uint64_t */
    packed = (uint64_t)timeval->tv_sec << 32;
    /* Bit OR into the 4 least significant bytes of the packed uint64_t */
    packed |= timeval->tv_usec;

    return packed;
}


/*
 * @brief Create a simple 5-tuple data record.
 *
 * Make a basic data record that holds the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 * The new data record will use the \p flow_record to encode the appropriate
 * information according to the IPFIX specification.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @param fr_record Joy flow record created during the metric observation
 *                  phase of the process, i.e. process_packet(). It contains
 *                  information that will be encoded into the new data record.
 *
 * @return The desired data record, otherwise NULL for failure.
 */
static struct ipfix_exporter_data *ipfix_exp_create_simple_data_record
(const struct flow_record *fr_record) {
  struct ipfix_exporter_data *data_record = NULL;
  uint8_t protocol = 0;

  data_record = ipfix_exp_data_record_malloc();

  if (data_record != NULL) {
    /*
     * Assign the data fields
     */
    /* IPFIX_SOURCE_IPV4_ADDRESS */
    data_record->record.simple.source_ipv4_address = fr_record->key.sa.s_addr;

    /* IPFIX_DESTINATION_IPV4_ADDRESS */
    data_record->record.simple.destination_ipv4_address = fr_record->key.da.s_addr;

    /* IPFIX_SOURCE_TRANSPORT_PORT */
    data_record->record.simple.source_transport_port = fr_record->key.sp;

    /* IPFIX_DESTINATION_TRANSPORT_PORT */
    data_record->record.simple.destination_transport_port = fr_record->key.dp;

    /* IPFIX_PROTOCOL_IDENTIFIER */
    protocol = (uint8_t)(fr_record->key.prot & 0xff);
    data_record->record.simple.protocol_identifier = protocol;

    /*
     * IPFIX_FLOW_START_MICROSECONDS
     * Using an unsigned 64 bit integer, pack the seconds into the most-significant 32 bits,
     * and pack the fractional microseconds into the least-significant 32 bits.
     */
    data_record->record.simple.flow_start_microseconds = timeval_pack_uint64_t(&fr_record->start);

    /*
     * IPFIX_FLOW_END_MICROSECONDS
     * Using an unsigned 64 bit integer, pack the seconds into the most-significant 32 bits,
     * and pack the fractional microseconds into the least-significant 32 bits.
     */
    data_record->record.simple.flow_end_microseconds = timeval_pack_uint64_t(&fr_record->end);

  } else {
    loginfo("error: unable to malloc data record");
  }

  /* Set the type of template for identification */
  data_record->type = IPFIX_SIMPLE_TEMPLATE;

  /* Set the length (number of bytes) of the data record */
  data_record->length = SIZE_IPFIX_DATA_SIMPLE;

  return data_record;
}

/*
 * @brief Create an IDP data record.
 *
 * Make a basic data record that holds the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 * The new data record will use the \p flow_record to encode the appropriate
 * information according to the IPFIX specification.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @param fr_record Joy flow record created during the metric observation
 *                  phase of the process, i.e. process_packet(). It contains
 *                  information that will be encoded into the new data record.
 *
 * @return The desired data record, otherwise NULL for failure.
 */
static struct ipfix_exporter_data *ipfix_exp_create_idp_data_record
(const struct flow_record *fr_record) {
  struct ipfix_exporter_data *data_record = NULL;
  uint8_t protocol = 0;
  uint16_t idp_payload_len = 0;

  data_record = ipfix_exp_data_record_malloc();

  if (data_record != NULL) {
    /*
     * Assign the data fields
     */
    /* IPFIX_SOURCE_IPV4_ADDRESS */
    data_record->record.simple.source_ipv4_address = fr_record->key.sa.s_addr;

    /* IPFIX_DESTINATION_IPV4_ADDRESS */
    data_record->record.simple.destination_ipv4_address = fr_record->key.da.s_addr;

    /* IPFIX_SOURCE_TRANSPORT_PORT */
    data_record->record.simple.source_transport_port = fr_record->key.sp;

    /* IPFIX_DESTINATION_TRANSPORT_PORT */
    data_record->record.simple.destination_transport_port = fr_record->key.dp;

    /* IPFIX_PROTOCOL_IDENTIFIER */
    protocol = (uint8_t)(fr_record->key.prot & 0xff);
    data_record->record.simple.protocol_identifier = protocol;

    /*
     * IPFIX_FLOW_START_MICROSECONDS
     * Using an unsigned 64 bit integer, pack the seconds into the most-significant 32 bits,
     * and pack the fractional microseconds into the least-significant 32 bits.
     */
    data_record->record.simple.flow_start_microseconds = timeval_pack_uint64_t(&fr_record->start);

    /*
     * IPFIX_FLOW_END_MICROSECONDS
     * Using an unsigned 64 bit integer, pack the seconds into the most-significant 32 bits,
     * and pack the fractional microseconds into the least-significant 32 bits.
     */
    data_record->record.simple.flow_end_microseconds = timeval_pack_uint64_t(&fr_record->end);

    /*
     * IPFIX_IDP
     */

    /* 
     * Set the flag indicating variable length.
     * Figure S from RFC 7011
     */
    data_record->record.idp_record.idp_field.flag = 255;

    /* The length in bytes of the IDP payload */
    idp_payload_len = fr_record->idp_len;

    /* The length of the whole IDP field inside the IPFIX data record */
    data_record->record.idp_record.idp_field.length = idp_payload_len;

    /*
     * Copy the IDP into the data record.
     */ 
    if (idp_payload_len != 0) {
      data_record->record.idp_record.idp_field.info =
          calloc(idp_payload_len, sizeof(unsigned char));

      memcpy(data_record->record.idp_record.idp_field.info, fr_record->idp,
             idp_payload_len);
    }
  } else {
    loginfo("error: unable to malloc data record");
  }

  /* Set the type of template for identification */
  data_record->type = IPFIX_IDP_TEMPLATE;

  /* Set the length (number of bytes) of the data record */
  data_record->length = idp_payload_len + SIZE_IPFIX_DATA_IDP;

  return data_record;
}


/*
 * @brief Create a data record, given a valid type.
 *
 * Create a new data record on the heap according to the
 * \p template_type. If the template type is not supported then
 * an error is logged and no data record is made because
 * all data records must have a related template in order to
 * be sucessfully interpreted.
 *
 * WARNING: The end user of the newly allocated data record is
 * responsible for freeing that memory.
 *
 * @param template_type A valid entry from the enum ipfix_template_type list.
 * @param fr_record Joy flow record created during the metric observation
 *                  phase of the process, i.e. process_packet(). It contains
 *                  information that will be encoded into the new data record.
 *
 * @return The desired data record, otherwise NULL for failure.
 */
static struct ipfix_exporter_data *ipfix_exp_create_data_record
(enum ipfix_template_type template_type,
 const struct flow_record *fr_record) {

  struct ipfix_exporter_data *data_record = NULL;

  switch (template_type) {
    case IPFIX_SIMPLE_TEMPLATE:
      data_record = ipfix_exp_create_simple_data_record(fr_record);
      break;

    case IPFIX_IDP_TEMPLATE:
      data_record = ipfix_exp_create_idp_data_record(fr_record);
      break;

    default:
      loginfo("api-error: template type is not supported");
      break;
  }

  if (data_record == NULL) {
    loginfo("error: unable to create data record");
  }

  return data_record;
}


static void ipfix_exp_template_add_field(struct ipfix_exporter_template *t,
                                         struct ipfix_exporter_template_field f) {
    t->fields[t->hdr.field_count] = f;
    t->hdr.field_count++;
    t->length += 4;
}

static void ipfix_exp_template_add_ent_field(struct ipfix_exporter_template *t,
                                             struct ipfix_exporter_template_field f) {
    t->fields[t->hdr.field_count] = f;
    t->hdr.field_count++;
    t->length += 8;
}


/*
 * @brief Create a simple 5-tuple template.
 *
 * Make a basic template that represents the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @return The desired template, otherwise NULL for failure.
 */
static struct ipfix_exporter_template *ipfix_exp_create_simple_template(void) {
  struct ipfix_exporter_template *template = NULL;
  uint16_t num_fields = 7;

  template = ipfix_exp_template_malloc(num_fields);

  if (template != NULL) {
    /*
     * Add the fields
     */
    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_SOURCE_IPV4_ADDRESS, 4));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_DESTINATION_IPV4_ADDRESS, 4));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_SOURCE_TRANSPORT_PORT, 2));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_DESTINATION_TRANSPORT_PORT, 2));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_PROTOCOL_IDENTIFIER, 1));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_FLOW_START_MICROSECONDS, 8));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_FLOW_END_MICROSECONDS, 8));

  } else {
    loginfo("error: template is null");
  }

  /* Set the type of template for identification */
  template->type = IPFIX_SIMPLE_TEMPLATE;

  return template;
}


/*
 * @brief Create an IDP template.
 *
 * Make a basic template that represents the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @return The desired template, otherwise NULL for failure.
 */
static struct ipfix_exporter_template *ipfix_exp_create_idp_template(void) {
  struct ipfix_exporter_template *template = NULL;
  uint16_t num_fields = 8;

  template = ipfix_exp_template_malloc(num_fields);

  if (template != NULL) {
    /*
     * Add the fields
     */
    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_SOURCE_IPV4_ADDRESS, 4));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_DESTINATION_IPV4_ADDRESS, 4));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_SOURCE_TRANSPORT_PORT, 2));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_DESTINATION_TRANSPORT_PORT, 2));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_PROTOCOL_IDENTIFIER, 1));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_FLOW_START_MICROSECONDS, 8));

    ipfix_exp_template_add_field(template,
        ipfix_exp_template_field_macro(IPFIX_FLOW_END_MICROSECONDS, 8));

    ipfix_exp_template_add_ent_field(template,
        ipfix_exp_template_ent_field_macro(IPFIX_IDP, 65535));

  } else {
    loginfo("error: template is null");
  }

  /* Set the type of template for identification */
  template->type = IPFIX_IDP_TEMPLATE;

  return template;
}


/*
 * @brief Create a template, given a valid type.
 *
 * Create a new template on the heap according to the
 * \p template_type. If the template type is not supported then
 * an error is logged and no template is made.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @param template_type A valid entry from the enum ipfix_template_type list.
 *
 * @return The desired template, otherwise NULL for failure.
 */
static struct ipfix_exporter_template *ipfix_exp_create_template
(enum ipfix_template_type template_type) {

  struct ipfix_exporter_template *template = NULL;

  switch (template_type) {
    case IPFIX_SIMPLE_TEMPLATE:
      template = ipfix_exp_create_simple_template();
      break;

    case IPFIX_IDP_TEMPLATE:
      template = ipfix_exp_create_idp_template();
      break;

    default:
      loginfo("api-error: template type is not supported");
      break;
  }

  if (template != NULL) {
    template->hdr.template_id = exporter_template_id;
    ipfix_xts_append(template);
  } else {
    loginfo("error: unable to create template");
  }

  return template;
}


/*
 * @brief Encode a template set into an IPFIX message.
 *
 * Take a \p set of Ipfix templates, and encode the whole
 * \p set into a \p message_buf according RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 * A handle to \p msg_length is used, where the value represents
 * the total running length of the \p message. This is used by
 * calling functions to keep track of how much data has been
 * written into the \p message and for the \p message_buf write offset.
 *
 * @param set Single set of multiple Ipfix templates.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_template_set(struct ipfix_exporter_template_set *set,
                                         unsigned char *message_buf,
                                         uint16_t *msg_length) {
  struct ipfix_exporter_template *current = NULL;
  unsigned char *data_ptr = NULL;
  uint16_t bigend_set_id = 0;
  uint16_t bigend_set_len = 0;

  if (message_buf == NULL) {
    loginfo("api-error: message_buf is null");
    return 1;
  }

  if (set == NULL) {
    loginfo("api-error: set is null");
    return 1;
  }

  if (set->set_hdr.length > (IPFIX_MAX_SET_LEN - *msg_length)) {
    loginfo("error: set is larger than remaining message buffer");
    return 1;
  }

  data_ptr = message_buf + *msg_length;

  bigend_set_id = htons(set->set_hdr.set_id);
  bigend_set_len = htons(set->set_hdr.length);

  /* Encode the set header into message */
  memcpy(data_ptr, (const void *)&bigend_set_id, 2);
  data_ptr += 2;
  *msg_length += 2;

  memcpy(data_ptr, (const void *)&bigend_set_len, 2);
  data_ptr += 2;
  *msg_length += 2;

  current = set->records_head;

  /* Encode the set templates into message */
  while (current != NULL) {
    int i = 0;
    uint16_t bigend_template_id = htons(current->hdr.template_id);
    uint16_t bigend_template_field_count = htons(current->hdr.field_count);

    /* Encode the template header into message */
    memcpy(data_ptr, (const void *)&bigend_template_id, 2);
    data_ptr += 2;
    *msg_length += 2;

    memcpy(data_ptr, (const void *)&bigend_template_field_count, 2);
    data_ptr += 2;
    *msg_length += 2;

    for (i = 0; i < current->hdr.field_count; i++) {
      uint16_t bigend_field_id = htons(current->fields[i].info_elem_id);
      uint16_t bigend_field_len = htons(current->fields[i].fixed_length);
      uint32_t bigend_ent_num = htonl(current->fields[i].enterprise_num);

      /* Encode the field element into message */
      memcpy(data_ptr, (const void *)&bigend_field_id, 2);
      data_ptr += 2;
      *msg_length += 2;

      memcpy(data_ptr, (const void *)&bigend_field_len, 2);
      data_ptr += 2;
      *msg_length += 2;

      /* Enterprise number */
      if (bigend_ent_num) {
        memcpy(data_ptr, (const void *)&bigend_ent_num, sizeof(uint32_t));
        data_ptr += sizeof(uint32_t);
        *msg_length += sizeof(uint32_t);
      }
    }

    current = current->next;
  }

  return 0;
}


/*
 * @brief Encode a simple 5-tuple data record into an IPFIX message.
 *
 * Using the \p data_record container, encode the attached fields
 * into the \p message buf according to the RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 *
 * @param data_record Single Ipfix data record.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_data_record_simple(struct ipfix_exporter_data *data_record,
                                               unsigned char *message_buf) {
  unsigned char *ptr = NULL;
  uint16_t bigend_src_port = 0;
  uint16_t bigend_dest_port = 0;
  uint64_t bigend_end_time = 0;
  uint64_t bigend_start_time = 0;

  if (data_record == NULL) {
    loginfo("api-error: data_record is null");
    return 1;
  }

  if (data_record->type != IPFIX_SIMPLE_TEMPLATE) {
    loginfo("api-error: wrong data record type");
    return 1;
  }

  /* Get starting position in target message buffer */
  ptr = message_buf;

  /* IPFIX_SOURCE_IPV4_ADDRESS */
  memcpy(ptr, &data_record->record.simple.source_ipv4_address, sizeof(uint32_t));
  ptr += sizeof(uint32_t);

  /* IPFIX_DESTINATION_IPV4_ADDRESS */
  memcpy(ptr, &data_record->record.simple.destination_ipv4_address, sizeof(uint32_t));
  ptr += sizeof(uint32_t);

  /* IPFIX_SOURCE_TRANSPORT_PORT */
  bigend_src_port = htons(data_record->record.simple.source_transport_port);
  memcpy(ptr, &bigend_src_port, sizeof(uint16_t));
  ptr += sizeof(uint16_t);

  /* IPFIX_DESTINATION_TRANSPORT_PORT */
  bigend_dest_port = htons(data_record->record.simple.destination_transport_port);
  memcpy(ptr, &bigend_dest_port, sizeof(uint16_t));
  ptr += sizeof(uint16_t);

  /* IPFIX_PROTOCOL_IDENTIFIER */
  memcpy(ptr, &data_record->record.simple.protocol_identifier, sizeof(uint8_t));
  ptr += sizeof(uint8_t);

  /* IPFIX_FLOW_START_MICROSECONDS */
  bigend_start_time = hton64(data_record->record.simple.flow_start_microseconds);
  memcpy(ptr, &bigend_start_time, sizeof(uint64_t));
  ptr += sizeof(uint64_t);

  /* IPFIX_FLOW_END_MICROSECONDS */
  bigend_end_time = hton64(data_record->record.simple.flow_end_microseconds);
  memcpy(ptr, &bigend_end_time, sizeof(uint64_t));

  return 0;
}


/*
 * @brief Encode an IDP data record into an IPFIX message.
 *
 * Using the \p data_record container, encode the attached fields
 * into the \p message buf according to the RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 *
 * @param data_record Single Ipfix data record.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_data_record_idp(struct ipfix_exporter_data *data_record,
                                            unsigned char *message_buf) {
  unsigned char *ptr = NULL;
  uint16_t bigend_src_port = 0;
  uint16_t bigend_dest_port = 0;
  uint64_t bigend_end_time = 0;
  uint64_t bigend_start_time = 0;
  uint16_t bigend_variable_length = 0;

  if (data_record == NULL) {
    loginfo("api-error: data_record is null");
    return 1;
  }

  if (data_record->type != IPFIX_IDP_TEMPLATE) {
    loginfo("api-error: wrong data record type");
    return 1;
  }

  /* Get starting position in target message buffer */
  ptr = message_buf;

  /* IPFIX_SOURCE_IPV4_ADDRESS */
  memcpy(ptr, &data_record->record.idp_record.source_ipv4_address, sizeof(uint32_t));
  ptr += sizeof(uint32_t);

  /* IPFIX_DESTINATION_IPV4_ADDRESS */
  memcpy(ptr, &data_record->record.idp_record.destination_ipv4_address, sizeof(uint32_t));
  ptr += sizeof(uint32_t);

  /* IPFIX_SOURCE_TRANSPORT_PORT */
  bigend_src_port = htons(data_record->record.idp_record.source_transport_port);
  memcpy(ptr, &bigend_src_port, sizeof(uint16_t));
  ptr += sizeof(uint16_t);

  /* IPFIX_DESTINATION_TRANSPORT_PORT */
  bigend_dest_port = htons(data_record->record.idp_record.destination_transport_port);
  memcpy(ptr, &bigend_dest_port, sizeof(uint16_t));
  ptr += sizeof(uint16_t);

  /* IPFIX_PROTOCOL_IDENTIFIER */
  memcpy(ptr, &data_record->record.idp_record.protocol_identifier, sizeof(uint8_t));
  ptr += sizeof(uint8_t);

  /* IPFIX_FLOW_START_MICROSECONDS */
  bigend_start_time = hton64(data_record->record.idp_record.flow_start_microseconds);
  memcpy(ptr, &bigend_start_time, sizeof(uint64_t));
  ptr += sizeof(uint64_t);

  /* IPFIX_FLOW_END_MICROSECONDS */
  bigend_end_time = hton64(data_record->record.idp_record.flow_end_microseconds);
  memcpy(ptr, &bigend_end_time, sizeof(uint64_t));
  ptr += sizeof(uint64_t);

  /*
   * IPFIX_IDP
   */
  /* Encode the flag */
  memcpy(ptr, &data_record->record.idp_record.idp_field.flag, sizeof(uint8_t));
  ptr += sizeof(uint8_t);

  /* Encode the IDP variable length */
  bigend_variable_length = htons(data_record->record.idp_record.idp_field.length);
  memcpy(ptr, &bigend_variable_length, sizeof(uint16_t));
  ptr += sizeof(uint16_t);

  /* Copy the IDP */
  memcpy(ptr, data_record->record.idp_record.idp_field.info,
         data_record->record.idp_record.idp_field.length);

  return 0;
}



/*
 * @brief Encode a data set into an IPFIX message.
 *
 * Take a \p set of Ipfix data records, and encode the whole
 * \p set into a \p message_buf according RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 * A handle to \p msg_length is used, where the value represents
 * the total running length of the \p message. This is used by
 * calling functions to keep track of how much data has been
 * written into the \p message.
 *
 * @param set Single set of multiple Ipfix data records.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_data_set(struct ipfix_exporter_data_set *set,
                                     unsigned char *message_buf,
                                     uint16_t *msg_length) {
  struct ipfix_exporter_data *this_data_record = NULL;
  unsigned char *data_ptr = NULL;
  uint16_t bigend_set_id = 0;
  uint16_t bigend_set_len = 0;

  if (message_buf == NULL) {
    loginfo("api-error: message_buf is null");
    return 1;
  }

  if (set == NULL) {
    loginfo("api-error: set is null");
    return 1;
  }

  if (set->set_hdr.length > (IPFIX_MAX_SET_LEN - *msg_length)) {
    loginfo("error: set is larger than remaining message buffer");
    return 1;
  }

  data_ptr = message_buf + *msg_length;

  bigend_set_id = htons(set->set_hdr.set_id);
  bigend_set_len = htons(set->set_hdr.length);

  /* Encode the set header into message */
  memcpy(data_ptr, &bigend_set_id, 2);
  data_ptr += 2;
  *msg_length += 2;

  memcpy(data_ptr, &bigend_set_len, 2);
  data_ptr += 2;
  *msg_length += 2;

  this_data_record = set->records_head;

  /* Encode the set data records into message */
  while (this_data_record != NULL) {
    switch (this_data_record->type) {
      case IPFIX_SIMPLE_TEMPLATE:
        if (ipfix_exp_encode_data_record_simple(this_data_record, data_ptr)) {
          loginfo("error: could not encode the simple data record into message");
          return 1;
        }
        break;

      case IPFIX_IDP_TEMPLATE:
        if (ipfix_exp_encode_data_record_idp(this_data_record, data_ptr)) {
          loginfo("error: could not encode the simple data record into message");
          return 1;
        }
        break;

      default:
        loginfo("error: invalid data record type, cannot encode into message");
        return 1;
    }

    data_ptr += this_data_record->length;
    *msg_length += this_data_record->length;
    this_data_record = this_data_record->next;
  }

  return 0;
}


/*
 * @brief Encode a set node into an IPFIX message.
 *
 * Take a \p set_node and inspect it see see whether
 * it contains a template set, option set, or data set.
 * After figuring out which set is contained, the appropriate
 * set encoding function will be called, passing down the
 * \p raw_msg_buf and \p buf_len to the sub-functions.
 *
 * @param set_node Single set node encapsulating a template/option/data set..
 * @param raw_msg_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_set_node(struct ipfix_exporter_set_node *set_node,
                                     unsigned char *raw_msg_buf,
                                     uint16_t *buf_len) {
  uint16_t set_type = 0;

  if (set_node == NULL) {
    loginfo("api-error: set_node is null");
    return 1;
  }

  set_type = set_node->set_type;

  if (set_type == IPFIX_TEMPLATE_SET) {
    /* Encode the template set into the message */
    ipfix_exp_encode_template_set(set_node->set.template_set,
                                  raw_msg_buf, buf_len);
  } else if (set_type == IPFIX_OPTION_SET) {
    /* Encode the option set into the message */
    // TODO call option set encoding function here
    loginfo("warning: option set encoding not supported yet");
  } else if (set_type >= 256) {
    /* Encode the data set into the message */
    ipfix_exp_encode_data_set(set_node->set.data_set,
                              raw_msg_buf, buf_len);
  } else {
    loginfo("error: invalid set type");
    return 1;
  }

  return 0;
}


/*
 * @brief Encode a message container into the buffer for sending over network.
 *
 * Take a \p message and iterate over it's attached sub-containers
 * which may include template/option/data sets. As each set is encountered
 * the data contained within will be encoded according to the IPFIX specification
 * and subsequently written into a buffer for sending over the network.
 *
 * @param message Message entity related to all sub-container entities.
 * @param raw_msg_buf Buffer for message that the template \p set will be encoded and written into.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_message(struct ipfix_message *message,
                                    unsigned char *raw_msg_buf) {
  struct ipfix_exporter_set_node *this_set_node = NULL;
  uint16_t buf_len = 0;

  if (message == NULL) {
    loginfo("api_error: message is null");
    return 1;
  }

  if (message->sets_head == NULL) {
    loginfo("error: message does not contain any sets");
    return 1;
  }

  /* Get the head of set node list */
  this_set_node = message->sets_head;

  while (buf_len < IPFIX_MAX_SET_LEN) {
    /* FIXME need to make this length check actually robust */
    if (this_set_node == NULL) {
      /* Reached end of set node list */
      break;
    }

    /* Encode the node into the message */
    if (ipfix_exp_encode_set_node(this_set_node, raw_msg_buf, &buf_len)) {
      loginfo("error: could not encode set node");
      return 1;
    }

    /* Go to next node in the list */
    this_set_node = this_set_node->next;
  }

  return 0;
}


/*
 * @brief Send an IPFIX message using a configured exporter.
 *
 * An IPFIX exporter, \p e, that has been properly configured
 * is used to send a \p msg to an IPFIX collector server.
 * It is important to stress that at this point, both the exporter \p e,
 * and the message \p msg, are both initialized, setup, and containing valid
 * data that adheres to the RFC7011 specification.
 *
 * @param e Single set of multiple Ipfix templates.
 * @param message IPFIX message that the \p set will be encoded and written into.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_export_send_message(struct ipfix_exporter *e,
                                     struct ipfix_message *message) {
  ssize_t bytes = 0;
  size_t msg_len = message->hdr.length;

  memset(&raw_message, 0, sizeof(struct ipfix_raw_message));

  /*
   * Encode the message contents according to RFC7011,
   * and pack it into the raw_message for sending
   */
  ipfix_exp_encode_message(message, raw_message.payload);

  /* Convert the header length to network-byte order */  
  message->hdr.length = htons(message->hdr.length);
  /* Write the time message is exported */
  message->hdr.export_time = htonl(time(NULL));
  /* Write message sequence number relative to current session */
  message->hdr.sequence_number = htonl(e->msg_count);

  /*
   * Copy message header into raw_message header
   */
  memcpy(&raw_message.hdr, &message->hdr, sizeof(struct ipfix_hdr));

  /* Send the message */
  bytes = sendto(e->socket, (const char*)&raw_message, msg_len, 0,
                 (struct sockaddr *)&e->clctr_addr,
                 sizeof(e->clctr_addr));

  if (bytes < 0) {
    loginfo("error: ipfix message could not be sent");
    return 1;
  } else {
    loginfo("info: sequence # %d, sent %lu bytes", e->msg_count, bytes);
  }

  /* Increment the exporter's message count */
  e->msg_count++;

  return 0;
}


/*
 * @brief Flush an IPFIX message using a configured exporter.
 *
 * An IPFIX exporter, that has been properly configured
 * is used to send a leftover ipfix_message to an IPFIX collector server.
 * It is important to stress that at this point, both the exporter,
 * and the message, should both initialized, setup, and containing valid
 * data that adheres to the RFC7011 specification. If there are no leftover
 * messages in the IPFIX module, no message is flushed.
 *
 * @return 0 for success, 1 for failure
 */
int ipfix_export_flush_message(void) {
  if (gateway_export.socket == 0) {
    loginfo("error: gateway_export not configured, unable to flush message");
    return 1;
  }

  if (export_message == NULL) {
    return 0;
  }

  /* Send the message */
  if (ipfix_export_send_message(&gateway_export, export_message)) {
    loginfo("error: unable to send message");
    return 1;
  }

  return 0;
}


void ipfix_module_cleanup(void) {
  ipfix_cts_cleanup();
  ipfix_xts_cleanup();
  if (export_message != NULL) {
    ipfix_delete_exp_message(export_message);
    export_message = NULL;
  }
}

/*
 * @brief Encapsulate a data record within a data set and then
 *        attach it to an IPFIX \p message.
 *
 * @param fr_record Joy flow record created during the metric observation
 *                  phase of the process, i.e. process_packet(). It contains
 *                  information that will be encoded into the new data record.
 * @param message IPFIX message that the data record/set will be encoded and written into.
 * @param template_type The template that will be adhered to for new data record creation.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_export_message_attach_data_set(const struct flow_record *fr_record,
                                                struct ipfix_message *message,
                                                enum ipfix_template_type template_type) {
    struct ipfix_exporter_set_node *set_node = NULL;
    struct ipfix_exporter_data_set *data_set = NULL;
    struct ipfix_exporter_data *data_record = NULL;
    struct ipfix_exporter_template *template = NULL;
    int signal = 0;
    int rc = 1;

    /*
     * Get a template corresponding to the requested type
     * and make a new data record that adheres to the template_type.
     */
    switch (template_type) {
        case IPFIX_SIMPLE_TEMPLATE:
            template = ipfix_xts_search(IPFIX_SIMPLE_TEMPLATE, NULL);
            data_record = ipfix_exp_create_data_record(IPFIX_SIMPLE_TEMPLATE,
                                                       fr_record);
            break;
        case IPFIX_IDP_TEMPLATE:
            template = ipfix_xts_search(IPFIX_IDP_TEMPLATE, NULL);
            data_record = ipfix_exp_create_data_record(IPFIX_IDP_TEMPLATE,
                                                       fr_record);
            break;
        default:
            loginfo("error: template type not supported for exporting");
            goto end;
    }

    /* Try to get an existing data set in the message */
    data_set = ipfix_exp_message_find_data_set(message,
                                               template->hdr.template_id);

    if (data_set == NULL) {
        /*
         * The message doesn't contain a data set related to
         * the specified template type. Create and init the
         * set node with a new data set. Finally, the set node
         * will be attached to the message.
         */
        set_node = ipfix_exp_set_node_malloc(template->hdr.template_id);
        if (set_node == NULL) {
            loginfo("error: unable to create a data set_node");
            goto end;
        }

        /* Point local data_set to inside set_node for easy manipulation */
        data_set = set_node->set.data_set;

        /* Add the data_record to the data_set */
        ipfix_exp_data_set_add(data_set, data_record);

        /* 
         * Try to attach the data set node to the message container.
         * If the message is full, return the code indicating that
         * a new message should be made with the current fr_record.
         * A.k.a. try again
         */
        signal = ipfix_exp_message_add(message, set_node);

        if (signal == 1) {
            loginfo("error: unable to attach set_node to message");
            goto end;
        } else if (signal == 2) {
            /* Not enough space in message */
            rc = 2;
            goto end;
        }
    } else {
        /*
         * The valid Data Set already exists in message.
         * Simply make the data record and attach to the data_set.
         * If the message if full, return the code indicating that
         * a new message should be made with the current fr_record.
         * A.k.a. try again
         */
        if (data_record->length + message->hdr.length <= IPFIX_MAX_SET_LEN) {
            /* Add the data record to the existing data set */
            ipfix_exp_data_set_add(data_set, data_record);
        } else {
            /* Not enough space in message */
            rc = 2;
            goto end;
        }
    }

    /* Successfully attached */
    rc = 0;

end:
    if (rc) {
        /* Did not attach to message so cleanup here */
        if (set_node) {
            ipfix_delete_exp_set_node(set_node);
        }
        if (data_record) {
            ipfix_delete_exp_data_record(data_record);
        }
    }

    return rc;
}

/*
 * @brief Encapsulate a template record within a template set and then
 *        attach it to an IPFIX \p message.
 *
 * @param message IPFIX message that the template record/set will be encoded and written into.
 * @param template_type The template type to create.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_export_message_attach_template_set(struct ipfix_message *message,
                                                    enum ipfix_template_type template_type) {
    struct ipfix_exporter_set_node *set_node = NULL;
    struct ipfix_exporter_template_set *template_set = NULL;
    struct ipfix_exporter_template *xts_tmp = NULL;
    struct ipfix_exporter_template *local_tmp = NULL;
    int flag_send_template = 0;
    int signal = 0;
    int flag_cleanup = 1;
    int rc = 1;

    /*
     * Search for the template in the xts. If it's already there,
     * simply let the search function take care of copying into the
     * local template. If it does not already exist in xts, create
     * an entry in the xts and copy locally to here. No need to
     * free the xts_tmp because exists within the store.
     */
    switch (template_type) {
        case IPFIX_SIMPLE_TEMPLATE:
            if (!ipfix_xts_search(IPFIX_SIMPLE_TEMPLATE, &local_tmp)) {
                xts_tmp = ipfix_exp_create_template(IPFIX_SIMPLE_TEMPLATE);
                if (ipfix_xts_copy(&local_tmp, xts_tmp)) {
                    loginfo("error: copy from export template store failed");
                    goto end;
                }
            }
            break;
        case IPFIX_IDP_TEMPLATE:
            if (!ipfix_xts_search(IPFIX_IDP_TEMPLATE, &local_tmp)) {
                xts_tmp = ipfix_exp_create_template(IPFIX_IDP_TEMPLATE);
                if (ipfix_xts_copy(&local_tmp, xts_tmp)) {
                    loginfo("error: copy from export template store failed");
                    goto end;
                }
            }
            break;
        default:
            loginfo("error: template type not supported for exporting");
            goto end;
    }

    /*
     * Check if template needs to be sent
     */
    if (((XTS_RESEND_TIME <= (time(NULL) - local_tmp->last_sent)) &&
        ((time(NULL) - local_tmp->last_sent) < XTS_EXPIRE_TIME)) ||
        local_tmp->last_sent == 0) {
        /*
         * The template is within the resend period or has not been
         * previously sent before.
         */
        flag_send_template = 1;
    }

    if (flag_send_template) {
        struct ipfix_exporter_template *db_tmp = NULL;

        /* Get a valid template set to attach to, if possible */
        template_set = ipfix_exp_message_find_template_set(message);

        /*
         * Get a pointer to the XTS database template.
         * This is for updating the time and other attributes on
         * the template object.
         */
        switch (template_type) {
            case IPFIX_SIMPLE_TEMPLATE:
                db_tmp = ipfix_xts_search(IPFIX_SIMPLE_TEMPLATE, NULL);
                break;
            case IPFIX_IDP_TEMPLATE:
                db_tmp = ipfix_xts_search(IPFIX_IDP_TEMPLATE, NULL);
                break;
            default:
                loginfo("error: template type not supported for exporting");
                goto end;
        }

        if (template_set == NULL) {
            /*
             * The message doesn't contain a template set yet.
             * Create and init the set node with a new template set.
             * Finally, the set node will be attached to the message.
             */

            /* Create and init the set node with a template set for use */
            set_node = ipfix_exp_set_node_malloc(IPFIX_TEMPLATE_SET);
            if (set_node == NULL) {
                loginfo("error: unable to create a template set_node");
                goto end;
            }

            /* Point local template_set to inside set_node for easy manipulation */
            template_set = set_node->set.template_set;

            /* Add the new template to the template_set */
            ipfix_exp_template_set_add(template_set, local_tmp);

            /* 
             * Try to attach the template set node to the message container.
             * If the message is full, the set node will be deleted, and the function
             * will call itself with the current flow record to get a new message started.
             */
            signal = ipfix_exp_message_add(message, set_node);
            if (signal == 0) {
                /* 
                 * Update the last_sent time on template
                 * in exporter template store (xts)
                 */
                if (db_tmp) {
                    db_tmp->last_sent = time(NULL);
                }
            } else if (signal == 1) {
                loginfo("error: unable to attach set_node to message");
                goto end;
            } else if (signal == 2) {
                /* Not enough space in message */
                rc = 2;
                goto end;
            }
        } else {
            /*
             * A valid Template Set already exists in message.
             * Simply make the template and attach to the template_set.
             */
            if (local_tmp->length + message->hdr.length <= IPFIX_MAX_SET_LEN) {
                /* Add the new template to the template_set */
                ipfix_exp_template_set_add(template_set, local_tmp);

                /* 
                 * Update the last_sent time on template
                 * in exporter template store (xts)
                 */
                if (db_tmp) {
                    db_tmp->last_sent = time(NULL);
                }
            } else {
                /* Not enough space in message */
                rc = 2;
                goto end;
            }
        }

        /*
         * Attached the set node and template to message
         * so don't cleanup those objects.
         */
        flag_cleanup = 0;
    }

    /* Successfully attached */
    rc = 0;

end:
    if (flag_cleanup) {
        /* Did not attach to message so cleanup here */
        if (set_node) {
            ipfix_delete_exp_set_node(set_node);
        }
        if (local_tmp) {
            ipfix_delete_exp_template(local_tmp);
        }
    }

    return rc;
}

/*
 * @brief The main IPFIX exporting control function for creating messages that
 *        that will be sent along the network.
 *
 * @param fr_record Joy flow record created during the metric observation
 *                  phase of the process, i.e. process_packet(). It contains
 *                  information that will be encoded into the message.
 *
 * @return 0 for success, 1 for failure
 */
int ipfix_export_main(const struct flow_record *fr_record) {
    int attach_code = 0;

    /* Init the exporter for use, if not done already */
    if (gateway_export.socket == 0) {
        ipfix_exporter_init(&gateway_export, ipfix_export_remote_host);
    }

    /* Create and init the IPFIX message */
    if (export_message == NULL) {
        if (!(export_message = ipfix_exp_message_malloc())) {
            loginfo("error: unable to create a message");
            return 1;
        }
    }

    /*
     * Attach a template if necessary.
     */
    attach_code = ipfix_export_message_attach_template_set(export_message,
                                                           export_template_type);
    if (attach_code == 2) {
        /* 
         * Could not attach template to the message because
         * it was already full. Here we send off the packed message
         * and then make a new one to attach this template to.
         */
        ipfix_export_send_message(&gateway_export, export_message);

        if (export_message) {
            /* Cleanup the message */
            ipfix_delete_exp_message(export_message);

            /* Make new message */
            if (!(export_message = ipfix_exp_message_malloc())) {
                loginfo("error: unable to create a message");
                return 1;
            }
        }

        if (ipfix_export_message_attach_template_set(export_message,
                                                     export_template_type)) {
            /*
             * We either had an error or could not attach again.
             * This is a problem...
             */
            return 1;
        }
    }

    /*
     * Attach data record.
     */
    attach_code = ipfix_export_message_attach_data_set(fr_record,
                                                       export_message,
                                                       export_template_type);
    if (attach_code == 2) {
        /* 
         * Could not attach data record to the message because
         * it was already full. Here we send off the packed message
         * and then make a new one to attach this data record to.
         */
        ipfix_export_send_message(&gateway_export, export_message);

        if (export_message) {
            /* Cleanup the message */
            ipfix_delete_exp_message(export_message);

            /* Make new message */
            if (!(export_message = ipfix_exp_message_malloc())) {
                loginfo("error: unable to create a message");
                return 1;
            }
        }

        if (ipfix_export_message_attach_data_set(fr_record,
                                                 export_message,
                                                 export_template_type)) {
            /*
             * We either had an error or could not attach again.
             * This is a problem...
             */
            return 1;
        }
    }

    return 0;
}

