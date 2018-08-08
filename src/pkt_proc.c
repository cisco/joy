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
 * \file pkt_proc.c
 *
 * \brief packet processing function implementation
 *
 */
#include <stdio.h>
#include <pcap.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include "pkt_proc.h"
#include "p2f.h"
#include "pkt.h"
#include "err.h"
#include "tls.h"
#include "nfv9.h"
#include "ipfix.h"
#include "utils.h"
#include "proto_identify.h"
#include "pthread.h"
#include "joy_api_private.h"

/** netflow version 9 structure templates */
static struct nfv9_template v9_templates[MAX_TEMPLATES];

/** number of templates in use */
static u_short num_templates = 0;

pthread_mutex_t nfv9_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * \fn int data_sanity_check ()
 * \param none
 * \return ok
 * \return failure
 */
int data_sanity_check () {
    assert(sizeof(struct ip_hdr) == 20);
    assert(sizeof(struct tcp_hdr) == 20);
    assert(sizeof(struct udp_hdr) == 8);
    assert(sizeof(struct icmp_hdr) == 8);
    return ok;
}

#if 0
static void print_payload(const char *payload, int len);

static void print_hex_ascii_line(const char *payload, int len, int offset);
#endif

#if 0
/*
 * print_hex_ascii_line prints data in rows of 16 bytes, with a format
 * of offset, hex bytes, then ASCII characters.
 */
void print_hex_ascii_line (const char *data, int len, int offset) {
    const char *d;
    int i, j;

    fprintf(info, "%05d   ", offset);
    d = data;
    for(i = 0; i < len; i++) {
        fprintf(info, "%02x ", *d);
        d++;
        if (i == 7)
            fprintf(info, " ");
    }
    if (len < 8)
        fprintf(info, " ");

    if (len < 16) {
        j = 16 - len;
        for (i = 0; i < j; i++) {
            fprintf(info, "   ");
        }
    }
    fprintf(info, "   ");

    d = data;
    for(i = 0; i < len; i++) {
        if (isprint(*d))
            fprintf(info, "%c", *d);
        else
            fprintf(info, ".");
        d++;
    }
    fprintf(info, "\n");

    return;
}
#endif

#if 0
/*
 * print packet payload data (avoid printing binary data)
 */
static void print_payload (const char *payload, int len) {
    int len_rem = len;
    int line_width = 16;                        /* number of bytes per line */
    int line_len;
    int offset = 0;                     /* zero-based offset counter */
    const char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}
#endif

static void flow_record_process_packet_length_and_time_ack (flow_record_t *record,
                                                            unsigned int length, 
                                                            const struct timeval *time,
                                                            const struct tcp_hdr *tcp) {

    if (record->op >= NUM_PKT_LEN) {
        return;  /* no more room */
    }

    switch(glb_config->salt_algo) {
        case rle:
            if (glb_config->include_zeroes || length != 0) {
                if (length == record->last_pkt_len) {
		    if (record->pkt_len[record->op] < 32768) {
			record->op++;
		    }
		    (record->pkt_len[record->op])--;
		    record->pkt_time[record->op] = *time;
		    // fprintf(info, " == pkt_len[%d]: %d\n", record->op, record->pkt_len[record->op]);
                } else {
		    if (record->pkt_len[record->op] != 0) {
			record->op++;
		    }
		    record->pkt_len[record->op] = length;
		    record->pkt_time[record->op] = *time;
		    record->last_pkt_len = length;
		    // fprintf(info, " != pkt_len[%d]: %d\n", record->op, record->pkt_len[record->op]);
                }
            }
            break;

        case aggregated:
            if (glb_config->include_zeroes || length != 0) {
                record->pkt_len[record->op] += length;
                record->pkt_time[record->op] = *time;
            }
            if (ntohl(tcp->tcp_ack) > record->tcp.ack) {
		if (record->pkt_len[record->op] != 0) {
		    record->op++;
		}
            }
            break;

        case defragmented:
            if (glb_config->include_zeroes || length != 0) {
                if (length == record->last_pkt_len) {
		    record->op--;
		    record->pkt_len[record->op] += length;
		    record->pkt_time[record->op] = *time;
		    record->op++;
                } else {
		    record->pkt_len[record->op] = length;
		    record->pkt_time[record->op] = *time;
		    record->last_pkt_len = length;
		    record->op++;
                }
            }
            if (ntohl(tcp->tcp_ack) > record->tcp.ack) {
                if (record->pkt_len[record->op] != 0) {
		    record->op++;
                }
                record->last_pkt_len = length;
            }
            break;

        default:
        case raw:
            if (glb_config->include_zeroes || (length != 0)) {
                record->pkt_len[record->op] = length;
                record->pkt_time[record->op] = *time;
                record->op++;
            }
            break;
    }

    record->pkt_flags[record->op] = tcp->tcp_flags;
    record->tcp.seq = ntohl(tcp->tcp_seq);
    record->tcp.ack = ntohl(tcp->tcp_ack);
}

/*
 * @brief Process IPFIX message contents.
 *
 * @param start Beginning of IPFIX message data.
 * @param len Total length of the data.
 * @param r Flow record tracking the inbound network packet.
 */
joy_status_e process_ipfix(joy_ctx_data *ctx, const char *start,
			   int len,
			   flow_record_t *r) {

    const ipfix_hdr_t *ipfix = (const ipfix_hdr_t*)start;
    const ipfix_set_hdr_t *ipfix_sh;
    flow_key_t prev_key;
    uint16_t message_len = ntohs(ipfix->length);
    int set_num = 0;
    const flow_key_t rec_key = r->key;
    char ipv4_addr[INET_ADDRSTRLEN];
    
    memset(&prev_key, 0, sizeof(flow_key_t));
    
    if (ntohs(ipfix->version_number) != 10) {
        joy_log_warn("ipfix version number is invalid");
    }
    
    if (message_len > len) {
        joy_log_warn("ipfix message claims to be longer than packet length");
    }
    
    joy_log_info("Processing ipfix packet");
    inet_ntop(AF_INET, &r->key.sa, ipv4_addr, INET_ADDRSTRLEN);
    joy_log_debug(" Source IP: %s\n", ipv4_addr);
    joy_log_debug(" Observation Domain ID: %i", htonl(ipfix->observe_dom_id));
    joy_log_debug(" Packet len: %u", len);
    
#if 0
    if (len > 0) {
        joy_log_debug("Payload:");
        if (verbosity == JOY_LOG_DEBUG) {
            print_payload(start, len);
        }
    }
#endif
    
    /* Move past ipfix_hdr, i.e. IPFIX message header */
    start += 16;
    message_len -= 16;
    
    /*
     * Parse IPFIX message for template, options, or data sets.
     */
    while (message_len > sizeof(ipfix_set_hdr_t)) {
        ipfix_sh = (const ipfix_set_hdr_t*)start;
        uint16_t set_id = ntohs(ipfix_sh->set_id);
        
        joy_log_debug("Set ID: %i\n", set_id);
        joy_log_debug("Set Length: %i\n", ntohs(ipfix_sh->length));
        
        if ((set_id <= 1) || ((4 <= set_id) && (set_id <= 255))) {
            /* The set_id is invalid, either Netflow or reserved */
            joy_log_warn("Set ID is invalid\n");
        }
        /*
         * Set ID is a Template Set
         */
        else if (set_id == 2) {
            /* Set template pointer to right after set header */
            const void *template_start = start + 4;
            uint16_t template_set_len = htons(ipfix_sh->length) - 4;
            
            /* Parse the template set */
            ipfix_parse_template_set(ipfix, template_start,
                                     template_set_len, rec_key);
        }
        /*
         * Set ID is an Options Template Set
         */
        else if (set_id == 3) {
            /* Ignore Options Template for now, what is this used for? */
            joy_log_warn("Options Template NYI\n");
        }
        /*
         * Set ID is a Data Set
         */
        else {
            const void *data_start = start + 4;
            uint16_t data_set_len = ntohs(ipfix_sh->length) - 4;
            
            ipfix_parse_data_set(ctx, ipfix, data_start, data_set_len,
                                 set_id, rec_key, &prev_key);
        }
        
        start += ntohs(ipfix_sh->length);
        message_len -= ntohs(ipfix_sh->length);
        set_num += 1;
    }
    
    return ok;
}

static joy_status_e process_nfv9 (joy_ctx_data *ctx, 
                                  const struct pcap_pkthdr *header, 
                                  const char *start, int len, 
                                  flow_record_t *r) {

    const struct nfv9_hdr *nfv9 = (const struct nfv9_hdr*)start;
    flow_key_t prev_key;
    int flowset_num = 0;
    char ipv4_addr[INET_ADDRSTRLEN];

    joy_log_info("Processing NFV9");
    joy_log_info("Source ID: %i", htonl(nfv9->SourceID));
    inet_ntop(AF_INET, &r->key.sa, ipv4_addr, INET_ADDRSTRLEN);
    joy_log_info("Source IP: %s", ipv4_addr);
    joy_log_debug("Packet len: %u", len);

#if 0
    /* Print payload */
    if (len > 0) {
        joy_log_debug("Payload:");
        if (verbosity == JOY_LOG_DEBUG) {
            print_payload(start, len);
        }
    }
#endif

    memset(&prev_key, 0x0, sizeof(flow_key_t));

    start += 20;
    len -= 20;
    const struct nfv9_flowset_hdr *nfv9_fh;

    while (len > sizeof(struct nfv9_flowset_hdr)) {
        flowset_num += 1;
        nfv9_fh = (const struct nfv9_flowset_hdr*)start;

        u_short flowset_id = htons(nfv9_fh->FlowSetID);
        joy_log_debug("Flowset ID: %i",flowset_id);
        joy_log_debug("Flowset Length: %i",htons(nfv9_fh->Length));

        // check if FlowsetID is a data template, and if so, add to templates
        if (flowset_id == 0) {

            // process multiple templates within the same flowset
            int flowset_length = htons(nfv9_fh->Length);
            // added -4 for the potentially non-existent corner case of padding after multiple templates
            const char *template_ptr = start + 4;
            flowset_length -= 4;

            while (flowset_length-4 > 0) {

                      // define data template key {source IP + source ID + template ID}
                      const struct nfv9_template_hdr *template_hdr = (const struct nfv9_template_hdr*)template_ptr;
                      flowset_length -= 4;
                      template_ptr += 4;
                      u_short template_id = htons(template_hdr->TemplateID);
                      u_short field_count = htons(template_hdr->FieldCount);

                      struct nfv9_template_key nf_template_key;
                      memset(&nf_template_key, 0x0, sizeof(struct nfv9_template_key));
                      nfv9_template_key_init(&nf_template_key, r->key.sa.s_addr, htonl(nfv9->SourceID), template_id);

                      // check to see if template already exists, if so, continue
                      int i;
                      int redundant_template = 0;
                      for (i = 0; i < num_templates; i++) {
                          if (nfv9_template_key_cmp(&nf_template_key,&v9_templates[i].template_key) == 0) {
                              redundant_template = 1;
                              break ;
                          }
                      }

                      if (redundant_template) {
                          template_ptr += 4*field_count;
                          flowset_length -= 4*field_count;
                      } else {
                          // create list of fields for template
                          struct nfv9_template v9_template;
                          v9_template.hdr.TemplateID = template_id;
                          v9_template.hdr.FieldCount = field_count;
                          for (i = 0; i < field_count; i++) {
                              const struct nfv9_template_field *tmp_field = (const struct nfv9_template_field*)template_ptr;
                              template_ptr += 4;
                              flowset_length -= 4;

                              v9_template.fields[i].FieldType = tmp_field->FieldType;
                              v9_template.fields[i].FieldLength = tmp_field->FieldLength;
                          }
                          v9_template.template_key = nf_template_key;

                          // save template
                          v9_templates[num_templates] = v9_template;
                          num_templates += 1;
                          num_templates %= MAX_TEMPLATES;
                      }
            }
        } else if (flowset_id == 1) {
            /*
             * Options templaye not yet implemented
             */
            joy_log_warn("Options Template NYI\n");
        } else { // process flow data if we know the template
            // define data template key {source IP + source ID + template ID}
            u_short template_id = flowset_id;

            struct nfv9_template_key nf_template_key;
            nfv9_template_key_init(&nf_template_key, r->key.sa.s_addr, htonl(nfv9->SourceID), template_id);

            // construct key and look for templates
            const struct nfv9_template *cur_template = NULL;
            int i;
            for (i = 0; i < num_templates; i++) {
                      /*
                if (nfv9_template_key_cmp(&nf_template_key,&v9_templates[i].template_key) == 0) {
                          cur_template = &v9_templates[i];
                          break ;
                      }
                */
                      if (nf_template_key.src_id == v9_templates[i].template_key.src_id &&
                          nf_template_key.template_id == v9_templates[i].template_key.template_id &&
                          nf_template_key.src_addr.s_addr == v9_templates[i].template_key.src_addr.s_addr) {
                          cur_template = &v9_templates[i];
                          break ;
                      }
            }

            if (cur_template != NULL) {
                      // find length of template
                      int flow_record_size = 0;
                      for (i = 0; i < cur_template->hdr.FieldCount; i++) {
                          flow_record_size += htons(cur_template->fields[i].FieldLength);
                      }

                      if (flow_record_size <= 0) {
                          joy_log_warn("flow record size is 0");
                          return failure;
                      }

                      // process multiple flow records within a single template
                      int flow_records_in_set;
                      for (flow_records_in_set = 0; flow_records_in_set < (htons(nfv9_fh->Length)-4)/flow_record_size;
                         flow_records_in_set++) {

                          // fill out key
                          flow_key_t key;
                          const void *flow_data = (start+flow_record_size*flow_records_in_set) + 4;

                          // init key
                          nfv9_flow_key_init(&key, cur_template, flow_data);

                      /*
                       * Either get an existing record for the netflow data or make a new one.
                       * Don't include the header because it is the packet that was sent
                       * by exporter -> collector (not the netflow data).
                       */
                          flow_record_t *nf_record = NULL;
                          nf_record = flow_key_get_record(ctx, &key, CREATE_RECORDS, NULL);

                          // fill out record
                          if (memcmp(&key,&prev_key,sizeof(flow_key_t)) != 0) {
                              nfv9_process_flow_record(nf_record, cur_template, flow_data, 0);
                          } else {
                              nfv9_process_flow_record(nf_record, cur_template, flow_data, 1);
                          }
                          memcpy(&prev_key,&key,sizeof(flow_key_t));

                          flowset_num += 1;

                          /* print the record immediately to output */
                          //flow_record_print_json(nf_record);

                      }
            } else {
                joy_log_warn("Current template is null");
            }
        }

        start += htons(nfv9_fh->Length);
        len -= htons(nfv9_fh->Length);
    }

    return ok;
}

static flow_record_t *
process_tcp (joy_ctx_data *ctx, const struct pcap_pkthdr *header, const char *tcp_start, int tcp_len, flow_key_t *key) {
    unsigned int tcp_hdr_len;
    const char *payload;
    unsigned int size_payload;
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)tcp_start;
    flow_record_t *record = NULL;

    joy_log_info("Protocol: TCP");

    tcp_hdr_len = tcp_hdr_length(tcp);
    if (tcp_hdr_len < 20 || tcp_hdr_len > tcp_len) {
        joy_log_err("Invalid TCP header length: %u bytes", tcp_hdr_len);
        return NULL;
    }

    /* define/compute tcp payload (segment) offset */
    payload = (char *)(tcp_start + tcp_hdr_len);

    /* compute tcp payload (segment) size */
    size_payload = tcp_len - tcp_hdr_len;

    joy_log_info("Src port: %d", ntohs(tcp->src_port));
    joy_log_info("Dst port: %d", ntohs(tcp->dst_port));
    joy_log_info("Payload len: %u", size_payload);
    joy_log_debug("TCP len: %u", tcp_len);
    joy_log_debug("TCP hdr len: %u", tcp_hdr_len);
    joy_log_debug("flags:");
    if (tcp->tcp_flags & TCP_FIN) { joy_log_debug("* FIN"); }
    if (tcp->tcp_flags & TCP_SYN) { joy_log_debug("* SYN"); }
    if (tcp->tcp_flags & TCP_RST) { joy_log_debug("* RST"); }
    if (tcp->tcp_flags & TCP_PSH) { joy_log_debug("* PSH"); }
    if (tcp->tcp_flags & TCP_ACK) { joy_log_debug("* ACK"); }
    if (tcp->tcp_flags & TCP_URG) { joy_log_debug("* URG"); }
    if (tcp->tcp_flags & TCP_ECE) { joy_log_debug("* ECE"); }
    if (tcp->tcp_flags & TCP_CWR) { joy_log_debug("* CWR"); }

#if 0
    if (size_payload > 0) {
        joy_log_debug("Payload:");
        if (verbosity == JOY_LOG_DEBUG) {
            print_payload(payload, size_payload);
        }
    }
#endif

    key->sp = ntohs(tcp->src_port);
    key->dp = ntohs(tcp->dst_port);

    record = flow_key_get_record(ctx, key, CREATE_RECORDS, header);
    if (record == NULL) {
        return NULL;
    }

    joy_log_debug("SEQ: %d -- relative SEQ: %d", ntohl(tcp->tcp_seq), ntohl(tcp->tcp_seq) - record->tcp.seq);
    joy_log_debug("ACK: %d -- relative ACK: %d", ntohl(tcp->tcp_ack), ntohl(tcp->tcp_ack) - record->tcp.ack);

    if (size_payload > 0) {
        if (ntohl(tcp->tcp_seq) < record->tcp.seq) {
            joy_log_debug("retransmission detected");
            record->tcp.retrans++;
            if (!glb_config->include_retrans) {
                // do not process TCP retransmissions
                return NULL;
            }
        }
    }
    if (glb_config->include_zeroes || size_payload > 0) {
          flow_record_process_packet_length_and_time_ack(record, size_payload, &header->ts, tcp);
    }

    if (tcp->tcp_flags == 2 || tcp->tcp_flags == 18) { // SYN==2, SYN/ACK==18
        /* Initial SYN or SYN/ACK packet */
        unsigned int opt_len = tcp_hdr_len - 20;

        if (!record->tcp.flags) {
            record->tcp.flags = tcp->tcp_flags;
        }

        /* Get initial sequence number */
        if (tcp->tcp_flags == 2 && record->tcp.first_seq == 0) {
            record->tcp.first_seq = ntohl(tcp->tcp_seq);
        }

        /* Get initial window size */
        if (!record->tcp.first_window_size) {
            record->tcp.first_window_size = ntohs(tcp->tcp_win);
        }

        if (opt_len > 0) {
            /* Copy options data into buffer */
            if (opt_len > TCP_OPT_LEN) {
                record->tcp.opt_len = TCP_OPT_LEN;
                memcpy(record->tcp.opts, tcp_start + 20, TCP_OPT_LEN);
            } else {
                record->tcp.opt_len = opt_len;
                memcpy(record->tcp.opts, tcp_start + 20, opt_len);
            }
        }
    }

    record->ob += size_payload;

    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);

    /*
     * Estimate the TCP application protocol
     * Optimization: stop after first 2 packets that have non-zero payload
     */
    if ((!record->app) && record->op <= 2) {
        const struct pi_container *pi = proto_identify_tcp(payload, size_payload);
        if (pi != NULL) {
            record->app = pi->app;
            record->dir = pi->dir;
        }
    }

    /*
     * Run protocol modules!
     */
    update_all_features(payload_feature_list);

    /*
     * update header description
     */
    if (size_payload >= glb_config->report_hd) {
        header_description_update(&record->hd, payload, glb_config->report_hd);
    }

    return record;
}

static flow_record_t *
process_udp (joy_ctx_data *ctx, const struct pcap_pkthdr *header, const char *udp_start, int udp_len, flow_key_t *key) {
    unsigned int udp_hdr_len;
    const char *payload;
    unsigned int size_payload;
    const struct udp_hdr *udp = (const struct udp_hdr *)udp_start;
    flow_record_t *record = NULL;

    joy_log_info("Protocol: UDP");

    udp_hdr_len = 8;
    if (udp_len < 8) {
        joy_log_err("Invalid UDP packet length: %u bytes", udp_len);
        return NULL;
    }

    payload = (char *)(udp_start + udp_hdr_len);
    size_payload = udp_len - udp_hdr_len;

    joy_log_info("Src port: %d", ntohs(udp->src_port));
    joy_log_info("Dst port: %d", ntohs(udp->dst_port));
    joy_log_info("Payload len: %d", size_payload);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
#if 0
    if (size_payload > 0) {
        joy_log_debug("payload (%d bytes):", size_payload);
        if (verbosity == JOY_LOG_DEBUG) {
            print_payload(payload, size_payload);
        }
    }
#endif

    key->sp = ntohs(udp->src_port);
    key->dp = ntohs(udp->dst_port);

    record = flow_key_get_record(ctx, key, CREATE_RECORDS, header);
    if (record == NULL) {
        return NULL;
    }
    if (record->op < NUM_PKT_LEN) {
        if (glb_config->include_zeroes || (size_payload != 0)) {
            record->pkt_len[record->op] = size_payload;
            record->pkt_time[record->op] = header->ts;
            record->op++;
        }
    }
    record->ob += size_payload;

    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);

    /*
     * Estimate the UDP application protocol
     * Optimization: stop after first 2 packets that have non-zero payload
     */
    if ((!record->app) && record->op <= 2) {
        const struct pi_container *pi = proto_identify_udp(payload, size_payload);
        if (pi != NULL) {
            record->app = pi->app;
            record->dir = pi->dir;
        }
    }

    /*
     * Run protocol modules!
     */
    update_all_features(payload_feature_list);

    if (glb_config->nfv9_capture_port && (key->dp == glb_config->nfv9_capture_port)) {
        pthread_mutex_lock(&nfv9_lock);
        process_nfv9(ctx, header, payload, size_payload, record);
        pthread_mutex_unlock(&nfv9_lock);
    }

    if (glb_config->ipfix_collect_port && (key->dp == glb_config->ipfix_collect_port)) {
      process_ipfix(ctx, payload, size_payload, record);
    }

    return record;
}

static flow_record_t *
process_icmp (joy_ctx_data *ctx, const struct pcap_pkthdr *header, const char *start, int len, flow_key_t *key) {
    int size_icmp_hdr;
    const char *payload;
    int size_payload;
    const struct icmp_hdr *icmp = (const struct icmp_hdr *)start;
    flow_record_t *record = NULL;

    joy_log_info("Protocol: ICMP");

    size_icmp_hdr = 8;
    if (len < size_icmp_hdr) {
        joy_log_err("Invalid ICMP packet length: %u bytes", len);
        return NULL;
    }

    joy_log_info("Type: %d", icmp->type);
    joy_log_info("Code: %d", icmp->code);

    payload = (char *)(start + size_icmp_hdr);
    size_payload = len - size_icmp_hdr;

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
#if 0
    if (size_payload > 0) {
        joy_log_debug("Payload (%d bytes):", size_payload);
        if (verbosity == JOY_LOG_DEBUG) {
            print_payload(payload, size_payload);
        }
    }
#endif

    /*
     * signify ICMP by using sp = dp = 0 (which is an IANA-reserved
     * value); this key will be distinguished from the keys of TCP and
     * UDP flows by the key->prot value
     */
    key->sp = 0;
    key->dp = 0;

    record = flow_key_get_record(ctx, key, CREATE_RECORDS, header);
    if (record == NULL) {
        return NULL;
    }
    if (record->op < NUM_PKT_LEN) {
        if (glb_config->include_zeroes || (size_payload != 0)) {
            record->pkt_len[record->op] = size_payload;
            record->pkt_time[record->op] = header->ts;
            record->op++;
        }
    }
    record->ob += size_payload;

    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);
    update_all_features(payload_feature_list);

    return record;
}

static flow_record_t *
process_ip (joy_ctx_data *ctx, const struct pcap_pkthdr *header, const void *ip_start, int ip_len, flow_key_t *key) {
    const char *payload;
    int size_payload;
    flow_record_t *record = NULL;

    joy_log_info("Protocol: IP");

    payload = (char *)(ip_start);
    size_payload = ip_len;

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
#if 0
    if (size_payload > 0) {
        joy_log_debug("Payload (%d bytes):\n", size_payload);
        if (verbosity == JOY_LOG_DEBUG) {
            print_payload(payload, size_payload);
        }
    }
#endif

    record = flow_key_get_record(ctx, key, CREATE_RECORDS, header);
    if (record == NULL) {
        return NULL;
    }
    if (record->op < NUM_PKT_LEN) {
        if (glb_config->include_zeroes || (size_payload != 0)) {
            record->pkt_len[record->op] = size_payload;
            record->pkt_time[record->op] = header->ts;
            record->op++;
        }
    }
    record->ob += size_payload;

    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);
    update_all_features(payload_feature_list);

    return record;
}

/**
 * \fn void process_packet (unsigned char *ctx_ptr, const struct pcap_pkthdr *plkt_header,
                     const unsigned char *packet)
 * \param ctx_ptr currently used to store the context data pointer
 * \param pkt_header pointer to the packer header structure
 * \param packet pointer to the packet
 * \return none
 */
void process_packet (unsigned char *ctx_ptr, const struct pcap_pkthdr *pkt_header,
                     const unsigned char *packet) {
    //  static int packet_count = 1;
    flow_record_t *record;
    unsigned char proto = 0;
    unsigned int allocated_packet_header = 0;
    uint16_t ether_type = 0,vlan_ether_type = 0;
    char ipv4_addr[INET_ADDRSTRLEN];
    struct pcap_pkthdr *header = (struct pcap_pkthdr*)pkt_header;

    /* grab the context for this packet */
    joy_ctx_data *ctx = (joy_ctx_data*)ctx_ptr;
    if (ctx == NULL) {
        joy_log_err("NULL Data Context Pointer");
        return;
    }

    /* declare pointers to packet headers */
    const struct ip_hdr *ip;
    unsigned int transport_len;
    unsigned int ip_hdr_len;
    const void *transport_start;
    flow_key_t key;
    
    memset(&key, 0x00, sizeof(flow_key_t));

    flocap_stats_incr_num_packets(ctx);
    joy_log_info("++++++++++ Packet %lu ++++++++++", ctx->stats.num_packets);
    //  packet_count++;

    // ethernet = (struct ethernet_hdr*)(packet);
    ether_type = ntohs(*(uint16_t *)(packet + 12));//Offset to get ETH_TYPE
    /* Support for both normal ethernet and 802.1q . Distinguish between 
     * the two accepted types
    */
    switch(ether_type) {
       case ETH_TYPE_IP:
           joy_log_info("Ethernet type - normal");
           ip = (struct ip_hdr*)(packet + ETHERNET_HDR_LEN);
           ip_hdr_len = ip_hdr_length(ip);
           break;
       case ETH_TYPE_DOT1Q:
           joy_log_info("Ethernet type - 802.1Q VLAN");
           //Offset to get VLAN_TYPE
           vlan_ether_type = ntohs(*(uint16_t *)(packet + ETHERNET_HDR_LEN + 2));
           switch(vlan_ether_type) {
               case ETH_TYPE_IP:
                   ip = (struct ip_hdr*)(packet + ETHERNET_HDR_LEN + DOT1Q_HDR_LEN);
                   ip_hdr_len = ip_hdr_length(ip);
                   break;
               default :
                   return;
           }
           break;
       default:
           return;
    }  
    
    if (ip_hdr_len < 20) {
        joy_log_err(" Invalid IP header length: %u bytes", ip_hdr_len);
        return;
    }

    /* make sure we have a valid packet header */
    if (header == NULL) {
        struct timeval now;

        header = calloc(1,sizeof(struct pcap_pkthdr));
        if (header == NULL) {
            joy_log_err(" Couldn't allocate memory for packet header.");
            return;
        }
        allocated_packet_header = 1;
        gettimeofday(&now,NULL);
        header->ts.tv_sec = now.tv_sec;
        header->ts.tv_usec = now.tv_usec;
        header->caplen = ip->ip_len;
        header->len = ip->ip_len;
    }

    if (ntohs(ip->ip_len) < sizeof(struct ip_hdr) || ntohs(ip->ip_len) > header->caplen) {
        /*
         * IP packet is malformed (shorter than a complete IP header, or
         * claims to be longer than it is), or not entirely captured by
         * libpcap (which will depend on MTU and SNAPLEN; you can change
         * the latter if need be).
         */
        if (allocated_packet_header)
            free(header);
        return ;
    }
    transport_len =  ntohs(ip->ip_len) - ip_hdr_len;

    /* print source and destination IP addresses */
    inet_ntop(AF_INET, &ip->ip_src, ipv4_addr, INET_ADDRSTRLEN);
    joy_log_info("Source IP: %s", ipv4_addr);
    inet_ntop(AF_INET, &ip->ip_dst, ipv4_addr, INET_ADDRSTRLEN);
    joy_log_info("Dest IP: %s", ipv4_addr);
    joy_log_info("Len: %u", ntohs(ip->ip_len));
    joy_log_debug("IP header len: %u", ip_hdr_len);

    if (ip_fragment_offset(ip) == 0) {

        /* fill out IP-specific fields of flow key, plus proto selector */
        key.sa = ip->ip_src;
        key.da = ip->ip_dst;
        key.prot = ip->ip_prot;
        proto = (unsigned char)key.prot;

    }  else {
        // fprintf(info, "found IP fragment (offset: %02x)\n", ip_fragment_offset(ip));

        /*
         * select IP processing, since we don't have a TCP or UDP header
         */
        key.sa = ip->ip_src;
        key.da = ip->ip_dst;
        key.prot = IPPROTO_IP;
        proto = (unsigned char)key.prot;
    }

    /*
     * Keep track of the most recent packet time.
     * For all intents and purposes, this should be used as the "current" time in Joy.
     * In addition to being usable in real-time (online) scenarios, it also works
     * in situations where we can't use the real time, such as offline PCAP processing
     * because the time is contextual based.
     */
    if (joy_timer_lt(&ctx->global_time, &header->ts)) {
        ctx->global_time = header->ts;
    }

    /* determine transport protocol and handle appropriately */

    transport_start = (char *)ip + ip_hdr_len;
    switch(proto) {
        case IPPROTO_TCP:
            record = process_tcp(ctx, header, transport_start, transport_len, &key);
            if (record) {
              update_all_tcp_features(tcp_feature_list);
            }
            break;
        case IPPROTO_UDP:
            record = process_udp(ctx, header, transport_start, transport_len, &key);
            break;
        case IPPROTO_ICMP:
            record = process_icmp(ctx, header, transport_start, transport_len, &key);
            break;
        case IPPROTO_IP:
        default:
            record = process_ip(ctx, header, transport_start, transport_len, &key);
            break;
    }

    /*
     * if our packet is malformed TCP, UDP, or ICMP, then the process
     * functions will return NULL; we deal with that case by treating it
     * as just an IP packet
     */
    if (record == NULL) {
#if 1
        record = process_ip(ctx, header, transport_start, transport_len, &key);
        if (record == NULL) {
            joy_log_err("Unable to process ip packet (improper length or otherwise malformed)");
            return;
        }
        record->invalid++;
#else
        /*
         * if the processing of malformed packets causes trouble, choose
         * this code path instead
         */
        if (allocated_packet_header)
            free(header);
        return;
#endif
    }

    /*
     * Get IP ID
     */
    if (record->ip.num_id < MAX_NUM_IP_ID) {
        record->ip.id[record->ip.num_id] = ntohs(ip->ip_id);
        record->ip.num_id++;
    }

    /*
     * Set minimum ttl in flow record
     */
    if (record->ip.ttl > ip->ip_ttl) {
        record->ip.ttl = ip->ip_ttl;
    }

    /* increment packet count in flow record */
    record->np++;

    /* update flow record timestamps */
    if (timerisset(&record->start)) {
        record->end = header->ts;
    } else {
        record->start = record->end = header->ts;
    }

    /*
     * copy initial data packet, if configured to report idp, and this
     * is the first packet in the flow with nonzero data payload
     */
    if ((glb_config->idp) && record->op && (record->idp_len == 0)) {
        if (record->idp != NULL) {
            free(record->idp);
        }
        record->idp_len = (ntohs(ip->ip_len) < glb_config->idp ? ntohs(ip->ip_len) : glb_config->idp);
        record->idp = calloc(1, record->idp_len);
        if (!record->idp) {
            joy_log_err("Out of memory");
            if (allocated_packet_header)
                free(header);
            return;
        }

        memcpy(record->idp, ip, record->idp_len);
        joy_log_debug("Stashed %u bytes of IDP", record->idp_len);
    }

    /* increment overall byte count */
    flocap_stats_incr_num_bytes(ctx,transport_len);

    /* if we allocated the packet header, then free it now */
    if (allocated_packet_header)
        free(header);
    return;
}

/* END packet processing */
