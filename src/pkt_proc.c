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
#include "config.h"

/*
 * external variables, defined in pcap2flow
 */
extern FILE *output;
extern FILE *info;
extern unsigned int num_pkt_len;
extern unsigned int output_level;
extern unsigned int include_zeroes;
extern unsigned int include_tls;
extern unsigned int report_idp;
extern unsigned int report_hd;
extern unsigned int nfv9_capture_port;
extern unsigned int ipfix_capture_port;
extern enum SALT_algorithm salt_algo;
extern enum print_level output_level;
extern struct flocap_stats stats;
extern struct configuration config;

define_all_features_config_extern_uint(feature_list);

/** maximum number of templates allowed */
#define MAX_TEMPLATES 100

/** netflow version 9 structure templates */
struct nfv9_template v9_templates[MAX_TEMPLATES];

/** number of templates in use */
u_short num_templates = 0;

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

static void print_payload(const unsigned char *payload, int len);

static void print_hex_ascii_line(const unsigned char *payload, int len, int offset);

/*
 * print_hex_ascii_line prints data in rows of 16 bytes, with a format
 * of offset, hex bytes, then ASCII characters.
 */
void print_hex_ascii_line (const unsigned char *data, int len, int offset) {
    const unsigned char *d;
    int i, j;

    fprintf(output, "%05d   ", offset);	
    d = data;
    for(i = 0; i < len; i++) {
        fprintf(output, "%02x ", *d);
        d++;
        if (i == 7)
            fprintf(output, " ");
    }
    if (len < 8)
        fprintf(output, " ");
	
    if (len < 16) {
        j = 16 - len;
        for (i = 0; i < j; i++) {
            fprintf(output, "   ");
        }
    }
    fprintf(output, "   ");
	
    d = data;
    for(i = 0; i < len; i++) {
        if (isprint(*d))
            fprintf(output, "%c", *d);
        else
            fprintf(output, ".");
        d++;
    }
    fprintf(output, "\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
static void print_payload (const unsigned char *payload, int len) {
    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;		        /* zero-based offset counter */
    const unsigned char *ch = payload;

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

static void flow_record_process_packet_length_and_time_ack (struct flow_record *record,
		    unsigned int length, const struct timeval *time,
		    const struct tcp_hdr *tcp) {

    if (record->op >= num_pkt_len) {
        return;  /* no more room */
    }

    switch(salt_algo) {
        case rle:
            if (include_zeroes || length != 0) {
                if (length == record->last_pkt_len) {
	                  if (record->pkt_len[record->op] < 32768) {
	                      record->op++;
	                  }
	                  (record->pkt_len[record->op])--;
	                  record->pkt_time[record->op] = *time;
	                  // fprintf(output, " == pkt_len[%d]: %d\n", record->op, record->pkt_len[record->op]);
                } else {
	                  if (record->pkt_len[record->op] != 0) {
	                      record->op++;
	                  }
	                  record->pkt_len[record->op] = length;
	                  record->pkt_time[record->op] = *time;
	                  record->last_pkt_len = length;
	                  // fprintf(output, " != pkt_len[%d]: %d\n", record->op, record->pkt_len[record->op]);
                }
            }
            break;

        case aggregated:
            if (include_zeroes || length != 0) {
                record->pkt_len[record->op] += length;
                record->pkt_time[record->op] = *time;
            } 
            if (ntohl(tcp->tcp_ack) > record->ack) {
	              if (record->pkt_len[record->op] != 0) {
	                  record->op++; 	  
	              }
            }
            break;

        case defragmented:
            if (include_zeroes || length != 0) {
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
            if (ntohl(tcp->tcp_ack) > record->ack) {
                if (record->pkt_len[record->op] != 0) {
	                  record->op++;
                }
                record->last_pkt_len = length;
            }
            break;

        default:
        case raw:
            if (include_zeroes || (length != 0)) {
                record->pkt_len[record->op] = length;
                record->pkt_time[record->op] = *time;
                record->op++; 
            }
            break;
    }

    record->pkt_flags[record->op] = tcp->tcp_flags;
    record->seq = ntohl(tcp->tcp_seq);
    record->ack = ntohl(tcp->tcp_ack);
}


/*
 * @brief Process IPFIX message contents.
 *
 * @param start Beginning of IPFIX message data.
 * @param len Total length of the data.
 * @param r Flow record tracking the inbound network packet.
 */
enum status process_ipfix(const void *start,
                          int len,
                          struct flow_record *r) {

  const struct ipfix_hdr *ipfix = start;
  const struct ipfix_set_hdr *ipfix_sh;
  struct flow_key prev_key;
  int set_num = 0;
  const struct flow_key rec_key = r->key;

  if (ntohs(ipfix->version_number) != 10) {
    if (output_level > none) {
      fprintf(info, "ERROR: ipfix version number is invalid\n");
    }
  }

  /* debugging output */
  if (output_level > none) {
    fprintf(info, "processing ipfix packet\n");
    fprintf(output, "   protocol: ipfix");
    fprintf(output, " packet len: %u\n", len);

    if (output_level > packet_summary) {
      if (len > 0) {
        fprintf(output, "    payload:\n");
        print_payload(start, len);
      }
    }

    fprintf(info,"Source IP: %s\n",inet_ntoa(r->key.sa));
    fprintf(info,"Observation Domain ID: %i\n", htonl(ipfix->observe_dom_id));
  }

  /* Move past ipfix_hdr, i.e. IPFIX message header */
  start += 16;
  len -= 16;

  /*
   * Parse IPFIX message for template, options, or data sets.
   */
  while (len > 0) {
    ipfix_sh = start;
    uint16_t set_id = ntohs(ipfix_sh->set_id);

    if (output_level > none) {
      fprintf(info,"Set ID: %i\n", set_id);
      fprintf(info,"Set Length: %i\n", ntohs(ipfix_sh->length));
    }

    if ((set_id <= 1) || ((4 <= set_id) && (set_id <= 255))) {
      /* The set_id is invalid, either Netflow or reserved */
      if (output_level > none) {
        fprintf(info, "ERROR: Set ID is invalid\n");
      }
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
      if (output_level > none) {
	      fprintf(info,"Options Template NYI\n");
      }
    }
    /*
     * Set ID is a Data Set
     */
    else {
      const void *data_start = start + 4;
      uint16_t data_set_len = ntohs(ipfix_sh->length) - 4;

      ipfix_parse_data_set(ipfix, data_start, data_set_len,
                           set_id, rec_key, &prev_key);
    }

    start += ntohs(ipfix_sh->length);
    len -= ntohs(ipfix_sh->length);
    set_num += 1;
  }

  return ok;
}


static enum status process_nfv9 (const struct pcap_pkthdr *h, const void *start, int len, struct flow_record *r) {

    /* debugging output */
    if (output_level > none) {
        fprintf(info, "processing nfv9 packet\n");
        fprintf(output, "   protocol: nfv9");
        fprintf(output, " packet len: %u\n", len);

        if (output_level > packet_summary) {
            if (len > 0) {
	              fprintf(output, "    payload:\n");
	              print_payload(start, len);
            }
        }
    }

    /* 
     * if the nfv9 packet contains a template, then store it in the flow_record 
     */
    const struct nfv9_hdr *nfv9 = start;
    struct flow_key prev_key;
    int flowset_num = 0;

    if (output_level > none) {
        fprintf(info,"Source IP: %s\n",inet_ntoa(r->key.sa));
        fprintf(info,"Source ID: %i\n",htonl(nfv9->SourceID));
    }

    start += 20;
    len -= 20;
    const struct nfv9_flowset_hdr *nfv9_fh;
    while (len > 0) {
        flowset_num += 1;
        nfv9_fh = start;

        u_short flowset_id = htons(nfv9_fh->FlowSetID);
        if (output_level > none) {
            fprintf(info,"Flowset ID: %i\n",flowset_id);
            fprintf(info,"Flowset Length: %i\n",htons(nfv9_fh->Length));
        }
        // check if FlowsetID is a data template, and if so, add to templates
        if (flowset_id == 0) {

            // process multiple templates within the same flowset
            int flowset_length = htons(nfv9_fh->Length);
            // added -4 for the potentially non-existent corner case of padding after multiple templates
            const void *template_ptr = start + 4;
            flowset_length -= 4;

            while (flowset_length-4 > 0) {

	              // define data template key {source IP + source ID + template ID}
	              const struct nfv9_template_hdr *template_hdr = template_ptr;
	              flowset_length -= 4;
	              template_ptr += 4;
	              u_short template_id = htons(template_hdr->TemplateID);
	              u_short field_count = htons(template_hdr->FieldCount);
	
	              struct nfv9_template_key nf_template_key;
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
	                      const struct nfv9_template_field *tmp_field = template_ptr;
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
        // ignore options template for now, what is this used for?
        } else if (flowset_id == 1) {
            if (output_level > none) {
	              fprintf(info,"Options Template NYI\n");
            }
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

	              // process multiple flow records within a single template
	              int flow_records_in_set;
	              for (flow_records_in_set = 0; flow_records_in_set < (htons(nfv9_fh->Length)-4)/flow_record_size; 
                         flow_records_in_set++) {

	                  // fill out key
	                  struct flow_key key;
	                  const void *flow_data = (start+flow_record_size*flow_records_in_set) + 4;

	                  // init key
	                  nfv9_flow_key_init(&key, cur_template, flow_data);

	                  // get a nf record
	                  struct flow_record *nf_record;
	                  nf_record = flow_key_get_record(&key, CREATE_RECORDS); 
    
	                  // fill out record
	                  if (memcmp(&key,&prev_key,sizeof(struct flow_key)) != 0) {
	                      nfv9_process_flow_record(nf_record, cur_template, flow_data,0);
	                  } else {
	                      nfv9_process_flow_record(nf_record, cur_template, flow_data,1);
	                  }
	                  memcpy(&prev_key,&key,sizeof(struct flow_key));

	                  flowset_num += 1;

	                  /* print the record immediately to output */
	                  //flow_record_print_json(nf_record);

	              }
            } else {
                printf("cur template is null\n");
            }
        }

        start += htons(nfv9_fh->Length);
        len -= htons(nfv9_fh->Length);
    }

    return ok;
}

static struct flow_record *
process_tcp (const struct pcap_pkthdr *h, const void *tcp_start, int tcp_len, struct flow_key *key) {
    unsigned int tcp_hdr_len;
    const unsigned char *payload;
    unsigned int size_payload;
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)tcp_start;
    struct flow_record *record = NULL;
    unsigned int cur_itr = 0;
  
    if (output_level > none) {
        fprintf(output, "   protocol: TCP\n");
    }

    //  tcp_hdr_len = TCP_OFF(tcp)*4;
    tcp_hdr_len = tcp_hdr_length(tcp);
    if (tcp_hdr_len < 20 || tcp_hdr_len > tcp_len) {
        // fprintf(output, "   * Invalid TCP header length: %u bytes\n", tcp_hdr_len);
        return NULL;
    }
    
    /* define/compute tcp payload (segment) offset */
    payload = (unsigned char *)(tcp_start + tcp_hdr_len);
  
    /* compute tcp payload (segment) size */
    size_payload = tcp_len - tcp_hdr_len;

    if (output_level > none) {
        fprintf(output, "   src port: %d\n", ntohs(tcp->src_port));
        fprintf(output, "   dst port: %d\n", ntohs(tcp->dst_port));
        fprintf(output, "payload len: %u\n", size_payload);
        fprintf(output, "    tcp len: %u\n", tcp_len);
        fprintf(output, "tcp hdr len: %u\n", tcp_hdr_len);
        fprintf(output, "      flags:");
        if (tcp->tcp_flags & TCP_FIN) { fprintf(output, "FIN "); }
        if (tcp->tcp_flags & TCP_SYN) { fprintf(output, "SYN "); }
        if (tcp->tcp_flags & TCP_RST) { fprintf(output, "RST "); }
        if (tcp->tcp_flags & TCP_PSH) { fprintf(output, "PSH "); }
        if (tcp->tcp_flags & TCP_ACK) { fprintf(output, "ACK "); }
        if (tcp->tcp_flags & TCP_URG) { fprintf(output, "URG "); }
        if (tcp->tcp_flags & TCP_ECE) { fprintf(output, "ECE "); }
        if (tcp->tcp_flags & TCP_CWR) { fprintf(output, "CWR "); }
        fprintf(output, "\n");

        if (output_level > packet_summary) {
            if (size_payload > 0) {
	              fprintf(output, "    payload:\n");
	              print_payload(payload, size_payload);
            }
        }
    }

    key->sp = ntohs(tcp->src_port);
    key->dp = ntohs(tcp->dst_port);

    record = flow_key_get_record(key, CREATE_RECORDS); 
    if (record == NULL) {
        return NULL;
    }
    if (output_level > none) {
        fprintf(output, "   SEQ:      %d\trelative SEQ: %d\n", ntohl(tcp->tcp_seq), ntohl(tcp->tcp_seq) - record->seq);
        fprintf(output, "   ACK:      %d\trelative ACK: %d\n", ntohl(tcp->tcp_ack), ntohl(tcp->tcp_ack) - record->ack);
        // fprintf(output, "   SEQ:      %d\n", ntohl(tcp->tcp_seq) - record->seq);
        // fprintf(output, "   ACK:      %d\n", ntohl(tcp->tcp_ack) - record->ack);
    }

    if (size_payload > 0) {
        if (ntohl(tcp->tcp_seq) < record->seq) {
            // fprintf(info, "retransmission detected\n");
            record->retrans++;
        } 
    }
    if (include_zeroes || size_payload > 0) {
          flow_record_process_packet_length_and_time_ack(record, size_payload, &h->ts, tcp);
    }

    // if initial SYN packet, get TCP sequence number
    if (size_payload > 0) {
        if (tcp->tcp_flags == 2 && record->initial_seq == 0) { // SYN==2
            record->initial_seq = ntohl(tcp->tcp_seq);
        }
    }

    // if initial SYN/ACK packet, parse TCP options
    unsigned int offset = 20;
    if (tcp->tcp_flags == 2 || tcp->tcp_flags == 18) { // SYN==2, SYN/ACK==18
        // get initial window size
        if (!record->tcp_initial_window_size) {
            record->tcp_initial_window_size = ntohs(tcp->tcp_win);
        }

        // get SYN packet size
        if (tcp->tcp_flags == 2) {
            record->tcp_syn_size = tcp_len;
        }

        // parse TCP options
        cur_itr = 0;
        while (offset < tcp_hdr_len) { // while there are TCP options present
            cur_itr += 1;
            if (cur_itr > 20) {
	              break;
            }
            if ((unsigned int)*(const unsigned char *)(tcp_start+offset) <= 0) { // EOL
	              break ;
            }
            if ((unsigned int)*(const unsigned char *)(tcp_start+offset) == 1) { // NOP
	              record->tcp_option_nop += 1;
	              offset += 1;
            } else if ((unsigned int)*(const unsigned char *)(tcp_start+offset) == 2) { // MSS
	              if ((unsigned int)*(const unsigned char *)(tcp_start+offset+1) == 4) {
	                  record->tcp_option_mss = htons(*(const unsigned short *)(tcp_start+offset+2));
	              }
	              offset += (unsigned int)*(const unsigned char *)(tcp_start+offset+1);
            } else if ((unsigned int)*(const unsigned char *)(tcp_start+offset) == 3) { // WSCALE
	              record->tcp_option_wscale = (unsigned int)*(const unsigned char *)(tcp_start+offset+2);
    
	              offset += (unsigned int)*(const unsigned char *)(tcp_start+offset+1);
            } else if ((unsigned int)*(const unsigned char *)(tcp_start+offset) == 4) { // SACK
	              record->tcp_option_sack = 1;
    
	              offset += (unsigned int)*(const unsigned char *)(tcp_start+offset+1);
            } else if ((unsigned int)*(const unsigned char *)(tcp_start+offset) == 8) { // TSTAMP
	              record->tcp_option_tstamp = 1;
    
	              offset += (unsigned int)*(const unsigned char *)(tcp_start+offset+1);
            } else if ((unsigned int)*(const unsigned char *)(tcp_start+offset) == 34) { // TCP FAST OPEN
	              record->tcp_option_fastopen = 1;
    
	              offset += (unsigned int)*(const unsigned char *)(tcp_start+offset+1);
            } else { // if all TCP options are being correctly parsed, this else should not be called
	              offset += (unsigned int)*(const unsigned char *)(tcp_start+offset+1);
            }
        }
    }

    record->ob += size_payload; 
  
    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);
    update_all_features(feature_list);
    
    /* if packet has port 443 and nonzero data length, process it as TLS */
    if (include_tls && size_payload && (key->sp == 443 || key->dp == 443)) {
        process_tls(h->ts, payload, size_payload, &record->tls_info);
    }
  
    /* if packet has port 80 and nonzero data length, process it as HTTP */
    if (config.http && size_payload && (key->sp == 80 || key->dp == 80)) {
        http_update(&record->http_data, payload, size_payload, config.http);
    }

    /*
     * update header description
     */
    if (size_payload >= report_hd) {
        header_description_update(&record->hd, payload, report_hd);
    }

    return record;
}


static struct flow_record *
process_udp (const struct pcap_pkthdr *h, const void *udp_start, int udp_len, struct flow_key *key) {
    unsigned int udp_hdr_len;
    const unsigned char *payload;
    unsigned int size_payload;
    const struct udp_hdr *udp = (const struct udp_hdr *)udp_start;
    struct flow_record *record = NULL;
  
    if (output_level > none) {
        fprintf(output, "   protocol: UDP\n");
    }

    udp_hdr_len = 8;
    if (udp_len < 8) {
        // fprintf(output, "   * Invalid UDP packet length: %u bytes\n", udp_len);
        return NULL;
    }
  
    payload = (unsigned char *)(udp_start + udp_hdr_len);  
    size_payload = udp_len - udp_hdr_len;
    if (output_level > none) {
        fprintf(output, "   src port: %d\n", ntohs(udp->src_port));
        fprintf(output, "   dst port: %d\n", ntohs(udp->dst_port));
        fprintf(output, "payload len: %d\n", size_payload);
    }
  
    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        if (output_level > packet_summary) {
            fprintf(output, "   payload (%d bytes):\n", size_payload);
            print_payload(payload, size_payload);
        }
    }
  
    key->sp = ntohs(udp->src_port);
    key->dp = ntohs(udp->dst_port);
  
    record = flow_key_get_record(key, CREATE_RECORDS); 
    if (record == NULL) {
        return NULL;
    }
    if (record->op < num_pkt_len) {
        if (include_zeroes || (size_payload != 0)) {
            record->pkt_len[record->op] = size_payload;
            record->pkt_time[record->op] = h->ts;
            record->op++; 
        }
    }
    record->ob += size_payload; 

    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);
    update_all_features(feature_list);

    if (nfv9_capture_port && (key->dp == nfv9_capture_port)) {
        process_nfv9(h, payload, size_payload, record);
    }

    if (ipfix_capture_port && (key->dp == ipfix_capture_port)) {
      process_ipfix(payload, size_payload, record);
    }

    return record;
}


static struct flow_record *
process_icmp (const struct pcap_pkthdr *h, const void *start, int len, struct flow_key *key) {
    int size_icmp_hdr;
    const unsigned char *payload;
    int size_payload;
    const struct icmp_hdr *icmp = (const struct icmp_hdr *)start;
    struct flow_record *record = NULL;
  
    if (output_level > none) {
        fprintf(output, "   protocol: ICMP\n");
    }

    size_icmp_hdr = 8;
    if (len < size_icmp_hdr) {
        // fprintf(output, "   * Invalid ICMP packet length: %u bytes\n", len);
        return NULL;
    }
  
    if (output_level > none) {
        fprintf(output, "   type: %d\n", icmp->type);
        fprintf(output, "   code: %d\n", icmp->code);
    }
    payload = (unsigned char *)(start + size_icmp_hdr);  
    size_payload = len - size_icmp_hdr;
  
    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        if (output_level > packet_summary) {
            fprintf(output, "   payload (%d bytes):\n", size_payload);
            print_payload(payload, size_payload);
        }
    }

    /* 
     * signify ICMP by using sp = dp = 0 (which is an IANA-reserved
     * value); this key will be distinguished from the keys of TCP and
     * UDP flows by the key->prot value
     */
    key->sp = 0;
    key->dp = 0;
    
    record = flow_key_get_record(key, CREATE_RECORDS); 
    if (record == NULL) {
        return NULL;
    }
    if (record->op < num_pkt_len) {
        if (include_zeroes || (size_payload != 0)) {
            record->pkt_len[record->op] = size_payload;
            record->pkt_time[record->op] = h->ts;
            record->op++; 
        }
    }
    record->ob += size_payload; 

    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);
    update_all_features(feature_list);
  
    return record;
}


static struct flow_record *
process_ip (const struct pcap_pkthdr *h, const void *ip_start, int ip_len, struct flow_key *key) {
    const unsigned char *payload;
    int size_payload;
    //  const struct udp_hdr *udp = (const struct udp_hdr *)udp_start;
    struct flow_record *record = NULL;

    if (output_level > none) {
        fprintf(output, "   protocol: IP\n");
    }

    payload = (unsigned char *)(ip_start);  
    size_payload = ip_len;
  
    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        if (output_level > packet_summary) {
            fprintf(output, "   payload (%d bytes):\n", size_payload);
            print_payload(payload, size_payload);
        }
    }
  
    /* signify IP by using zero (reserved) port values */
    key->sp = key->dp = 0;
  
    record = flow_key_get_record(key, CREATE_RECORDS); 
    if (record == NULL) {
        return NULL;
    }
    if (record->op < num_pkt_len) {
        if (include_zeroes || (size_payload != 0)) {
            record->pkt_len[record->op] = size_payload;
            record->pkt_time[record->op] = h->ts;
            record->op++; 
        }
    }
    record->ob += size_payload; 
  
    flow_record_update_byte_count(record, payload, size_payload);
    flow_record_update_compact_byte_count(record, payload, size_payload);
    flow_record_update_byte_dist_mean_var(record, payload, size_payload);
    update_all_features(feature_list);

    return record;
}

/**
 * \fn void process_packet (unsigned char *ignore, const struct pcap_pkthdr *header, 
                     const unsigned char *packet)
 * \param ignore currently unused
 * \param header pointer to the packer header structure
 * \param packet pointer to the packet
 * \return none
 */
void process_packet (unsigned char *ignore, const struct pcap_pkthdr *header,
                     const unsigned char *packet) {
    //  static int packet_count = 1;                   
    struct flow_record *record;
    unsigned char proto = 0;

    /* declare pointers to packet headers */
    const struct ip_hdr *ip;              
    unsigned int transport_len;
    unsigned int ip_hdr_len;
    const void *transport_start;

    struct flow_key key;
    
    flocap_stats_incr_num_packets();
    if (output_level > none) {
        fprintf(output, "\npacket number %lu:\n", flocap_stats_get_num_packets());
    }
    //  packet_count++;
  
    // ethernet = (struct ethernet_hdr*)(packet);
  
    /* define/compute ip header offset */
    ip = (struct ip_hdr*)(packet + ETHERNET_HDR_LEN);
    ip_hdr_len = ip_hdr_length(ip);
    if (ip_hdr_len < 20) {
        if (output_level > none) { 
            fprintf(output, "   * Invalid IP header length: %u bytes\n", ip_hdr_len);
        }
        return;
    }
    if (ntohs(ip->ip_len) < sizeof(struct ip_hdr) || ntohs(ip->ip_len) > header->caplen) {
        /* 
         * IP packet is malformed (shorter than a complete IP header, or
         * claims to be longer than it is), or not entirely captured by
         * libpcap (which will depend on MTU and SNAPLEN; you can change
         * the latter if need be).
         */
        return ;
    }
    transport_len =  ntohs(ip->ip_len) - ip_hdr_len;

    /* print source and destination IP addresses */
    if (output_level > none) {
        fprintf(output, "       from: %s\n", inet_ntoa(ip->ip_src));
        fprintf(output, "         to: %s\n", inet_ntoa(ip->ip_dst));
        fprintf(output, "     ip len: %u\n", ntohs(ip->ip_len));
        fprintf(output, " ip hdr len: %u\n", ip_hdr_len);
    }

    if (ip_fragment_offset(ip) == 0) {

        /* fill out IP-specific fields of flow key, plus proto selector */
        key.sa = ip->ip_src;
        key.da = ip->ip_dst;
        proto = key.prot = ip->ip_prot;  

    }  else {
        // fprintf(info, "found IP fragment (offset: %02x)\n", ip_fragment_offset(ip));

        /*
         * select IP processing, since we don't have a TCP or UDP header 
         */
        key.sa = ip->ip_src;
        key.da = ip->ip_dst;
        proto = key.prot = IPPROTO_IP;
    }  

    /* determine transport protocol and handle appropriately */

    transport_start = (void *)ip + ip_hdr_len;
    switch(proto) {
        case IPPROTO_TCP:
            record = process_tcp(header, transport_start, transport_len, &key);
            break;
        case IPPROTO_UDP:
            record = process_udp(header, transport_start, transport_len, &key);
            break;
        case IPPROTO_ICMP:
            record = process_icmp(header, transport_start, transport_len, &key);
            break;    
        case IPPROTO_IP:
        default:
            record = process_ip(header, transport_start, transport_len, &key);
            break;
    }

    /*
     * if our packet is malformed TCP, UDP, or ICMP, then the process
     * functions will return NULL; we deal with that case by treating it
     * as just an IP packet
     */
    if (record == NULL) {
#if 1
        record = process_ip(header, transport_start, transport_len, &key);
        if (record == NULL) {
            fprintf(info, "warning: unable to process ip packet (improper length or otherwise malformed)\n");
            return;
        }
        record->invalid++;
#else
        /*
         * if the processing of malformed packets causes trouble, choose
         * this code path instead 
         */
        return;
#endif
    }
  
    /*
     * set minimum ttl in flow record
     */
    if (record->ttl > ip->ip_ttl) {
        record->ttl = ip->ip_ttl; 
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
    if ((report_idp) && record->op && (record->idp_len == 0)) {
        record->idp_len = (ntohs(ip->ip_len) < report_idp ? ntohs(ip->ip_len) : report_idp);
        record->idp = malloc(record->idp_len);
        memcpy(record->idp, ip, record->idp_len);
        if (output_level > none) {
            fprintf(output, "stashed %u bytes of IDP\n", record->idp_len);
        }
    }

    /* increment overall byte count */
    flocap_stats_incr_num_bytes(transport_len);
 
    return;
}

/* END packet processing */
