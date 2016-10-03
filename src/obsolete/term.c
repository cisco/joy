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
/* BEGIN session termination */

/*
 * TCP session termination model
 * 
 * Sessions to be terminated are entered into the session table; each
 * entry holds the the network five-tuple of that session, in the form
 * of a flow_key structure.  To terminate an ongoing active session,
 * the flow record is looked up, and a pointer to the session termination
 * function is made.
 * 
 */

#if 1

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "err.h"
#include "p2f.h"
#include "pkt.h"

extern unsigned int output_level;
extern FILE *output;


int raw_socket;

int session_termination_init() {
  raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (raw_socket == -1) {
    return failure;
  }
  return ok;
}


#define MAX_PKT_LEN 2048

int tcp_construct_reset(const struct ip_hdr *ip, const struct tcp_hdr *tcp, void *pkt) {
  struct ip_hdr *reset = pkt;
  struct tcp_hdr *reset_tcp;
  
  /* set IP header */
  reset->ip_vhl = ip->ip_vhl;
  reset->ip_tos = ip->ip_tos;
  reset->ip_len = 40;             /* is this always right? */
  reset->ip_id = ip->ip_id;
  reset->ip_flgoff = ip->ip_flgoff;
  reset->ip_ttl = 255;            /* this should be more carefully chosen */
  reset->ip_prot = ip->ip_prot;   /* 6, for TCP */
  reset->ip_cksum = 0;            /* to be set later */
  reset->ip_src.s_addr = ip->ip_dst.s_addr;
  reset->ip_dst.s_addr = ip->ip_src.s_addr;

  /* set TCP header */
  reset_tcp = pkt + sizeof(struct ip_hdr);
  reset_tcp->src_port = tcp->dst_port;
  reset_tcp->dst_port = tcp->src_port;
  reset_tcp->tcp_seq = 0xcafebabe;   /* should be set randomly */
  reset_tcp->tcp_ack = tcp->tcp_seq;
  reset_tcp->tcp_offrsv = 0;
  reset_tcp->tcp_flags = TCP_RST;
  reset_tcp->tcp_win = 0;
  reset_tcp->tcp_csm = 0;          /* to be set later */
  reset_tcp->tcp_urp = 0;
  
  return ok;
}

int packet_terminate_session(unsigned char *ignore, const struct pcap_pkthdr *header, const unsigned char *packet) {
  const struct ip_hdr *ip;              
  unsigned int transport_len;
  int size_ip;
  const void *transport_start;
  unsigned char pkt[MAX_PKT_LEN];
  struct sockaddr_in target;

  if (output_level > none) {
    fprintf(output, "terminating session\n");
  }
  
  /* define/compute ip header offset */
  ip = (struct ip_hdr*)(packet + ETHERNET_HDR_LEN);
  size_ip = ip_hdr_length(ip);
  if (size_ip < 20) {
    if (output_level > none) fprintf(output, "   * Invalid IP header length: %u bytes\n", size_ip);
    return failure;
  }

  /* print source and destination IP addresses */
  if (output_level > none) {
    fprintf(output, "       from: %s\n", inet_ntoa(ip->ip_src));
    fprintf(output, "         to: %s\n", inet_ntoa(ip->ip_dst));
  }
    
  /* determine transport protocol and handle appropriately */
  transport_len =  ntohs(ip->ip_len) - size_ip;
  transport_start = packet + ETHERNET_HDR_LEN + size_ip;
  switch(ip->ip_prot) {
  case IPPROTO_TCP:
    tcp_construct_reset(ip, transport_start, pkt);
    break;
  case IPPROTO_UDP:
    break;
  case IPPROTO_ICMP:
    break;    
  default:
    break;
  }

  /* send packet */
  target.sin_family = AF_INET;
  target.sin_port = 0;
  target.sin_addr.s_addr = ip->ip_src.s_addr;

  if (sendto(raw_socket, pkt, 40, 0, (struct sockaddr *)&target, sizeof(target)) != 40) {
    return failure;
  }

  return ok;
}


#endif /* 0/1 */

/* END session termination */
