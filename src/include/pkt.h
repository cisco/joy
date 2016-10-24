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
 * \file pkt.h
 *
 * \brief packet interface
 */
#ifndef PKT_H
#define PKT_H

#include <netinet/in.h> 

#ifdef LINUX
#include <endian.h>
#else /* SYSNAME=DARWIN */
// no special include needed
#endif

#define CPU_IS_BIG_ENDIAN (__BYTE_ORDER == __BIG_ENDIAN)

/** ethernet header */
#define ETHERNET_HDR_LEN 14
#define ETHERNET_ADR_LEN  6

/** ethernet header structure */
struct ethernet_hdr {
    unsigned char dst_addr[ETHERNET_ADR_LEN];  
    unsigned char src_addr[ETHERNET_ADR_LEN];  
    unsigned short ether_type;                  
};

/** Internet Protocol (IP) version four header */
#if CPU_IS_BIG_ENDIAN
#define IP_RF    0x8000 /* Reserved           */
#define IP_DF    0x4000 /* Don't Fragment     */
#define IP_MF    0x2000 /* More Fragments     */
#define IP_FOFF  0x1fff /* Fragment Offset    */ 

#define ip_is_fragment(ip) (htons((ip)->ip_flgoff) & (IP_MF | IP_FOFF))
#define ip_fragment_offset(ip) (htons((ip)->ip_flgoff) & IP_FOFF)

#define ip_hdr_length(ip) ((((ip)->ip_vhl) & 0x0f)*4)
#define ip_version(ip)    (((ip)->ip_vhl) >> 4)

#else

#define IP_RF    0x0080 /* Reserved           */
#define IP_DF    0x0040 /* Don't Fragment     */
#define IP_MF    0x0020 /* More Fragments     */
#define IP_FOFF  0xff1f /* Fragment Offset    */

#define ip_is_fragment(ip) (((ip)->ip_flgoff) & (IP_MF | IP_FOFF))
#define ip_fragment_offset(ip) ((ip)->ip_flgoff & IP_FOFF)

#define ip_hdr_length(ip) ((((ip)->ip_vhl) & 0x0f)*4)
#define ip_version(ip)    (((ip)->ip_vhl) >> 4)
#endif


/** IP header structure */
struct ip_hdr {
    unsigned char  ip_vhl;    /* version and hdr length */
    unsigned char  ip_tos;    /* type of service        */
    unsigned short ip_len;    /* packet length          */
    unsigned short ip_id;     /* identification         */
    unsigned short ip_flgoff; /* flags, frag off field  */
    unsigned char  ip_ttl;    /* time to live           */
    unsigned char  ip_prot;   /* protocol               */
    unsigned short ip_cksum;  /* checksum               */
    struct in_addr ip_src;    /* source address         */
    struct in_addr ip_dst;    /* destination address    */
};

/** Transmission Control Protocol (TCP) header */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS   (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
#define TCP_OFF(h)  (((h)->tcp_off2 & 0xf0) >> 4)
#define tcp_hdr_length(h) (((h)->tcp_offrsv >> 4) * 4)

/** TCP header structure */
struct tcp_hdr {
    unsigned short src_port;   /* source port            */
    unsigned short dst_port;   /* destination port       */
    unsigned int   tcp_seq;    /* sequence number        */
    unsigned int   tcp_ack;    /* acknowledgement number */
    unsigned char  tcp_offrsv; /* data offset and rsrvd  */
    unsigned char  tcp_flags;  /* flags                  */
    unsigned short tcp_win;    /* window                 */
    unsigned short tcp_csm;    /* checksum               */
    unsigned short tcp_urp;    /* urgent pointer         */
};


/** User Datagram Protocol (UDP) */
struct udp_hdr {
    unsigned short src_port;  /* source port            */
    unsigned short dst_port;  /* destination port       */
    unsigned short udp_len;   /* packet length          */
    unsigned short udp_csm;   /* checksum               */
};

/** ICMP header structure */
struct icmp_hdr {
    unsigned char  type; 
    unsigned char  code; 
    unsigned short checksum;
    unsigned int   rest_of_header;
};

#endif /* PKT_H */
