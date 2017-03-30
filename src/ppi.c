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
 * \file ppi.c
 *
 * \brief Per-Packet Information (PPI) data feature module, using the
 * C preprocessor generic programming interface defined in feature.h.
 *
 */

#include <stdio.h>  
#include <string.h>   /* for memset()    */
#include "pkt.h"      /* for tcp macros  */
#include "utils.h"    /* for enum role   */
#include "ppi.h"     

/* helper functions defined below */

static void pkt_info_print_interleaved(zfile f,
				       const struct pkt_info *pkt_info,
				       unsigned int np,
				       const struct pkt_info *pkt_info2,
				       unsigned int np2);

/**
 * \fn inline void ppi_init (struct ppi *ppi)
 * \param ppi structure to initialize
 * \return none
 */
inline void ppi_init (struct ppi *ppi) {
    ppi->np = 0;
    memset(ppi->pkt_info, 0, sizeof(ppi->pkt_info));
}

/**
 * \fn void ppi_update (struct ppi *ppi,
        const void *data,
        unsigned int len,
        unsigned int report_ppi)
 * \param ppi structure to initialize
 * \param data data to use for update
 * \param len length of the data
 * \param report_ppi flag to determine if we filter ppi
 * \return none
 */
void ppi_update (struct ppi *ppi, 
		 const struct pcap_pkthdr *header,
		 const void *tcp_start, 
		 unsigned int tcp_len, 
		 unsigned int report_ppi) {
    const struct tcp_hdr *tcp = tcp_start;  
    unsigned int tcp_hdr_len;
    //    const unsigned char *payload;
    unsigned int size_payload;
  
    tcp_hdr_len = tcp_hdr_length(tcp);
    if (tcp_hdr_len < 20 || tcp_hdr_len > tcp_len) {
        return;
    }
    
    /* define/compute tcp payload (segment) offset */
    // payload = (unsigned char *)(tcp_start + tcp_hdr_len);
  
    /* compute tcp payload (segment) size */
    size_payload = tcp_len - tcp_hdr_len;

    if (report_ppi) {
        if (ppi->np < MAX_NUM_PKT) {
	    ppi->pkt_info[ppi->np].seq = ntohl(tcp->tcp_seq);
	    ppi->pkt_info[ppi->np].ack = ntohl(tcp->tcp_ack);	
	    ppi->pkt_info[ppi->np].flags = tcp->tcp_flags;
	    ppi->pkt_info[ppi->np].len = size_payload;
	    ppi->pkt_info[ppi->np].time = header->ts;
	    ppi->np++;
	} 
    }
}

/**
 * \fn void ppi_print_json (const struct ppi *x1, const struct ppi *x2, zfile f)
 * \param x1 pointer to ppi structure
 * \param x2 pointer to ppi structure (or NULL)
 * \param f output file
 * \return none
 */
void ppi_print_json (const struct ppi *x1, const struct ppi *x2, zfile f) {

    pkt_info_print_interleaved(f, 
			       x1->pkt_info, 
			       x1->np, 
			       x2 ? x2->pkt_info : NULL, 
			       x2 ? x2->np : 0);

}

/**
 * \fn void ppi_delete (struct ppi *ppi)
 * \param ppi pointer to ppi stucture
 * \return none
 */
void ppi_delete (struct ppi *ppi) { 
    /* no memory needs to be freed */
}

/**
 * \fn void ppi_unit_test ()
 * \param none
 * \return none
 */
void ppi_unit_test () {
    
    /* no unit test at this time */

} 

/*
 * BEGIN helper functions for ppi.c
 */

#include "p2f.h"
#define NUM_PKT_LEN 50  // should be defined somewhere else
unsigned int num_pkts = NUM_PKT_LEN;

#define OUT "<"
#define IN  ">"

static inline unsigned int timer_lt (const struct timeval *a, const struct timeval *b) {
    return (a->tv_sec == b->tv_sec) ? (a->tv_usec < b->tv_usec) : (a->tv_sec < b->tv_sec);
}

static inline void timer_clear (struct timeval *a) { 
    a->tv_sec = a->tv_usec = 0; 
}

static unsigned int timeval_to_milliseconds (struct timeval ts) {
    unsigned int result = ts.tv_usec / 1000 + ts.tv_sec * 1000;
    return result;
}

void tcp_flags_to_string(unsigned char flags, char *string) {
    if (TCP_FIN & flags) {
	*string++ = 'F';   
    }
    if (TCP_SYN & flags) {
	*string++ = 'S';
    }
    if (TCP_RST & flags) {
	*string++ = 'R';
    }
    if (TCP_PSH & flags) {
	*string++ = 'P';
    }
    if (TCP_ACK & flags) {
	*string++ = 'A';
    }
    if (TCP_URG & flags) {
	*string++ = 'U';
    }
    if (TCP_ECE & flags) {
	*string++ = 'E';
    }
    if (TCP_CWR & flags) {
	*string++ = 'C';
    }
    *string = 0; /* null-terminate string */

}

#define seq_lt(x,y) ((int)((x)-(y)) < 0)
#define seq_gt(x,y) ((int)((x)-(y)) > 0)
#define seq_leq(x,y) ((int)((x)-(y)) <= 0)
#define seq_geq(x,y) ((int)((x)-(y)) >= 0)

struct tcp_state {
    unsigned seq;
    enum role role;
};

static void pkt_info_process(zfile f, 
			     const struct pkt_info *pkt_info, 
			     struct tcp_state *tcp_state, 
			     struct tcp_state *rev_tcp_state,
			     struct timeval ts) {
    long int rseq, rack;
    char flags_string[9];
    char *dir = "?";
    struct timeval tmp;

    if (pkt_info->flags & TCP_SYN) {
	tcp_state->seq = pkt_info->seq;
	rseq = 0;
    } else {
	rseq = (long int) pkt_info->seq - tcp_state->seq;	
	if (seq_gt(pkt_info->seq, tcp_state->seq)) { 
	    tcp_state->seq = pkt_info->seq;
	    /* note: we don't check upper window boundary */
	}
    }
    if (pkt_info->flags & TCP_ACK) {
	rack = (long int) pkt_info->ack - rev_tcp_state->seq;
    } else { 
	rack = 0; 
    }
    /*
     * we might have missed the SYN and SYN/ACK packets, and need to sync anyway
     */
    if (tcp_state->role == role_unknown) {
	if (rev_tcp_state->role == role_unknown) {
	    tcp_state->role = role_client;
	    tcp_state->seq = pkt_info->seq;
	    rseq = 0;
	    rack = 0;
	} else if (rev_tcp_state->role == role_client) {
	    tcp_state->role = role_server;
	    tcp_state->seq = pkt_info->seq;
	    rseq = 0;
	} else if (rev_tcp_state->role == role_server) {
	    tcp_state->role = role_client;
	}
    }

    /* note: we don't remove SYN and FIN bytes from message seq numbers */

    if (tcp_state->role == role_server) {
	dir = "<";
    } else {
	dir = ">";
    }

    timer_sub(&pkt_info->time, &ts, &tmp); 
    tcp_flags_to_string(pkt_info->flags, flags_string);
    zprintf(f, 
	    "{\"seq\":%u,\"ack\":%u,\"rseq\":%ld,\"rack\":%ld,\"b\":%u,\"dir\":\"%s\",\"t\":%u,\"flags\":\"%s\"}", 
	    pkt_info->seq, 
	    pkt_info->ack,
	    rseq,
	    rack,
	    pkt_info->len, 
	    dir, 
	    timeval_to_milliseconds(tmp), // note: not pkt_info->time 
	    flags_string);

}



static void pkt_info_print_interleaved(zfile f,
				       const struct pkt_info *pkt_info,
				       unsigned int np,
				       const struct pkt_info *pkt_info2,
				       unsigned int np2) {
    
    unsigned int i, j, imax, jmax;
    struct timeval ts_last;
    struct tcp_state tcp_state = { 0, };
    struct tcp_state rev_tcp_state = { 0, };

    imax = np  > num_pkts ? num_pkts : np;

    if (pkt_info2 == NULL) {  /* unidirectional tcp flow, no interleaving needed */

        if (!np) {
	    return; /* nothing to report */
        }

        zprintf(f, ",\"ppi\":[");
        ts_last = pkt_info[0].time;
        for (i=0; i < imax; i++) { 
	    pkt_info_process(f, &pkt_info[i], &tcp_state, &rev_tcp_state, ts_last);
        }
        zprintf(f, "]");	

    } else { /*  bidirectional tcp flow in (pkt_info, pkt_info2), interleaving needed */

        if (timer_lt(&pkt_info[0].time, &pkt_info2[0].time)) {
            ts_last = pkt_info[0].time;
        } else {
            ts_last = pkt_info2[0].time;
        }

        jmax = np2 > num_pkts ? num_pkts : np2;
	if (!imax || !jmax) {
	  return;   /* nothing to output */
	}
	zprintf(f, ",\"ppi\":[");
        i = j = 0;
        while ((i < imax) || (j < jmax)) {      
	  
            if (i >= imax) {  /* record list is exhausted, so use twin */
		pkt_info_process(f, &pkt_info2[j], &rev_tcp_state, &tcp_state, ts_last);
		j++;
            } else if (j >= jmax) {  /* twin list is exhausted, so use record */
		pkt_info_process(f, &pkt_info[i], &tcp_state, &rev_tcp_state, ts_last);
		i++;
	    } else { /* neither list is exhausted, so use list with lowest time */     

	            if (timer_lt(&pkt_info[i].time, &pkt_info2[j].time)) {
			pkt_info_process(f, &pkt_info[i], &tcp_state, &rev_tcp_state, ts_last);
	                if (i < imax) {
	                    i++;
	                }
	            } else {
			pkt_info_process(f, &pkt_info2[j], &rev_tcp_state, &tcp_state, ts_last);
	                if (j < jmax) {
	                    j++;
	                }
	            }
	    }
	    if (!((i == imax) & (j == jmax))) { /* we are done */
	        zprintf(f, ",");
	    }
	}
	zprintf(f, "]");	
    }
}

/*
 * END helper functions for ppi.c
 */
