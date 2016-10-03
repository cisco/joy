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
 * classify.h
 *
 * header file for inline Classification functionality
 */

#ifndef CLASSIFY_H
#define CLASSIFY_H

/* constants */
#define NUM_PARAMETERS_SPLT_LOGREG 208
#define NUM_PARAMETERS_BD_LOGREG 464
#define MC_BINS_LEN 10
#define MC_BINS_TIME 10
#define MC_BIN_SIZE_TIME 50
#define MC_BIN_SIZE_LEN 150
#define MAX_BIN_LEN 1500
#define NUM_BD_VALUES 256

extern float parameters_bd[NUM_PARAMETERS_BD_LOGREG];
extern float parameters_splt[NUM_PARAMETERS_SPLT_LOGREG];


/* Classifier functions */
float classify(const unsigned short *pkt_len, const struct timeval *pkt_time,
	       const unsigned short *pkt_len_twin, const struct timeval *pkt_time_twin,
	       struct timeval start_time, struct timeval start_time_twin, uint32_t max_num_pkt_len,
	       uint16_t sp, uint16_t dp, uint32_t op, uint32_t ip, uint32_t np_o, uint32_t np_i,
		 uint32_t ob, uint32_t ib, uint16_t use_bd, const uint32_t *bd, const uint32_t *bd_t);

void merge_splt_arrays(const uint16_t *pkt_len, const struct timeval *pkt_time, 
		       const uint16_t *pkt_len_twin, const struct timeval *pkt_time_twin,
		       struct timeval start_time, struct timeval start_time_twin,
		       uint16_t s_idx, uint16_t r_idx,
		       uint16_t *merged_lens, uint16_t *merged_times,
		       uint32_t max_num_pkt_len, uint32_t max_merged_num_pkts);

void get_mc_rep_lens(uint16_t *lens, float *mc_lens, uint16_t num_packets);

void get_mc_rep_times(uint16_t *times, float *mc_times, uint16_t num_packets);

void update_params(char *splt_params, char *bd_params);

#endif /* CLASSIFY_H */








