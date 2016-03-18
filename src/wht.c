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
 * wht.c
 *
 * walsh-hadamard transform implementation
 *
 */

#include <stdint.h>   /* for uint8_t, uint16_t, ... */
#include <string.h>   /* for memcpy()               */
#include <stdio.h>    /* for fprintf()              */
#include "wht.h"     

inline void wht_init(struct wht *wht) {
  wht->spectrum[0] = 0;
  wht->spectrum[1] = 0;
  wht->spectrum[2] = 0;
  wht->spectrum[3] = 0;
}

inline void wht_process_four_bytes(struct wht *wht, const uint8_t *d) {
  int16_t x[4];
  
  x[0] = d[0] + d[2];
  x[1] = d[1] + d[3];
  x[2] = d[0] - d[2];
  x[3] = d[1] - d[3];
  wht->spectrum[0] += (x[0] + x[1]);
  wht->spectrum[1] += (x[0] - x[1]);
  wht->spectrum[2] += (x[2] + x[3]);
  wht->spectrum[3] += (x[2] - x[3]);
}

void wht_update(struct wht *wht, const void *data, unsigned int len, unsigned int report_wht) {
  const uint8_t *d = data;

  if (report_wht) {
    while (len > 4) {
      wht_process_four_bytes(wht, d);
      d += 4;
      len -= 4;
    }
    if (len > 0) {
      uint8_t buffer[4];
      
      memcpy(buffer, d, len);
      wht_process_four_bytes(wht, buffer);
    }
  }
}

void wht_printf(const struct wht *wht, FILE *f) {
  
  fprintf(f, ",\"wht\":[%d,%d,%d,%d]",
	  wht->spectrum[0], wht->spectrum[1], wht->spectrum[2], wht->spectrum[3]);
  
}

void wht_printf_scaled(const struct wht *wht, FILE *f, unsigned int num_bytes) {

  if (num_bytes == 0) {
    return;
  }
  
  fprintf(f, ",\"wht\":[%.5g,%.5g,%.5g,%.5g]",
	  (float) wht->spectrum[0] / num_bytes, 
	  (float) wht->spectrum[1] / num_bytes,
	  (float) wht->spectrum[2] / num_bytes,
	  (float) wht->spectrum[3] / num_bytes);
  
}

void wht_printf_scaled_bidir(const struct wht *w1, unsigned int b1,
			     const struct wht *w2, unsigned int b2,
			     FILE *f) {
  int64_t s[4];
  uint64_t n = b1 + b2;

  if (n == 0) {
    return;    /* there was no data, so there is no WHT to print */
  }

  /* combine each direction */
  s[0] = w1->spectrum[0] + w2->spectrum[0];  
  s[1] = w1->spectrum[1] + w2->spectrum[1];  
  s[2] = w1->spectrum[2] + w2->spectrum[2];  
  s[3] = w1->spectrum[3] + w2->spectrum[3];  

  fprintf(f, ",\"wht\":[%.5g,%.5g,%.5g,%.5g]",
	  (float) s[0] / n, 
	  (float) s[1] / n,
	  (float) s[2] / n,
	  (float) s[3] / n);
#if 0
  fprintf(f, ",\"RAW1\":[%d,%d,%d,%d]",
	  w1->spectrum[0], 
	  w1->spectrum[1],
	  w1->spectrum[2],
	  w1->spectrum[3]);
  fprintf(f, ",\"RAW2\":[%d,%d,%d,%d]",
	  w1->spectrum[0], 
	  w1->spectrum[1],
	  w1->spectrum[2],
	  w1->spectrum[3]);
#endif 
}


void wht_unit_test() {
  struct wht wht, wht2;
  uint8_t buffer1[8] = {
    1, 1, 1, 1, 1, 1, 1, 1
  };
  uint8_t buffer2[8] = {
    1, 0, 1, 0, 1, 0, 1, 0
  };
  uint8_t buffer3[8] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 
    //    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf
  };
  uint8_t buffer4[4] = {
    255, 254, 253, 252
  };

  wht_init(&wht);
  wht_update(&wht, buffer1, sizeof(buffer1), 1);
  wht_printf_scaled(&wht, stdout, sizeof(buffer1));

  wht_init(&wht);
  wht_update(&wht, buffer2, sizeof(buffer2), 1);
  wht_printf_scaled(&wht, stdout, sizeof(buffer2));

  wht_init(&wht);
  wht_update(&wht, buffer3, sizeof(buffer3), 1);
  wht_printf_scaled(&wht, stdout, sizeof(buffer3));

  wht_init(&wht);
  wht_init(&wht2);
  wht_update(&wht, buffer4, 1, 1); /* note: only reading first byte */
  wht_update(&wht, buffer4, 1, 1); /* note: only reading first byte */
  wht_update(&wht, buffer4, 1, 1); /* note: only reading first byte */
  wht_printf_scaled_bidir(&wht, 3, &wht2, 0, stdout);

} 
