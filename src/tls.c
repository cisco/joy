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
 * tls.c
 *
 * contains the functionality for TLS awareness
 * 
 */

#include <stdio.h>    /* for fprintf(), etc */
#include <pcap.h>     /* for pcap_hdr       */
#include <ctype.h>    /* for isprint()      */
#include <string.h>   /* for memcpy()       */
#include <stdlib.h>
#include <netinet/in.h>
#include "tls.h"


inline unsigned int timer_gt_tls(const struct timeval *a, const struct timeval *b) {
  return (a->tv_sec == b->tv_sec) ? (a->tv_usec > b->tv_usec) : (a->tv_sec > b->tv_sec);
}

inline unsigned int timer_lt_tls(const struct timeval *a, const struct timeval *b) {
  return (a->tv_sec == b->tv_sec) ? (a->tv_usec < b->tv_usec) : (a->tv_sec < b->tv_sec);
}

inline void timer_sub_tls(const struct timeval *a, const struct timeval *b, struct timeval *result)  {  
  result->tv_sec = a->tv_sec - b->tv_sec;        
  result->tv_usec = a->tv_usec - b->tv_usec;     
  if (result->tv_usec < 0) {                         
    --result->tv_sec;                                
    result->tv_usec += 1000000;                      
  }                                                    
}

inline void timer_clear_tls(struct timeval *a) { 
  a->tv_sec = a->tv_usec = 0; 
}

unsigned int timeval_to_milliseconds_tls(struct timeval ts) {
  unsigned int result = ts.tv_usec / 1000 + ts.tv_sec * 1000;
  return result;
}

/* initialize data associated with TLS */
void tls_record_init(struct tls_information *r) {
  r->tls_op = 0;
  r->num_ciphersuites = 0;
  r->num_tls_extensions = 0;
  r->num_server_tls_extensions = 0;
  r->tls_sid_len = 0;
  r->tls_v = 0;
  r->tls_client_key_length = 0;

  memset(r->tls_len, 0, sizeof(r->tls_len));
  memset(r->tls_time, 0, sizeof(r->tls_time));
  memset(r->tls_type, 0, sizeof(r->tls_type));
  memset(r->ciphersuites, 0, sizeof(r->ciphersuites));
  memset(r->tls_extensions, 0, sizeof(r->tls_extensions));
  memset(r->server_tls_extensions, 0, sizeof(r->server_tls_extensions));
  memset(r->tls_sid, 0, sizeof(r->tls_sid));
  memset(r->tls_random, 0, sizeof(r->tls_random));
}

/* free data associated with TLS */
void tls_record_delete(struct tls_information *r) {
  int i;
  for (i=0; i<r->num_tls_extensions; i++) {
    if (r->tls_extensions[i].data) {
      free(r->tls_extensions[i].data);
    }
  }
  for (i=0; i<r->num_server_tls_extensions; i++) {
    if (r->server_tls_extensions[i].data) {
      free(r->server_tls_extensions[i].data);
    }
  }
}


unsigned short raw_to_unsigned_short(const void *x) {
  unsigned short int y;
  const unsigned char *z = x;

  y = z[0];
  y *= 256;
  y += z[1];
  return y;
}

/*
void TLSClientKeyExchange_get_key_length(const void *x, int len, int version,
					 struct tls_information *r) {
  const unsigned char *y = x;

  if (r->tls_op > 1 || len < 32) {
    return ;
  }
  // SPDY was somehow getting here and causing havoc
  if (r->tls_client_key_length > 0) {
    return ;
  }
  // check for random encrypted handshake messages, not the best check
  //if (r->twin != NULL && r->twin->tls_client_key_length > 0) {
  //  return ;
  //}

  // SSL 3.0 uses a slightly different format
  //if (version == 2) {
  //  if (htons(*(const unsigned short *)(y-2))*8 < 8193) {
  //    r->tls_client_key_length = htons(*(const unsigned short *)(y-2))*8;
  //  }
  //  return ;
  //}

  // there must be a better check, but DH/EC sometimes uses 1/2 byte(s) for len
  if (len > 256 || ((int)*(const char *)y) <= 0) {
    if (htons(*(const unsigned short *)y)*8 < 8193) {
      r->tls_client_key_length = htons(*(const unsigned short *)y)*8;
    }
  } else {
    if (*(const char *)y*8 < 8193) {
      r->tls_client_key_length = *(const char *)y*8;
    }
  }
}
*/

void TLSClientHello_get_ciphersuites(const void *x, int len, 
				     struct tls_information *r) {
  unsigned int session_id_len;
  const unsigned char *y = x;
  unsigned short int cipher_suites_len;
  unsigned int i = 0;

  //  mem_print(x, len);
  //  fprintf(stderr, "TLS version %0x%0x\n", y[0], y[1]);

  if ((y[0] != 3) || (y[1] > 3)) {
    // fprintf(stderr, "warning: TLS version %0x%0x\n", y[0], y[1]);
    return;  
  }

  /* record the 32-byte Random field */
  memcpy(r->tls_random, y+2, 32); 

  y += 34;  /* skip over ProtocolVersion and Random */
  session_id_len = *y;

  len -= (session_id_len + 3);
  if (len < 0) {
    //fprintf(info, "error: TLS session ID too long\n"); 
    return;   /* error: session ID too long */
  }

  /* record the session id, if there is one */
  if (session_id_len) {
    r->tls_sid_len = session_id_len;
    memcpy(r->tls_sid, y+1, session_id_len); 
  }

  y += (session_id_len + 1);   /* skip over SessionID and SessionIDLen */
  // mem_print(y, 2);
  cipher_suites_len = raw_to_unsigned_short(y);
  if (len < cipher_suites_len) {
    //fprintf(info, "error: TLS ciphersuite list too long\n"); 
    return;   /* error: session ID too long */
  }
  y += 2;

  r->num_ciphersuites = cipher_suites_len/2;
  r->num_ciphersuites = r->num_ciphersuites > MAX_CS ? MAX_CS : r->num_ciphersuites;
  for (i=0; i < r->num_ciphersuites; i++) {
    unsigned short int cs;
    
    cs = raw_to_unsigned_short(y);
    r->ciphersuites[i] = cs;
    y += 2;
  }
}

void TLSClientHello_get_extensions(const void *x, int len, 
				     struct tls_information *r) {
  unsigned int session_id_len, compression_method_len;
  const unsigned char *y = x;
  unsigned short int cipher_suites_len, extensions_len;
  unsigned int i = 0;


  len -= 4; // get handshake message length
  if ((y[0] != 3) || (y[1] > 3)) {
    return;  
  }

  y += 34;  /* skip over ProtocolVersion and Random */
  len -= 34;
  session_id_len = *y;

  len -= (session_id_len + 3);
  if (len < 0) {
    //fprintf(info, "error: TLS session ID too long\n"); 
    return;   /* error: session ID too long */
  }

  y += (session_id_len + 1);   /* skip over SessionID and SessionIDLen */

  cipher_suites_len = raw_to_unsigned_short(y);
  if (len < cipher_suites_len) {
    //fprintf(info, "error: TLS ciphersuite list too long\n"); 
    return;   /* error: session ID too long */
  }
  y += 2;
  len -= 2;

  // skip over ciphersuites
  y += cipher_suites_len;
  len -= cipher_suites_len;

  // skip over compression methods
  compression_method_len = *y;
  y += 1+compression_method_len;
  len -= 1+compression_method_len;

  // extensions length
  extensions_len = raw_to_unsigned_short(y);
  if (len < extensions_len) {
    //fprintf(info, "error: TLS extensions too long\n"); 
    return;   /* error: session ID too long */
  }
  y += 2;
  len -= 2;

  i = 0;
  while (len > 0) {
    r->tls_extensions[i].type = raw_to_unsigned_short(y);
    r->tls_extensions[i].length = raw_to_unsigned_short(y+2);
    // should check if length is reasonable?
    r->tls_extensions[i].data = malloc(r->tls_extensions[i].length);
    memcpy(r->tls_extensions[i].data, y+4, r->tls_extensions[i].length);

    r->num_tls_extensions += 1;
    i += 1;

    len -= 4;
    len -= raw_to_unsigned_short(y+2);
    y += 4 + raw_to_unsigned_short(y+2);
  }
}

void TLSServerHello_get_ciphersuite(const void *x, unsigned int len,
				    struct tls_information *r) {
  unsigned int session_id_len;
  const unsigned char *y = x;
  unsigned short int cs; 

  //  mem_print(x, len);

  if ((y[0] != 3) || (y[1] > 3)) {
    // fprintf(stderr, "warning: TLS version %0x%0x\n", y[0], y[1]);
    return;  
  }

  /* record the 32-byte Random field */
  memcpy(r->tls_random, y+2, 32); 

  y += 34;  /* skip over ProtocolVersion and Random */
  session_id_len = *y;
  if (session_id_len + 3 > len) {
    //fprintf(info, "error: TLS session ID too long\n"); 
    return;   /* error: session ID too long */
  }

  /* record the session id, if there is one */
  if (session_id_len) {
    r->tls_sid_len = session_id_len;
    memcpy(r->tls_sid, y+1, session_id_len); 
  }

  y += (session_id_len + 1);   /* skip over SessionID and SessionIDLen */
  // mem_print(y, 2);
  cs = raw_to_unsigned_short(y);

  r->num_ciphersuites = 1;
  r->ciphersuites[0] = cs;
}

void TLSServerHello_get_extensions(const void *x, unsigned int len,
				    struct tls_information *r) {
  unsigned int session_id_len, compression_method_len;
  const unsigned char *y = x;
  unsigned short int extensions_len;
  unsigned int i = 0;

  //  mem_print(x, len);
  len -= 4;
  if ((y[0] != 3) || (y[1] < 3)) {
    //printf("warning: TLS version %0x%0x\n", y[0], y[1]);
    return;  
  }

  y += 34;  /* skip over ProtocolVersion and Random */
  len -= 34;
  session_id_len = *y;

  len -= (session_id_len + 1);
  y += (session_id_len + 1);   /* skip over SessionID and SessionIDLen */

  len -= 2; /* skip over scs */
  y += 2;

  // skip over compression methods
  compression_method_len = *y;
  y += 1+compression_method_len;
  len -= 1+compression_method_len;

  // extensions length
  extensions_len = raw_to_unsigned_short(y);
  if (len < extensions_len) {
    //fprintf(info, "error: TLS extensions too long\n"); 
    return;   /* error: session ID too long */
  }
  y += 2;
  len -= 2;

  i = 0;
  while (len > 0) {
    r->server_tls_extensions[i].type = raw_to_unsigned_short(y);
    r->server_tls_extensions[i].length = raw_to_unsigned_short(y+2);
    if (r->server_tls_extensions[i].length > 64) {
      break;
    }
    // should check if length is reasonable?
    r->server_tls_extensions[i].data = malloc(r->server_tls_extensions[i].length);
    memcpy(r->server_tls_extensions[i].data, y+4, r->server_tls_extensions[i].length);

    r->num_server_tls_extensions += 1;
    i += 1;

    len -= 4;
    len -= raw_to_unsigned_short(y+2);
    y += 4 + raw_to_unsigned_short(y+2);
  }
}

unsigned int TLSHandshake_get_length(const struct TLSHandshake *H) {
  return H->lengthLo + ((unsigned int) H->lengthMid) * 0x100 
    + ((unsigned int) H->lengthHi) * 0x10000;
}

unsigned int tls_header_get_length(const struct tls_header *H) {
  return H->lengthLo + ((unsigned int) H->lengthMid) * 0x100;
}


char *tls_version_get_string(enum tls_version v) {
  switch(v) {
  case 1:
    return "sslv2";
    break;
  case 2:
    return "sslv3";
    break;
  case 3:
    return "tls1.0";
    break;
  case 4:
    return "tls1.1";
    break;
  case 5:
    return "tls1.2";
    break;
  case 0:
    ;
    break;
  }
  return "unknown";
}

unsigned char tls_version(const void *x) {
  const unsigned char *z = x;

  // printf("tls_version: ");  mem_print(x, 2);

  switch(z[0]) {
  case 3:
    switch(z[1]) {
    case 0:
      return tls_sslv3;
      break;
    case 1:
      return tls_tls1_0;
      break;
    case 2:
      return tls_tls1_1;
      break;
    case 3:
      return tls_tls1_2;
      break;
    }
    break;
  case 2:
    return tls_sslv2;
    break;
  default:
    ;
  } 
  return tls_unknown;
}

unsigned int packet_is_sslv2_hello(const void *data) {
  const unsigned char *d = data;
  unsigned char b[3];
  
  b[0] = d[0];
  b[1] = d[1];
  b[2] = d[2];

  if (b[0] & 0x80) {
    b[0] &= 0x7F;
    if (raw_to_unsigned_short(b) > 9) {
      if (b[2] == 0x01) {
	return tls_sslv2;
      }
    }    
  }

  return tls_unknown;
}

struct tls_information *
process_tls(const struct pcap_pkthdr *h, const void *start, int len, struct tls_information *r) {
  const struct tls_header *tls;
  unsigned int tls_len;
  unsigned int levels = 0;

  /* currently skipping SSLv2 */

  while (len > 0) {
    tls = start;
    tls_len = tls_header_get_length(tls);
    if (tls->ContentType == application_data) {
      levels++;

      /* sanity check version number */
      if ((tls->ProtocolVersionMajor != 3) || (tls->ProtocolVersionMinor > 3)) {
	return NULL;
      }
      r->tls_v = tls_version(&tls->ProtocolVersionMajor);

    } else if (tls->ContentType == handshake) {
      if (tls->Handshake.HandshakeType == client_hello) {
	
	TLSClientHello_get_ciphersuites(&tls->Handshake.body, tls_len, r);
	TLSClientHello_get_extensions(&tls->Handshake.body, tls_len, r);

      } else if (tls->Handshake.HandshakeType == server_hello) {

	TLSServerHello_get_ciphersuite(&tls->Handshake.body, tls_len, r);
	TLSServerHello_get_extensions(&tls->Handshake.body, tls_len, r);

      } else if (tls->Handshake.HandshakeType == client_key_exchange) {

	//	TLSClientKeyExchange_get_key_length(&tls->Handshake.body, tls_len, tls_version(&tls->ProtocolVersionMajor), r);
	if (r->tls_client_key_length == 0) {
	  r->tls_client_key_length = (unsigned int)tls->Handshake.lengthLo*8 + 
	    (unsigned int)tls->Handshake.lengthMid*8*256 + 
	    (unsigned int)tls->Handshake.lengthHi*8*256*256;
	  if (r->tls_client_key_length > 8193) {
	    r->tls_client_key_length = 0;
	  }
	}

      } if (((tls->Handshake.HandshakeType > 2) & 
	     (tls->Handshake.HandshakeType < 11)) ||
	    ((tls->Handshake.HandshakeType > 16) & 
	     (tls->Handshake.HandshakeType < 20)) ||
	    (tls->Handshake.HandshakeType > 20)) {
	
	/*
	 * we encountered an unknown handshaketype, so this packet is
	 * not actually a TLS handshake, so we bail on decoding it
	 */
	return NULL;
      }

      if (r->tls_op < MAX_NUM_RCD_LEN) {
	r->tls_type[r->tls_op].handshake = tls->Handshake.HandshakeType;
      }      
    } else if (tls->ContentType != change_cipher_spec || 
	       tls->ContentType != alert) {
      
      /* 
       * we encountered an unknown contenttype, so this is not
       * actually a TLS record, so we bail on decoding it
       */      
      return NULL;
    }

    /* record TLS record lengths and arrival times */
    if (r->tls_op < MAX_NUM_RCD_LEN) {
      r->tls_type[r->tls_op].content = tls->ContentType;
      r->tls_len[r->tls_op] = tls_len;
      r->tls_time[r->tls_op] = h->ts;
    }

    /* increment TLS record count in tls_information */
    r->tls_op++;

    tls_len += 5; /* advance over header */
    start += tls_len;
    len -= tls_len;
  }

  return NULL;
}

void fprintf_raw_as_hex_tls(FILE *f, const void *data, unsigned int len) {
  const unsigned char *x = data;
  const unsigned char *end = data + len;
  
  fprintf(f, "\"");   /* quotes needed for JSON */
  while (x < end) {
    fprintf(f, "%02x", *x++);
  }
  fprintf(f, "\"");

}

void print_bytes_dir_time_tls(unsigned short int pkt_len, char *dir, struct timeval ts, struct tls_type_code type, char *term, FILE *f) {

  fprintf(f, "\t\t\t\t\t{ \"b\": %u, \"dir\": \"%s\", \"ipt\": %u, \"tp\": \"%u:%u\" }%s", 
	  pkt_len, dir, timeval_to_milliseconds_tls(ts), type.content, type.handshake, term);

}

unsigned int num_pkt_len_tls = NUM_PKT_LEN_TLS;

void len_time_print_interleaved_tls(unsigned int op, const unsigned short *len, const struct timeval *time, const struct tls_type_code *type,
				    unsigned int op2, const unsigned short *len2, const struct timeval *time2, const struct tls_type_code *type2, FILE *f) {
  unsigned int i, j, imax, jmax;
  struct timeval ts, ts_last, ts_start, tmp;
  unsigned int pkt_len;
  char *dir;
  struct tls_type_code typecode;

  fprintf(f, ",\n\t\t\t\t\"srlt\": [\n");

  if (len2 == NULL) {
    
    ts_start = *time;

    imax = op > num_pkt_len_tls ? num_pkt_len_tls : op;
    if (imax == 0) { 
      ; /* no packets had data, so we print out nothing */
    } else {
      for (i = 0; i < imax-1; i++) {
	if (i > 0) {
	  timer_sub_tls(&time[i], &time[i-1], &ts);
	} else {
	  timer_clear_tls(&ts);
	}
	print_bytes_dir_time_tls(len[i], OUT, ts, type[i], ",\n", f);
      }
      if (i == 0) {        /* this code could be simplified */ 	
	timer_clear_tls(&ts);  
      } else {
	timer_sub_tls(&time[i], &time[i-1], &ts);
      }
      print_bytes_dir_time_tls(len[i], OUT, ts, type[i], "\n", f);
    }
    fprintf(f, "\t\t\t\t]"); 
  } else {

    if (timer_lt_tls(time, time2)) {
      ts_start = *time;
    } else {
      ts_start = *time2;
    }

    imax = op > num_pkt_len_tls ? num_pkt_len_tls : op;
    jmax = op2 > num_pkt_len_tls ? num_pkt_len_tls : op2;
    i = j = 0;
    ts_last = ts_start;
    while ((i < imax) || (j < jmax)) {      

      if (i >= imax) {  /* record list is exhausted, so use twin */
	dir = OUT;
	ts = time2[j];
	pkt_len = len2[j];
	typecode = type2[j];
	j++;
      } else if (j >= jmax) {  /* twin list is exhausted, so use record */
	dir = IN;
	ts = time[i];
	pkt_len = len[i];
	typecode = type[i];
	i++;
      } else { /* neither list is exhausted, so use list with lowest time */     

	if (timer_lt_tls(&time[i], &time2[j])) {
	  ts = time[i];
	  pkt_len = len[i];
	  typecode = type[i];
	  dir = IN;
	  if (i < imax) {
	    i++;
	  }
	} else {
	  ts = time2[j];
	  pkt_len = len2[j];
	  typecode = type2[j];
	  dir = OUT;
	  if (j < jmax) {
	    j++;
	  }
	}
      }
      timer_sub_tls(&ts, &ts_last, &tmp);
      print_bytes_dir_time_tls(pkt_len, dir, tmp, typecode, "", f);
      ts_last = ts;
      if ((i == imax) & (j == jmax)) { /* we are done */
      	fprintf(f, "\n"); 
      } else {
	fprintf(f, ",\n");
      }
    }
    fprintf(f, "\t\t\t\t]");
  }

}

void tls_printf(const struct tls_information *data, const struct tls_information *data_twin, FILE *f) {
  int i;

  if (!data->tls_v && (data_twin == NULL || !data_twin->tls_v)) { // no reliable TLS information
    return ;
  }
  fprintf(f, ",\n\t\t\t\"tls\": {");

  if (data->tls_v) {
    fprintf(f, "\n\t\t\t\t\"tls_ov\": %u", data->tls_v);
  }
  if (data_twin && data_twin->tls_v) {
    if (data->tls_v) {
      fprintf(f, ",\n\t\t\t\t\"tls_iv\": %u", data_twin->tls_v);
    } else {
      fprintf(f, "\n\t\t\t\t\"tls_iv\": %u", data_twin->tls_v);
    }
  }

  if (data->tls_client_key_length) {
    fprintf(f, ",\n\t\t\t\t\"tls_client_key_length\": %u", data->tls_client_key_length);
  }
  if (data_twin && data_twin->tls_client_key_length) {
    fprintf(f, ",\n\t\t\t\t\"tls_client_key_length\": %u", data_twin->tls_client_key_length);
  }

  /*
   * print out TLS random, using the ciphersuite count as a way to
   * determine whether or not we have seen a clientHello or a
   * serverHello
   */

  if (data->num_ciphersuites) {
    fprintf(f, ",\n\t\t\t\t\"tls_orandom\": ");
    fprintf_raw_as_hex_tls(f, data->tls_random, 32);
  }
  if (data_twin && data_twin->num_ciphersuites) {
    fprintf(f, ",\n\t\t\t\t\"tls_irandom\": ");
    fprintf_raw_as_hex_tls(f, data_twin->tls_random, 32);
  }

  if (data->tls_sid_len) {
    fprintf(f, ",\n\t\t\t\t\"tls_osid\": ");
    fprintf_raw_as_hex_tls(f, data->tls_sid, data->tls_sid_len);
  }
  if (data_twin && data_twin->tls_sid_len) {
    fprintf(f, ",\n\t\t\t\t\"tls_isid\": ");
    fprintf_raw_as_hex_tls(f, data_twin->tls_sid, data_twin->tls_sid_len);
  }

  if (data->num_ciphersuites) {
    if (data->num_ciphersuites == 1) {
      fprintf(f, ",\n\t\t\t\t\"scs\": \"%04x\"", data->ciphersuites[0]);
    } else {
      fprintf(f, ",\n\t\t\t\t\"cs\": [ ");
      for (i = 0; i < data->num_ciphersuites-1; i++) {
	if ((i % 8) == 0) {
	  fprintf(f, "\n\t\t\t\t        ");	    
	}
	fprintf(f, "\"%04x\", ", data->ciphersuites[i]);
      }
      fprintf(f, "\"%04x\"\n\t\t\t\t]", data->ciphersuites[i]);
    }
  }  
  if (data_twin && data_twin->num_ciphersuites) {
    if (data_twin->num_ciphersuites == 1) {
      fprintf(f, ",\n\t\t\t\t\"scs\": \"%04x\"", data_twin->ciphersuites[0]);
    } else {
      fprintf(f, ",\n\t\t\t\t\"cs\": [ ");
      for (i = 0; i < data_twin->num_ciphersuites-1; i++) {
	if ((i % 8) == 0) {
	  fprintf(f, "\n\t\t\t\t        ");	    
	}
	fprintf(f, "\"%04x\", ", data_twin->ciphersuites[i]);
      }
      fprintf(f, "\"%04x\"\n\t\t\t\t]", data_twin->ciphersuites[i]);
    }
  }    
  
  if (data->num_tls_extensions) {
    fprintf(f, ",\n\t\t\t\t\"tls_ext\": [ ");
    for (i = 0; i < data->num_tls_extensions-1; i++) {
      fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data->tls_extensions[i].type);
      fprintf(f, "\"length\": %i, \"data\": ", data->tls_extensions[i].length);
      fprintf_raw_as_hex_tls(f, data->tls_extensions[i].data, data->tls_extensions[i].length);
      fprintf(f, "},");
    }
    fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data->tls_extensions[i].type);
    fprintf(f, "\"length\": %i, \"data\": ", data->tls_extensions[i].length);
    fprintf_raw_as_hex_tls(f, data->tls_extensions[i].data, data->tls_extensions[i].length);
    fprintf(f, "}\n\t\t\t\t]");
  }  
  if (data_twin && data_twin->num_tls_extensions) {
    fprintf(f, ",\n\t\t\t\t\"tls_ext\": [ ");
    for (i = 0; i < data_twin->num_tls_extensions-1; i++) {
      fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data_twin->tls_extensions[i].type);
      fprintf(f, "\"length\": %i, \"data\": ", data_twin->tls_extensions[i].length);
      fprintf_raw_as_hex_tls(f, data_twin->tls_extensions[i].data, data_twin->tls_extensions[i].length);
      fprintf(f, "},");
    }
    fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data_twin->tls_extensions[i].type);
    fprintf(f, "\"length\": %i, \"data\": ", data_twin->tls_extensions[i].length);
    fprintf_raw_as_hex_tls(f, data_twin->tls_extensions[i].data, data_twin->tls_extensions[i].length);
    fprintf(f, "}\n\t\t\t\t]");
  }
  
  if (data->num_server_tls_extensions) {
    fprintf(f, ",\n\t\t\t\t\"s_tls_ext\": [ ");
    for (i = 0; i < data->num_server_tls_extensions-1; i++) {
      fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data->server_tls_extensions[i].type);
      fprintf(f, "\"length\": %i, \"data\": ", data->server_tls_extensions[i].length);
      fprintf_raw_as_hex_tls(f, data->server_tls_extensions[i].data, data->server_tls_extensions[i].length);
      fprintf(f, "},");
    }
    fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data->server_tls_extensions[i].type);
    fprintf(f, "\"length\": %i, \"data\": ", data->server_tls_extensions[i].length);
    fprintf_raw_as_hex_tls(f, data->server_tls_extensions[i].data, data->server_tls_extensions[i].length);
    fprintf(f, "}\n\t\t\t\t]");
  }  
  if (data_twin && data_twin->num_server_tls_extensions) {
    fprintf(f, ",\n\t\t\t\t\"s_tls_ext\": [ ");
    for (i = 0; i < data_twin->num_server_tls_extensions-1; i++) {
      fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data_twin->server_tls_extensions[i].type);
      fprintf(f, "\"length\": %i, \"data\": ", data_twin->server_tls_extensions[i].length);
      fprintf_raw_as_hex_tls(f, data_twin->server_tls_extensions[i].data, data_twin->server_tls_extensions[i].length);
      fprintf(f, "},");
    }
    fprintf(f, "\n\t\t\t\t\t{ \"type\": \"%04x\", ", data_twin->server_tls_extensions[i].type);
    fprintf(f, "\"length\": %i, \"data\": ", data_twin->server_tls_extensions[i].length);
    fprintf_raw_as_hex_tls(f, data_twin->server_tls_extensions[i].data, data_twin->server_tls_extensions[i].length);
    fprintf(f, "}\n\t\t\t\t]");
  }
  
    /* print out TLS application data lengths and times, if any */

    if (data->tls_op) {
      if (data_twin) {
	len_time_print_interleaved_tls(data->tls_op, data->tls_len, data->tls_time, data->tls_type,
				       data_twin->tls_op, data_twin->tls_len, data_twin->tls_time, data_twin->tls_type, f);
      } else {
	/*
	 * unidirectional TLS does not typically happen, but if it
	 * does, we need to pass in zero/NULLs, since there is no twin
	 */
	len_time_print_interleaved_tls(data->tls_op, data->tls_len, data->tls_time, data->tls_type, 0, NULL, NULL, NULL, f);
      }
    }
 
  fprintf(f, "\n\t\t\t}");
}
