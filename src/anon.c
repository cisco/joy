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

/* START address anonymization  */

/*
 * The anonymization key is generated via calls to /dev/random, and is
 * stored in the file ANON_KEYFILE in encrypted form, with the
 * decryption key being stored inside the executable.  A user who can
 * access ANON_KEYFILE and the executable will be able to determine
 * the anonymization key; it is essential to provide strong access
 * control on ANON_KEYFILE in particular.
 */

#include <stdio.h>         
#include <ctype.h>         /* for isdigit()      */
#include <stdlib.h>        /* for atoi()         */
#include <string.h>        /* for memcpy()       */
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>    /* for struct in_addr */
#include <sys/socket.h>    /* for inet_aton()    */
#include <arpa/inet.h>     /* for inet_aton()    */
#include <openssl/aes.h>
#include "err.h"           /* for error codes    */
#include "anon.h" 
#include "addr.h"
#include "radix_trie.h"

FILE *anon_info;

#define MAX_KEY_SIZE 16

struct anon_aes_128_ipv4_key {
  AES_KEY key;
};

struct anon_aes_128_ipv4_key key;

#define ANON_KEYFILE "pcap2flow.bin"

unsigned int anonymize = 0;

enum status key_init() {
  int fd;
  ssize_t bytes;
  unsigned char buf[MAX_KEY_SIZE];
  unsigned char x[16] = {
    0xa9, 0xd1, 0x62, 0x94, 
    0x4b, 0x7c, 0x20, 0x18, 
    0xac, 0x6d, 0x1a, 0x6b, 
    0x42, 0x8a, 0x0b, 0x2e
  };
  AES_KEY tmp;
  unsigned char c[16];

  fd = open(ANON_KEYFILE, O_RDWR);
  if (fd > 0) {
    
    /* key file exists, so read contents */
    bytes = read(fd, c, MAX_KEY_SIZE);
    close(fd);
    if (bytes != MAX_KEY_SIZE) {
      perror("error: could not read anonymization key");
      return failure;
    } else {
      AES_set_decrypt_key(x, 128, &tmp);
      AES_decrypt(c, buf, &tmp);
    }
  } else {

    /* key file does not exist, so generate new one */
    fd = open("/dev/random", O_RDONLY);
    if (fd < 0) {
      perror("error: could not open /dev/random");
      return failure;
    }
    bytes = read(fd, buf, MAX_KEY_SIZE);
    close(fd);
    if (bytes != MAX_KEY_SIZE) {
      perror("error: could not read key from /dev/random");
      return failure;
    }
    AES_set_encrypt_key(x, 128, &tmp);
    AES_encrypt(buf, c, &tmp);

    fd = open(ANON_KEYFILE, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    if (fd < 0) {
      perror("error: could not create pcap2flow.bin");
    } else {
      bytes = write(fd, c, MAX_KEY_SIZE);
      close(fd);
      if (bytes != MAX_KEY_SIZE) {
	perror("error: could not write anonymization key");
	return failure;
      }
    } 
  } 
  AES_set_encrypt_key(buf, 128, &key.key);    
  anonymize = 1;

  return ok; 
}

void print_binary(FILE *f, const void *x, unsigned int bytes) {
  const unsigned char *buf = x;

  while (bytes-- > 0) {
    unsigned char bit = 128;
    
    while (bit > 0) {
      if (bit & *buf) {
	fprintf(f, "1");
      } else {
	fprintf(f, "0");
      }
      bit >>= 1;
    }
    fprintf(f, "|");
    buf++;
  }
  //  fprintf(f, "\n");
}


struct subnet {
  struct in_addr addr;
  struct in_addr mask;
};

#define MAX_ANON_SUBNETS 256

struct subnet anon_subnet[MAX_ANON_SUBNETS];

unsigned int num_subnets = 0;

enum status anon_subnet_add(struct in_addr a, unsigned int netmasklen) {
  if (num_subnets >= MAX_ANON_SUBNETS) {
    return failure;
  } else {
    // fprintf(output, "adding subnet %u\n", num_subnets);
    anon_subnet[num_subnets].addr = a;
    anon_subnet[num_subnets].mask.s_addr = ipv4_mask(netmasklen);
    // fprintf(anon_info, "addr: %s\t", inet_ntoa(anon_subnet[num_subnets].addr));
    // print_binary(anon_info, &anon_subnet[num_subnets].addr, 4);
    // fprintf(anon_info, "\t");
    // print_binary(anon_info, &anon_subnet[num_subnets].mask.s_addr, 4);
    // fprintf(anon_info, "\n");
    num_subnets++;
  }
  return ok;
}

enum status anon_subnet_add_from_string(char *addr) {
  int i, masklen = 0;
  char *mask = NULL;
  struct in_addr a;
  extern FILE *anon_info;

  //  fprintf(anon_info, "loading anonymizer subnet %s\n", addr);
  for (i=0; i<80; i++) {
    if (addr[i] == '/') {
      mask = addr + i + 1;
      addr[i] = 0;
      break;
    }
  }
  // fprintf(output, "address: %s\n", addr);
  if (mask) {

    /* avoid confusing atoi() with nondigit characters */
    for (i=0; i<80; i++) {
      if (mask[i] == 0) {
	break;
      }
      if (!isdigit(mask[i])) {
	mask[i] = 0;   /* null terminate */
	break;
      }
    }    
    masklen = atoi(mask);
    if (masklen < 1 || masklen > 32) {
      fprintf(anon_info, "error: cannot parse subnet; netmask is %d bits\n", masklen);
      return failure;
    }
    // fprintf(output, "masklen: %d\n", masklen);
    
    inet_aton(addr, &a);
    // print_binary(anon_info, &a, sizeof(a));
    a.s_addr = addr_mask(a.s_addr, masklen);
    
    return anon_subnet_add(a, masklen);
  }			 
  return failure;
}

unsigned int addr_is_in_set(const struct in_addr *a) {
  int i;

  for (i=0; i < num_subnets; i++) {
    if ((a->s_addr & anon_subnet[i].mask.s_addr) == anon_subnet[i].addr.s_addr) {
      // printf("address %s -", inet_ntoa(*a)); 
      // fprintf(output, "found match with %s\n", inet_ntoa(anon_subnet[i].addr));  
      return 1;
    } 
  }
  //  fprintf(output, "no matches in set\n");
  return 0;
}

unsigned int bits_in_mask(void *a, unsigned int bytes) {
  unsigned int n = 0;
  extern FILE *anon_info;
  unsigned char *buf = (unsigned char *)a;

  while (bytes-- > 0) {
    unsigned char bit = 128;
    
    while (bit > 0) {
      n++;
      if ((bit & *buf) == 0) {
	return n-1;
      }
      bit >>= 1;
    }
    buf++;
  }
  return 32;
}

int anon_print_subnets(FILE *f) {
  if (num_subnets > MAX_ANON_SUBNETS) {
    fprintf(f, "error: %u anonymous subnets configured, but maximum is %u\n", 
	    num_subnets, MAX_ANON_SUBNETS);
    return failure;
  } else {
    unsigned int i;

    for (i=0; i<num_subnets; i++) {
      fprintf(f, "anon subnet %u: %s/%d\n", i, 
	      inet_ntoa(anon_subnet[i].addr),
	      bits_in_mask(&anon_subnet[i].mask, 4));
    }
  }
  return ok;
}

#include <ctype.h>

enum status anon_init(const char *pathname, FILE *logfile) {
  enum status s;
  FILE *fp;
  size_t len;
  char *line = NULL;
  extern FILE *anon_info;

  if (logfile != NULL) {
    anon_info = logfile;
  } else {
    anon_info = stderr;
  }

  fp = fopen(pathname, "r");
  if (fp == NULL) {
    return failure;
  } else {
    
    while (getline(&line, &len, fp) != -1) {
      char *addr = line;
      int i, got_input = 0;

      for (i=0; i<80; i++) {
	if (line[i] == '#') {
	  break;
	}
	if (isblank(line[i])) {
	  if (got_input) {
	    line[i] = 0; /* null terminate */
	  } else {
	    addr = line + i + 1;
	  }
	}
	if (!isprint(line[i])) {
	  break;
	}
	if (isxdigit(line[i])) {
	  got_input = 1;
	}
      }
      if (got_input) {
	if (anon_subnet_add_from_string(addr) != ok) {
	  fprintf(anon_info, "error: could not add subnet %s to anon set\n", addr);
	  return failure;
	}
      }
    }

    anon_print_subnets(anon_info);
    fprintf(anon_info, "configured %d subnets for anonymization\n", num_subnets);
      
    free(line);
    
    fclose(fp);
  } 

  s = key_init();

  return s;
}

char hexout[33];

char *addr_get_anon_hexstring(const struct in_addr *a) {
  unsigned char pt[16] = { 0, };
  unsigned char c[16];

  memcpy(pt, a, sizeof(struct in_addr));
  AES_encrypt(pt, c, &key.key);
  snprintf(hexout, 33, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
	   c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], 
	   c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);
 
  return hexout;
}


unsigned int ipv4_addr_needs_anonymization(const struct in_addr *a) {
  if (anonymize) {
    return addr_is_in_set(a);
  }
  return 0;
}

int anon_unit_test() {
  struct in_addr inp;
  extern FILE *anon_info;

  anon_init("internal.net", stderr);

  if (inet_aton("64.104.192.129", &inp) == 0) {
    fprintf(anon_info, "error: could not convert address\n");
  }  
  if (ipv4_addr_needs_anonymization(&inp) != 1) {
    fprintf(anon_info, "error in anon_unit_test\n");
  } else {
    fprintf(anon_info, "passed\n");
  }

  return ok;
}

/* END address anonymization  */

/* START http anonymization */

#include "str_match.h"

str_match_ctx usernames_ctx = NULL;

enum status anon_http_init(const char *pathname, FILE *logfile) {
  enum status s;

  if (logfile != NULL) {
    anon_info = logfile;
  } else {
    anon_info = stderr;
  }

  usernames_ctx = str_match_ctx_alloc();
  if (usernames_ctx == NULL) {
    fprintf(stderr, "error: could not allocate string matching context\n");
    return -1;
  }
  if (str_match_ctx_init_from_file(usernames_ctx, pathname) != 0) {
    fprintf(stderr, "error: could not init string matching context from file\n");
    exit(EXIT_FAILURE);
  }

  /* make sure that key is initialized */
  s = key_init();

  return s;
}

void fprintf_nbytes(FILE *f, char *s, size_t len) {
  char tmp[1024];
  
  if (len > 1024) {
    fprintf(stdout, "error: string longer than fixed buffer (length: %zu)\n", len);
    return;
  }
  memcpy(tmp, s, len);
  tmp[len] = 0;
  fprintf(f, "%s", tmp);
  
}

void fprintf_anon_nbytes(FILE *f, char *s, size_t len) {
  char tmp[1024];
  unsigned int i;

  if (len > 1024) {
    fprintf(stdout, "error: string longer than fixed buffer (length: %zu)\n", len);
    return;
  }
  for (i=0; i<len; i++) {
    tmp[i] = '*';
  }
  tmp[len] = 0;
  fprintf(f, "%s", tmp);
  
}

int is_special(char *ptr) {
  char c = *ptr;
  // printf("\nc='%c'\n", c); 
  return (c=='?')||(c=='&')||(c=='/')||(c=='-')||(c=='\\')||(c=='_')||(c=='.')||(c=='=')||(c==';')||(c==0);
}

void anon_print_uri(FILE *f, struct matches *matches, char *text) {
  unsigned int i;

  if (matches->count == 0) {
    fprintf(f, "%s", text);
    return;
  }

  fprintf_nbytes(f, text, matches->start[0]);   /* nonmatching */
  for (i=0; i < matches->count; i++) {

    if ((matches->start[i] == 0 || is_special(text + matches->start[i] - 1)) && is_special(text + matches->stop[i] + 1)) {
      fprintf_anon_nbytes(f, text + matches->start[i], matches->stop[i] - matches->start[i] + 1);   /* matching and special */
    } else {
      fprintf_nbytes(f, text + matches->start[i], matches->stop[i] - matches->start[i] + 1);   /* matching, not special */
    }
    if (i < matches->count-1) {
      fprintf_nbytes(f, text + matches->stop[i] + 1, matches->start[i+1] - matches->stop[i] - 1); /* nonmatching */
    } else {
      fprintf(f, "%s", text + matches->stop[i] + 1);  /* nonmatching */
    }
  }
}


/* END http anonymization */
