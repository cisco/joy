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
 * jfd-anon
 * 
 * json flow data anonymization tool
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "anon.h"
#include "radix_trie.h"   /* for rt_test() */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


char *address_string_anonymize(char *addr_string) {
  struct in_addr addr;
  int l;

  l = strnlen(addr_string, 256);
  if (l >= 32) {
    return addr_string;  /* probably already anonymized */
  }

  if (inet_aton(addr_string, &addr) == 0) {
    return NULL;
  }
  if (ipv4_addr_needs_anonymization(&addr)) {
    return addr_get_anon_hexstring(&addr);
  }
  return addr_string;
}

void anon_addresses(char *line) {
  char *addr;
  char addr_string[256];

  addr = strstr(line, "\"sa\":");
  if (addr) {
    sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
    printf("\t\t\t\"sa\": \"%s\",\n", address_string_anonymize(addr_string));
    //      printf("%s", addr);
  } else {
    addr = strstr(line, "\"da\":");
    if (addr) {
      sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
      printf("\t\t\t\"da\": \"%s\",\n", address_string_anonymize(addr_string));
      //      printf("%s", addr);
    } else {
      printf("%s", line);
    }
  }   
}

void check_anon_addresses(char *line) {
  char *addr;
  char addr_string[256];
  char *retval;

  addr = strstr(line, "\"sa\":");
  if (addr) {
    sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
    
    retval =  address_string_anonymize(addr_string);
    if (retval && retval != addr_string) {
      printf("sa needs anonymization: %s\t%s\n", addr_string, retval);
    }
  } else {
    addr = strstr(line, "\"da\":");
    if (addr) {
      sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
      retval =  address_string_anonymize(addr_string);
      if (retval && retval != addr_string) {
	printf("da needs anonymization: %s\t%s\n", addr_string, retval);
      }
    }   
  }
}


int usage(char *name) {
  fprintf(stderr, "usage: %s [-c] [ anonfile ]\n", name);
  fprintf(stderr, "   reads JSON Flow Data from stdin, and anonymizes the subnets in anonfile\n");
  return 1;
}

enum mode {
  translate = 0,
  check = 1
};


int main(int argc, char *argv[]) {
  ssize_t bytes_read;
  size_t len;
  char *line = NULL;  
  enum status err;
  char *anonfile = NULL;
  enum mode mode = translate;

  // rt_test();
  // exit(1);

  if (argc == 1) {
    mode = translate;   /* this option just copies stdin to stdout */
  } else if (argc == 2) {
    anonfile = argv[1];
  } else if (argc == 3) {
    if (strcmp(argv[1], "-c")) {
      usage(argv[0]);
    }
    mode = check;
    anonfile = argv[2];
  } else {    
    return usage(argv[0]);
  }
  if (anonfile) {
    err = anon_init(anonfile, stderr);
    if (err) {
      fprintf(stderr, "error: could not initialize anonymization from file %s\n",
	      argv[1]);
      return EXIT_FAILURE;
    }
  }
  //  printf("mode: %u\n", mode);

  /*
   * read and then process each line of input
   */
  while ((bytes_read = getline(&line, &len, stdin)) != -1) {

#if 0
    unsigned int i;
    char *text;
    char lhs[256];

    /* remove leading whitespace */
    i = 0;
    text = line;
    while (isblank(*text) && (i < len)) { 
      text++;
      i++;
    } 

#if 0
    if (*text == '{') {
      printf("{");
    } else if (*text == '}') {
      printf("}");
    }
#endif

    if (sscanf(text, "%[\"a-zA-Z_{}]", lhs) > 0) {
      printf("lhs: %s\n", lhs);
      if (strncmp(lhs, "flow", 5) == 0) {
	printf("found flow\n");
      }
    }

#else 
    
    if (mode == translate) {
      anon_addresses(line);
    } else {
      /* mode == check */
      check_anon_addresses(line);
    }
#endif    


  }
      
  free(line);
 
  return 0;
}
