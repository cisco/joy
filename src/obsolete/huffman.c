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
 * huffman.c
 *
 * huffman code generation, encoding, and decoding routines
 */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>  /* for isblank() */

#include "err.h"   /* for failure and ok */

#define COUNT_SIZE 0xffffff

unsigned int counts[COUNT_SIZE];
unsigned int values[COUNT_SIZE];
unsigned int num_values = 0;

struct huffman_node {
  unsigned int count;   /* number of instances of this node   */
  unsigned int value;   /* codeword, if this node is a leaf   */
  struct huffman_node *left;  /* left child, or NULL if leaf  */
  struct huffman_node *right; /* right child, or NULL if leaf */
}; 

#include <math.h>
#include <float.h>   /* for FLT_EPSILON */

float compute_entropy(const unsigned int *counts, 
		      unsigned int num_elements) {
  unsigned int i;
  unsigned long long int total_count = 0;
  float tmp, sum = 0.0;

  for (i=0; i<num_elements; i++) {
    total_count += counts[i];
  }

  for (i=0; i<num_elements; i++) {
    tmp = (float) counts[i] / (float) total_count;
    if (tmp > FLT_EPSILON) {
      sum -= tmp * logf(tmp);
    }
    // fprintf(output, "tmp: %f\tsum: %f\n", tmp, sum);
  }
  return sum / logf(2.0);
}

struct huffman_node *make_code(unsigned int counts[COUNT_SIZE]) {
  unsigned int i;
  struct huffman_node *list;
  struct huffman_node *node_array[COUNT_SIZE];

  for (i=0; i<COUNT_SIZE; i++) {
    /*
     * allocate and initialize huffman_node
     */
    struct huffman_node *node = malloc(sizeof(struct huffman_node));
    if (node == NULL) {
      return NULL;   
    }
    node->left = NULL;
    node->right = NULL;
    node->count = counts[i];
    node_array[i] = node;
  }

  /* heapify */
  
  return NULL;
}

#define LINEMAX 1024

int file_read_weights_and_values(const char *fname) {
  FILE *f;
  char *line = NULL;
  size_t ignore;
  ssize_t len;
  unsigned int linecount = 0;
  char *c;
  unsigned int i = 0;

  f = fopen(fname, "r");
  if (f == NULL) {
    fprintf(stderr, "error: could not open file %s\n", fname);
    return failure;
  } 

  while ((len = getline(&line, &ignore, f)) != -1) {
    int num;
    unsigned int weight, value;

    linecount++;
    if (len > LINEMAX) {
      fprintf(stderr, "error: line too long in file %s\n", fname);
      return failure;
    }

    /* ignore blank lines and comments */
    c = line;
    while (isblank(*c)) {
      c++;
    }
    if (*c == '#' || *c == '\n') {
      ;
    } else {
    
      /*
       * a valid command line consists of two unsigned integers, a
       * weight and a value; if a "#" appears after the second
       * integer, it will be ignored
       */
      num = sscanf(line, "%u %u", &weight, &value);
      if (num == 2) {
	if (value > 0xffffffff) {
	  printf("error: value %u too large at line %u in file %s\n", value, linecount, fname);
	  exit(EXIT_FAILURE);
	}

	// printf("got weight %u and value %u\n", weight, value);
	counts[i] = weight;
	values[i] = value;
	i++;
      	
      } else if (num == 1) {
	  printf("error: could not parse line %u in file %s as a weight and value\n", 
		 linecount, fname);
	  exit(EXIT_FAILURE);
	
      } else {
	printf("error: could not parse line %s in file %s\n", line, fname);
	fprintf(stderr, "error: could not parse line %s in file %s\n", 
		   line, fname);
      }
    }

  }
  
  free(line);

  num_values = i;

  return ok;
}

void usage(const char *progname) {
  printf("%s: computes huffman code given a file of weights and values\n", progname);
}

int main(int argc, char *argv[]) {

  if (argc == 2) {
    file_read_weights_and_values(argv[1]);
  } else {
    usage(argv[0]);
  }

  printf("entropy: %f\n", compute_entropy(counts, num_values));
  
  return 0;
}
