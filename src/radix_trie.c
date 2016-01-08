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
 * START radix_trie.c
 *
 * a radix trie implementation for efficient matching of addresses
 * against one or more subnets
 *
 *
 *
 */

#include <stdio.h>       /* for printf(), etc.           */
#include <stdlib.h>      /* for malloc()                 */
#include <string.h>      /* for memset()                 */
#include <ctype.h>       /* for isblank(), etc.          */
#include "radix_trie.h"
#include "addr.h"

/*
 * radix_trie internals
 * 
 * A radix_trie contains two types of nodes: internal and leaf.  An
 * internal node contains a 256-entry table that indicates how
 * branching is done based on the digit of the current level of the
 * tree.  That is, table[key[i]] is the pointer to the next node where
 * i is the level and key[i] is the ith digit of the key.
 * 
 * A leaf (terminal) node contains a flags value, which is a bitmask
 * that indicates the set of labels associated with the key value.
 *
 * Example 1: start with an empty trie, and set flag(0xcafebabe) = 1;
 * then the following nodes will be created:
 *     level 0: table[0xca] = next node
 *     level 1: table[0xfe] = next node
 *     level 2: table[0xba] = next node
 *     level 3: table[0xbe] = next node
 *     level 4: leaf.value = 1
 *
 * Example 2: after Example 1, set flag(0xcafe) = 2; then the
 * following nodes will be in the tree:
 *     level 0: table[0xca] = next node; all other table entries NULL
 *     level 1: table[0xfe] = next node; all other table entries NULL
 *     level 2: table[0xba] = next node; all other entries leaf.value = 2
 *     level 3: table[0xbe] = next node
 *     level 4: leaf.value = 1 & 2
 *    
 *
 */

// #define debug_printf(...) (fprintf(stdout, "debug: " __VA_ARGS__)) 


/* 
 * memory allocation and usage tracking functions
 */
static unsigned int rt_mem_usage = 0; /* bytes alloced by radix_trie(s) */

inline void *rt_malloc(size_t s) {
  debug_printf("rt_malloc of %zu bytes\n", s);
  rt_mem_usage += s;
  return malloc(s);
}

unsigned int get_rt_mem_usage() {
  return rt_mem_usage;
}

/*
 * internal radix_trie data types 
 */
enum radix_trie_node_type {
  reserved = 0,
  internal = 1,
  leaf = 2
};

struct radix_trie_node {
  enum radix_trie_node_type type;    /* internal */
  struct radix_trie_node *table[256];
};

struct radix_trie_leaf {
  enum radix_trie_node_type type;   /* leaf      */
  attr_flags value;
};

#define MAX_LABEL_LEN 256

struct radix_trie {
  struct radix_trie_node *root;
  unsigned int num_flags;
  char *flag[MAX_NUM_FLAGS];
};

struct radix_trie *radix_trie_alloc() {
  return rt_malloc(sizeof(struct radix_trie));
}

struct radix_trie_node *radix_trie_node_init() {
  struct radix_trie_node *radix_trie;
  
  radix_trie = rt_malloc(sizeof(struct radix_trie_node));
  
  if (radix_trie) {
    radix_trie->type = internal;

    /* initialize table entries to NULL */
    memset(radix_trie->table, 0, sizeof(radix_trie->table));
  }

  return radix_trie;   /* could be NULL */
}

struct radix_trie_leaf *radix_trie_leaf_init(attr_flags value) {
  struct radix_trie_leaf *radix_trie;
  
  radix_trie = rt_malloc(sizeof(struct radix_trie_leaf));
  
  if (radix_trie) {
    radix_trie->type = leaf;
    radix_trie->value = value;
  }

  return radix_trie;   /* could be NULL */
}

attr_flags radix_trie_lookup_addr(struct radix_trie *trie, struct in_addr addr) {
  unsigned char *a = (void *) &addr.s_addr;
  unsigned int i;
  struct radix_trie_node *rt = trie->root;
  
  debug_printf("lookup\n");

  /* sanity check */
  if (rt == NULL) {
    return failure;
  }

  for (i=0; i<4; i++) {
    debug_printf("a[%d]: %x\n", i, a[i]); 
    rt = rt->table[a[i]];
    if (rt == NULL) {
      return 0;  /* indicate that no match occured */
    } 
    if (rt->type == leaf) {
      break;
    }
  }  
  if (rt->type == leaf) {
    struct radix_trie_leaf *leaf = (struct radix_trie_leaf *)rt;
    debug_printf("found leaf (value: %x)\n", leaf->value);
    return leaf->value; /* indicate success by returning flags  */
  }

  return 0;  /* indicate that no match occured */
}

inline void radix_trie_node_add_flag_to_all_leaves(const struct radix_trie_node *rt, attr_flags flags) {
  unsigned int i;
  
  if (rt == NULL) {
    return;
  }
  switch(rt->type) {
  case leaf:
    ((struct radix_trie_leaf *)rt)->value |= flags;
    debug_printf("adding flag %x to leaf (current value: %x)\n", flags, ((struct radix_trie_leaf *)rt)->value);
    break;
  case internal:
    for (i=0; i<256; i++) {    
     debug_printf("adding flags %x to leaves at %x\n", flags, i);
      radix_trie_node_add_flag_to_all_leaves(rt->table[i], flags);
    }
    break;
  default:
    ;
  }
  return;
}

#define MAX(x,y) (x > y ? x : y)

enum status radix_trie_add_subnet(struct radix_trie *trie, struct in_addr addr, unsigned int netmasklen, attr_flags flags) {
  unsigned char *a = (void *) &addr.s_addr;
  unsigned int i, x, bits, bytes, max, num_internal_nodes;
  struct radix_trie_node *tmp;
  struct radix_trie_node *rt = trie->root;

  /* sanity checks */
  if (!trie || (netmasklen > 32)) {
    return failure;   /* no null pointers or giant netmasks allowed */
  }
  if (!flags) {
    return failure;   /* flags must be nonzero; 0 value indicates the absence of flags */
  }
  
  bytes = netmasklen / 8;
  bits = netmasklen - (bytes * 8);
  //  num_internal_nodes = MAX(bytes-1,1);
  num_internal_nodes = (netmasklen-1)/8;
  max = 1 << (8-bits);

  debug_printf("add\tflags: %x\tnetmask: %u\tbytes: %u\tbits: %u\tloops: %u\tmax: %u\n", flags, netmasklen, bytes, bits, num_internal_nodes, max);

  /* loop over bytes, creating internal nodes where needed */
  for (i=0; i < num_internal_nodes; i++) {
    debug_printf("I: a[%d]: %x\n", i, a[i]); 
    tmp = rt->table[a[i]];
    if (tmp == NULL) {
      tmp = radix_trie_node_init();
      if (tmp == NULL) {
	return failure;
      }
      rt->table[a[i]] = tmp;
    }
    if (tmp->type == leaf) {
      debug_printf("warning: found a leaf during creation\n");
      break;
    }
    rt = tmp;
  }  

  /* create leaf node(s) */
  if (bits == 0) {
    debug_printf("L: a[%d]: %x\n", i, a[i]); 

    if (rt->table[a[i]] != NULL) {
      radix_trie_node_add_flag_to_all_leaves(rt->table[a[i]], flags);
    } else {
      tmp = (struct radix_trie_node *)radix_trie_leaf_init(flags);
      if (tmp == NULL) {
	return failure;
      }
      rt->table[a[i]] = tmp;
    }
  } else {
    unsigned char mask = 0xff << (8-bits);
    unsigned int prefix = a[i] & mask;

    /* loop over all bytes with common prefix */
    for (x=0; x<max; x++) {
      debug_printf("L: a[%u]: %x\n", i, prefix|x); 

      /* if table entry exists, then add flag into all leaves */
      if (rt->table[prefix|x] != NULL) {
	radix_trie_node_add_flag_to_all_leaves(rt->table[prefix|x], flags);
      } else { 
	tmp = (struct radix_trie_node *)radix_trie_leaf_init(flags);
	if (tmp == NULL) {
	  return failure;
	}
	rt->table[prefix|x] = tmp;
      }
    } 
  }

  return ok;
}

unsigned int index_to_flag(unsigned int x) {
  unsigned int flag;

  if (x > MAX_NUM_FLAGS) {
    return 0;  /* failure; not that many flags */
  }
  flag = 1;
  flag = flag << x;
  return flag;
}

unsigned int flag_to_index(unsigned int y) {
  unsigned int i = 0;
  
  while (y > 0) {
    y = y >> 1;
    i++;
  }
  return i-1;
}

attr_flags radix_trie_add_attr_label(struct radix_trie *rt, const char *attr_label) {
  
  if (!attr_label) {
    return 0;     /* NULL is an error                              */
  }
  if (strlen(attr_label) > MAX_LABEL_LEN-1) { 
    return 0;     /* not enough room for label and null terminator */
  }
  if (rt->num_flags >= MAX_NUM_FLAGS-1) {
    return 0;     /* this trie already has too many labels         */
  }
  /* add label by allocating string corresponding to flag */
  if ((rt->flag[rt->num_flags] = strdup(attr_label)) == NULL) {
    return 0;     /* failure */
  }
  
  return index_to_flag(rt->num_flags++);
}


char *radix_trie_attr_get_label(const struct radix_trie *rt, attr_flags a) {
  return rt->flag[flag_to_index(a)];
}

char *radix_trie_attr_get_next_label(const struct radix_trie *rt,
				     attr_flags attr) {
  
  return rt->flag[flag_to_index(attr_get_next_flag(&attr))];
}


void attr_flags_print_labels(const struct radix_trie *rt, attr_flags f) {
  unsigned int i, c=0;

  for (i=0; i < rt->num_flags; i++) {
    if (index_to_flag(i) & f) {
      if (c) {
	printf(", ");
      }
      printf("%s", rt->flag[i]);
      c++;
    }
  }
  printf("\n");
}

void attr_flags_json_print_labels(const struct radix_trie *rt, attr_flags f, char *prefix, FILE *file) {
  unsigned int i, c=0;

  if (f == 0) {
    return;    /* print nothing */
  }
  fprintf(file, "\t\t\t\"%s\": [ ", prefix);
  for (i=0; i < rt->num_flags; i++) {
    if (index_to_flag(i) & f) {
      if (c) {
	fprintf(file, ", ");
      }
      fprintf(file, "\"%s\" ", rt->flag[i]);
      c++;
    }
  }
  fprintf(file, "],\n");
}

enum status radix_trie_init(struct radix_trie *rt) {
  rt->root = radix_trie_node_init();
  rt->num_flags = 0;
  memset(rt->flag, 0, sizeof(rt->flag));
  return ok;
}


enum status radix_trie_add_subnet_from_string(struct radix_trie *rt, char *addr, attr_flags attr, FILE *loginfo) {
  int i, masklen = 0;
  char *mask = NULL;
  struct in_addr a;

  debug_printf("adding subnet %s\n", addr);
  for (i=0; i<80; i++) {
    if (addr[i] == '/') {
      mask = addr + i + 1;
      addr[i] = 0;
      break;
    }
    if (addr[i] == '\n') {
      addr[i] = 0;
      break;
    }
  }
  debug_printf("address: %s\n", addr);
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
      fprintf(loginfo, "error: cannot parse subnet; netmask is %d bits\n", masklen);
      return failure;
    }
    debug_printf("masklen: %d\n", masklen);
        
  } else {
    masklen = 32;   /* no netmask, so match entire address */
  }
  
  inet_aton(addr, &a);
  a.s_addr = addr_mask(a.s_addr, masklen);
		 
  return radix_trie_add_subnet(rt, a, masklen, attr);
  // return failure;
}


enum status radix_trie_add_subnets_from_file(struct radix_trie *rt,
					     const char *pathname, 
					     attr_flags attr,
					     FILE *logfile) {
  enum status s = ok;
  FILE *fp;
  size_t len;
  char *line = NULL;

  if (logfile == NULL) {
    logfile = stderr;
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
	if (radix_trie_add_subnet_from_string(rt, addr, attr, logfile) != ok) {
	  fprintf(logfile, "error: could not add subnet %s to radix_trie\n", line);
	  return failure;
	}
      }
    }
      
    free(line);
    
    fclose(fp);
  } 

  return s;
}


/* debugging/unit test functions start here  */

struct in_addr hex2addr(unsigned int x) {
  struct in_addr a;
  a.s_addr = htonl(x);
  return a;
}

#include <string.h>

void radix_trie_node_print(const struct radix_trie *r, 
			   const struct radix_trie_node *rt, char *string) {
  unsigned int i;
  char tmp[256], *ptr;
  strcpy(tmp, string);
  ptr = index(tmp, 0);
  *ptr++ = ' ';
  *ptr++ = ' ';
  *ptr++ = ' ';
  *ptr = 0;
  
  if (rt == NULL) {
    return;
  }
  switch(rt->type) {
  case leaf:
    //    printf("%s flags: %x\n", string, ((struct radix_trie_leaf *)rt)->value);
    printf("%s flags: ", string);
    attr_flags_print_labels(r, ((struct radix_trie_leaf *)rt)->value);
    break;
  case internal:
    for (i=0; i<256; i++) {    
      if (rt->table[i] != NULL) {
	printf("%s [%x]\n", string, i);
	radix_trie_node_print(r, rt->table[i], tmp);
      }
    }
    break;
  default:
    ;
  }
  return; 
}

void radix_trie_print(const struct radix_trie *rt) {
  radix_trie_node_print(rt, rt->root, "");
}

int radix_trie_high_level_unit_test() {
  struct radix_trie rt;
  attr_flags flag_internal, flag_malware, flag;
  char *configfile = "internal.net";
  struct in_addr addr;
  enum status err;
  unsigned test_failed = 0;
  
  /* initialize */
  err = radix_trie_init(&rt);
  if (err != ok) {
   fprintf(stderr, "error: could not initialize radix_trie\n");
  }

  /* create a label */
  flag_internal = radix_trie_add_attr_label(&rt, "internal");
  if (flag_internal == 0) {
    fprintf(stderr, "error: count not add label\n");
    test_failed = 1;
    return failure;
  }
  flag_malware = radix_trie_add_attr_label(&rt, "malware");
  if (flag_internal == 0) {
    fprintf(stderr, "error: count not add label\n");
    test_failed = 1;
    return failure;
  }

  /* add subnets from file */
  err = radix_trie_add_subnets_from_file(&rt, configfile, flag_internal, stderr);
  if (err != ok) {
    fprintf(stderr, "error: could not add subnets to radix_trie from file %s\n", configfile);
    test_failed = 1;
  }  
  printf("++++++++++++\n");
  err = radix_trie_add_subnets_from_file(&rt, configfile, flag_malware, stderr);
  if (err != ok) {
    fprintf(stderr, "error: could not add subnets to radix_trie from file %s\n", configfile);
    test_failed = 1;
  }
  
  /* verify addresses and labels */
  addr.s_addr = htonl(0xc0a80101);   /* 192.168.1.1 */
  flag = radix_trie_lookup_addr(&rt, addr); 
  if ((flag & flag_internal) == 0) {
    fprintf(stdout, "error: attribute lookup failed (expected %x, got %x)\n",
	    flag_internal, flag);
    test_failed = 1;
  }
  attr_flags_json_print_labels(&rt, flag, "addr", stdout);
  
  addr.s_addr = htonl(0x08080808);   /* not internal */
  flag = radix_trie_lookup_addr(&rt, addr); 
  if ((flag & flag_internal) == 1) {
    fprintf(stdout, "error: attribute lookup failed (did not expect %x, but got %x)\n",
	    flag_internal, flag);
    test_failed = 1;
  }
  attr_flags_json_print_labels(&rt, flag, "addr", stdout);

  printf("\n==================\n");
  radix_trie_print(&rt);
  
  if (test_failed) {
    printf("FAILURE; at least one test failed\n");
  } else {
    printf("all tests passed\n");
  }
  
  return test_failed; /* 0 on success, 1 otherwise */
}

int radix_trie_unit_test() {
  struct radix_trie rt, rt2;
  enum status err;
  struct in_addr a[10];
  unsigned int af[10];
  unsigned int i;
  unsigned int test_failed = 0;
  unsigned int flag;
  
  for (i=0; i<32; i++) {
    flag = index_to_flag(i);
    printf("index: %u\tflag: %x\tindex: %u\n", i, flag, flag_to_index(flag));
  }

  err = radix_trie_init(&rt);
  if (err != ok) {
   fprintf(stderr, "error: could not initialize radix_trie\n");
  }
  
  a[0].s_addr = htonl(0xcafebabe); af[0] = 1;
  a[1].s_addr = htonl(0xcafedada); af[1] = 2;
  a[2].s_addr = htonl(0xbaddecaf); af[2] = 4;
  a[3].s_addr = htonl(0x01234567); af[3] = 8;
  a[4].s_addr = htonl(0xffeeddcc); af[4] = 16;
  a[5].s_addr = htonl(0x0a9b8c7d); af[5] = 32;
  a[6].s_addr = htonl(0xfedcba98); af[6] = 64;
  a[7].s_addr = htonl(0x76543210); af[7] = 128;
  a[8].s_addr = htonl(0xa1b2c3d4); af[8] = 256;

  printf("testing add\n");
  flag = 1;
  for (i=0; i<3; i++) {
    if (radix_trie_add_subnet(&rt, a[i], 32, af[i]) != ok) {
      fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }

  for (i=6; i<9; i++) {
    if (radix_trie_add_subnet(&rt, a[i], 16, af[i]) != ok) {
      fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }

  printf("testing lookup (expecting success)\n");
  for (i=0; i<3; i++) {
    if (radix_trie_lookup_addr(&rt, a[i]) != af[i]) {
      fprintf(stdout, "error: could not lookup subnet %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }
  for (i=6; i<9; i++) {
    if (radix_trie_lookup_addr(&rt, a[i]) != af[i]) {
      fprintf(stdout, "error: could not lookup subnet %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }

  printf("testing lookup (expecting failure)\n");
  for (i=3; i<6; i++) {
    if (radix_trie_lookup_addr(&rt, a[i]) != 0) {
      fprintf(stdout, "error: false positive lookup subnet %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }

  printf("testing 14-bit add\n");
  for (i=0; i<3; i++) {
    if (radix_trie_add_subnet(&rt, a[i], 14, 0x100) != ok) {
      fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }

  printf("testing 14-bit lookup (expecting success)\n");
  for (i=0; i<3; i++) {
    unsigned int f = radix_trie_lookup_addr(&rt, a[i]);
    if (f != (af[i] | 0x100)) {
      fprintf(stdout, "error: could not lookup address %s (%x), got %x instead\n", 
	      inet_ntoa(a[i]), htonl(a[i].s_addr), f);
      test_failed = 1;
    }
  }

  printf("testing 15-bit add\n");
  for (i=0; i<3; i++) {
    if (radix_trie_add_subnet(&rt, a[i], 15, 0x1000) != ok) {
      fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }

  printf("testing 15-bit lookup (expecting success)\n");
  for (i=0; i<3; i++) {
    unsigned int f = radix_trie_lookup_addr(&rt, a[i]);
    if (f != (af[i] | 0x1000 | 0x100)) {
      fprintf(stdout, "error: could not lookup address %s (%x), got %x but expected %x\n", 
	      inet_ntoa(a[i]), htonl(a[i].s_addr), f, (af[i] | 0x1000 | 0x100));
      test_failed = 1;
    }
  }

  printf("testing lookup (expecting failure)\n");
  for (i=3; i<6; i++) {
    if (radix_trie_lookup_addr(&rt, a[i]) != 0) {
      fprintf(stdout, "error: false positive lookup address %s\n", inet_ntoa(a[i]));
      test_failed = 1;
    }
  }

  if (test_failed) {
    printf("FAILURE; at least one test failed\n");
  } else {
    printf("all tests passed\n");
  }
  
  printf("-----------------------------------\n");
  radix_trie_print(&rt);

  printf("testing high level interface\n");
  err = radix_trie_init(&rt2);
  if (err != ok) {
    fprintf(stderr, "error: could not initialize radix_trie\n");
  }

  attr_flags internal_attr, c2_attr, watchlist_attr, attr;
  struct in_addr addr;

  internal_attr = radix_trie_add_attr_label(&rt2, "internal");
  printf("attr: %x\n", internal_attr);
  c2_attr = radix_trie_add_attr_label(&rt2, "c2");
  watchlist_attr = radix_trie_add_attr_label(&rt2, "watchlist");

  addr = hex2addr(0xcafe0000);
  if (radix_trie_add_subnet(&rt2, addr, 16, internal_attr) != ok) { 
    fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(addr));
    test_failed = 1;
  }
  attr = radix_trie_lookup_addr(&rt2, addr); 
  if ((attr & internal_attr) == 0) {
    fprintf(stdout, "error: attribute lookup failed (expected %x, got %x)\n",
	    internal_attr, attr);
    test_failed = 1;
  }
  addr = hex2addr(0xdecaf000);
  if (radix_trie_add_subnet(&rt2, addr, 20, internal_attr) != ok) {
    fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(addr));
    test_failed = 1;
  }
  attr = radix_trie_lookup_addr(&rt2, addr); 
  if ((attr & internal_attr) == 0) {
    fprintf(stdout, "error: attribute lookup failed (expected %x, got %x)\n",
	    internal_attr, attr);
    test_failed = 1;
  }
  addr = hex2addr(0xdadacafe);
  if (radix_trie_add_subnet(&rt2, addr, 32, c2_attr) != ok) {
    fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(addr));
    test_failed = 1;
  }
  attr = radix_trie_lookup_addr(&rt2, addr); 
  if ((attr & c2_attr) == 0) {
    fprintf(stdout, "error: attribute lookup failed (expected %x, got %x)\n",
	    c2_attr, attr);
    test_failed = 1;
  }
  addr = hex2addr(0xdadacafe);
  if (radix_trie_add_subnet(&rt2, addr, 8, watchlist_attr) != ok) {
    fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(addr));
    test_failed = 1;
  }
  attr = radix_trie_lookup_addr(&rt2, addr); 
  if ((attr & watchlist_attr) == 0) {
    fprintf(stdout, "error: attribute lookup failed (expected %x, got %x)\n",
	    watchlist_attr, attr);
    test_failed = 1;
  }
 
  addr = hex2addr(0xffffffff);
  if (radix_trie_add_subnet(&rt2, addr, 1, watchlist_attr) != ok) {
    fprintf(stdout, "error: could not add subnet %s\n", inet_ntoa(addr));
    test_failed = 1;
  }
  attr = radix_trie_lookup_addr(&rt2, addr); 
  if ((attr & watchlist_attr) == 0) {
    fprintf(stdout, "error: attribute lookup failed (expected %x, got %x)\n",
	    c2_attr, attr);
    test_failed = 1;
  }
   
  if (test_failed) {
    printf("FAILURE; at least one test failed\n");
  } else {
    printf("all high level interface tests passed\n");
  }

  printf("-----------------------------------\n");
  radix_trie_print(&rt2);

  printf("-----------------------------------\n");

  if (radix_trie_high_level_unit_test() != ok) {
    test_failed = 1;
  }

  return test_failed; /* 0 on success, 1 otherwise */
}


/* END radix_trie.c */
