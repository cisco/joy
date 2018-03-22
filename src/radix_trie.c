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
 * \file radix_trie.c
 *
 * \brief a radix trie implementation for efficient matching of addresses
 * against one or more subnets
 *
 ** A radix_trie contains two types of nodes: internal and leaf.  An
 * internal node contains a 256-entry table that indicates how
 * branching is done based on the digit of the current level of the
 * tree.  That is, table[key[i]] is the pointer to the next node where
 * i is the level and key[i] is the ith digit of the key.
 * 
 ** A leaf (terminal) node contains a flags value, which is a bitmask
 * that indicates the set of labels associated with the key value.
 *
 ** Example 1: start with an empty trie, and set flag(0xcafebabe) = 1;
 ** then the following nodes will be created:
 *
 **    level 0: table[0xca] = next node
 *
 **    level 1: table[0xfe] = next node
 *
 **    level 2: table[0xba] = next node
 *
 **    level 3: table[0xbe] = next node
 *
 **    level 4: leaf.value = 1
 *
 **  Example 2: after Example 1, set flag(0xcafe) = 2; then the
 ** following nodes will be in the tree:
 *
 **    level 0: table[0xca] = next node; all other table entries NULL
 *
 **    level 1: table[0xfe] = next node; all other table entries NULL
 *
 **    level 2: table[0xba] = next node; all other entries leaf.value = 2
 *
 **    level 3: table[0xbe] = next node
 *
 **    level 4: leaf.value = 1 & 2
 *    
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "radix_trie.h"
#include "addr.h"
#include "output.h"
#include "updater.h"

#ifdef WIN32
#include "Ws2tcpip.h"

size_t getline(char **lineptr, size_t *n, FILE *stream);

#endif

/** maximum label string length */
#define MAX_LABEL_LEN 256

/** reutrn maximum between two values */
#define MAX(x,y) (x > y ? x : y)

/** values for node types */
enum radix_trie_node_type {
    reserved = 0,
    internal = 1,
    leaf = 2
};

/** node definition for radix trie */
struct radix_trie_node {
    enum radix_trie_node_type type;    /** internal */
    struct radix_trie_node *table[256];
};

/** leaf node definition for radix trie */
struct radix_trie_leaf {
    enum radix_trie_node_type type;   /** leaf */
    attr_flags value;
};

/** main radix trie structure definition */
struct radix_trie {
    struct radix_trie_node *root;
    unsigned int num_flags;
    char *flag[MAX_NUM_FLAGS];
};

/** hex to address structure used in testing/debugging functions */
static struct in_addr hex2addr (unsigned int x) {
    struct in_addr a;
    a.s_addr = htonl(x);
    return a;
}

/** mutex used to ensure the radix_trie isn't being accessed by another thread */
pthread_mutex_t radix_trie_lock = PTHREAD_MUTEX_INITIALIZER;

/* 
 * radix trie memory allocation function
 * returns pointer to memory allocated
 * returns NULL on failure
 */
static __inline void *rt_malloc (size_t s) {
    void *p = NULL;
    p = malloc(s);
    if (p != NULL) {
        debug_printf("rt_malloc[0x%x] of %zu bytes\n", (unsigned int)p, s);
    }
    return (p);
}

/* 
 * radix trie memory free function
 *     sets pointer p to NULL after free
 */
static __inline void rt_free (void *p) {
    if (p != NULL) {
        debug_printf("rt_free[0x%x]\n", (unsigned int)p);
        free(p);
    }
    p = NULL;
}

/**
 * \fn struct radix_trie *radix_trie_alloc()
 * \params none
 * \return pointer to radix_trie structure
 */
struct radix_trie *radix_trie_alloc () {
    return rt_malloc(sizeof(struct radix_trie));
}

/*
 * main entry for allocating a new radix trie node and initializing
 * returns radix_trie_node pointer
 * returns NULL on failure
 */
static struct radix_trie_node *radix_trie_node_init () {
    struct radix_trie_node *rt_node = NULL;
  
    rt_node = rt_malloc(sizeof(struct radix_trie_node));
    if (rt_node != NULL) {
        rt_node->type = internal;

        /* initialize table entries to NULL */
        memset(rt_node->table, 0, sizeof(rt_node->table));
    }

    return rt_node;  /* could be NULL */
}

/*
 * main entry for allocating a new radix trie leaf node and initializing
 * returns radix_trie_leaf pointer
 * returns NULL on failure
 */
static struct radix_trie_leaf *radix_trie_leaf_init (attr_flags value) {
    struct radix_trie_leaf *rt_leaf = NULL;
  
    rt_leaf = rt_malloc(sizeof(struct radix_trie_leaf));
    if (rt_leaf != NULL) {
        rt_leaf->type = leaf;
        rt_leaf->value = value;
    }

    return rt_leaf;   /* could be NULL */
}

/**
 * \fn attr_flags radix_trie_lookup_addr (struct radix_trie *trie, struct in_addr addr)
 * \param trie radix_trie pointer
 * \param addr address to lookup in the radix_trie
 * \return flags of the node found
 */
attr_flags radix_trie_lookup_addr (struct radix_trie *trie, struct in_addr addr) {
    unsigned int i = 0;
    attr_flags rc_flags = 0;
    unsigned char *a = (void *) &addr.s_addr;
    struct radix_trie_node *rt = trie->root;
  
    /* get the mutex to avoid potential threading issues */
    pthread_mutex_lock(&radix_trie_lock);

    /* sanity check */
    if (rt == NULL) {
        debug_printf("%s:radix_trie is NULL\n", __FUNCTION__);
        pthread_mutex_unlock(&radix_trie_lock);
        return failure;
    }

    for (i=0; i<4; i++) {
        debug_printf("%s:a[%d]: %x\n", __FUNCTION__, i, a[i]); 
        rt = rt->table[a[i]];
        if (rt == NULL) {
            pthread_mutex_unlock(&radix_trie_lock);
            return 0;  /* indicate that no match occured */
        } 
        if (rt->type == leaf) {
            break;
        }
    }  
    if (rt->type == leaf) {
        struct radix_trie_leaf *leaf = (struct radix_trie_leaf *)rt;
        debug_printf("%s:found leaf (value: %x)\n", __FUNCTION__, leaf->value);
        rc_flags = leaf->value;
        pthread_mutex_unlock(&radix_trie_lock);
        return rc_flags; /* indicate success by returning flags  */
    }

    pthread_mutex_unlock(&radix_trie_lock);
    return 0;  /* indicate that no match occured */
}

/*
 * fucntion add flags to all leaf nodes 
 */
static void radix_trie_node_add_flag_to_all_leaves (const struct radix_trie_node *rt, attr_flags flags) {
    unsigned int i = 0;
  
    /* sanity check */
    if (rt == NULL) {
        debug_printf("%s:radix trie node is NULL\n", __FUNCTION__);
        return;
    }

    switch(rt->type) {
        case leaf:
            ((struct radix_trie_leaf *)rt)->value |= flags;
            debug_printf("%s:adding flag %x to leaf (current value: %x)\n", __FUNCTION__,
                        flags, ((struct radix_trie_leaf *)rt)->value);
            break;
        case internal:
            /* look through the table of this node */
            for (i=0; i<256; i++) {    
                debug_printf("%s:adding flags %x to leaves at %x\n", __FUNCTION__, flags, i);
                radix_trie_node_add_flag_to_all_leaves(rt->table[i], flags);
            }
            break;
        default:
            break;
    }
    return;
}

/**
 * \fn enum status radix_trie_add_subnet (struct radix_trie *trie, struct in_addr addr, unsigned int netmasklen, attr_flags flags)
 * \param trie radix_trie to use for the addition
 * \param addr address to add into the trie
 * \param netmasklen network mask length of the address to add
 * \param flags flags that are to be assigned to node when added to the trie
 * \return success
 * \return failure
 */
enum status radix_trie_add_subnet (struct radix_trie *trie, struct in_addr addr, unsigned int netmasklen, attr_flags flags) {
    unsigned int i, x, bits, bytes, max, num_internal_nodes = 0;
    unsigned char *a = (void *) &addr.s_addr;
    struct radix_trie_node *tmp = NULL;
    struct radix_trie_node *rt = trie->root;

    /* sanity checks */
    if (!trie || (netmasklen > 32)) {
        debug_printf("%s:sanity checks failed\n", __FUNCTION__);
        return failure;   /* no null pointers or giant netmasks allowed */
    }
    if (!flags) {
        debug_printf("%s:flags present are 0, flags must be nonzero\n", __FUNCTION__);
        return failure;   /* flags must be nonzero; 0 value indicates the absence of flags */
    }
  
    /* get mutex for radix trie operations */
    pthread_mutex_lock(&radix_trie_lock);

    bytes = netmasklen / 8;
    bits = netmasklen - (bytes * 8);
    //num_internal_nodes = MAX(bytes-1,1);
    num_internal_nodes = (netmasklen-1)/8;
    max = 1 << (8-bits);

    debug_printf("%s:add\tflags: %x\tnetmask: %u\tbytes: %u\tbits: %u\tloops: %u\tmax: %u\n",
                __FUNCTION__, flags, netmasklen, bytes, bits, num_internal_nodes, max);

    /* loop over bytes, creating internal nodes where needed */
    for (i=0; i < num_internal_nodes; i++) {
        debug_printf("%s:I: a[%d]: %x\n", __FUNCTION__, i, a[i]); 
        tmp = rt->table[a[i]];
        if (tmp == NULL) {
            tmp = radix_trie_node_init();
            if (tmp == NULL) {
	              	return failure;
            }
            rt->table[a[i]] = tmp;
        }
        if (tmp->type == leaf) {
            debug_printf("%s:warning: found a leaf during creation\n", __FUNCTION__);
            break;
        }
        rt = tmp;
    }  

    /* create leaf node(s) */
    if (bits == 0) {
        debug_printf("%s:L: a[%d]: %x\n", __FUNCTION__, i, a[i]); 

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
            debug_printf("%s:L: a[%u]: %x\n", __FUNCTION__, i, prefix|x); 

            /* if table entry exists, then add flag into all leaves */
            if (rt->table[prefix|x] != NULL) {
                radix_trie_node_add_flag_to_all_leaves(rt->table[prefix|x], flags);
            } else { 
		              tmp = (struct radix_trie_node *)radix_trie_leaf_init(flags);
		              if (tmp == NULL) {
                    pthread_mutex_unlock(&radix_trie_lock);
		                  return failure;
		              }
		              rt->table[prefix|x] = tmp;
            }
        } 
    }
    pthread_mutex_unlock(&radix_trie_lock);
    return ok;
}

/*
 * convert an index into a flag
 * returns flag
 */ 
static unsigned int index_to_flag (unsigned int x) {
    unsigned int flag = 0;

    /* sanity check */
    if (x > MAX_NUM_FLAGS) {
        return 0;  /* failure; not that many flags */
    }

    flag = 1;
    flag = flag << x;
    return flag;
}

/*
 * converts a flag into an index
 * returns index
 */
static unsigned int flag_to_index (unsigned int y) {
    unsigned int i = 0;
  
    while (y > 0) {
        y = y >> 1;
        i++;
    }
    return i-1;
}

/**
 * \fn attr_flags radix_trie_add_attr_label (struct radix_trie *rt, const char *attr_label) 
 * \brief  function to add a label to the radix trie
 *
 * adds a labeled flag with the name "label" to a radix_trie, and returns the attribute flag
 * corresponding to that label if successful.  If unsuccessful, zero  is returned.
 *
 * \param rt radix_trie pointer
 * \param attr_label pointer to the label to be added
 * \return flags added
 */
attr_flags radix_trie_add_attr_label (struct radix_trie *rt, const char *attr_label) {
    unsigned int rc_flag = 0;
  
    /* sanity check */
    if (!attr_label) {
        return 0;     /* NULL is an error */
    }

    /* ensure label will fit into the trie */
    if (strlen(attr_label) > MAX_LABEL_LEN-1) { 
        return 0;     /* not enough room for label and null terminator */
    }

    /* make sure we room left for labels */
    if (rt->num_flags >= MAX_NUM_FLAGS-1) {
        return 0;     /* this trie already has too many labels */
    }

    /* add label by allocating string corresponding to flag */
    if ((rt->flag[rt->num_flags] = strdup(attr_label)) == NULL) {
        return 0;     /* failure */
    }
  
    pthread_mutex_lock(&radix_trie_lock);
    rc_flag = index_to_flag(rt->num_flags++);
    pthread_mutex_unlock(&radix_trie_lock);

    return rc_flag;
}

/*
 * function to print out the labels in a trie
 */
static void attr_flags_print_labels (const struct radix_trie *rt, attr_flags f) {
    unsigned int i, c = 0;

    pthread_mutex_lock(&radix_trie_lock);
    for (i=0; i < rt->num_flags; i++) {
        if (index_to_flag(i) & f) {
            if (c) {
		              printf(", ");
            }
            printf("%s", rt->flag[i]);
            c++;
        }
    }
    pthread_mutex_unlock(&radix_trie_lock);
    printf("\n");
}

/**
 * \fn void attr_flags_json_print_labels (const struct radix_trie *rt, attr_flags f, char *prefix, zfile file)
 * \param rt radix_trie pointer
 * \param f attribute flags
 * \param prefix prefix to use for JSON output
 * \param zfile file pointer of where to send output
 * \return none
 */
void attr_flags_json_print_labels (const struct radix_trie *rt, attr_flags f, char *prefix, zfile file) {
    unsigned int i, c = 0;

    /* sanity check */
    if (f == 0) {
        return;    /* print nothing */
    }

    pthread_mutex_lock(&radix_trie_lock);
    zprintf(file, "\"%s\": [ ", prefix);
    for (i=0; i < rt->num_flags; i++) {
        if (index_to_flag(i) & f) {
            if (c) {
	               zprintf(file, ", ");
            }
            zprintf(file, "\"%s\" ", rt->flag[i]);
            c++;
        }
    }
    pthread_mutex_unlock(&radix_trie_lock);
    zprintf(file, "],");
}

/**
 * \fn enum status radix_trie_init (struct radix_trie *rt)
 * \param rt radix_trie pointer to initialize
 * \return ok
 * \return failure
 */
enum status radix_trie_init (struct radix_trie *rt) {
    pthread_mutex_lock(&radix_trie_lock);
    if (rt != NULL) {
        rt->root = radix_trie_node_init();
        rt->num_flags = 0;
        memset(rt->flag, 0, sizeof(rt->flag));
        pthread_mutex_unlock(&radix_trie_lock);
        return ok;
    } else {
        pthread_mutex_unlock(&radix_trie_lock);
        return failure;
    }
}

/*
 * Function to free up the memory for leaf and internal nodes
 * returns ok
 */
static enum status radix_trie_deep_free (const struct radix_trie_node *rt) {
    int i = 0;

    switch (rt->type) {
        case leaf:
           /* found a leaf free up the memory */
           rt_free((void*)rt);
           break;
        case internal:
           /* follow deeper */
           for (i=0; i<256; i++) {
               if (rt->table[i] != NULL) {
                   radix_trie_deep_free(rt->table[i]);
               }
           }
           /* now free the internal node */
           rt_free((void*)rt);
           break;
        default:
           break;
    }
    return ok;
}

/**
 * \fn enum status radix_trie_free (struct radix_trie *r)
 * \param r radix_trie pointer to free up
 * \return ok
 */
enum status radix_trie_free (struct radix_trie *r) {
    int i = 0;

    /* sanity check the trie */
    if (r == NULL) {
        /* nothing to free */
        return ok;
    }

    if (r->num_flags) {
        /* Free any flags attached to the radix_trie */
        for (i = 0; i < r->num_flags; i++) {
            free(r->flag[i]);
        }
    }

    /* sanity check the root node */
    if (r->root == NULL) {
        /* no root node, just free radix_trie structure */
        rt_free(r);
        return ok;
    }

    /* perform deep free of radix_trie starting at the root */
    radix_trie_deep_free(r->root);

    /* now free the radix_trie structure */
    rt_free((void*)r);

    return ok;
}

/*
 * Function to add a subnet to a radix trie from a string
 * returns success
 * returns failure
 */
static enum status radix_trie_add_subnet_from_string (struct radix_trie *rt, char *addr, attr_flags attr, FILE *loginfo) {
    int i, masklen = 0;
    char *mask = NULL;
    struct in_addr a;

    debug_printf("%s:adding subnet %s\n", __FUNCTION__, addr);
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

    debug_printf("%s:address: %s\n", __FUNCTION__, addr);
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
            fprintf(loginfo, "%s: error: cannot parse subnet; netmask is %d bits\n",
                       __FUNCTION__, masklen);
            return failure;
        }
        debug_printf("%s:masklen: %d\n", __FUNCTION__,  masklen);
        
    } else {
        masklen = 32;   /* no netmask, so match entire address */
    }
  
#ifdef WIN32
	inet_pton(AF_INET,addr, &a);
#else
    inet_aton(addr, &a);
#endif
	a.s_addr = addr_mask(a.s_addr, masklen);
    return radix_trie_add_subnet(rt, a, masklen, attr);
}

/**
 * \fn enum status radix_trie_add_subnets_from_file (struct radix_trie *rt, const char *pathname, attr_flags attr, FILE *logfile)
 * \param rt radix_trie pointer
 * \param pathname path and filename of the subnets file to be added
 * \param attr flags to be associated with the subnets
 * \param logfile file pointer of the logging file for any errors to be sent
 * \return ok
 * \return failure
 */
enum status radix_trie_add_subnets_from_file (struct radix_trie *rt,
					     const char *pathname, attr_flags attr, FILE *logfile) {
    enum status s = ok;
    FILE *fp = NULL;
    size_t len = 0;
    char *line = NULL;

    /* assign logfile if not specified */
    if (logfile == NULL) {
      logfile = stderr;
    }

    fp = fopen(pathname, "r");
    if (fp == NULL) {
	       fprintf(logfile, "%s: error: could not open file '%s'\n",
                __FUNCTION__, pathname);
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
	                   fprintf(logfile, "%s: error: could not add subnet %s to radix_trie\n",
                            __FUNCTION__, line);
	                   return failure;
	               }
            }
        }
      
        free(line);
    
        fclose(fp);
    } 
    return s;
}

/*
 * function to print out the contents of a node
 */
static void radix_trie_node_print (const struct radix_trie *r, 
			   const struct radix_trie_node *rt, char *string) {
    unsigned int i = 0;
    char tmp[256];
    char *ptr = NULL;

    /* sanity checks */
    if ((r == NULL) || (rt == NULL) || (string == NULL)) {
        return;
    }

#if 0
	// Wow this code is totally unsafe
	strcpy(tmp, string);
    ptr = index(tmp, 0);
    *ptr++ = ' ';
    *ptr++ = ' ';
    *ptr++ = ' ';
    *ptr = 0;
#endif
	//safe copy of string into tmp buffer
	strncpy(tmp, string, 255);
	tmp[255] = 0; // make sure string is terminated
	//replacement for index function
	for (i = 0; i < 255; ++i) {
		//find first occurance of 0 in tmp
		if (tmp[i] == 0) {
			ptr = &tmp[i];
			break;
		}
	}
	//let's make sure we don't write past the end of the tmp buffer;
	if (i <= 252) {
		*ptr++ = ' ';
		*ptr++ = ' ';
		*ptr++ = ' ';
		*ptr = 0;
	}

    switch(rt->type) {
        case leaf:
            //printf("%s flags: %x\n", string, ((struct radix_trie_leaf *)rt)->value);
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
            break;
    }
    return; 
}

/*
 * Main entry point for print out a radix trie
 */
static void radix_trie_print (const struct radix_trie *rt) {
    radix_trie_node_print(rt, rt->root, "");
}

/*
 * Function to initiate the radix_trie unit tests
 * returns 0 on success
 * returns 1 on failure
 */
static int radix_trie_high_level_unit_test () {
    struct radix_trie *rt = NULL;
    attr_flags flag_internal, flag_malware, flag;
    char *configfile = "internal.net";
    struct in_addr addr;
    enum status err;
    unsigned test_failed = 0;

    /* initialize */
    rt = radix_trie_alloc();
    err = radix_trie_init(rt);
    if (err != ok) {
       joy_log_err("could not initialize radix_trie");
    }

    /* create a label */
    flag_internal = radix_trie_add_attr_label(rt, "internal");
    if (flag_internal == 0) {
        joy_log_err("count not add label");
        test_failed = 1;
        return failure;
    }
    flag_malware = radix_trie_add_attr_label(rt, "malware");
    if (flag_internal == 0) {
        joy_log_err("count not add label");
        test_failed = 1;
        return failure;
    }

    /* add subnets from file */
    err = radix_trie_add_subnets_from_file(rt, configfile, flag_internal, stderr);
    if (err != ok) {
        joy_log_err("could not add subnets to radix_trie from file %s", configfile);
        test_failed = 1;
    }  
    printf("++++++++++++\n");
    err = radix_trie_add_subnets_from_file(rt, configfile, flag_malware, stderr);
    if (err != ok) {
        joy_log_err("could not add subnets to radix_trie from file %s", configfile);
        test_failed = 1;
    }
  
    /* verify addresses and labels */
    addr.s_addr = htonl(0xc0a80101);   /* 192.168.1.1 */
    flag = radix_trie_lookup_addr(rt, addr); 
    if ((flag & flag_internal) == 0) {
        joy_log_err("attribute lookup failed (expected %x, got %x)", flag_internal, flag);
		test_failed = 1;
    }
  
    addr.s_addr = htonl(0x08080808);   /* not internal */
    flag = radix_trie_lookup_addr(rt, addr); 
    if ((flag & flag_internal) == 1) {
		joy_log_err("attribute lookup failed (did not expect %x, but got %x)", flag_internal, flag);
        test_failed = 1;
    }

    printf("\n==================\n");
    radix_trie_print(rt);

    radix_trie_free(rt);
  
    if (test_failed) {
        printf("FAILURE; at least one test failed\n");
    } else {
        printf("all tests passed\n");
    }
  
    return test_failed; /* 0 on success, 1 otherwise */
}

/** 
 * \fn int radix_trie_unit_test()
 * \params none
 * \return 0 on success
 * \return 1 on failure
 */
int radix_trie_unit_test () {
    struct radix_trie *rt, *rt2 = NULL;
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

    rt = radix_trie_alloc();
    err = radix_trie_init(rt);
    if (err != ok) {
       joy_log_err("could not initialize radix_trie");
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

    flag = 1;
    for (i=0; i<3; i++) {
        if (radix_trie_add_subnet(rt, a[i], 32, af[i]) != ok) {
			joy_log_err("could not add subnet %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    for (i=6; i<9; i++) {
        if (radix_trie_add_subnet(rt, a[i], 16, af[i]) != ok) {
            joy_log_err("could not add subnet %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    for (i=0; i<3; i++) {
        if (radix_trie_lookup_addr(rt, a[i]) != af[i]) {
            joy_log_err("could not lookup subnet %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    for (i=6; i<9; i++) {
        if (radix_trie_lookup_addr(rt, a[i]) != af[i]) {
            joy_log_err("could not lookup subnet %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    for (i=3; i<6; i++) {
        if (radix_trie_lookup_addr(rt, a[i]) != 0) {
            joy_log_err("false positive lookup subnet %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    for (i=0; i<3; i++) {
        if (radix_trie_add_subnet(rt, a[i], 14, 0x100) != ok) {
            joy_log_err("14-bit add, could not add subnet %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    for (i=0; i<3; i++) {
        unsigned int f = radix_trie_lookup_addr(rt, a[i]);
        if (f != (af[i] | 0x100)) {
            joy_log_err("14-bit, could not lookup address %s (%x), got %x instead", 
	                    inet_ntoa(a[i]), htonl(a[i].s_addr), f);
            test_failed = 1;
        }
    }

    printf("testing 15-bit add\n");
    for (i=0; i<3; i++) {
        if (radix_trie_add_subnet(rt, a[i], 15, 0x1000) != ok) {
            joy_log_err("15-bit, could not add subnet %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    for (i=0; i<3; i++) {
        unsigned int f = radix_trie_lookup_addr(rt, a[i]);
        if (f != (af[i] | 0x1000 | 0x100)) {
            joy_log_err("15-bit, could not lookup address %s (%x), got %x but expected %x", 
	                    inet_ntoa(a[i]), htonl(a[i].s_addr), f, (af[i] | 0x1000 | 0x100));
            test_failed = 1;
        }
    }

    for (i=3; i<6; i++) {
        if (radix_trie_lookup_addr(rt, a[i]) != 0) {
            joy_log_err("false positive lookup address %s", inet_ntoa(a[i]));
            test_failed = 1;
        }
    }

    if (test_failed) {
        printf("FAILURE; at least one test failed\n");
    } else {
        printf("all tests passed\n");
    }
  
    printf("-----------------------------------\n");
    radix_trie_print(rt);
    radix_trie_free(rt);

    printf("testing high level interface\n");
    rt2 = radix_trie_alloc();
    err = radix_trie_init(rt2);
    if (err != ok) {
        joy_log_err("could not initialize radix_trie");
    }

    attr_flags internal_attr, c2_attr, watchlist_attr, attr;
    struct in_addr addr;

    internal_attr = radix_trie_add_attr_label(rt2, "internal");
    printf("attr: %x\n", internal_attr);
    c2_attr = radix_trie_add_attr_label(rt2, "c2");
    watchlist_attr = radix_trie_add_attr_label(rt2, "watchlist");

    addr = hex2addr(0xcafe0000);
    if (radix_trie_add_subnet(rt2, addr, 16, internal_attr) != ok) { 
        joy_log_err("could not add subnet %s", inet_ntoa(addr));
        test_failed = 1;
    }
    attr = radix_trie_lookup_addr(rt2, addr); 
    if ((attr & internal_attr) == 0) {
        joy_log_err("attribute lookup failed (expected %x, got %x)",
	                internal_attr, attr);
        test_failed = 1;
    }

    addr = hex2addr(0xdecaf000);
    if (radix_trie_add_subnet(rt2, addr, 20, internal_attr) != ok) {
        joy_log_err("could not add subnet %s", inet_ntoa(addr));
        test_failed = 1;
    }
    attr = radix_trie_lookup_addr(rt2, addr); 
    if ((attr & internal_attr) == 0) {
        joy_log_err("attribute lookup failed (expected %x, got %x)",
	                internal_attr, attr);
        test_failed = 1;
    }

    addr = hex2addr(0xdadacafe);
    if (radix_trie_add_subnet(rt2, addr, 32, c2_attr) != ok) {
        joy_log_err("could not add subnet %s", inet_ntoa(addr));
        test_failed = 1;
    }
    attr = radix_trie_lookup_addr(rt2, addr); 
    if ((attr & c2_attr) == 0) {
        joy_log_err("attribute lookup failed (expected %x, got %x)",
	                c2_attr, attr);
        test_failed = 1;
    }

    addr = hex2addr(0xdadacafe);
    if (radix_trie_add_subnet(rt2, addr, 8, watchlist_attr) != ok) {
        joy_log_err("could not add subnet %s", inet_ntoa(addr));
        test_failed = 1;
    }
    attr = radix_trie_lookup_addr(rt2, addr); 
    if ((attr & watchlist_attr) == 0) {
        joy_log_err("attribute lookup failed (expected %x, got %x)",
	                watchlist_attr, attr);
        test_failed = 1;
    }
 
    addr = hex2addr(0xffffffff);
    if (radix_trie_add_subnet(rt2, addr, 1, watchlist_attr) != ok) {
        joy_log_err("could not add subnet %s", inet_ntoa(addr));
        test_failed = 1;
    }
    attr = radix_trie_lookup_addr(rt2, addr); 
    if ((attr & watchlist_attr) == 0) {
        joy_log_err("attribute lookup failed (expected %x, got %x)",
	                c2_attr, attr);
        test_failed = 1;
    }
   
    if (test_failed) {
        printf("FAILURE; at least one test failed\n");
    } else {
        printf("all high level interface tests passed\n");
    }

    printf("-----------------------------------\n");
    radix_trie_print(rt2);
    radix_trie_free(rt2);

    printf("-----------------------------------\n");

    if (radix_trie_high_level_unit_test() != ok) {
        test_failed = 1;
    }

    return test_failed; /* 0 on success, 1 otherwise */
}

/* END radix_trie.c */
