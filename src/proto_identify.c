/*
 *
 * Copyright (c) 2018 Cisco Systems, Inc.
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
 * \file proto_identify.c
 *
 * \brief Protocol identification (source)
 *
 */

#include <stdlib.h>
#include <string.h>

#include "proto_identify.h"
#include "err.h"


/* Values indicating direction of the flow */
#define DIR_UNKNOWN 0
#define DIR_CLIENT 1
#define DIR_SERVER 2

struct pi_container {
    uint8_t dir; /* Flow direction */
    uint16_t app; /* Application protocol prediction */
};

#define MAX_CHILDREN 257 /**< Full range of 1 byte, plus an extra slot for "wildcard" */

struct keyword_dict_node {
    uint16_t edge[MAX_CHILDREN]; /**< 16bit value, so that it can hold "wildcard"
                                      in addition to full-range of single byte (0-255) */
    struct keyword_dict_node *children; /* Pointer to first child */
    struct keyword_dict_node *sibling; /* Pointer to next sibling */
    uint16_t num_children; /* Number of children under this node */
    struct pi_container pi;
};


static struct keyword_dict_node *alloc_kdn(void) {

    return calloc(1, sizeof(struct keyword_dict_node));
}

static void destroy_kdn(struct keyword_dict_node *node) {

    struct keyword_dict_node *child = NULL;
    struct keyword_dict_node *sibling = NULL;

    if (node == NULL) {
        return;
    }

    if (node->children == NULL || node->num_children == 0) {
        free(node);
        return;
    }

    /* The first child */
    child = node->children;

    while (child != NULL) {
        /* Get the next child node before deleting this one */
        sibling = child->sibling;

        /* Recurse */
        destroy_kdn(child);

        /* Tee up the next one */
        child = sibling;
    }

    /* Now delete the parent */
    free(node);
    return;
}

#if 0
static struct keyword_dict_node *kdn_append_child(struct keyword_dict_node *node,
                                                  uint16_t edge) {
    struct keyword_dict_node *new_child = NULL;

    if (node == NULL) {
        return NULL;
    }

    if (node->children) {
        /*
         * This node already has at least one child.
         * We need to create a sibling instead :)
         */
        struct keyword_dict_node *child = NULL;

        if (node->num_children == (MAX_CHILDREN - 1)) {
            joy_log_err("already at MAX_CHILDREN(%d)", MAX_CHILDREN);
            return NULL;
        }

        child = node->children;
        while (child->sibling) {
            /* Get the sibling node if it exists */
            child = child->sibling;
        }

        /*
         * We now have the "last" child.
         * Create a sibling for them.
         */
        child->sibling = alloc_kdn();
        new_child = child->sibling;
    } else {
        /* The first one! */
        node->children = alloc_kdn();
        new_child = node->children;
    }

    /* Set the edge value corresponding to this child */
    node->edge[node->num_children] = edge;

    /* Increment household count */
    node->num_children++;

    return new_child;
}
#endif

static struct keyword_dict_node *kdn_create_child(struct keyword_dict_node *node,
                                                  uint16_t edge) {
    if (node == NULL) {
        return NULL;
    }

    if (node->children || (node->num_children != 0)) {
        joy_log_err("child already exists");
        return NULL;
    }

    node->children = alloc_kdn();

    /* Set the edge value corresponding to this child */
    node->edge[node->num_children] = edge;

    /* Increment household count */
    node->num_children++;

    return node->children;
}

static struct keyword_dict_node *kdn_create_sibling(struct keyword_dict_node *parent,
                                                    struct keyword_dict_node *child,
                                                    uint16_t edge) {
    if (parent == NULL || child == NULL) {
        return NULL;
    }

    if (child->sibling != NULL) {
        joy_log_err("child already has a sibling");
    }

    if (parent->num_children == (MAX_CHILDREN - 1)) {
        joy_log_err("already at MAX_CHILDREN(%d)", MAX_CHILDREN);
        return NULL;
    }

    /* The first one! */
    child->sibling = alloc_kdn();

    /* Set the edge value corresponding to this child */
    parent->edge[parent->num_children] = edge;

    /* Increment household count */
    parent->num_children++;

    return child->sibling;
}

static int keyword_dict_add_string(struct keyword_dict_node *root,
                                   const uint16_t *str,
                                   unsigned int str_len) {
    struct keyword_dict_node *node = NULL;
    int i = 0;

    if (root == NULL) {
        return 0;
    }

    if (str == NULL || str_len == 0) {
        return 0;
    }

    /* The root node of the tree */
    node = root;

    for (i = 0; i < str_len; i++) {
        /* Grab the next value of string for comparison */
        uint16_t val = *(str + i);

        if (node->children) {
            struct keyword_dict_node *child = node->children;
            int match = 0;
            int k = 0;

            while (k < node->num_children) {
                /*
                 * Compare this character to all the children edges
                 */
                if (val == node->edge[k]) {
                    /* Matches the edge to this child */
                    match = 1;
                    break;
                }

                /* Point to the next child */
                child = child->sibling;
            }

            if (match) {
                node = child;
            } else {
                /* Make a new sibling node/edge */
                node = kdn_create_sibling(node, child, val);
            }
        } else {
            /*
             * No existing children.
             * Make a new child node/edge.
             */
            node = kdn_create_child(node, val);
        }
    }

    return 0;
}

#define WILDCARD 0x100

static struct keyword_dict_node *construct_keyword_dict(void) {
    struct keyword_dict_node *root = NULL;
    const uint16_t str[] = {0x16, 0x03, 0x01, WILDCARD, WILDCARD};
    unsigned int str_len = sizeof(str) / sizeof(uint16_t);
    int ret = 0;

    root = alloc_kdn();

    /* TODO loop through adding all strings */
    ret = keyword_dict_add_string(root, str, str_len);
    if (ret != 0) {
        joy_log_err("couldn't add string");
    }

    return root;
}

struct keyword_dict_node *kd_root = NULL;

int proto_identify_init_keyword_dict(void) {
    if (kd_root != NULL) {
        return 1;
    }

    kd_root = construct_keyword_dict();

    return 0;
}

void proto_identify_destroy_keyword_dict(void) {
    if (kd_root == NULL) {
        return;
    }

    destroy_kdn(kd_root);
}

uint16_t identify_tcp_protocol(const char *tcp_data, unsigned int len) {

    if (len == 0) {
        return 0;
    }

    if (kd_root == NULL) {
        kd_root = construct_keyword_dict();
    }

    return 0;
}

