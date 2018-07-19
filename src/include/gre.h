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
 * \file gre.h
 *
 * \brief Generic Routing Encapsulation (header)
 */

#ifndef JOY_GRE_H
#define JOY_GRE_H

#ifdef WIN32
# include "ws2tcpip.h"
#else
# include <netinet/in.h>
#endif

#include <stdint.h>

#define GRE_TYPE_IP 0x0800 /* decimal 2048 */

#define GRE_MAX 64

#define GRE_KEY_BIT(field) field & (1 << 2)
#define GRE_SEQ_BIT(field) field & (1 << 3)

/**
 * \brief Holds a single instance of GRE information.
 */
typedef struct gre_info {
    uint16_t flags_and_ver;
    uint16_t protocol_type;
    uint32_t sequence; /* Optional Sequence (RFC2890) */
} gre_info_T;

/**
 * \brief GRE structure
 */
typedef struct gre {
    struct in_addr sa; /* Outer IP source address */
    struct in_addr da; /* Outer IP destination address */
    uint32_t key; /* Optional Key (RFC2890) */
    struct gre_info info[GRE_MAX];
    uint16_t count; /* Number of "info" */
} gre_T;

#endif /* JOY_GRE_H */

