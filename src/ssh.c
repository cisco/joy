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
 * ssh.c
 *
 * Secure Shell (SSH) awareness for joy
 *
 */

#include <stdio.h>      /* for fprintf()           */
#include <ctype.h>      /* for isprint()           */
#include <stdint.h>     /* for uint32_t            */
#include <arpa/inet.h>  /* for ntohl()             */
#include <string.h>     /* for memset()            */
#include "ssh.h"     
#include "p2f.h"        /* for zprintf_ ...        */

void copy_printable_string(char *buf, 
			   unsigned int buflen, 
			   const void *data,
			   unsigned int datalen) {
    const char *d = data;

    while (buflen-- && datalen--) {
	if (!isprint(*d)) {
	    break;
	}
	*buf++ = *d++;
    }

    *buf = 0; /* null terminate buffer */
}


/*
 * from http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml
 */
enum ssh_msg_type {
    SSH_MSG_DISCONNECT 	            = 1, 	
    SSH_MSG_IGNORE 		    = 2, 	
    SSH_MSG_UNIMPLEMENTED 	    = 3, 	
    SSH_MSG_DEBUG 		    = 4, 	
    SSH_MSG_SERVICE_REQUEST 	    = 5, 	
    SSH_MSG_SERVICE_ACCEPT 	    = 6, 	
    SSH_MSG_KEXINIT 		    = 20, 	
    SSH_MSG_NEWKEYS 		    = 21, 	
    SSH_MSG_USERAUTH_REQUEST 	    = 50, 	
    SSH_MSG_USERAUTH_FAILURE 	    = 51, 	
    SSH_MSG_USERAUTH_SUCCESS 	    = 52, 	
    SSH_MSG_USERAUTH_BANNER 	    = 53, 	
    SSH_MSG_USERAUTH_INFO_REQUEST     = 60, 	
    SSH_MSG_USERAUTH_INFO_RESPONSE    = 61,	
    SSH_MSG_GLOBAL_REQUEST 	    = 80,	
    SSH_MSG_REQUEST_SUCCESS 	    = 81,	
    SSH_MSG_REQUEST_FAILURE 	    = 82,	
    SSH_MSG_CHANNEL_OPEN 		    = 90,	
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,		
    SSH_MSG_CHANNEL_OPEN_FAILURE 	    = 92,	
    SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93, 	
    SSH_MSG_CHANNEL_DATA 		    = 94,	
    SSH_MSG_CHANNEL_EXTENDED_DATA     = 95,	
    SSH_MSG_CHANNEL_EOF 		    = 96, 	
    SSH_MSG_CHANNEL_CLOSE 	    = 97, 	
    SSH_MSG_CHANNEL_REQUEST 	    = 98, 	
    SSH_MSG_CHANNEL_SUCCESS 	    = 99, 	
    SSH_MSG_CHANNEL_FAILURE 	    = 100
}; 	

/*
 * from RFC 4253:
 *   Each packet is in the following format:
 *
 *    uint32    packet_length
 *    byte      padding_length
 *    byte[n1]  payload; n1 = packet_length - padding_length - 1
 *    byte[n2]  random padding; n2 = padding_length
 *    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 *
 */
struct ssh_packet { 
    uint32_t      packet_length;
    unsigned char padding_length;
    unsigned char payload;
} __attribute__((__packed__));    

unsigned int ssh_packet_parse(const void *pkt, unsigned int datalen, unsigned char *msg_code) {
    const struct ssh_packet *ssh_packet = pkt;
    uint32_t length;

    if (datalen < sizeof(ssh_packet)) {
	return 0;
    }

    length = ntohl(ssh_packet->packet_length);
    if (length > 32768) {
	return 0;   /* indicate parse error */
    }
    *msg_code = ssh_packet->payload;

    /* robustness check */
    length -= ssh_packet->padding_length - 5;
    if (length > 32768) {
      return 0;
    }

    return length;
}

unsigned int decode_uint32(const void *data) {
    const uint32_t *x = data;
  
    return ntohl(*x);
}

enum status decode_ssh_string(const void **dataptr, unsigned int *datalen, void *dst, unsigned dstlen) { 
    const void *data = *dataptr;
    unsigned int length;

    if (*datalen < 4) { 
	fprintf(stderr, "ERROR: wanted %u, only have %u\n", 4, *datalen);
	return failure;
    }
    length = decode_uint32(data);
    *datalen -= 4;
    if (length > *datalen) {
	fprintf(stderr, "ERROR: wanted %u, only have %u\n", length, *datalen);
	return failure;
    }
    data += 4;

    /* robustness check */
    if (*datalen >= 1024) {
      return failure;
    }

    copy_printable_string(dst, dstlen, data, *datalen);    
    data += length;
    *datalen -= length;

    *dataptr = data;
    return ok;
}

/*
 * from RFC 4253 Section 7.1
 * 
 *    Key exchange begins by each side sending the following packet:
 *
 *    byte         SSH_MSG_KEXINIT
 *    byte[16]     cookie (random bytes)
 *    name-list    kex_algorithms
 *    name-list    server_host_key_algorithms
 *    name-list    encryption_algorithms_client_to_server
 *    name-list    encryption_algorithms_server_to_client
 *    name-list    mac_algorithms_client_to_server
 *    name-list    mac_algorithms_server_to_client
 *    name-list    compression_algorithms_client_to_server
 *    name-list    compression_algorithms_server_to_client
 *    name-list    languages_client_to_server
 *    name-list    languages_server_to_client
 *    boolean      first_kex_packet_follows
 *    uint32       0 (reserved for future extension)
 *
 */
void ssh_parse_kexinit(struct ssh *ssh, const void *data, unsigned int datalen) {

    /* copy the cookie  */
    if (datalen < 16) {
	return;
    }
    memcpy(ssh->cookie, data, 16);
    data += 16;
    datalen -= 16;

    /* copy all name-list strings */
    if (decode_ssh_string(&data, &datalen, ssh->kex_algos, sizeof(ssh->kex_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->s_host_key_algos, sizeof(ssh->s_host_key_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->c_encryption_algos, sizeof(ssh->c_encryption_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->s_encryption_algos, sizeof(ssh->s_encryption_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->c_mac_algos, sizeof(ssh->c_mac_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->s_mac_algos, sizeof(ssh->s_mac_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->c_comp_algos, sizeof(ssh->c_comp_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->s_comp_algos, sizeof(ssh->s_comp_algos)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->c_languages, sizeof(ssh->c_languages)) == failure) {
	return;
    }
    if (decode_ssh_string(&data, &datalen, ssh->s_languages, sizeof(ssh->s_languages)) == failure) {
	return;
    }

    return;
}


/*
 * start of ssh feature functions
 */

inline void ssh_init(struct ssh *ssh) {
    ssh->role = role_unknown;
    ssh->protocol[0] = 0; /* null terminate string */
    memset(ssh->cookie, 0, sizeof(ssh->cookie));
    memset(ssh->kex_algos, 0, sizeof(ssh->kex_algos));
    memset(ssh->s_host_key_algos, 0, sizeof(ssh->s_host_key_algos));
    memset(ssh->c_encryption_algos, 0, sizeof(ssh->c_encryption_algos));
    memset(ssh->s_encryption_algos, 0, sizeof(ssh->s_encryption_algos));
    memset(ssh->c_mac_algos, 0, sizeof(ssh->c_mac_algos));
    memset(ssh->s_mac_algos, 0, sizeof(ssh->s_mac_algos));
    memset(ssh->c_comp_algos, 0, sizeof(ssh->c_comp_algos));
    memset(ssh->s_comp_algos, 0, sizeof(ssh->s_comp_algos));
    memset(ssh->c_languages, 0, sizeof(ssh->c_languages));
    memset(ssh->s_languages, 0, sizeof(ssh->s_languages));
}

void ssh_update(struct ssh *ssh,
                const void *data,
                unsigned int len,
                unsigned int report_ssh,
                const void *extra,
                const unsigned int extra_len,
                const EXTRA_TYPE extra_type) {
    unsigned int length;
    unsigned char msg_code;

    if (len == 0) {
	return;        /* skip zero-length messages */
    }

    if (report_ssh) {

	if (ssh->role == role_unknown) {
	    if (ssh->protocol[0] == 0) {   
		copy_printable_string(ssh->protocol, sizeof(ssh->protocol), data, len);
		ssh->role = role_client; /* ? */
	    }
	}
	length = ssh_packet_parse(data, len, &msg_code);
	if (length == 0) {
	    return;
	}
	switch (msg_code) {
	case SSH_MSG_KEXINIT:

	    /* robustness check */
	    if ((ssh->c_encryption_algos[0] != 0) && (ssh->s_encryption_algos[0] != 0)) {
	      return ;
	    }

	    ssh_parse_kexinit(ssh, data + sizeof(struct ssh_packet), length);
	    break;
	default:
	    ; /* noop */
	}
    
    }

}

void ssh_print_json(const struct ssh *x1, const struct ssh *x2, zfile f) {

    if (x1->role != role_unknown) {
	zprintf(f, ",\"ssh\":{");
	if (x1->protocol[0] != 0) {
	    zprintf(f, "\"protocol\":\"%s\"", x1->protocol);
	    if (x1->cookie[0] != 0) {
		zprintf(f, ",\"cookie\":");
		zprintf_raw_as_hex(f, x1->cookie, sizeof(x1->cookie));
	    }
	    zprintf(f, ",\"kex_algos\":\"%s\"", x1->kex_algos);
	    zprintf(f, ",\"s_host_key_algos\":\"%s\"", x1->s_host_key_algos);
	    zprintf(f, ",\"c_encryption_algos\":\"%s\"", x1->c_encryption_algos);
	    zprintf(f, ",\"s_encryption_algos\":\"%s\"", x1->s_encryption_algos);
	    zprintf(f, ",\"c_mac_algos\":\"%s\"", x1->c_mac_algos);
	    zprintf(f, ",\"s_mac_algos\":\"%s\"", x1->s_mac_algos);
	    zprintf(f, ",\"c_comp_algos\":\"%s\"", x1->c_comp_algos);
	    zprintf(f, ",\"s_comp_algos\":\"%s\"", x1->s_comp_algos);
	    zprintf(f, ",\"c_languages\":\"%s\"", x1->c_languages);
	    zprintf(f, ",\"s_languages\":\"%s\"", x1->s_languages);
	}
	zprintf(f, "}");
    }
  
}

void ssh_delete(struct ssh *ssh) { 
    /* no memory needs to be freed */
}

void ssh_unit_test() {
    struct ssh ssh;
    zfile output;
    char *msg = "should use a valid KEXT ssh msg here";

    output = zattach(stdout, "w");
    if (output == NULL) {
	fprintf(stderr, "error: could not initialize (possibly compressed) stdout for writing\n");
    }
    ssh_init(&ssh);
    ssh_update(&ssh, msg, 1, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 2, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 3, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 4, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 5, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 6, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 7, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 8, 1, NULL, 0, 0);
    ssh_update(&ssh, msg, 9, 1, NULL, 0, 0);
    ssh_print_json(&ssh, NULL, output);
 
} 
