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
 * \file mtpt.c
 *
 * \brief Meterpreter payload communication detection
 */
#include <ctype.h>
#include <string.h> 
#include <stdlib.h>
#include <inttypes.h>
#include "mtpt.h"
#include "http.h"
#include "p2f.h"
#include "str_match.h"
#include "err.h"

/** user name match structure */
extern str_match_ctx usernames_ctx;

#define PARSE_FAIL (-1)
/*
 * declarations of functions that are internal to this file
 */
static void mtpt_print_message(zfile f, const struct mtpt_session *ses);

static struct mtpt_header header_parser(char *data, int data_length);

/**
 *
 * \brief Initialize the memory of mtpt struct.
 *
 * \param mtpt_handle contains mtpt structure to initialize
 *
 * \return none
 */
void mtpt_init (struct mtpt **mtpt_handle) {
    if (*mtpt_handle != NULL) {
        mtpt_delete(mtpt_handle);
    }

    *mtpt_handle = malloc(sizeof(struct mtpt));
    if (*mtpt_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
    memset(*mtpt_handle, 0, sizeof(struct mtpt));
    http_init(&(*mtpt_handle)->http_msg);
}

/**
 * \brief Parse, process, and record mtpt session \p data.
 *
 * \param mtpt Meterpreter session structure pointer
 * \param header PCAP packet header pointer
 * \param data Beginning of the HTTP / TCP payload data.
 * \param len Length in bytes of the \p data.
 * \param report_mtpt Flag indicating whether this feature should run.
 *                    0 for no, 1 for yes
 *
 * \return none
 */
void mtpt_update(struct mtpt *mtpt,
			     const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_mtpt) {
    
    if (!report_mtpt)
        return;
    
    if (mtpt->session_nb >= MAX_SESSIONS)
        return;
    
    /*
    
    Test if HTTP or TCP
    
    */
    
    char data_start[5];
    memcpy(data_start, data, 4*sizeof(char));
    data_start[4] = '\0';
    if(!strcmp(data_start, "HTTP")){
        // HTTP
        
        uint16_t num_messages = mtpt->http_msg->num_messages;
        http_update(mtpt->http_msg, header, data, data_len, 1);
        
        if (num_messages == mtpt->http_msg->num_messages || mtpt->http_msg->num_messages == 0)
            return;

        struct http_message *last_msg = &mtpt->http_msg->messages[mtpt->http_msg->num_messages-1];

        if ((last_msg->header.line_type == HTTP_LINE_REQUEST && !strcmp(last_msg->header.line.request.method, "POST")) 
            || (last_msg->header.line_type == HTTP_LINE_STATUS && !strcmp(last_msg->header.line.status.code, "200")) ){

            uint32_t content_length = 0;
            uint8_t i;
            for(i = 0; i < last_msg->header.num_elements; i++){
                if (!strcmp(last_msg->header.elements[i].name, "Content-Length")){
                    content_length = (uint32_t) atoi(last_msg->header.elements[i].value);
                    break;
                }
            }

            if (content_length < 32){
                // This might not a mtpt packet
                return;
            }

            struct mtpt_header hdr = header_parser(last_msg->body, last_msg->body_length);

            if (content_length - hdr.length != 24){                
                // This is not a mtpt packet
                if(mtpt->sessions[mtpt->session_nb].msg_nb)
                    mtpt->session_nb++;
                return;
            }

            if (mtpt->sessions[mtpt->session_nb].msg_nb < MAX_HEADERS)
                mtpt->sessions[mtpt->session_nb].headers[mtpt->sessions[mtpt->session_nb].msg_nb++] = hdr;
            
            // 
        }
    } else {
        // TCP
        
        if (!data_len)
            return;
        
        /*
        First case : We are still reading a message
        */
        if (mtpt->buffer_size){
            int i;
            for (i = 0; i < mtpt->buffer_size; i++){
                
                /*
                 * if the buffer is marked as invalid, continue
                 */
                if (mtpt->buffer[i].invalid)
                    continue;
                
                int left_to_read = mtpt->buffer[i].bytes_left_to_read;

                /*
                 * if this is not a valid mtpt packet, we close this session and create a new one
                 */
                if (left_to_read < data_len){
                    mtpt->buffer[i].invalid = 1;
                    continue;
                }

                /*
                 * if this may be a valid mtpt packet but we still haven't gotten to the end of the data
                 */
                if (left_to_read > data_len){
                    mtpt->buffer[i].bytes_left_to_read -= data_len;
                    continue;
                }

                /* 
                 * last case : this is the end of the data. We close all other buffers and add this one to correct session
                 * if we already have seen messages and this is not directly next to them, create new session
                 */

                if (mtpt->sessions[mtpt->session_nb].msg_nb && i)
                    mtpt->session_nb++;
                
                if (mtpt->session_nb >= MAX_SESSIONS)
                    return;
                
                /*
                 * append this to current session 
                 */
                if (mtpt->sessions[mtpt->session_nb].msg_nb < MAX_HEADERS) 
                    mtpt->sessions[mtpt->session_nb].headers[mtpt->sessions[mtpt->session_nb].msg_nb++] = mtpt->buffer[i].header;
                
                /*
                 * erase buffer
                 */
                mtpt->buffer_size = 0;
                return;
            }
        }
        
        /*
        Second case : New message
        */
        
        struct mtpt_header hdr = header_parser((char *)data, data_len);
        
        /*
        Sanity check
        */
        if (!hdr.length || hdr.length + 24 < data_len || (hdr.encrypted != 1 && hdr.encrypted != 0)){
            
            /*
             * if we are currently buffering, so we just forget about this packet
             * if not, this breaks the current session
             */
            if (mtpt->buffer_size){
                ;
            } else if (mtpt->sessions[mtpt->session_nb].msg_nb) {
                mtpt->session_nb++;
            }
            
            return;
        }
        
        /*
         * if this is a full packet, discard buffer and append to new session if we were buffering, add to current session if not
         */
        if (hdr.length + 24 == data_len){
            if (mtpt->buffer_size){
                mtpt->buffer_size = 0;
                if (mtpt->sessions[mtpt->session_nb].msg_nb && ++mtpt->session_nb >= MAX_SESSIONS)
                    return;
            }
            
            if (mtpt->sessions[mtpt->session_nb].msg_nb < MAX_HEADERS)
                mtpt->sessions[mtpt->session_nb].headers[mtpt->sessions[mtpt->session_nb].msg_nb++] = hdr;
            
            return;
        }
        
        /*
         * last case : if this is a fragment, create a new buffer item with this as the first element
         */
        
        int index = mtpt->buffer_size;
        if (mtpt->buffer_size < MAX_BUFFER){
            mtpt->buffer_size++;
        } else {
            index = mtpt->buffer_size-1;
        }
        
        mtpt->buffer[index].header = hdr;
        mtpt->buffer[index].bytes_left_to_read = (hdr.length + 24 - data_len);
        mtpt->buffer[index].invalid = 0;
        
        return;
    }
    
    
} 

/**
 * \brief Print the mtpt struct to JSON output file \p f.
 *
 * \param h1 pointer to mtpt structure
 * \param h2 pointer to twin mtpt structure
 * \param f destination file for the output
 *
 * \return none
 */
void mtpt_print_json(struct mtpt *h1,
                     struct mtpt *h2,
                     zfile f) {
    
    unsigned int total_messages = 0;
    int i = 0;

    /* Sanity check */
    if (h1 == NULL) {
        zprintf(f, ",\"mtpt\":\"BUG\"");
        return;
    }
    if (h1->sessions[h1->session_nb].msg_nb)
        h1->session_nb++;
    
    if (h2 != NULL && h2->sessions[h2->session_nb].msg_nb)
        h2->session_nb++;
    
    /* Check if there's data to print */
    if (h2 != NULL) {
        if (h1->session_nb == 0 && h2->session_nb == 0) {
            /* No data to print */
            return;
        }
        if (!h1->sessions[0].msg_nb && !h2->sessions[0].msg_nb)
            return;
    } else {
        if (h1->session_nb == 0 || !h1->sessions[0].msg_nb) {
            /* No data to print */
            return;
        }
    }

    /* Get the highest message count */
    if (h2) {
        if (h1->session_nb > h2->session_nb) {
            total_messages = h1->session_nb;
        } else {
            total_messages = h2->session_nb;
        }
    } else {
        total_messages = h1->session_nb;
    }

    /* Start http array */
    zprintf(f, ",\"mtpt\":[");
    
    for (i = 0; i < total_messages; i++) {
        int comma = 0;

        zprintf(f, "{");

        if (h1->session_nb > i) {
            const struct mtpt_session *msg = &h1->sessions[i];

            zprintf(f, "\"out\":");

            mtpt_print_message(f, msg);

            comma = 1;
        }

        if (h2) {
            /* Twin */
            if (h2->session_nb > i) {
                const struct mtpt_session *msg = &h2->sessions[i];

                if (comma) {
                    zprintf(f, ",\"in\":");
                } else {
                    zprintf(f, "\"in\":");
                }

                mtpt_print_message(f, msg);
            }
        }

        if (i == total_messages - 1) {
            zprintf(f, "}");
        } else {
            zprintf(f, "},");
        }

    }

    /* End http array */
    zprintf(f, "]");
}

/**
 * \fn void mtpt_delete (http_data_t *data)
 * \param data pointer to the mtpt data structure
 * \return none
 */
void mtpt_delete (struct mtpt **mtpt_handle) {
    struct mtpt *mtpt = *mtpt_handle;

    if (mtpt == NULL) {
        return;
    }

    http_delete(&(mtpt->http_msg));
    free(mtpt);
    *mtpt_handle = 0;
}

/* ************************
 * **********************
 * Internal Functions
 * **********************
 * ************************
 */

void mtpt_print_message(zfile f, const struct mtpt_session *ses){
    zprintf(f, "{");
    
    if (!ses->msg_nb){
        zprintf(f, "}");
        return;
    }
    
    // Number of messages
    zprintf(f, "\"count\": \"%d\",", ses->msg_nb);
    
    // Message lengths
    zprintf(f, "\"message_lengths\": [\"%d\"", ses->headers[0].length + 24);
    int i;
    for(i = 0; i < ses->msg_nb; i++)
        zprintf(f, ",\"%d\"", ses->headers[i].length + 24);
    zprintf(f, "],");
    
    // Encrypted
    zprintf(f, "\"encrypted\": \"%d\",", ses->headers[ses->msg_nb-1].encrypted);
    
    // Type
    zprintf(f, "\"type\": \"%d\"}", ses->headers[ses->msg_nb-1].type);
}

struct mtpt_header header_parser(char *data, int data_length){
    // Returns the data field of the header
    if (data_length < 32)
        return (struct mtpt_header){.length = 0};
    
    struct mtpt_header_raw *mtpt_raw = (struct mtpt_header_raw*) data;
    
    uint32_t len = 0;
    int offset;
    for(offset=0; offset < 4; offset++)
        len += (1<<(8*(3-offset))) * (uint32_t)(mtpt_raw->length[offset] ^ mtpt_raw->xor_key[offset%4]);
    
    uint32_t encrypted = 0;
    for(offset = 0; offset < 4; offset++)
        encrypted += (1<<(8*(3-offset))) * (uint32_t)(mtpt_raw->encrypt_flag[offset] ^ mtpt_raw->xor_key[offset%4]);
    
    uint32_t type = 0;
    for(offset = 0; offset < 4; offset++)
        type += (1<<(8*(3-offset))) * (uint32_t)(mtpt_raw->type[offset] ^ mtpt_raw->xor_key[offset%4]);
    
    struct mtpt_header hdr = {.length = len, .type = type, .encrypted = encrypted};
    memcpy(hdr.xor_key, mtpt_raw->xor_key, 4*sizeof(char));
    memcpy(hdr.guid, mtpt_raw->guid, 16*sizeof(char));
    
    return hdr;
}

void mtpt_unit_test(){
    return;
}