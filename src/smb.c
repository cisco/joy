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
 * \file smb.c
 *
 * \brief SMB parser
 */
#include <ctype.h>
#include <string.h> 
#include <stdlib.h>
#include <inttypes.h>
#include "smb.h"
#include "p2f.h"
#include "str_match.h"
#include "err.h"

/** user name match structure */
extern str_match_ctx usernames_ctx;

#define PARSE_FAIL (-1)
#define NETBIOS_LEN(nb) (65536*nb[0] + 256*nb[1] + nb[2])
/*
 * declarations of functions that are internal to this file
 */
static void smb_print_message(zfile f, const struct SMB *ses);

static int packet_parser(struct SMB *saveto, const void *data, unsigned int data_length);

static void aprintf(zfile f, const uint8_t *array, int array_length);
static char bin_to_hex(uint8_t n);

/**
 *
 * \brief Initialize the memory of smb struct.
 *
 * \param smb_handle contains smb structure to initialize
 *
 * \return none
 */
void smb_init (smb_t **smb_handle) {
    if (*smb_handle != NULL) {
        smb_delete(smb_handle);
    }

    *smb_handle = malloc(sizeof(smb_t));
    if (*smb_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
    memset(*smb_handle, 0, sizeof(smb_t));
}

/**
 * \brief Parse, process, and record smb session \p data.
 *
 * \param smb SMB session structure pointer
 * \param header PCAP packet header pointer
 * \param data Beginning of the HTTP / TCP payload data.
 * \param len Length in bytes of the \p data.
 * \param report_smb Flag indicating whether this feature should run.
 *                    0 for no, 1 for yes
 *
 * \return none
 */
void smb_update(smb_t *smb,
			     const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_smb) {
    
   
    if (!report_smb)
        return;

   
    if (smb->nb_packets >= MAX_SMB_PACKETS)
        return;
    
   
    if (data_len < sizeof(struct SMB_raw))
        return;
    
   
    if (packet_parser(&smb->packets[smb->nb_packets], data, data_len) == PARSE_FAIL)
        return;
    
   
    smb->nb_packets++;
}


static int packet_parser(struct SMB *saveto, const void *data, unsigned int data_length){
    
    struct SMB_raw *mask = (struct SMB_raw *)data;
    
    /*
     * NetBIOS sanity checks
     */
   
    if (mask->netbios_hdr.message_type)
        return PARSE_FAIL;
    
   
    if ( (int) NETBIOS_LEN(mask->netbios_hdr.length) + 4 != data_length)
        return PARSE_FAIL;
    
    /*
     * SMB sanity checks
     */
    
   
    if (!(mask->header.deliminator + 1))
        return PARSE_FAIL;
    /*
     * Length validation
     */
   
    int raw_size = sizeof(struct SMB_raw);
    int word_count = mask->word_count;
    int byte_count = *(uint16_t *)(data + sizeof(struct SMB_raw) + sizeof(uint16_t)*mask->word_count);
   

    if ( raw_size + 2*word_count + 2 + byte_count != NETBIOS_LEN(mask->netbios_hdr.length) + 4 )
        return PARSE_FAIL;
    /*
     * now we're pretty sure this is SMB. We can put this data into the saveto structure
     */
   
    memcpy(saveto, mask, sizeof(struct SMB_raw));
    
    void *command = (void *) (mask + 1);
    memcpy(&saveto->command.words, command, (saveto->command.word_count < MAX_PARAMETER_SIZE ? saveto->command.word_count : MAX_PARAMETER_SIZE) * sizeof(uint16_t));
    
    struct SMB_data *data_field = (struct SMB_data *)(command + saveto->command.word_count*sizeof(uint16_t));
    memcpy(&saveto->data, data_field, sizeof(uint16_t) + sizeof(uint8_t)*(data_field->byte_count < MAGIC_SMB ? data_field->byte_count : MAGIC_SMB));
    
    return 0;
}


/**
 * \brief Print the smb struct to JSON output file \p f.
 *
 * \param h1 pointer to smb structure
 * \param h2 pointer to twin smb structure
 * \param f destination file for the output
 *
 * \return none
 */
void smb_print_json(const smb_t *h1,
                    const smb_t *h2,
                    zfile f) {

    unsigned int total_messages = 0;
    int i = 0;

    /* Sanity check */
    if (h1 == NULL)
        return;
    
    /* Check if there's data to print */
    if (h2 != NULL) {
        if (h1->nb_packets == 0 && h2->nb_packets == 0) {
            /* No data to print */
            return;
        }
    } else {
        if (h1->nb_packets == 0) {
            /* No data to print */
            return;
        }
    }

    /* Get the highest message count */
    if (h2) {
        if (h1->nb_packets > h2->nb_packets) {
            total_messages = h1->nb_packets;
        } else {
            total_messages = h2->nb_packets;
        }
    } else {
        total_messages = h1->nb_packets;
    }

    /* Start http array */
    zprintf(f, ",\"smb\":[");
    
    for (i = 0; i < total_messages; i++) {
        int comma = 0;

        zprintf(f, "{");

        if (h1->nb_packets > i) {
            const struct SMB *msg = &h1->packets[i];

            zprintf(f, "\"out\":");

            smb_print_message(f, msg);

            comma = 1;
        }

        if (h2) {
            /* Twin */
            if (h2->nb_packets > i) {
                const struct SMB *msg = &h2->packets[i];

                if (comma) {
                    zprintf(f, ",\"in\":");
                } else {
                    zprintf(f, "\"in\":");
                }

                smb_print_message(f, msg);
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
 * \fn void smb_delete (http_data_t *data)
 * \param data pointer to the smb data structure
 * \return none
 */
void smb_delete (smb_t **smb_handle) {
    smb_t *smb = *smb_handle;

    if (smb == NULL) {
        return;
    }

    free(smb);
    *smb_handle = 0;
}

/* ************************
 * **********************
 * Internal Functions
 * **********************
 * ************************
 */

/*
 * print a single SMB packet
 */
static void smb_print_message(zfile f, 
                              const struct SMB *smb){
    zprintf(f, "{");
    const struct SMB_header *h = &smb->header;
    const struct SMB_parameter *c = &smb->command;
    const struct SMB_data *d = &smb->data;
    
    /*
     * display all info in header
     */
    
    zprintf(f, "\"SMB_Header\": {");
    
    // Command
    zprintf(f, "\"command_id\": \"%d\",", h->cmd);
    // Error class
    zprintf(f, "\"err_class\": \"%d\",", h->error_class);
    // Error code
    zprintf(f, "\"err_code\": \"%d\",", h->error_code);
    
    // Flags1
    zprintf(f, "\"flags1\": \"%d\",", *(uint8_t *)&h->flags1);
    // Flags2
    zprintf(f, "\"flags2\": \"%d\",", *(uint16_t *)&h->flags2);
    
    // PID High
    zprintf(f, "\"process_id_high\": \"%d\",", h->pid_high);
    // PID Low
    zprintf(f, "\"process_id_low\": \"%d\",", h->pid_low);
    // Tree ID
    zprintf(f, "\"tree_id\": \"%d\",", h->tid);
    // User ID
    zprintf(f, "\"user_id\": \"%d\",", h->uid);
    // Multiplex ID
    zprintf(f, "\"multiplex_id\": \"%d\",", h->mid);
    
    // Signature
    zprintf(f, "\"signature\": \"");
    aprintf(f, (const uint8_t *) h->signature, 8);
    zprintf(f,"\"},");
    
    /*
     * display command info
     */
    
    zprintf(f, "\"SMB_Command\": {");
    
    // Word Count
    zprintf(f, "\"word_count\": \"%d\"", c->word_count);
    // Full parameter
    if (c->word_count){
        zprintf(f, ",\"command\": \"");
        aprintf(f, (const uint8_t *) c->words, 2*(c->word_count < MAX_PARAMETER_SIZE ? c->word_count : MAX_PARAMETER_SIZE));
        zprintf(f, "\"},");
    }
    else{
        zprintf(f, "},");
    }
    
    /*
     * display data info
     */
    
    zprintf(f, "\"SMB_Data\": {");
    
    // Byte Count
    zprintf(f, "\"byte_count\": \"%d\"", d->byte_count);
    // Full data
    if (d->byte_count){
        zprintf(f, ",\"data\": \"");
        aprintf(f, d->data, (d->byte_count < MAGIC_SMB ? d->byte_count : MAGIC_SMB));
        zprintf(f, "\"}}");
    }
    else{
        zprintf(f, "}}");
    }
}

/*
 * prints a uint8_t array to hex format
 */
static void aprintf(zfile f, 
                    const uint8_t *array, 
                    int array_length){
    char str[2*MAX_PRINT_SIZE + 1];
    int i;
    for(i = 0; i < (array_length < MAX_PRINT_SIZE ? array_length : MAX_PRINT_SIZE); i++){
        str[2*i] = bin_to_hex(array[i] >> 4);
        str[2*i + 1] = bin_to_hex(array[i]);
    }
    str[2*(array_length < MAX_PRINT_SIZE ? array_length : MAX_PRINT_SIZE)] = '\0';
    zprintf(f, "%s", str);
}

/*
 * Returns the hex representation of the lower 4 bits
 */
static char bin_to_hex(uint8_t n){
    n &= 15;
    switch(n){
        case 0 ... 9:
            return (char) (n+48);
            break;
        case 10 ... 15:
            return (char) (n+87);
            break;
    }
    return '0';
}

void smb_unit_test(){
    return;
}