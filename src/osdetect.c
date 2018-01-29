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
 * \file osdetect.c
 *
 * \brief operating system identification implementation
 */

#include "osdetect.h"

/**
 * \fn void os_printf (zfile f, int ttl, int iws, int ttl_twin, int iws_twin)
 * \param f output file
 * \param ttl
 * \param iws
 * \param ttl_twin
 * \param iws_twin
 * \return none
 */
void os_printf (zfile f, int ttl, int iws, int ttl_twin, int iws_twin) {
    char os_name[32] = { 0 };
    int empty = 1;
    detect_os(ttl, iws, os_name, sizeof(os_name));

    if (*os_name) {
        zprintf(f, ",\"probable_os\":{\"out\":\"%s\"", os_name);
        empty = 0;
    }
    if (ttl_twin) {
	os_name[0] = 0;
        detect_os(ttl_twin, iws_twin, os_name, sizeof(os_name));
        if (*os_name) {
            if (empty) {
                zprintf(f, ",\"probable_os\":{\"in\":\"%s\"", os_name);
                empty = 0;
            } else {
                zprintf(f, ",\"in\":\"%s\"", os_name);
            }
        }
    }

    if (! empty) {
        zprintf(f, "}");
    }
}

/**
 * \fn void detect_os (int ttl, int iws, char* os_name, int buf_size)
 * \brief \verbatim
   takes a TTL and initial window size and tries to find an OS
   This new OS classification is based on the TTL and initial window size as
     described in Packet Inspection for Unauthorized OS Detection in Enterprises,
     Tyagi et al., IEEE Security & Privacy magazine. Table 1.
  
   Results should be taken with caution, I have not personally validated
     that Table 1 was in fact correct.
   \endverbatim
 * \param ttl
 * \param iws
 * \param os_name
 * \param buf_size
 * \return none
 */
void detect_os (int ttl, int iws, char* os_name, int buf_size) {
    //int slack = 31; // packet has probably gone through at least 1 TTL decrement
                      // Need to determine best value for this.

    if ((ttl >= 33) && (ttl <= 64) && (iws == 5840)) {
        strncpy(os_name, "Linux 2.4 and 2.6", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 33) && (ttl <= 64) && (iws == 5720)) {
        strncpy(os_name, "Google Customized Linux", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 33) && (ttl <= 64) && (iws == 16384)) {
        strncpy(os_name, "OpenBSD, AIX 4.3", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 33) && (ttl <= 64) && (iws == 32120)) {
        strncpy(os_name, "Linux Kernel 2.2", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 33) && (ttl <= 64) && (iws == 65535)) {
        strncpy(os_name, "FreeBSD / OS X", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 65) && (ttl <= 128) && (iws == 8192)) {
        strncpy(os_name, "Windows 7, Vista, and Server 8", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 65) && (ttl <= 128) && (iws == 16384)) {
        strncpy(os_name, "Windows 2000", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 65) && (ttl <= 128) && (iws == 65535)) {
        strncpy(os_name, "Windows XP", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 129) && (ttl <= 255) && (iws == 4128)) {
        strncpy(os_name, "Cisco Router IOS 12.4", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }
    if ((ttl >= 129) && (ttl <= 255) && (iws == 8760)) {
        strncpy(os_name, "Solaris 7", buf_size-1);
        os_name[buf_size - 1] = '\0';
        return ;
    }

    memset(os_name, 0, buf_size);
    return ;

}


