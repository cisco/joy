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
 * \file procwatch.h
 *
 * \brief process watcher interface file
 */

#ifndef PROCWATCH_H
#define PROCWATCH_H

#define PROC_EXE_LEN 32
#define PROC_PATH_LEN 128
#define PROC_HASH_LEN 65

#define ALL_PROC_SOCKETS 1
#define ACTIVE_PROC_SOCKETS_ONLY 0

#define HOST_PROC_FLOW_TABLE_LEN 1024

struct host_flow {
	struct flow_key key;
	unsigned long pid;
	unsigned long parent_pid;
	unsigned long inode;
	unsigned int threads;
	char *exe_name;
	char *full_path;
	char *file_version;
	char *hash;
};

/*
 * The function get_host_flow_data() obtains information about the
 * processes running on the host that are associated with packet
 * flows, and enters this information into flow_records as appropriate
 *
 * This function should be called occassionally, e.g. once per second.
 * On Linux, it reads through several /proc directories, which may
 * take a while.  On the other hand, if this function is called too
 * infrequently, then there may be process information about flows
 * that it misses, because of the transient nature of the OS
 * structures.
 */

/** main function for host process to flow mapping */
int get_host_flow_data();

#endif /* PROCWATCH_H */
