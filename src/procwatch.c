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
  * \file procwatch.c
  *
  * \brief process watcher implementation
  */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include "p2f.h"
#include "procwatch.h"
#include "err.h"

#ifdef WIN32
#include "Ws2tcpip.h"
#include "windows.h"
#include "iphlpapi.h"
#include "psapi.h"
#include "tlhelp32.h"
#include "winver.h"
#else 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <ctype.h> 
#include <string.h> 
#include <stdlib.h> 
#include "p2f.h"
#include "err.h" 
#include <openssl/sha.h>

static struct host_flow host_proc_flow_table_array[HOST_PROC_FLOW_TABLE_LEN];

int calculate_sha256_hash(unsigned char* path, unsigned char *output)
{
	SHA256_CTX sha256;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	const int bufSize = 32768;
	int bytesRead = 0;
	int i = 0;
	unsigned char* buffer = NULL;
	FILE* file = NULL;
	
	file = fopen((const char*)path, "rb");
	if (file == NULL) {
		return -1;
	}

	memset(hash, 0x00, SHA256_DIGEST_LENGTH);
	memset(&sha256, 0x00, sizeof(SHA256_CTX));
	SHA256_Init(&sha256);
    
	buffer = malloc(bufSize);
	if (buffer == NULL) {
		return -1;
	}

	while ((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA256_Update(&sha256, buffer, bytesRead);
	}
	SHA256_Final(hash, &sha256);

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf((char*)(output + (i * 2)), "%02x", hash[i]);
	}

	// NULL terminate the hash string
	*(output + (2 * SHA256_DIGEST_LENGTH)) = 0;

	fclose(file);
	free(buffer);
	return 0;
}

static void host_flow_table_init() {
	int i;

	for (i = 0; i < HOST_PROC_FLOW_TABLE_LEN; ++i) {
		if (host_proc_flow_table_array[i].exe_name != NULL)
			free(host_proc_flow_table_array[i].exe_name);
		if (host_proc_flow_table_array[i].full_path != NULL)
			free(host_proc_flow_table_array[i].full_path);
		if (host_proc_flow_table_array[i].file_version != NULL)
			free(host_proc_flow_table_array[i].file_version);
		if (host_proc_flow_table_array[i].hash != NULL)
			free(host_proc_flow_table_array[i].hash);
		memset(&host_proc_flow_table_array[i], 0, sizeof(struct host_flow));
	}
}

static struct host_flow *get_host_flow(struct flow_key *key) {
	int i;
	struct flow_key empty_key;
	struct host_flow *record = NULL;

        if (key == NULL) {
            return NULL;
        }

	memset(&empty_key, 0, sizeof(struct flow_key));
	for (i = 0; i < HOST_PROC_FLOW_TABLE_LEN; ++i) {
		record = &host_proc_flow_table_array[i];
		if (memcmp(&(record->key), key, sizeof(struct flow_key)) == 0) {
			return record;
		}
		else if (memcmp(&(record->key), &empty_key, sizeof(struct flow_key)) == 0) {
			// found an empty slot
			memcpy(&(record->key), key, sizeof(struct flow_key));
			return record;
		}
	}

	// if we get here, we didn't find the key and there 
	// are no free entries in the table, return NULL
	joy_log_err("no more free entires in the host_flow_table");
	return NULL;
}

int print_flow_table() {
	int i, entries = 0;
	char szAddr[128];
	struct flow_key empty_key;
	struct host_flow *record;

	memset(&empty_key, 0, sizeof(struct flow_key));
	for (i = 0; i < HOST_PROC_FLOW_TABLE_LEN; ++i) {
		record = &host_proc_flow_table_array[i];
		if (memcmp(&(record->key), &empty_key, sizeof(struct flow_key)) == 0) {
			//end of entires in table
			break;
		}
#ifdef WIN32
		strcpy_s(szAddr, sizeof(szAddr), inet_ntoa(record->key.sa));
#else
		strncpy(szAddr, inet_ntoa(record->key.sa), sizeof(szAddr));
#endif
		printf("\t========================\n");
		printf("\tTABLE Local Addr: %s\n", szAddr);
		printf("\tTABLE Local Port: %d \n", ntohs(record->key.sp));

#ifdef WIN32
		strcpy_s(szAddr, sizeof(szAddr), inet_ntoa(record->key.da));
#else
		strncpy(szAddr, inet_ntoa(record->key.da), sizeof(szAddr));
#endif
		printf("\tTABLE Remote Addr: %s\n", szAddr);
		printf("\tTABLE Remote Port: %d\n", ntohs(record->key.dp));
		printf("\tTABLE Protocol: %d\n", record->key.prot);
		printf("\tTABLE Process PID: %d\n", (int)record->pid);
		if (record->exe_name != NULL)
			printf("\tTABLE Exe Name: %s\n", record->exe_name);
		else
			printf("\tTABLE Exe Name: <unknown>\n");
		if (record->full_path != NULL)
			printf("\tTABLE Full Path: %s\n", record->full_path);
		else
			printf("\tTABLE Full Path: <unknown>\n");
		if (record->file_version != NULL)
			printf("\tTABLE File Version: %s\n", record->file_version);
		else
			printf("\tTABLE File Version: <unknown>\n");
		if (record->hash != NULL)
			printf("\tTABLE Hash: %s\n", record->hash);
		else
			printf("\tTABLE Hash: <unknown>\n");
		printf("\tTABLE Thread Count: %d\n", record->threads);
		printf("\tTABLE Parent PID: %d\n", (int)record->parent_pid);
		printf("\t-----------------------\n");
		++entries;
	}
	printf("\tTotal Entires: %d\n", entries);
	printf("\tTable Size: %zd bytes\n", sizeof(host_proc_flow_table_array));
	printf("\t========================\n");

	return 0;
}

#ifdef WIN32

void process_get_file_version(struct host_flow *record) {
	DWORD  verHandle = 0;
	UINT   size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD  verSize = 0;
		
	verSize = GetFileVersionInfoSize(record->full_path, &verHandle);

	if (verSize != 0)
	{
		LPSTR verData = malloc(verSize);

		if (GetFileVersionInfo(record->full_path, verHandle, verSize, verData))
		{
			if (VerQueryValue(verData, "\\", (VOID FAR* FAR*)&lpBuffer, &size))
			{
				if (size)
				{
					VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
					if (verInfo->dwSignature == 0xfeef04bd)
					{
						record->file_version = malloc(PROC_EXE_LEN);
						if (record->file_version != NULL) {
							// Doesn't matter if you are on 32 bit or 64 bit,
							// DWORD is always 32 bits, so first two revision numbers
							// come from dwFileVersionMS, last two come from dwFileVersionLS
							memset(record->file_version, 0, PROC_EXE_LEN);
							snprintf(record->file_version, PROC_EXE_LEN, "%d.%d.%d.%d",
								(verInfo->dwFileVersionMS >> 16) & 0xffff,
								(verInfo->dwFileVersionMS >> 0) & 0xffff,
								(verInfo->dwFileVersionLS >> 16) & 0xffff,
								(verInfo->dwFileVersionLS >> 0) & 0xffff
								);
						}
					}
				}
			}
		}
		free(verData);
	}
}

void get_process_info(HANDLE hProcessSnap, unsigned long pid, struct host_flow *record)
{
	DWORD len = PROC_PATH_LEN;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		joy_log_err("Process32First\n");
		return;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		// only check the processes in our records
		if (record->pid == pe32.th32ProcessID) {
			// store data we have already
			record->threads = pe32.cntThreads;
			record->parent_pid = pe32.th32ParentProcessID;
			record->exe_name = malloc(strlen(pe32.szExeFile) + 1);
			if (record->exe_name != NULL) {
				memset(record->exe_name, 0, (strlen(pe32.szExeFile) + 1));
				strncpy(record->exe_name, pe32.szExeFile, strlen(pe32.szExeFile));
			}

			// Retrieve the full path name class.
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL) {
				record->full_path = malloc(PROC_PATH_LEN);
				if (record->full_path != NULL) {
					memset(record->full_path, 0, PROC_PATH_LEN);
					QueryFullProcessImageName(hProcess, 0, record->full_path, &len);
					process_get_file_version(record);
					record->hash = malloc(2 * SHA256_DIGEST_LENGTH + 1);
					if (record->hash != NULL) {
						calculate_sha256_hash(record->full_path, record->hash);
					}
				}
				CloseHandle(hProcess);
			}
			break;
		}

	} while (Process32Next(hProcessSnap, &pe32));

} 


/**
* \fn int host_flow_table_add_tcp (int sockets)
* \param sockets - whether or not to analyze all sockets
* \return 0 - success
*         1 - failure
*/
int host_flow_table_add_tcp(int all_sockets) {
	// Declare and initialize variables
	HANDLE hProcessSnap;
	PMIB_TCPTABLE2 pTcpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;

	struct in_addr IpAddr;
	struct flow_key key;
	struct host_flow *record = NULL;
	int i;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		joy_log_err("CreateToolhelp32Snapshot (of processes)");
		return 1;
	}

	pTcpTable = (MIB_TCPTABLE2 *)malloc(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == NULL) {
		joy_log_err("Error allocating memory\n");
		CloseHandle(hProcessSnap);
		return 1;
	}

	ulSize = sizeof(MIB_TCPTABLE);
	// Make an initial call to GetTcpTable2 to
	// get the necessary size into the ulSize variable
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		free(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)malloc(ulSize);
		if (pTcpTable == NULL) {
			joy_log_err("Error allocating memory\n");
			CloseHandle(hProcessSnap);
			return 1;
		}
	}
	// Make a second call to GetTcpTable2 to get
	// the actual data we require
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if ((pTcpTable->table[i].dwRemoteAddr != 0) || (all_sockets)) {
				IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
				key.prot = 6; // TCP
				key.sa = IpAddr;
				key.sp = ntohs((u_short)pTcpTable->table[i].dwLocalPort);

				IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
				key.da = IpAddr;
				key.dp = ntohs((u_short)pTcpTable->table[i].dwRemotePort);
				record = get_host_flow(&key);
				if (record != NULL) {
					record->pid = pTcpTable->table[i].dwOwningPid;
					get_process_info(hProcessSnap, record->pid, record);
				}

			}
		}
	}
	else {
		joy_log_err("\tGetTcpTable2 failed with %d\n", dwRetVal);
		free(pTcpTable);
		CloseHandle(hProcessSnap);
		return 1;
	}

	if (pTcpTable != NULL) {
		free(pTcpTable);
		pTcpTable = NULL;
	}
	CloseHandle(hProcessSnap);
	return 0;
}

int host_flow_table_add_sessions (int sockets) {
    host_flow_table_add_tcp(sockets);
    return 0;
}

#endif

#ifdef LINUX 

int host_flow_table_add_sessions (int sockets) {
    return 0;
}

#endif /* LINUX */


#ifdef DARWIN

/* on Mac OS X we use lsof to figure out process information */
#include "libproc.h"
#include "errno.h"

#define BUFSIZE 32
#define RBUFSIZE 65536

enum lsof_status {
  lsof_EOL = 0,
  lsof_done = 1,
  lsof_got_flow = 2
};

struct lsof_flow {
    struct flow_key key;
    char command[PROC_PATH_LEN];   
    unsigned short pid;  
};

void lsof_flow_print(const struct lsof_flow *flow) {
    char srcbuf[BUFSIZE];
    char dstbuf[BUFSIZE];
    struct timeval now;

    gettimeofday(&now, NULL);
    inet_ntop(AF_INET, &flow->key.sa, srcbuf, BUFSIZE);
    inet_ntop(AF_INET, &flow->key.da, dstbuf, BUFSIZE);
    printf("{ \"command\": \"%s\", \"sa\": \"%s\", \"da\": \"%s\", \"sp\": %u, \"dp\": %u, \"pr\": %u, \"t\": %zd.%06zd }\n", 
	   flow->command, srcbuf, dstbuf, flow->key.sp, flow->key.dp, flow->key.prot, now.tv_sec, now.tv_usec);

}

int lsof_eat_string(char **sptr) {
    char *s = *sptr;

    while (*s != '\n') {
        if (*s == 0) {
            return 0;    /* indicate end of string */
        }
        s++;
    }
    s++;             /* advance over newline   */

    *sptr = s;
  
    return 1;
}

int lsof_set_name(struct lsof_flow *f, char **sptr) {
    unsigned int i = 0;
    char *s = *sptr + 1;

    while (*s != '\n') {
        if (*s == 0) {
            return 0;       /* indicate end of sptr */
        }
        f->command[i++] = *s++;
    }
    s++;                /* advance over newline   */
    f->command[i] = 0;  /* null terminate         */

    *sptr = s;
  
    return 1;
}

int lsof_set_pid(struct lsof_flow *f, char **sptr) {
    char *s = *sptr + 1;

    f->pid = strtoul(s, NULL, 10);

    return lsof_eat_string(sptr);
}

int lsof_set_prot(struct lsof_flow *f, char **sptr) {
    char *s = *sptr + 1;

    if (*s == 'U') {
        f->key.prot = 17; /* UDP */
    } else {
        f->key.prot = 6;  /* TCP */
    }
  
    return lsof_eat_string(sptr);
}

int lsof_set_addrs_ports(struct lsof_flow *f, char **sptr) {
    char *s = *sptr;
    char *start;
    unsigned int got_sa = 0;
    unsigned int got_sp = 0;
    unsigned int got_da = 0;
    enum lsof_status lsof_status = lsof_done;

    start = s+1;
    while (*s != '\n') {
        if (*s == 0) {
            return lsof_EOL;       /* indicate end of sptr */
        }

        /* ignore listening but not active sockets for now; skip over these lines */
        if (*s == '*') {
            *sptr = s;
            return lsof_eat_string(sptr);
        }

        /* ignore ipv6 for now; skip over these lines */
        if (*s == '[') {
            *sptr = s;
            return lsof_eat_string(sptr);
        }

        if (*s == ':') {
            *s = 0;   /* null terminate */
            if (got_sa) {
	        inet_pton(AF_INET, start, &f->key.da);
	        got_da = 1;
            } else {
	        inet_pton(AF_INET, start, &f->key.sa);
	        got_sa = 1;
            }	     
            start = s+1;
        }
        if (*s == '-') {
            *s = 0;   /* null terminate */
            f->key.sp = strtoul(start, NULL, 10);
            got_sp = 1;
            start = s+1;
        }
        if (*s == '>') {
            start = s+1;
        }
        s++;    
    
    }

    if (got_da) {
        f->key.dp = strtoul(start, NULL, 10);
        lsof_status = lsof_got_flow;
    }

    s++;                /* advance over newline   */
    *sptr = s;
    return lsof_status;
}

char* get_full_path_from_pid (int pid) {
    int ret;
    char *pbuf = NULL;
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];

    ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if ( ret <= 0 ) {
        return NULL;
    }

    pbuf = malloc(strlen(pathbuf)+1);
    if (pbuf != NULL) {
        strcpy(pbuf,pathbuf);
    }
    return(pbuf);
}

void lsof_process_output(char *s, int sockets) {
    struct lsof_flow f;
    struct host_flow *hf = NULL;
    enum lsof_status status;
    char srcAddr[BUFSIZE];

    memset(&f, 0, sizeof(struct lsof_flow));

    while (*s != '\n') {
        switch (*s) {
            case 'm': /* end of output marker */
            case 0:
            case 'n':
                status = lsof_set_addrs_ports(&f, &s);
                if (status == lsof_got_flow) { 
                    inet_ntop(AF_INET, &f.key.sa, srcAddr, BUFSIZE);
                    if ((strcmp(srcAddr,"127.0.0.1") != 0) || sockets) {
                        hf = get_host_flow(&f.key);
                        if (hf != NULL) {
                            hf->pid = f.pid;
                            hf->exe_name = malloc(strlen(f.command)+1);
                            if (hf->exe_name != NULL) {
                                strcpy(hf->exe_name,f.command);
                                hf->full_path = get_full_path_from_pid(hf->pid);
                                if (hf->full_path) {
                                    hf->hash = malloc(2 * SHA256_DIGEST_LENGTH + 1);
                                    if (hf->hash != NULL) {
                                        calculate_sha256_hash((unsigned char*)hf->full_path, (unsigned char*)hf->hash);
                                    }
                                }
                            }
                        }
                    }
                }
                if (status == lsof_EOL) {
	            return;
                } 
                break;
            case 'c':
                if (!lsof_set_name(&f, &s)) {
	            return;
                }
                break;
            case 'p':
                if (!lsof_set_pid(&f, &s)) {
	            return;
                } 
                break;
            case 'P':
                if (!lsof_set_prot(&f, &s)) {
	            return;
                }
                break;
            default:
                break;
        }
    }
}

void read_lsof_data (int sockets) {
    FILE *lsof_file; 
    char LSOF_COMMAND[] = "lsof -i -n -P -FcnP";
    char rbuf[RBUFSIZE];
    size_t bytes_read;

    lsof_file = popen(LSOF_COMMAND, "r");
    if (lsof_file == NULL) {
        joy_log_err("popen returned null (command: %s)\n", LSOF_COMMAND);
    }
  
    while (1) {
        bytes_read = fread(rbuf, 1, RBUFSIZE, lsof_file);
        lsof_process_output(rbuf, sockets);
        return;
    }
}

int host_flow_table_add_sessions (int sockets) {
    read_lsof_data(sockets);
    return 0;
}

#endif

/**
* \fn int get_host_flow_data ()
* \param none
* \return 0
*/
int get_host_flow_data() {
	int i;
	struct host_flow *record = NULL;

	host_flow_table_init();

	/* insert open TCP and UDP sockets into set */
	host_flow_table_add_sessions(ACTIVE_PROC_SOCKETS_ONLY);
	//print_flow_table();

	/*
	* for each entry in the host flow table, set the process info in the
	* corresponding flow in the packet-based flow table, if there
	* is one
	*/
	for (i = 0; i < HOST_PROC_FLOW_TABLE_LEN; i++) {
		struct flow_key twin;

		record = &host_proc_flow_table_array[i];
                if (record->pid == 0) {
                    /* we can stop, end of filled in entries in table */
                    break;
                }
		twin.sa = record->key.da;
		twin.da = record->key.sa;
		twin.sp = record->key.dp;
		twin.dp = record->key.sp;
		twin.prot = record->key.prot;

		flow_key_set_process_info(&record->key, record);
		flow_key_set_process_info(&twin, record);
	}

        /* clean up anything left in the table */
	host_flow_table_init();

	return 0;
}


