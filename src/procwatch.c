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
	const int bufSize = 4096;
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

static char *get_previous_hash_by_path (char *path) {
	int i;
	struct host_flow *record = NULL;

	if (path == NULL) {
		return NULL;
	}

	for (i = 0; i < HOST_PROC_FLOW_TABLE_LEN; ++i) {
		record = &host_proc_flow_table_array[i];
		/* see if we have a matching full path */
		if (record->full_path) {
			if ((strcmp(record->full_path, path) == 0) &&
				(record->hash != NULL)) {
				return record->hash;
			}
		}
		/* if we find a blank entry, we are done searching */
		if (record->key.sp == 0) {
			return NULL;
		}
	}

	/* if we get here, we didn't find the path in the table */
	return NULL;
}

static struct host_flow *get_host_flow (struct flow_key *key) {
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
		printf("\tTABLE Process PID: %lu\n", record->pid);
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
		printf("\tTABLE Uptime: %lu\n", record->uptime_seconds);
		printf("\tTABLE Thread Count: %d\n", record->threads);
		printf("\tTABLE Parent PID: %lu\n", record->parent_pid);
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
	union { /* Structure required for file time arithmetic. */
		LONGLONG li;
		FILETIME ft;
	} createTime, stopTime, elapsedTime;

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
					unsigned long seconds = 0;
					char *prev_hash = NULL;
					FILETIME kernelTime,userTime;
					SYSTEMTIME currentTime, upTime;

					memset(record->full_path, 0, PROC_PATH_LEN);
					QueryFullProcessImageName(hProcess, 0, record->full_path, &len);
					process_get_file_version(record);

					prev_hash = get_previous_hash_by_path(record->full_path);
					record->hash = malloc(2 * SHA256_DIGEST_LENGTH + 1);
					if (record->hash != NULL) {
						if (prev_hash) {
							strcpy(record->hash,prev_hash);
						} else {
							calculate_sha256_hash(record->full_path, record->hash);
						}
					}

					/* get the uptime of the process */
					GetProcessTimes(hProcess, &createTime, &stopTime, &kernelTime, &userTime);
					GetSystemTime(&currentTime);
					SystemTimeToFileTime(&currentTime, &stopTime);
					elapsedTime.li = stopTime.li - createTime.li;
					FileTimeToSystemTime(&elapsedTime.ft, &upTime);
					seconds = (uTime.wDay * 86400) + (upTime.wHour * 3600) + (upTime.wMinute * 60) + upTime.wSecond;
					record->uptime_seconds = seconds;
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

#ifndef WIN32

/* this function is the same for Linux and Mac OS X */

#define PID_MAX_LEN 64

static unsigned long get_process_uptime (unsigned long pid) {
    int day,hour,min,sec = 0;
    unsigned long ps_pid = 0;
    unsigned long process_uptime = 0;
    char PS_COMMAND[PID_MAX_LEN];
    char dummy_string[PID_MAX_LEN];
    int rc = 0;
    char *s = NULL;
    FILE *ps_file = NULL;

    /* set up the command to execute */
    sprintf(PS_COMMAND,"ps -p \"%lu\" -opid,etime",pid);

    ps_file = popen(PS_COMMAND, "r");
    if (ps_file == NULL) {
        joy_log_err("popen returned null (command(%d): %s)\n", rc, PS_COMMAND);
        return 0;
    }

    /* skip the header line */
    rc = fscanf(ps_file,"%[^\n]\n", dummy_string);

    /* process ps data */
    while (1) {
        /* clean out the variables */
        ps_pid = day = hour = min = sec = 0;

        /* process ps output 1 line at a time */
        rc = fscanf(ps_file,"%lu %s\n",&ps_pid,dummy_string);
        if ((pid == ps_pid) && (strlen(dummy_string) > 0)) {
            int got_hours = 0;
            int got_mins = 0;
            int got_secs = 0;

            /* format of elasped times is day-hr:min:sec
             * not all fields are always present, so process from
             * the back of the string.
             */
            s = dummy_string + strlen(dummy_string);
            while (s >= dummy_string) {
                if (s == dummy_string) {
                    if (got_hours) {
                        day = atoi(s);
                    } else if (got_mins) {
                        hour = atoi(s);
                    } else if (got_secs) {
                        min = atoi(s);
                    } else {
                        sec = atoi(s);
                    }
                }
                if (*s == '-') {
                    hour = atoi(s+1);
                    got_hours = 1;
                }
                if (*s == ':') {
                    if (got_secs) {
                        min = atoi(s+1);
                        got_mins = 1;
                    } else {
                        sec = atoi(s+1);
                        got_secs = 1;
                    }
                }
                --s;
            }
            process_uptime = ((day * 86400) + (hour * 3600) + (min * 60) + sec);
        }
        if (feof(ps_file)) {
            pclose(ps_file);
            return process_uptime;
        }
    }
    return 0;
}

#endif

#ifdef LINUX 

#define PROCESS_SRC 0
#define PROCESS_DST 1
#define ADDR_MAX_LEN 32
#define BUF_SIZE 512

struct ss_flow {
    struct flow_key key;
    char command[PROC_PATH_LEN];
    unsigned long pid;
};

/* global ss flow record */
struct ss_flow fr;

static void get_pid_path_hash (struct host_flow *hf) {
    int len = 0;
    char exe_name[PID_MAX_LEN];
    char buffer[BUF_SIZE];

    /* clean out buffers */
    memset(exe_name, 0x00, PID_MAX_LEN);
    memset(buffer, 0x00, BUF_SIZE);

    /* find the pid link */
    snprintf(exe_name,PID_MAX_LEN,"/proc/%lu/exe",hf->pid);
    len = readlink(exe_name, buffer, sizeof(buffer));
    if (len > 0) {
        /* got the link which has the full path */
        buffer[len] = 0;
        hf->full_path = malloc(strlen(buffer)+1);
        if (hf->full_path) {
            char *prev_hash = NULL;

            strcpy(hf->full_path,buffer);
            prev_hash = get_previous_hash_by_path(hf->full_path);
            hf->hash = malloc(2 * SHA256_DIGEST_LENGTH + 1);
            if (hf->hash != NULL) {
                if (prev_hash) {
                    strcpy(hf->hash,prev_hash);
                } else {
                    calculate_sha256_hash((unsigned char*)hf->full_path, (unsigned char*)hf->hash);
                }
            }
        }
    }
}

static void process_pid_string (char *string) {
    char *s = string;

    /* search to beginning of the app name */
    s = strstr(string,"\"");
    string = s + 1;
    s = string;

    /* find the end of the app name */
    s = strstr(string,"\"");
    *s = 0;

    /* copy app name into the flow record */
    strncpy(fr.command,string,strlen(string));

    /* skip over to the pid */
    s += 6;
    string = s;
    fr.pid = strtoul(s, NULL, 10);
}

static void process_addr_string (int which, char *string) {
    char *s = string;

    /* find the end of the ip address */
    s = strstr(string,":");

    /* null temrinate and store off ip address and port*/
    *s = 0;
    if (which == PROCESS_SRC) {
        inet_pton(AF_INET, string, &fr.key.sa);
        fr.key.sp = strtoul(s+1, NULL, 10);
    } else {
        inet_pton(AF_INET, string, &fr.key.da);
        fr.key.dp = strtoul(s+1, NULL, 10);
    }

    /* set the protocol to TCP */
    fr.key.prot = 6; /* TCP */
}

static void host_flow_table_add_tcp (unsigned int all_sockets) {
    char SS_COMMAND[] = "ss -tnp";
    char dummy_string[PID_MAX_LEN];
    char src_string[ADDR_MAX_LEN];
    char dst_string[ADDR_MAX_LEN];
    char pid_string[PID_MAX_LEN];
    int dummy_int = 0;
    int rc = 0;
    struct host_flow *hf = NULL;
    FILE *ss_file;

    ss_file = popen(SS_COMMAND, "r");
    if (ss_file == NULL) {
        joy_log_err("popen returned null (command(%d): %s)\n", rc, SS_COMMAND);
        return;
    }

    /* skip the header line */
    rc = fscanf(ss_file,"%[^\n]\n", dummy_string);

    /* process ss data */
    while (1) {
        /* clean out the ss flow record */
        memset(&fr,0x00,sizeof(struct ss_flow));

        /* process ss output 1 line at a time */
        rc = fscanf(ss_file,"%s %d %d %s %s %s\n", dummy_string,&dummy_int,&dummy_int,src_string,dst_string,pid_string);
        process_addr_string(PROCESS_SRC,src_string);
        process_addr_string(PROCESS_DST,dst_string);
        process_pid_string(pid_string);
        hf = get_host_flow(&fr.key);
        if (hf != NULL) {
            hf->pid = fr.pid;
            if (strlen(fr.command)) {
                hf->exe_name = malloc(strlen(fr.command)+1);
                strcpy(hf->exe_name,fr.command);
            }
            hf->uptime_seconds = get_process_uptime(hf->pid);
            get_pid_path_hash(hf);
        }

        if (feof(ss_file)) {
            pclose(ss_file);
            return;
        }
    }
}

int host_flow_table_add_sessions (int sockets) {
    host_flow_table_add_tcp(sockets);
    return 0;
}

#endif /* LINUX */


#ifdef DARWIN

/* on Mac OS X we use lsof to figure out process information */
#include "libproc.h"
#include "errno.h"

#define BUFSIZE 32
#define RBUFSIZE 128
#define PLIST_FILE_MAX 256

enum lsof_status {
  lsof_EOL = 0,
  lsof_done = 1,
  lsof_got_flow = 2
};

struct lsof_flow {
    struct flow_key key;
    char command[PROC_PATH_LEN];   
    unsigned long pid;  
};

/* global lsof flow record */
struct lsof_flow fr;

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

int lsof_set_addrs_ports(char **sptr) {
    char *s = *sptr;
    char *start;
    unsigned int got_sa = 0;
    unsigned int got_sp = 0;
    unsigned int got_da = 0;
    enum lsof_status lsof_status = lsof_done;

    start = s+1;
    while (*s != '\n') {
        if (*s == 0) {
            lsof_status = lsof_EOL;       /* indicate end of sptr */
            break;
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
	        inet_pton(AF_INET, start, &fr.key.da);
	        got_da = 1;
            } else {
	        inet_pton(AF_INET, start, &fr.key.sa);
	        got_sa = 1;
            }	     
            start = s+1;
        }
        if (*s == '-') {
            *s = 0;   /* null terminate */
            fr.key.sp = strtoul(start, NULL, 10);
            got_sp = 1;
            start = s+1;
        }
        if (*s == '>') {
            start = s+1;
        }
        s++;    
    
    }

    if (got_da) {
        fr.key.dp = strtoul(start, NULL, 10);
        lsof_status = lsof_got_flow;
    }

    s++;                /* advance over newline   */
    *sptr = s;
    return lsof_status;
}

char* get_full_path_from_pid (long pid) {
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

char* get_application_version (char* full_path) {
    int i = 0;
    int full_length = 0;
    int found_base = 0;
    char plist_file[PLIST_FILE_MAX];
    FILE *ver_file = NULL;
    char *ver_cmd = NULL;
    char *ver_string = NULL;

    /* get length of the file path */
    full_length = strlen(full_path);

    /* search from the back to front for the .app/ designation */
    for (i=full_length; i > 0; --i) {
        if ((*(full_path+i)   == '.') &&
            (*(full_path+i+1) == 'a') &&
            (*(full_path+i+2) == 'p') &&
            (*(full_path+i+3) == 'p') &&
            (*(full_path+i+4) == '/')) {
            found_base = i;
            break;
        }
    }

    /* see if we found the .app base of the full path */
    if (found_base > 0) {
        /* see if we have room to operate on this application */
        if ((found_base + 30) > PLIST_FILE_MAX) {
            /* can't operate on this application return NULL */
            return NULL;
        }
        /* setup the plist file name */
        memset(plist_file, 0x00, PLIST_FILE_MAX);
        strncpy(plist_file,full_path,found_base);
        strcat(plist_file,".app/Contents/Info.plist");

        /* setup the command to retireve the version info */
        ver_cmd = malloc(found_base + 100);
        ver_string = malloc(64);
        sprintf(ver_cmd,"plutil -p \"%s\" | grep CFBundleShortVersionString | awk \'{print $3}\' | tr -d \\\"", plist_file);

        /* execute command and read in the output */
        ver_file = popen(ver_cmd, "r");
        fscanf(ver_file,"%[^\n]\n",ver_string);

        /* close the pipe and free up the cmd memory */
        pclose(ver_file);
        free(ver_cmd);
 
        /* return version string of the application */
        return ver_string;
    }

    /* couldn't find the app base, just return NULL */
    return NULL;
}

void lsof_process_output(char *s, int sockets) {
    struct host_flow *hf = NULL;
    enum lsof_status status;
    char srcAddr[BUFSIZE];

    while (*s != '\n') {
        switch (*s) {
            case 'n':
                /* network address line (sa:sp->da:dp) */
                status = lsof_set_addrs_ports(&s);
                if (status == lsof_got_flow) { 
                    inet_ntop(AF_INET, &fr.key.sa, srcAddr, BUFSIZE);
                    if ((strcmp(srcAddr,"127.0.0.1") != 0) || sockets) {
                        hf = get_host_flow(&fr.key);
                        if (hf != NULL) {
                            hf->pid = fr.pid;
                            if (strlen(fr.command)) {
                                hf->exe_name = malloc(strlen(fr.command)+1);
                            }
                            if (hf->exe_name != NULL) {
                                strcpy(hf->exe_name,fr.command);
                                hf->full_path = get_full_path_from_pid(hf->pid);
                                if (hf->full_path) {
                                    char *prev_hash = NULL;

                                    prev_hash = get_previous_hash_by_path(hf->full_path);
                                    hf->hash = malloc(2 * SHA256_DIGEST_LENGTH + 1);
                                    if (hf->hash != NULL) {
                                        if (prev_hash) {
                                            strcpy(hf->hash,prev_hash);
                                        } else {
                                            calculate_sha256_hash((unsigned char*)hf->full_path, (unsigned char*)hf->hash);
                                        }
                                    }
                                    hf->file_version = get_application_version(hf->full_path);
                                    hf->uptime_seconds = get_process_uptime(hf->pid);
                                }
                            }
                        }
                    }
	            return;
                }
                if (status == lsof_EOL) {
	            return;
                }
                break;
            case 'c':
                /* process name line */
                strcpy(fr.command, (s+1));
	        return;
                break;

            case 'p':
                /* PID line (pid number) */
                fr.pid = strtoul((s+1), NULL, 10);
	        return;
                break;

            case 'P':
                /* protocol line UDP or TCP */
                if (*(s+1) == 'U') {
                     fr.key.prot = 17; /* UDP */
                } else {
                     fr.key.prot = 6;  /* TCP */
                }
	        return;
                break;
            default:
                break;
        }
    }
}

void read_lsof_data (int sockets) {
    FILE *lsof_file; 
    char LSOF_COMMAND[] = "lsof -i4TCP -n -P -FcnP -sTCP:^LISTEN";
    char rbuf[RBUFSIZE];

    lsof_file = popen(LSOF_COMMAND, "r");
    if (lsof_file == NULL) {
        joy_log_err("popen returned null (command: %s)\n", LSOF_COMMAND);
        return;
    }
  
    /* clean out the host flow record */
    memset(&fr,0x00,sizeof(struct lsof_flow));

    /* process lsof data */
    while (1) {
        /* process lsof output 1 line at a time */
        fscanf(lsof_file,"%[^\n]\n", rbuf);
        lsof_process_output(rbuf, sockets);
        if (feof(lsof_file)) {
            pclose(lsof_file);
            return;
        }
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
static struct timeval last_refresh_time = {0, 0};

int get_host_flow_data() {
    int i;
    struct timeval current_time;
    struct timeval delta_time;
    float seconds = 0.0;
    struct host_flow *record = NULL;

    /* get current time and determine the delta from last refresh */
    gettimeofday(&current_time, NULL);
    joy_timer_sub(&current_time, &last_refresh_time, &delta_time);
    seconds = (float) joy_timeval_to_milliseconds(delta_time) / 1000.0;

    /* see if we need to refresh the application process data */
    if (seconds > 30) {
        /* refresh the host data table */
        host_flow_table_init();

        /* insert active TCP sockets into set */
        host_flow_table_add_sessions(ACTIVE_PROC_SOCKETS_ONLY);

        /* store the last refresh timestamp */
        gettimeofday(&last_refresh_time, NULL);
    }

    /* print out the table if we want to debug anything */
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

    return 0;
}


