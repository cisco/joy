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
 * procwatch.c
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>        /* for isdigit() */
#include <string.h>       /* for strncpy() */
#include <stdlib.h>       /* for strtol() */

#include "p2f.h"
#include "err.h" 

#define NAME_LEN 128
#define HASH_LEN 65

struct host_flow {
  struct flow_key key;
  unsigned int inode;
  unsigned int pid;
  char exe_name[NAME_LEN];
  char hash[HASH_LEN];
  struct host_flow *next;
};


#include <openssl/sha.h>

#ifdef LINUX 

void exe_name_get_hash(const char *exe_name, char *hash) {
  char buf[HASH_LEN] = "cafebabefacedbaddecaf"; /* for testing only */

  memcpy(hash, buf, HASH_LEN);

}

void host_flow_print(const struct host_flow *hf) {
  const struct flow_key *key = &hf->key;

  /*
   * note: keep these printf() function calls separate! inet_ntoa()
   * uses a global buffer
   */
  printf("pid: %u\tind: %u\tsrc: %s:%-5u\t", 
	 hf->pid,
	 hf->inode, 
	 inet_ntoa(key->sa), key->sp);
  printf("dst: %s:%-5u\tprot: %-3u\texe: %s\n",
	 inet_ntoa(key->da), key->dp, 
	 key->prot, hf->exe_name);
}

#define host_flow_hash_mask 0x000000ff

#define HOST_FLOW_TABLE_LEN  (host_flow_hash_mask + 1)

struct host_flow *host_flow_table_array[HOST_FLOW_TABLE_LEN] = { 0, };

unsigned int inode_get_hash(unsigned int inode) {
  return (inode * 0x65cd52a5) & host_flow_hash_mask;
}

void host_flow_table_init() {
  memset(host_flow_table_array, 0, sizeof(host_flow_table_array));
}

void host_flow_table_print() {
  unsigned int i;
  struct host_flow *record = NULL; 

  for (i=0; i<HOST_FLOW_TABLE_LEN; i++) {
    record = host_flow_table_array[i];
    while (record != NULL) {
      host_flow_print(record);
      record = record->next;
    }
  }
}

#define CREATE_NEW 1
#define DONT_CREATE_NEW 0

struct host_flow *inode_get_host_flow(unsigned int inode, unsigned int create_new) {
  unsigned int hash_key;
  struct host_flow *record, *list_tail;
  
  hash_key = inode_get_hash(inode);
  record = list_tail = host_flow_table_array[hash_key];
  while (record != NULL) {
    if (inode == record->inode) {
      return record;
    }
    list_tail = record;
    record = record->next;
  }

  if (create_new && (record == NULL)) {
    
    record = malloc(sizeof(struct host_flow));
    memset(record, 0, sizeof(struct host_flow));
    record->inode = inode;

    if (host_flow_table_array[hash_key] == NULL) {
      host_flow_table_array[hash_key] = record;
    } else {
      list_tail->next = record;
    }
    record->next = NULL;
  }

  return record;
}


#define BUFLEN 10240

#define ALL_SOCKETS 1
#define ACTIVE_SOCKETS_ONLY 0

void host_flow_table_add_tcp(unsigned int all_sockets) {
  int fd;
  int len;
  char buffer[BUFLEN];
  char *line;
  unsigned int inode;
  struct host_flow tmp;
  struct flow_key *key = &tmp.key;
  
  fd = open("/proc/net/tcp", O_RDONLY);
  if (fd == -1) {
    perror("could not open /proc/net/tcp");
    return;
  }
  len = read(fd, buffer, sizeof(buffer));
  // printf("read %d bytes\n", len);
  // printf("%s\n", buffer);
  line = buffer + 156;
  while (len > 0) {
    //    line = buffer + 156;
    key->sa.s_addr = (strtoul(line, NULL, 16));
    //   printf("line: %s\n", line);
    // printf("addr: %x\n", addr);
    line += 9;
    key->sp = strtoul(line, NULL, 16);
    // printf("line: %s\n", line);
    // printf("port: %x\n", port);

    line += 5;
    key->da.s_addr = (strtoul(line, NULL, 16));
    //   printf("line: %s\n", line);
    // fprintf(stderr, "XXX addr: %s\n", inet_ntoa(key->da));
    line += 10;
    key->dp = strtoul(line, NULL, 16);
    // printf("line: %s\n", line);
    // printf("port: %x\n", port);

    line += 61;
    inode = strtoul(line, NULL, 10);
    
    key->prot = 6; /* tcp */

    if (key->da.s_addr != 0 || all_sockets) {
      struct host_flow *hf;

      /* ignore localhost source addresses */
      if (key->sa.s_addr != 0x7f000001) {

	/* found internet socket; create host_flow_table entry  */
	hf = inode_get_host_flow(inode, CREATE_NEW);
	if (hf == NULL) {
	  fprintf(stderr, "error: could not create host_flow\n");
	  return;
	}
	memcpy(&hf->key, key, sizeof(hf->key));
	
      // printf("saddr: %s:%u\t", inet_ntoa(hf->key.sa), hf->key.sp);
      // printf("daddr: %s:%u\t", inet_ntoa(hf->key.da), hf->key.dp);
      // printf("inode: %u\n", inode);
      }
    } 
    
    line += 65; /* advance to next line of data */
    len -= 202;
  }

  close(fd);
}


void host_flow_table_add_udp(unsigned int all_sockets) {
  int fd;
  int len;
  char buffer[BUFLEN];
  char *line;
  unsigned int inode;
  struct host_flow tmp;
  struct flow_key *key = &tmp.key;
  
  fd = open("/proc/net/udp", O_RDONLY);
  if (fd == -1) {
    perror("could not open /proc/net/udp");
    return;
  }
  len = read(fd, buffer, sizeof(buffer));
  // printf("read %d bytes\n", len);
  // printf("%s\n", buffer);
  line = buffer + 135;
  while (len > 0) {
    key->sa.s_addr = (strtoul(line, NULL, 16));
    // printf("line: %s\n", line);
    // printf("saddr: %x\n", key->sa.s_addr);
    line += 9; len -= 9;
    key->sp = strtoul(line, NULL, 16);
    // printf("line: %s\n", line);
    // printf("port: %x\n", key->sp);

    line += 5; len -= 5;
    key->da.s_addr = (strtoul(line, NULL, 16));
    // fprintf(stderr, "line: %s\n", line);
    // fprintf(stderr, "daddr: %x\n", key->da.s_addr);
    line += 9; len -= 9;
    key->dp = strtoul(line, NULL, 16);
    // printf("line: %s\n", line);
    // printf("port: %x\n", key->dp);

    line += 61; len -= 61;
    inode = strtoul(line, NULL, 10);
    // printf("line: %s\n", line);
    // printf("inode: %u\n", inode);
    
    key->prot = 17; /* udp */

    if (key->da.s_addr != 0 || all_sockets) {
      struct host_flow *hf;
      
      /* ignore localhost source addresses */
      if (key->sa.s_addr != 0x7f000001) {
	
	/* found internet socket; create host_flow_table entry  */
	hf = inode_get_host_flow(inode, CREATE_NEW);
	if (hf == NULL) {
	  fprintf(stderr, "error: could not create host_flow\n");
	  return;
	}
	hf->key = *key;
	
	// printf("saddr: %s:%u\t", inet_ntoa(key->sa), key->sp);
	// printf("daddr: %s:%u\t", inet_ntoa(key->da), key->dp);
	// printf("inode: %u\n", inode);
      } 
    }
    
    /* advance to next line of data */
    while (len > 0 && (*line != ':')) {
      line++; len--;
    } 
    line += 2; len -= 2;

    // line += 43; 
    // len -= 43;
  }

  close(fd);
}

int proc_get_fds(char *pid_string) {
  char fname[1024];
  char *f = fname;
  unsigned int fname_len;
  char exe_name[1024];
  char *exe = exe_name;
  int len;
  char buffer[1024];
  DIR *dir = NULL;
  struct dirent *process = NULL; 
  unsigned int inode;

  strncpy(f, "/proc/", 1024);
  f += 6;
  strncpy(f, pid_string, 1018);
  len = strnlen(pid_string, 1017);
  f += len;
  strncpy(exe_name, fname, 1024);
  exe += (6 + len);
  strncpy(f, "/fd", 1017-len);
  f += 3;

  //  printf("%s\n", fname);

  dir = opendir(fname);
  if (dir == NULL) {
    // typically, we get here because we don't have permission to open 
    // the directory; thus, we silently fail
    //
    // perror("could not open /proc/<pid>/fd subdirectory");
    return -1;
  }

  *f++ = '/';
  *f = 0;
  fname_len = 12 + len;

  process = readdir(dir); 
  while (process != NULL) {
   
    if (isdigit(process->d_name[0])) {
      // printf("d_name: %s\t d_type: %d\n", process->d_name, process->d_type);
      strncpy(f, process->d_name, fname_len);  
      // printf("fname: %s\n", fname);
      len = readlink(fname, buffer, sizeof(buffer));
      // printf("len: %d\n", len);
      if (len > 0) {

	/* if socket, get corresopnding executable name */
	if (memcmp("socket", buffer, 6) == 0) {
	  struct host_flow *hf;
	  
	  inode = strtoul(buffer + 8, NULL, 10);
	  // printf("name: %s\tinode: %u\t", fname, inode);
	  buffer[len] = 0;
	  // printf("%s\t", buffer);
	  strncpy(exe, "/exe", 1012);  
	  len = readlink(exe_name, buffer, sizeof(buffer));
	  if (len > 0) {
	    buffer[len] = 0;
	    // printf("exe: %s\n", buffer);
	  } else {
	     printf("error: could not read link\n");
	     buffer[0] = 0;
	  }

	  /* add information to internet host_flow, if one exists  */
	  hf = inode_get_host_flow(inode, DONT_CREATE_NEW);
	  if (hf != NULL) {
	    strncpy(hf->exe_name, buffer, NAME_LEN);
	    hf->pid = atoi(pid_string);

	    // printf("saddr: %s:%u\t", inet_ntoa(hf->key.sa), hf->key.sp);
	    // printf("daddr: %s:%u\t", inet_ntoa(hf->key.da), hf->key.dp);
	    // printf("inode: %u\n", hf->inode);
	    // host_flow_print(hf);
	    
	  }
	} 
      } else {
	perror("readlink failed");
      }
    }
    process = readdir(dir); 
  }

  closedir(dir);

  return 0;
}

int host_flow_table_update() {
  DIR *dir = NULL;
  struct dirent *process = NULL; // , *entry = NULL;

  /*
   * insert open TCP and UDP sockets into set
   */
  host_flow_table_add_tcp(ACTIVE_SOCKETS_ONLY);
  host_flow_table_add_udp(ACTIVE_SOCKETS_ONLY);

  /*
   * search all PIDs in /proc for open sockets
   */
  dir = opendir("/proc");
  if (dir == NULL) {
    perror("could not open /proc directory");
    return -1;
  }
  process = readdir(dir); 
  while (process != NULL) {
    if (isdigit(process->d_name[0])) {
      //      printf("%s\t%d\n", process->d_name, process->d_type);
      proc_get_fds(process->d_name);
    }
    process = readdir(dir); 
  }
  closedir(dir);

  return 0;
}

#ifndef MAIN 

int get_host_flow_data() {
  unsigned int i;
  struct host_flow *record = NULL; 
  struct host_flow *tmp;

  /*
   * initialize 
   */
  host_flow_table_init();

  /*
   * populate host_flow_table
   */
  host_flow_table_update();

  /*
   * for each entry in the host flow table, set the exe_name in the
   * corresponding flow in the packet-based flow table, if there 
   * is one
   */
  for (i=0; i<HOST_FLOW_TABLE_LEN; i++) {
    record = host_flow_table_array[i];
    while (record != NULL) {
      // fprintf(stderr, "exe_name: %s\n", record->exe_name);
      if (flow_key_set_exe_name(&record->key, record->exe_name) != ok) {
	struct flow_key twin;
	
	twin.sa = record->key.da;
	twin.da = record->key.sa;
	twin.sp = record->key.dp;
	twin.dp = record->key.sp;
	twin.prot = record->key.prot;
	if (flow_key_set_exe_name(&twin, record->exe_name) != ok) {
	  // fprintf(stderr, "twin host flow not found\n");
	  
	  /*
	   * too often no flow is found - this deserves investigation
	   */
	}

	// fprintf(stderr, "could not find matching flow: ");
	// host_flow_print(record);
      } else {
	// fprintf(stderr, "found matching flow: ");
	// host_flow_print(record);
      }
      tmp = record->next;
      free(record);
      record = tmp;
    }
    host_flow_table_array[i] = NULL;
  }
  return 0;
}

#endif

#ifdef MAIN

int main(int argc, char *argv[]) {

  /*
   * initialize 
   */
  host_flow_table_init();

  /*
   * populate host_flow_table
   */
  host_flow_table_update();

  /*
   * print out results
   */
  host_flow_table_print();

  return 0;
}


#endif /* MAIN */

#endif /* LINUX */

#ifdef DARWIN


/*
 * this feature is not yet supported on MacOSX, so for now we have a
 * stub function here  
 */

int get_host_flow_data() {
  return 0;
}

#endif
