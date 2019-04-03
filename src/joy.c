/*
 *  
 * Copyright (c) 2016-2019 Cisco Systems, Inc.
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
 * \file joy.c
 *
 * \brief converts pcap files or live packet capture using libpcap into
 * flow/intraflow data in JSON format
 * 
 */

#include <stdlib.h>  
#include <getopt.h>
#include <errno.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#ifndef WIN32
#include <libgen.h>
#endif

#include <sys/types.h>

#ifdef WIN32
#include "win_types.h"
#include "Ws2tcpip.h"
#include <ShlObj.h>
#else
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#endif

#include <limits.h>
#include <getopt.h>
#include <unistd.h>
#include <pthread.h>

#include "safe_lib.h"
#include "pkt_proc.h" /* packet processing               */
#include "p2f.h"      /* joy data structures       */
#include "config.h"   /* configuration                   */
#include "err.h"      /* error codes and error reporting */
#include "anon.h"     /* address anonymization           */
#include "tls.h"      /* TLS awareness                   */
#include "classify.h" /* inline classification           */
#include "procwatch.h"  /* process to flow mapping       */
#include "radix_trie.h" /* trie for subnet labels        */
#include "output.h"     /* compressed output             */
#include "updater.h"  /* updater thread */
#include "ipfix.h"    /* IPFIX cleanup */
#include "proto_identify.h"
#include "pcap.h"
#include "joy_api_private.h"

/**
 * \brief The supported operating modes that Joy can run in.
 */
typedef enum joy_operating_mode_ {
    MODE_NONE = 0,
    MODE_OFFLINE = 1,
    MODE_ONLINE = 2,
    MODE_IPFIX_COLLECT_ONLINE = 3
} joy_operating_mode_e;

/*
 * NOTE: NUM_PACKETS_BETWEEN_STATS_OUTPUT *must* be a multiple of
 * NUM_PACKETS_IN_LOOP, in order for stats output to periodically take place
 */
#define GET_ALL_PACKETS 0
#define NUM_PACKETS_IN_LOOP 10
#ifdef PKG_BUILD
#define NUM_PACKETS_BETWEEN_STATS_OUTPUT 1000000
#else
#define NUM_PACKETS_BETWEEN_STATS_OUTPUT 100000
#endif
#define MAX_RECORDS 2147483647
#define MAX_FILENAME_LEN 1024

/*
 * Local globals
 */
static joy_operating_mode_e joy_mode = MODE_NONE;
static pcap_t *handle = NULL;
static const char *filter_exp = "ip or ip6 or vlan";
static char full_path_output[MAX_FILENAME_LEN];

/* local definitions for the threading aspects */
#define MAX_JOY_THREADS 5
static pthread_t pkt_proc_thrd[MAX_JOY_THREADS];
static pthread_mutex_t thrd_lock[MAX_JOY_THREADS] =
  {PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,
   PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,
   PTHREAD_MUTEX_INITIALIZER};

/* config is the global configuration */
extern configuration_t active_config;
extern configuration_t *glb_config;

/* logfile definitions */
extern FILE *info;

/*
 * reopenLog is the flag set when SIGHUP is received
 * volatile as it is modified by a signal handler
 */
volatile int reopenLog = 0;

/*******************************************************************
 *******************************************************************
 * BEGIN network utility functions
 *******************************************************************
 *******************************************************************
 */
#define MAC_ADDR_LEN 6
#define MAC_ADDR_STR_LEN 32
#define IFL_MAX 16
#define INTFACENAMESIZE 64

#ifdef DARWIN
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include "pcap.h"
#define STRNCASECMP strncasecmp

#elif WIN32 // WINDOWS
#include "winsock2.h"
#include "winioctl.h"
#include "iphlpapi.h"
#include "ws2tcpip.h"
#include "winioctl.h"
#define IFNAMSIZ 16
#define STRNCASECMP strnicmp

#else
#include <sys/ioctl.h>
#include <net/if.h>
#define STRNCASECMP strncasecmp
#endif

struct intrface {
    unsigned char name [INTFACENAMESIZE];
    unsigned char mac_addr[MAC_ADDR_STR_LEN];
    unsigned char ip_addr4[INET_ADDRSTRLEN];
    unsigned char ip_addr6[INET6_ADDRSTRLEN];
    unsigned char active;
};

/*
 * Local interface globals
 */
static struct intrface ifl[IFL_MAX];
static unsigned int num_interfaces = 0;

static int find_interface_in_list(char *name) {
    int i;

    for (i = 0; i < IFL_MAX; ++i) {
        if (STRNCASECMP((char*)ifl[i].name, name, strlen(name)) == 0) {
            return i;
        }
    }
   return -1;
}

/**
 * \fn void get_mac_address (char *name, unsigned char mac_addr)
 * \param name interface name
 * \param mac_addr MAC address of interface
 * \return none
 */
void get_mac_address(char *name, unsigned char mac_addr[MAC_ADDR_STR_LEN])
{
#ifdef DARWIN
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (!strcmp((ifaptr)->ifa_name, name) && (((ifaptr)->ifa_addr)->sa_family == AF_LINK)) {
                ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
                sprintf((char*)mac_addr, "%02x%02x%02x%02x%02x%02x",
                         *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
                break;
            }
        }
        freeifaddrs(ifap);
    }
#elif WIN32
#include <winsock2.h>
#include <iphlpapi.h>
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);

    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) {
        return;
    }

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;

    do {
        int i = 0;
        int delta = 0;
        delta = strlen(name) - strlen(pAdapterInfo->AdapterName);
        if (delta != 0) {
            /* check the last N characters of the name */
            char *p = (char*)(name+delta);
            if (STRNCASECMP(p, pAdapterInfo->AdapterName, strlen(pAdapterInfo->AdapterName)) == 0) {
                sprintf((char*)mac_addr, "%02X%02X%02X%02X%02X%02X",
                    (int)pAdapterInfo->Address[0],
                    (int)pAdapterInfo->Address[1],
                    (int)pAdapterInfo->Address[2],
                    (int)pAdapterInfo->Address[3],
                    (int)pAdapterInfo->Address[4],
                    (int)pAdapterInfo->Address[5]);
                break;
            }
        } else {
            if (STRNCASECMP(name, pAdapterInfo->AdapterName, strlen(name)) == 0) {
                sprintf((char*)mac_addr, "%02X%02X%02X%02X%02X%02X",
                    (int)pAdapterInfo->Address[0],
                    (int)pAdapterInfo->Address[1],
                    (int)pAdapterInfo->Address[2],
                    (int)pAdapterInfo->Address[3],
                    (int)pAdapterInfo->Address[4],
                    (int)pAdapterInfo->Address[5]);
                break;
            }
        }
        pAdapterInfo = pAdapterInfo->Next;
    } while (pAdapterInfo);

#else
    struct ifreq ifr;
    int sock;

    sock=socket(PF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
	strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), name, sizeof(ifr.ifr_name)-1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1]='\0';
	ioctl(sock, SIOCGIFHWADDR, &ifr);

	sprintf((char*)mac_addr, "%02x%02x%02x%02x%02x%02x",
		(int)(unsigned char)ifr.ifr_hwaddr.sa_data[0],
		(int)(unsigned char)ifr.ifr_hwaddr.sa_data[1],
		(int)(unsigned char)ifr.ifr_hwaddr.sa_data[2],
		(int)(unsigned char)ifr.ifr_hwaddr.sa_data[3],
		(int)(unsigned char)ifr.ifr_hwaddr.sa_data[4],
		(int)(unsigned char)ifr.ifr_hwaddr.sa_data[5]);

	close(sock);
    } else {
	perror("Failed to create socket\n");
    }
#endif
}

/**
 * \fn void print_interfaces (FILE *f, int num_ifs)
 * \param f file to print to
 * \param num_ifs number of interfaces available
 * \return none
 */
void print_interfaces(FILE *f_info, int num_ifs) {
{
    int i;

    fprintf(f_info, "\nInterfaces\n");
    fprintf(f_info, "==========\n");
    for (i = 0; i < num_ifs; ++i) {
        fprintf(f_info, "Interface: %s\n", ifl[i].name);
        if (ifl[i].ip_addr4[0] != 0) {
            fprintf(f_info, "  IPv4 Address: %s\n", ifl[i].ip_addr4);
        }
        if (ifl[i].ip_addr6[0] != 0) {
            fprintf(f_info, "  IPv6 Address: %s\n", ifl[i].ip_addr6);
        }
        if (ifl[i].mac_addr[0] != 0) {
            fprintf(f_info, "  MAC Address: %c%c:%c%c:%c%c:%c%c:%c%c:%c%c\n",
                    ifl[i].mac_addr[0], ifl[i].mac_addr[1],
                    ifl[i].mac_addr[2], ifl[i].mac_addr[3],
                    ifl[i].mac_addr[4], ifl[i].mac_addr[5],
                    ifl[i].mac_addr[6], ifl[i].mac_addr[7],
                    ifl[i].mac_addr[8], ifl[i].mac_addr[9],
                    ifl[i].mac_addr[10], ifl[i].mac_addr[11]);
            }
        }
    }
}

static unsigned int interface_list_get(void) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i;
    unsigned int num_ifs = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list on the local machine */
    //if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return num_ifs;
    }
    memset_s(&ifl, sizeof(ifl), 0x00, sizeof(ifl));

    /* store off the interface list */
    for (d = alldevs; d; d = d->next) {
        char ip_string[INET6_ADDRSTRLEN];
        pcap_addr_t *dev_addr = NULL; //interface address that used by pcap_findalldevs()

        /* check if the device is suitable for live capture */
        for (dev_addr = d->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
            /* skip the loopback interfaces */
            /* MacOS */
            if (STRNCASECMP(d->name,"lo0",3) == 0) {
                continue;
            }
            /* Linux */
            if (STRNCASECMP(d->name,"lo",2) == 0) {
                continue;
            }
            if (dev_addr->addr && (dev_addr->addr->sa_family == AF_INET ||
				   dev_addr->addr->sa_family == AF_INET6)
		&& dev_addr->netmask) {
                i = find_interface_in_list(d->name);
                if (i > -1) {
                    /* seen this interface before */
                    memset_s(ip_string, INET6_ADDRSTRLEN, 0x00, INET6_ADDRSTRLEN);
                    if (dev_addr->addr->sa_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)dev_addr->addr)->sin6_addr, ip_string, INET6_ADDRSTRLEN);
                        snprintf((char*)ifl[i].ip_addr6, INET6_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    } else {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)dev_addr->addr)->sin_addr, ip_string, INET_ADDRSTRLEN);
                        snprintf((char*)ifl[i].ip_addr4, INET_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    }
                    get_mac_address((char*)ifl[i].name,ifl[i].mac_addr);
                } else {
                    /* first time seeing this interface add to list */
                    snprintf((char*)ifl[num_ifs].name, INTFACENAMESIZE, "%s", d->name);
                    memset_s(ip_string,  INET6_ADDRSTRLEN, 0x00, INET6_ADDRSTRLEN);
                    if (dev_addr->addr->sa_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)dev_addr->addr)->sin6_addr, ip_string, INET6_ADDRSTRLEN);
                        snprintf((char*)ifl[num_ifs].ip_addr6, INET6_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    } else {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)dev_addr->addr)->sin_addr, ip_string, INET_ADDRSTRLEN);
                        snprintf((char*)ifl[num_ifs].ip_addr4, INET_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
                    }
                    ifl[num_ifs].active = IFF_UP;
                    get_mac_address((char*)ifl[num_ifs].name,ifl[num_ifs].mac_addr);
                    ++num_ifs;
                }
            }
        }
    }

    if (num_ifs == 0) {
       fprintf(info, "No suitable interfaces found.\n\n");
    }

    pcap_freealldevs(alldevs);
    return num_ifs;
}

static void print_libpcap_stats(void) {
    struct pcap_stat cap_stats;

    memset_s(&cap_stats, sizeof(struct pcap_stat), 0x00, sizeof(struct pcap_stat));
    if (pcap_stats(handle, &cap_stats) == 0) {
        fprintf(info,"Libpcap Stats: Received %u, Mem Dropped %u, IF Dropped %u\n",
            cap_stats.ps_recv, cap_stats.ps_drop, cap_stats.ps_ifdrop);
    } else {
        /* stats failed to be retrieved */
        fprintf(info,"Libpcap Stats: -= unavailable =-\n");
    }
    fflush(info);
}

/*************************************************************************
 *************************************************************************
 * END network utility functions
 *************************************************************************
 *************************************************************************
 */

/*
 * sig_close() causes a graceful shutdown of the program after recieving
 * an appropriate signal
 */
#ifdef WIN32
__declspec(noreturn) static void sig_close (int signal_arg) {
#else
__attribute__((__noreturn__)) static void sig_close (int signal_arg) {
#endif
    int i;

    if (handle) {
      pcap_breakloop(handle);
    }

    /* obtain the locks from the child threads */
    if (glb_config->num_threads > 1) {
        for (i=0; i < glb_config->num_threads; ++i) {
            pthread_mutex_lock(&thrd_lock[i]);
        }
    }

    /*
     * flush remaining flow records in the child threads, and
     * print them even though they are not expired
     */
    for (i=0; i < glb_config->num_threads; ++i) {
        joy_print_flow_data(i, JOY_ALL_FLOWS);
        joy_print_flocap_stats_output(i);
        joy_context_cleanup(i);
    }

    if (handle) {
      print_libpcap_stats();
    }

    joy_shutdown();

    fprintf(info, "got signal %d, shutting down\n", signal_arg);
    exit(EXIT_SUCCESS);
}

/*
 * sig_reload()
 * Sets reopenLog flag when SIGHUP is received
 */
static void sig_reload (int signal_arg) {

    fprintf(info, "got signal %d, closing and reopening log file\n", signal_arg);
    reopenLog = 1;
}

/**
 * \brief Print the "help" usage message.
 *
 * \param s The name of binary that is being executed.
 *
 * \return -1 Indicates program exit
 */
static int usage (char *s) {
    printf("usage: %s [OPTIONS] file1 [file2 ... ]\n", s);
    printf("where OPTIONS are as follows:\n");
    printf("General options\n"
           "  -x F                       read configuration commands from file F\n"
           "  interface=I                read packets live from interface I\n"
           "  promisc=1                  put interface into promiscuous mode\n"
           "  output=F                   write output to file F (otherwise stdout is used)\n"
           "  logfile=F                  write secondary output to file F (otherwise stderr is used)\n"
           "  count=C                    rotate output files so each has about C records\n"
           "  upload=user@server:path    upload to user@server:path with scp after file rotation\n"
           "  keyfile=F                  use SSH identity (private key) in file F for upload\n"
           "  anon=F                     anonymize addresses matching the subnets listed in file F\n"
           "  retain=1                   retain a local copy of file after upload\n"
           "  preemptive_timeout=1       For active flows, look at incoming packets timestamp to decide if\n"
           "                             adding that packet to the flow record will automatically time it out.\n"
           "                             Default=0\n"
           "  nfv9_port=N                enable Netflow V9 capture on port N\n"
           "  ipfix_collect_port=N       enable IPFIX collector on port N\n"
           "  ipfix_collect_online=1     use an active UDP socket for IPFIX collector\n"
           "  ipfix_export_port=N        enable IPFIX export on port N\n"
           "  ipfix_export_remote_port=N IPFIX exporter will send to port N that exists on the remote server target\n"
           "                             Default=4739\n"
           "  ipfix_export_remote_host=\"host\"\n"
           "                             Use \"host\" as the remote server target for the IPFIX exporter\n"
           "                             Default=\"127.0.0.1\" (localhost)\n"
           "  ipfix_export_template=\"type\"\n"
           "                             Use \"type\" as the template for IPFIX exporter\n"
           "                             Default=\"simple\" (5-tuple)\n"
           "                             Available types: \"simple\", \"idp\"\n"
           "  aux_resource_path=\"path\"\n"
           "                             The path to directory where auxillary resources are stored\n"
           "  verbosity=L                Specify the lowest log level\n"
           "                             0=off, 1=debug, 2=info, 3=warning, 4=error, 5=critical\n"
           "                             Default=4\n"
           "  show_config=0              Show the configuration on stderr in the CLI on program run\n"
           "                             0=off, 1=show\n"
           "  show_interfaces=0          Show the interfaces on stderr in the CLI on program run\n"
           "                             0=off, 1=show\n"
           "  username=\"user\"          Drop privileges to username \"user\" after starting packet capture\n"
           "                             Default=\"joy\"\n"
           "  threads=N                  Number of threads to use for live capture (1-5). Default is 1.\n"
           "  updater=0                  Turn on or off dynamic updating of certain JOY parameters.\n"
           "                             0=off, 1=on, Default is off.\n"
           "Data feature options\n"
           "  bpf=\"expression\"           only process packets matching BPF \"expression\"\n"
           "  zeros=1                    include zero-length data (e.g. ACKs) in packet list\n"
           "  retrans=1                  include TCP retransmissions in packet list\n"
           "  bidir=1                    merge unidirectional flows into bidirectional ones\n"
           "  dist=1                     include byte distribution array\n"
           "  cdist=F                    include compact byte distribution array using the mapping file, F\n"
           "  entropy=1                  include byte entropy\n"
           "  http=1                     include HTTP data\n"
           "  exe=1                      include information about host process associated with flow\n"
           "  classify=1                 include results of post-collection classification\n"
           "  num_pkts=N                 report on at most N packets per flow (0 <= N < %d)\n"
           "  idp=N                      report N bytes of the initial data packet of each flow\n"
           "  label=L:F                  add label L to addresses that match the subnets in file F\n"
           "  URLmodel=URL               URL to be used to retrieve classisifer updates\n"
           "  model=F1:F2                change classifier parameters, SPLT in file F1 and SPLT+BD in file F2\n"
           "  hd=1                       include header description\n"
           "  URLlabel=URL               Full URL including filename to be used to retrieve label updates\n"
       get_usage_all_features(feature_list),
       MAX_NUM_PKT_LEN);
    printf("RETURN VALUE                 0 if no errors; nonzero otherwise\n");
    return -1;
}

/**
 * \brief Perform basic sanity checks on the config to ensure valid run state.
 *
 * \return 0 success, 1 failure
 */
static int config_sanity_check(void) {
    if (glb_config->ipfix_collect_port && glb_config->ipfix_export_port) {
        /*
         * Simultaneous IPFIX collection and exporting is not allowed
         */
        joy_log_crit("ipfix collection and exporting not allowed at same time");
        return 1;
    }

    if (glb_config->ipfix_collect_online && !(glb_config->ipfix_collect_port)) {
        /*
         * Cannot use online collection when the overall Ipfix collect feature is not enabled.
         */
        joy_log_crit("must enable IPFIX collection via ipfix_collect_port to use ipfix_collect_online");
        return 1;
    }

    return 0;
}

/**
 * \brief Set the operating mode that Joy will run in.
 *
 * \return 0 success, 1 failure
 */
static int set_operating_mode(void) {
    int cmp_ind;
    if (glb_config->intface != NULL && (strcmp_s(glb_config->intface, NULL_KEYWORD_LEN, NULL_KEYWORD, &cmp_ind) == EOK && cmp_ind != 0)) {
        /*
         * Network interface sniffing using Pcap
         */
        if (glb_config->ipfix_collect_port) {
            /* Ipfix collection does not use interface sniffing */
            joy_log_crit("ipfix collection and interface monitoring not allowed at same time");
            return 1;
        }

        joy_mode = MODE_ONLINE;
    } else if (glb_config->ipfix_collect_online) {
        /*
         * Ipfix live collecting process
         */
        joy_mode = MODE_IPFIX_COLLECT_ONLINE;
    } else {
        /*
         * Static Pcap file consumption
         */
        joy_mode = MODE_OFFLINE;
    }

    return 0;
}

/**
 * \brief Set the logging output to a file if given by user.
 *
 * \return 0 success, 1 failure
 */
static int set_logfile(void) {
    char logfile[MAX_FILENAME_LEN];
    int cmp_ind;
#ifdef WIN32
    PWSTR windir = NULL;
#endif

    if (glb_config->logfile && (strcmp_s(glb_config->logfile, NULL_KEYWORD_LEN, NULL_KEYWORD, &cmp_ind) == EOK && cmp_ind !=0)) {
#ifdef WIN32
        if (!strncmp(glb_config->logfile, "_WIN_INSTALL_", strlen("_WIN_INSTALL_"))) {
            /* Use the LocalAppDataFolder */
            SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &windir);

            snprintf(logfile, MAX_FILENAME_LEN, "%ls\\Joy\\%s", windir, "joy.log");

            if (windir != NULL) CoTaskMemFree(windir);
        } else {
            strncpy_s(logfile, MAX_FILENAME_LEN, glb_config->logfile, MAX_FILENAME_LEN-1);
        }
#else
        strncpy_s(logfile, MAX_FILENAME_LEN, glb_config->logfile, MAX_FILENAME_LEN-1);
#endif

        info = fopen(logfile, "a");
        if (info == NULL) {
            fprintf(stderr, "could not open log file %s", glb_config->logfile);
            return 1;
        }
        fprintf(stderr, "writing errors/warnings/info/debug output to %s\n", glb_config->logfile);
    }

    return 0;
}

/**
 * \brief Read the configuration into program memory, and perform
 *        some initial startup tasks.
 *
 * \param config_file Configuration that will be read into program state.
 * \param num_cmds The number of commands processed from the console.
 *
 * \return 0 success, 1 failure
 */
static int initial_setup(char *config_file, unsigned int num_cmds) {

    joy_log_debug("number of commands processed from cmd_line (%d)",num_cmds);

    if (config_file) {
        /*
         * Read in configuration from file; note that if we don't read in
         * a file, then the config structure will use the static defaults
         * set when it was declared, and from config_set_defaults().
         */
        config_set_from_file(glb_config, config_file);
    }

    /*
     * Config parsing will parse DHCP=1 and DHCPv6=1 to the same
     * configuration variable(dhcp). If we are interested in
     * DHCP, we would be interested in all DHCP (v4 and v6).
     * So, make sure DHCP V6 is the same as DHCP.
     */
    glb_config->report_dhcpv6 = glb_config->report_dhcp;

    /* Make sure the config is valid */
    if (config_sanity_check()) return 1;

    /* Determine the mode that Joy will be running in */
    if (set_operating_mode()) return 1;

    /* Set log to file or console */
    if (set_logfile()) return 1;

    /* Initialize the protocol identification module */
    if (proto_identify_init()) return 1;

    if (glb_config->show_config) {
        /* Print running configuration */
        config_print(info, glb_config);
    }

    if (joy_mode == MODE_ONLINE) {
        /* Get interface list */
        num_interfaces = interface_list_get();

        if (glb_config->show_interfaces) {
            /* Print the interfaces */
            print_interfaces(info, num_interfaces);
        }
    }

    /* set up BPF expression if specified */
    if (glb_config->bpf_filter_exp) {
        filter_exp = glb_config->bpf_filter_exp;
    }

    return 0;
}

/**
 * \brief Read in the splt and bd parameters if given.
 *
 * \return 0 success, 1 failure
 */
static int get_splt_bd_params(void) {
    char params_splt[LINEMAX];
    char params_bd[LINEMAX];
    int num;

    if (!glb_config->params_file) {
        return 0;
    }

    num = sscanf(glb_config->params_file, "%[^=:]:%[^=:\n#]", params_splt, params_bd);
    if (num != 2) {
        joy_log_err("could not parse command \"%s\" into form param_splt:param_bd", glb_config->params_file);
        return 1;
    } else {
        /*
         * process local files
         */
        joy_log_info("updating classifiers from supplied model(%s)\n", glb_config->params_file);
        joy_update_splt_bd_params(params_splt,params_bd);
    }

    return 0;
}

/**
 * \brief Get the labeled subnets.
 *
 * \return 0 success, 1 failure
 */
static int get_labeled_subnets(void) {
    unsigned int i = 0;

    if (!glb_config->num_subnets) {
        return 0;
    }

    for (i=0; i<glb_config->num_subnets; i++){
        int num;
        char label[LINEMAX], subnet_file[LINEMAX];

        num = sscanf(glb_config->subnet[i], "%[^=:]:%[^=:\n#]", label, subnet_file);
        if (num != 2) {
              joy_log_err("error: could not parse command \"%s\" into form label:subnet", glb_config->subnet[i]);
              return 1;
        }
        /* lower the subnet count - the api will add it back */
        --glb_config->num_subnets;
        joy_label_subnets(label, JOY_FILE_SUBNET, subnet_file);
    }
    joy_log_info("configured labeled subnets (radix_trie)");
    return 0;
}

/**
 * \brief Find and open the interface to monitor traffic on
 *
 * assigns the capture interface name to the pointer passed in
 *
 * \return 0 success, -1 failure
 */
static int open_interface (char **capture_if, char **capture_mac) {
    int linktype;
    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     * set capture interface as needed
     */
    if (strncmp(glb_config->intface, "auto", strlen("auto")) == 0) {
        *capture_if = (char*)ifl[0].name;
        *capture_mac = (char*)ifl[0].mac_addr;
        fprintf(info, "starting capture on interface %s\n", ifl[0].name);
    } else {
         unsigned int i;
         for (i = 0; i < num_interfaces; ++i) {
             if (STRNCASECMP((char*)ifl[i].name, glb_config->intface, strlen((char*)ifl[i].name)) == 0) {
                 *capture_if = (char*)ifl[i].name;
                 *capture_mac = (char*)ifl[i].mac_addr;
                 break;
             }
         }
    }

    if (*capture_if == NULL) {
        fprintf(info, "could not find specified capture device: %s\n", glb_config->intface);
        return -1;
    }

    errbuf[0] = 0;
    handle = pcap_open_live(*capture_if, 65535, glb_config->promisc, 10000, errbuf);
    if (handle == NULL) {
        fprintf(info, "could not open device %s: %s\n", *capture_if, errbuf);
        return -1;
    }
    if (errbuf[0] != 0) {
        fprintf(stderr, "warning: %s\n", errbuf);
    }

    /* verify that we can handle the link layer headers */
    linktype = pcap_datalink(handle);
    if (linktype != DLT_EN10MB) {
        fprintf(info, "device %s has unsupported linktype (%d)\n",
                *capture_if, linktype);
        return -1;
    }

    return 0;
}

/**
 \fn int process_directory_of_files (joy_ctx_data *ctx, char *input_directory)
 \brief logic to handle a directory of input files
 \param ctx the contex to use
 \param input_directory - directory of pcap input files
 \return 0 on success and negative number for processing error
 \return -11 on directory open failure
 */
static int first_input_pcap_file = 1;
static int process_directory_of_files(joy_ctx_data *ctx, char *input_directory) {
    int tmp_ret = 0;
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    struct stat st;
    struct dirent *ent = NULL;
    DIR *dir = NULL;
    char output_dir[MAX_FILENAME_LEN];
    char pcap_filename[MAX_FILENAME_LEN*2];
    int cmp_ind;

    tmp_ret = strnlen_s(input_directory, MAX_FILENAME_LEN*2);
    if (tmp_ret == 0 || tmp_ret >= MAX_FILENAME_LEN*2) {
	return -1;
    }
    /* initialize variables */
    memset_s(&fp,  sizeof(struct bpf_program), 0x00, sizeof(struct bpf_program));
    memset_s(&pcap_filename[0], (MAX_FILENAME_LEN*2), 0x00, (MAX_FILENAME_LEN*2));

    /* use the output filename as the directory to storing results */
    if (glb_config->filename) {
        strncpy_s(output_dir, (MAX_FILENAME_LEN-1), glb_config->filename, (MAX_FILENAME_LEN-1));

        /* create a directory to place all of the output files into */
        memset_s(&st,  sizeof(struct stat), 0x00, sizeof(struct stat));
        if (stat(output_dir, &st) == -1) {
#ifdef WIN32
            mkdir(output_dir);
#else
            tmp_ret = mkdir(output_dir, 0700);
            if (tmp_ret < 0) {
                joy_log_err("Error creating directory: %s\n", output_dir);
                return tmp_ret;
            }
#endif
        }
    }

    /* open the directory to read the files */
    if ((dir = opendir(input_directory)) != NULL) {

        while ((ent = readdir(dir)) != NULL) {
            static int fc_cnt = 1;

            /* initialize the data structures */
            memset_s(ctx, sizeof(joy_ctx_data), 0x00, sizeof(joy_ctx_data));
            if (glb_config->filename == NULL) {
                ctx->output = zattach(stdout, "w");
            }
            flow_record_list_init(ctx);
            flocap_stats_timer_init(ctx);

            if ((strcmp_s(ent->d_name, 1, ".", &cmp_ind) == EOK && cmp_ind !=0) &&
                (strcmp_s(ent->d_name, 2, "..", &cmp_ind) == EOK && cmp_ind !=0)) {
                strncpy_s(pcap_filename, (MAX_FILENAME_LEN*2), input_directory, (MAX_FILENAME_LEN*2)-1);
#ifdef WIN32
                if (pcap_filename[strlen(pcap_filename) - 1] != '\\') {
                    strcat_s(pcap_filename, MAX_FILENAME_LEN, "\\");
                }
                strcat_s(pcap_filename, MAX_FILENAME_LEN, ent->d_name);

                /* open new output file for multi-file processing */
                if (glb_config->filename) {
                    sprintf(full_path_output, "%s\\%s_%d_json%s", output_dir, ent->d_name, fc_cnt, zsuffix);
                    ++fc_cnt;
                    ctx->output = zopen(full_path_output, "w");
                }
#else
                if (pcap_filename[strlen(pcap_filename)-1] != '/') {
                    strncat_s(pcap_filename, MAX_FILENAME_LEN*2,"/", 1);
                }
                strcat(pcap_filename, ent->d_name);

                /* open new output file for multi-file processing */
                if (glb_config->filename) {
                    sprintf(full_path_output, "%s/%s_%d_json%s", output_dir, ent->d_name, fc_cnt, zsuffix);
                    ++fc_cnt;
                    ctx->output = zopen(full_path_output, "w");
                }
#endif
                /* initialize the outputfile and processing structures */
                if (glb_config->filename) {
                    joy_print_config(ctx->ctx_id, JOY_JSON_FORMAT);
                } else {
                    if (first_input_pcap_file) {
                        joy_print_config(ctx->ctx_id, JOY_JSON_FORMAT);
                        first_input_pcap_file = 0;
                    }
                }

                tmp_ret = process_pcap_file(ctx->ctx_id, pcap_filename, filter_exp, &net, &fp);
                if (tmp_ret < 0) {
		    closedir(dir);
                    return tmp_ret;
                }

                /* close the output file */
                if (glb_config->filename) {
                    zclose(ctx->output);
                    ctx->output = NULL;
                }
            }
        }

        closedir(dir);
    } else {
        /* error opening directory*/
        joy_log_err("Error opening directory: %s\n", input_directory);
        return -11;
    }
    return 0;
}

/**
 \fn int process_multiple_input_files (joy_ctx_data *ctx, char *input_filename, int fc_cnt)
 \brief logic to handle multiple input files
 \param ctx the context to use
 \param input_filename - the pcap file to process
 \param fc_cnt - the argument number of the current file being processed
 \return none
 */
static int process_multiple_input_files (joy_ctx_data *ctx, char *input_filename, int fc_cnt) {
    int tmp_ret = 0;
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    struct stat st;
    char output_dir[MAX_FILENAME_LEN];
    char input_path[MAX_FILENAME_LEN];
    char input_file_base_name[MAX_FILENAME_LEN];

#ifdef WIN32
    char fname[128];
    char ext[8];
#endif

    /* initialize variables */
    memset_s(&fp, sizeof(struct bpf_program), 0x00, sizeof(struct bpf_program));

    /* use the output filename as the directory to storing results */
    if (glb_config->filename) {
        strncpy_s(output_dir, (MAX_FILENAME_LEN-1), glb_config->filename, (MAX_FILENAME_LEN-1));

        /* create a directory to place all of the output files into */
        memset_s(&st, sizeof(struct stat), 0x00, sizeof(struct stat));
        if (stat(output_dir, &st) == -1) {
#ifdef WIN32
            mkdir(output_dir);
#else
            tmp_ret = mkdir(output_dir, 0700);
	    if (tmp_ret < 0) {
                joy_log_err("Error creating directory: %s\n", output_dir);
                return tmp_ret;
            }
#endif
        }
    }

    /* copy input filename path */
    strncpy_s(input_path, (MAX_FILENAME_LEN-1), input_filename, (MAX_FILENAME_LEN-1));

#ifdef WIN32
    /* get the input basename */
    _splitpath_s(input_path,NULL,0,NULL,0,fname,_MAX_FNAME,ext,_MAX_EXT);
    snprintf(input_file_base_name,128, "%s%s", fname, ext);

    /* full name for the new output file including directory */
    sprintf(full_path_output, "%s\\%s_%d_json%s", output_dir, input_file_base_name, fc_cnt, zsuffix);
    ++fc_cnt;
#else

    /* get the input basename */
    snprintf(input_file_base_name, 128, "%s", basename(input_path));

    /* full name for the new output file including directory */
    sprintf(full_path_output, "%s/%s_%d_json%s", output_dir, input_file_base_name, fc_cnt, zsuffix);
    ++fc_cnt;
#endif

    /* open new output file for multi-file processing */
    if (glb_config->filename) {
        ctx->output = zopen(full_path_output, "w");
    }

    /* print the json config */
    if (glb_config->filename) {
        joy_print_config(ctx->ctx_id, JOY_JSON_FORMAT);
    } else {
        if (first_input_pcap_file) {
            joy_print_config(ctx->ctx_id, JOY_JSON_FORMAT);
            first_input_pcap_file = 0;
        }
    }
    flow_record_list_init(ctx);
    flocap_stats_timer_init(ctx);

    /* process the file */
    tmp_ret = process_pcap_file(ctx->ctx_id, input_filename, filter_exp, &net, &fp);
    if (tmp_ret < 0) {
        return tmp_ret;
    }

    /* close output file */
    if (glb_config->filename) {
        zclose(ctx->output);
        ctx->output = NULL;
    }

    return tmp_ret;
}

/**
 \fn int process_single_input_file (joy_data_ctx *ctx, char *input_filename)
 \brief logic to handle a single input file
 \param ctx the context to use
 \param input_filename - pcap file to process
 \return 0 for success of negative number for processing error code
 */
static int process_single_input_file (joy_ctx_data *ctx, char *input_filename) {
    int tmp_ret = 0;
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    char full_outfile[MAX_FILENAME_LEN];

    /* initialize fp structure */
    memset_s(&fp, sizeof(struct bpf_program), 0x00, sizeof(struct bpf_program));

    /* set up full output file name */
    memset_s(&full_outfile, MAX_FILENAME_LEN, 0x00, MAX_FILENAME_LEN);
    if (glb_config->outputdir) {
        int len = strnlen_s(glb_config->outputdir, MAX_DIRNAME_LEN);
        if (len > (MAX_DIRNAME_LEN-1)) {
            /* output dir is too long, default to ./ */
            strncpy_s(full_outfile, MAX_DIRNAME_LEN, "./", 2);
        } else {
            strncpy_s(full_outfile, MAX_DIRNAME_LEN, glb_config->outputdir, len);
            if (full_outfile[len-1] != '/') {
                strncat_s(full_outfile, MAX_DIRNAME_LEN, "/", 1);
            }
        }
    } else {
        strncpy_s(full_outfile, MAX_DIRNAME_LEN, "./", 2);
    }

    /* open outputfile */
    if (glb_config->filename) {
        strncat_s(full_outfile, (MAX_DIRNAME_LEN-strlen(full_outfile)),
                  glb_config->filename, strlen(glb_config->filename));
        ctx->output = zopen(full_outfile,"w");
    }

    /* print configuration */
    joy_print_config(ctx->ctx_id, JOY_JSON_FORMAT);

    flow_record_list_init(ctx);
    flocap_stats_timer_init(ctx);

    tmp_ret = process_pcap_file(ctx->ctx_id, input_filename, filter_exp, &net, &fp);
    return tmp_ret;
}

static void* pkt_proc_thread_main(void* ctx_num) {
    uint8_t index = 0;
    unsigned long status_cnt = 0;
    joy_ctx_data *ctx = NULL;

    /* get the worker context from the thread number */
    index = (uint64_t)ctx_num;
    ctx = joy_index_to_context(index);
    if (ctx == NULL) {
        joy_log_crit("error:failed to find the context structure for index %d\n", index);
        return NULL;
    }

    while (1) {
        /* we process the flow records every 3 seconds */
        usleep(3000000); /* 3000000 = 3 sec */

        /* obtain the lock */
        pthread_mutex_lock(&thrd_lock[index]);

        /* report executable info if configured */
        if (glb_config->report_exe) {
            /*
             * periodically obtain host/process flow data
             */
            if (get_host_flow_data(ctx) != 0) {
                joy_log_warn("Could not obtain host/process flow data\n");
            }
        }

        /* Periodically report on progress */
        if (status_cnt < (ctx->stats.num_packets / NUM_PACKETS_BETWEEN_STATS_OUTPUT)) {
            joy_print_flocap_stats_output(ctx->ctx_id);
            print_libpcap_stats();
            status_cnt = (ctx->stats.num_packets / NUM_PACKETS_BETWEEN_STATS_OUTPUT);
        }

        /* Print out expired flows */
        joy_print_flow_data(ctx->ctx_id, JOY_EXPIRED_FLOWS);
        pthread_mutex_unlock(&thrd_lock[index]);
    }
    return NULL;
}

static void joy_get_packets(unsigned char *num_contexts,
                     const struct pcap_pkthdr *header,
                     const unsigned char *packet)
{
    uint64_t max_contexts = 0;
    uint64_t index = 0;
    joy_ctx_data *ctx = NULL;

    /* make sure we have a packet to process */
    if (packet == NULL) {
        return;
    }

    /* figure out the worker for this packet */
    max_contexts = (uint64_t)num_contexts;
    index = joy_packet_to_context(packet, max_contexts);
    ctx = joy_index_to_context(index);

    /* process the packet */
    pthread_mutex_lock(&thrd_lock[index]);
    process_packet((unsigned char*)ctx, header, packet);
    pthread_mutex_unlock(&thrd_lock[index]);
}

/**
 \fn int main (int argc, char **argv)
 \brief main entry point for joy
 \param argc command line argument count
 \param argv command line arguments
 \return 0
 */
int main (int argc, char **argv) {
    int opt_count = 0;
    unsigned int num_cmds = 0;
    unsigned int done_with_options = 0;
    char *config_file = NULL;
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    int tmp_ret;
    char output_filename[MAX_FILENAME_LEN];  /* data output file */
    char *capture_if = NULL;
    char *capture_mac = NULL;
    struct stat sb;
    pthread_t upd_thread;
    pthread_t uploader_thread;
    int upd_rc;
    pthread_t ipfix_cts_monitor_thread;
    int cts_monitor_thread_rc;
    int c, i = 0;
    int cmp_ind;
    joy_init_t init_data;
    int ctx_counter = 0;
#ifndef _WIN32
    struct passwd *pw = NULL;
    const char *user = NULL;
#endif

    /* initialize the config */
    memset_s(&active_config,  sizeof(configuration_t), 0x00, sizeof(configuration_t));
    glb_config = &active_config;

    /* Sanity check argument syntax */
    for (i=1; i<argc; i++) {
        if (strchr(argv[i], '=')) {
            if (done_with_options) {
                  joy_log_crit("option (%s) found after filename (%s)", argv[i], argv[i-1]);
                  exit(EXIT_FAILURE);
            }
        } else {
            done_with_options = 1;
        }
    }

    /*
     * set "info" to stderr; this output stream is used for
     * debug/info/warnings/errors.  setting it here is actually
     * defensive coding, just in case some function that writes to
     * "info" gets invoked before info gets set below (if we are in
     * online mode, it will be set to a log file)
     */
    info = stderr;

    /* in debug mode, turn off output buffering */
#if P2F_DEBUG
    setvbuf(stderr, NULL, _IONBF, 0);
    setbuf(stdout, NULL);
#endif

    /*
     * Set configuration from command line arguments that contain
     * LHS=RHS commands, then update argv/argc so that those arguments
     * are not subjected to any further processing
     */
    num_cmds = config_set_from_argv(glb_config, argv, argc);
    argv += num_cmds;
    argc -= num_cmds;

    /* Process command line options */
    while (1) {
        int option_index = 0;
        struct option long_options[] = {
            {"help",  no_argument,         0, 'h' },
            {"xconfig", required_argument, 0, 'x' },
            {0,         0,                 0,  0  }
        };

        c = getopt_long(argc, argv, "hx:", long_options, &option_index);

        if (c == -1) break;

        switch (c) {
            case 'x':
                config_file = optarg;
                opt_count++;
                break;
            case 'h':
            default:
                return usage(argv[0]);
        }
        opt_count++;
    }

    /*
     * Configure and prepare the program for execution
     */
    if (initial_setup(config_file, num_cmds)) exit(EXIT_FAILURE);

    /* setup library and context information */
    memset_s(&init_data, sizeof(joy_init_t), 0x00, sizeof(joy_init_t));
    if (joy_mode == MODE_ONLINE) {
       init_data.contexts = glb_config->num_threads;
    } else {
       glb_config->num_threads = 1;
       init_data.contexts = 1;
    }
    init_data.inact_timeout = 10;
    init_data.act_timeout = 20;

    /* config was already setup, use API with pre-set configuration */
    joy_initialize_no_config(glb_config, info, &init_data);

    /*
     * Retrieve sequence of packet lengths/times and byte distribution
     * parameters if supplied
     */
    if (get_splt_bd_params()) exit(EXIT_FAILURE);

    /* Retrieve the compact byte distribution if supplied */
    if (glb_config->compact_byte_distribution) {
        joy_update_compact_bd(glb_config->compact_byte_distribution);
    }

    /* Configure labeled subnets */
    if (get_labeled_subnets()) exit(EXIT_FAILURE);

    /* Configure anonymization */
    if (glb_config->anon_addrs_file) {
        joy_anon_subnets(glb_config->anon_addrs_file);
    }
    if (glb_config->anon_http_file) {
        joy_anon_http_usernames(glb_config->anon_http_file);
    }

    if (joy_mode != MODE_OFFLINE) {
        /*
         * Cheerful message to indicate the start of a new run of the program
         */
        fprintf(info, "--- Joy Initialization ---\n");
        for (ctx_counter=0; ctx_counter < init_data.contexts; ++ctx_counter) {
            joy_print_flocap_stats_output(ctx_counter);
        }
    }

    /* Open interface for live captures */
    if (joy_mode == MODE_ONLINE) {
        if (open_interface(&capture_if, &capture_mac) < 0) {
            fprintf(info, "error: open_interface for live capture session failed!\n");
            return -2;
        }
    }

    /* initialize the IPFix exporter if configured */
    if (glb_config->ipfix_export_port) {
        ipfix_exporter_init(glb_config->ipfix_export_remote_host);
    }

    if (joy_mode == MODE_ONLINE) {   /* live capture */

        /*
         * sanity check: we can't be in both offline mode and online mode
         * simultaneously
         */
        if (argc-opt_count > 1) {
            fprintf(info, "error: both interface (%s) and pcap input file (%s) specified\n",
                    glb_config->intface, argv[1+opt_count]);
            return usage(argv[0]);
        }

        anon_print_subnets(info);

        signal(SIGINT, sig_close);     /* Ctl-C causes graceful shutdown */
        signal(SIGTERM, sig_close);
#ifndef WIN32
        signal(SIGHUP, sig_reload);
#endif

        /* interface is already open, apply any filter expressions */
        if (filter_exp) {

            /* compile the filter expression */
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(info, "error: could not parse filter %s: %s\n",
                        filter_exp, pcap_geterr(handle));
                return -3;
            }

            /* apply the compiled filter */
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(info, "error: could not install filter %s: %s\n",
                        filter_exp, pcap_geterr(handle));
                return -4;
            }

        }

#ifndef _WIN32
        /*
         * Drop privileges once pcap handle exists
         */
        if (glb_config->username) {
            user = glb_config->username;
        } else {
            user = getenv("SUDO_USER");
        }

        if (user == NULL) {
            joy_log_crit("Please specify username=foo or run program with sudo");
            return -5;
        }

        pw = getpwnam(user);

        if (pw) {
            if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
                fprintf(info, "error: could not change to '%.32s' uid=%lu gid=%lu: %s\n",
                        pw->pw_name,
                        (unsigned long)pw->pw_uid,
                        (unsigned long)pw->pw_gid,
                        pcap_strerror(errno));
                return -5;
            }
            else {
                fprintf(info, "changed user to '%.32s' (uid=%lu gid=%lu)\n",
                        pw->pw_name,
                        (unsigned long)pw->pw_uid,
                        (unsigned long)pw->pw_gid);
            }
        }
        else {
            joy_log_crit("could not find user '%.32s'", user);
            return -5;
        }
#endif /* _WIN32 */

        /*
         * start the updater thread
         */
         if (glb_config->updater_on) {
             upd_rc = pthread_create(&upd_thread, NULL, updater_main, (void*)glb_config);
             if (upd_rc) {
                 joy_log_crit("critical: could not start uploader thread pthread_create() rc: %d\n", upd_rc);
                 return -6;
             }
         }

        /*
         * start up the uploader thread
         *   uploader is only active during live capture runs
         */
         if (glb_config->upload_servername) {
             upd_rc = pthread_create(&uploader_thread, NULL, uploader_main, (void*)glb_config);
             if (upd_rc) {
                 joy_log_crit("critical: could not start uploader thread pthread_create() rc: %d\n", upd_rc);
                 return -7;
             }
         }

        /*
         * flush "info" output stream to ensure log file accuracy
         */
        fflush(info);

        /*
         * write out JSON preamble
         */
        for (ctx_counter=0; ctx_counter < init_data.contexts; ++ctx_counter) {
            joy_print_config(ctx_counter,JOY_JSON_FORMAT);
        }

        /* spin up the threads */
        if (init_data.contexts > 1) {
            for (ctx_counter=0; ctx_counter < init_data.contexts; ++ctx_counter) {
                int thrd_rc = 0;
                uint64_t ctx_index = ctx_counter;

                /* start the threads */
                thrd_rc = pthread_create(&pkt_proc_thrd[ctx_counter], NULL, pkt_proc_thread_main, (void*)ctx_index);
                if (thrd_rc) {
                    joy_log_err("error: could not start packet_processing thread rc: %d\n", thrd_rc);
                    return -8;
                }
            }
        }

        while(1) {
            uint64_t max_contexts = init_data.contexts;
            if (max_contexts > 1) {
                /*
                 * Loop over packets captured from interface.
                 */
                pcap_dispatch(handle, NUM_PACKETS_IN_LOOP, joy_get_packets, (unsigned char*)max_contexts);
           } else {
                joy_ctx_data *ctx = joy_index_to_context(0);
                pcap_dispatch(handle, NUM_PACKETS_IN_LOOP, libpcap_process_packet, (unsigned char*)ctx);

                /* report executable info if configured */
                if (glb_config->report_exe) {
                    /*
                     * periodically obtain host/process flow data
                     */
                    if (get_host_flow_data(ctx) != 0) {
                        joy_log_warn("Could not obtain host/process flow data\n");
                    }
                }

                /* Periodically report on progress */
                if ((ctx->stats.num_packets) && ((ctx->stats.num_packets % NUM_PACKETS_BETWEEN_STATS_OUTPUT) == 0)) {
                    joy_print_flocap_stats_output(ctx->ctx_id);
                    print_libpcap_stats();
                }

                /* Print out expired flows */
                joy_print_flow_data(ctx->ctx_id, JOY_EXPIRED_FLOWS);
           }

           // Close and reopen the log file if reopenLog flag is set
           if (reopenLog && glb_config->logfile && (strcmp_s(glb_config->logfile, NULL_KEYWORD_LEN, NULL_KEYWORD, &cmp_ind) == EOK && cmp_ind!= 0)) {
              fclose(info);
              reopenLog = 0;
              info = fopen(glb_config->logfile, "a");
              if (info == NULL) {
                 fprintf(stderr, "error: could not open new log file %s\n", glb_config->logfile);
                 return -1;
              }
           }
        }

        if (filter_exp) {
            pcap_freecode(&fp);
        }

        pcap_close(handle);

    } else if (joy_mode == MODE_IPFIX_COLLECT_ONLINE) {
        joy_ctx_data *ctx = NULL;

        /* collection mode  only uses 1 context, so can use index 0 always */
        ctx = joy_index_to_context(0);
        if (ctx == NULL) {
            joy_log_crit("error:failed to find the context structure for index %d\n", 0);
            return -1;
        }

        /* IPFIX live collecting process */
        signal(SIGINT, sig_close);     /* Ctl-C causes graceful shutdown */
        signal(SIGTERM, sig_close);

        /*
         * Start up the IPFIX collector template store (cts) monitor
         * thread. Monitor is only active during live capture runs.
         */
        cts_monitor_thread_rc = pthread_create(&ipfix_cts_monitor_thread,
                                               NULL,
                                               ipfix_cts_monitor,
                                               (void*)NULL);
        if (cts_monitor_thread_rc) {
          fprintf(info, "error: could not start ipfix cts monitor thread\n");
          fprintf(info, "pthread_create() rc: %d\n", cts_monitor_thread_rc);
          return -7;
        }

        flow_record_list_init(ctx);

        ipfix_collect_main(ctx);

        joy_print_flow_data(ctx->ctx_id, JOY_ALL_FLOWS);
        fflush(info);

    } else { /* mode = mode_offline */
        int multi_file_input = 0;
        joy_ctx_data *ctx = NULL;

        /* offline only uses 1 context, so can use index 0 always */
        ctx = joy_index_to_context(0);
        if (ctx == NULL) {
            joy_log_crit("error:failed to find the context structure for index %d\n", 0);
            return -1;
        }

        if (argc-opt_count <= 1) {
            fprintf(stderr, "error: missing pcap file name(s)\n");
            return usage(argv[0]);
        }

        /* check if multiple files have been specified on the command line */
        if (argc > 2) {
           multi_file_input = 1;
        }

        /* check if a directory has been specified as the input file
         * and the output is not going to STDOUT
         */
        if ((stat(argv[1], &sb) == 0 && S_ISDIR(sb.st_mode)) && (glb_config->filename)) {
           multi_file_input = 1;
        }

        /* close out the existing open output file and remove it */
        if (glb_config->filename) {
            zclose(ctx->output);
            memset_s(output_filename, MAX_FILENAME_LEN, 0x00, MAX_FILENAME_LEN);
            snprintf(output_filename, MAX_FILENAME_LEN,"%s",ctx->output_file_basename);
            if (remove(output_filename) == -1) {
                fprintf(stderr, "error:failed to remove %s\n", output_filename);
                return -1;
            }
        }

        /* loop over remaining arguments to process files */
        for (i=1+opt_count; i<argc; i++) {
            /* intialize the data structures */
            memset_s(ctx, sizeof(joy_ctx_data), 0x00, sizeof(joy_ctx_data));
            if (glb_config->filename == NULL) {
                ctx->output = zattach(stdout, "w");
            }
            flow_record_list_init(ctx);
            flocap_stats_timer_init(ctx);

            if (stat(argv[i], &sb) == 0 && S_ISDIR(sb.st_mode)) {
                /* processing an input directory */
		tmp_ret = strnlen_s(argv[i], (MAX_FILENAME_LEN*2));
		if (tmp_ret == 0 || tmp_ret >= (MAX_FILENAME_LEN*2)) {
		    fprintf(stderr, "error:failed filename too long %s\n", argv[i]);
		    return -1;
		}
                tmp_ret = process_directory_of_files(ctx, argv[i]);
                if (tmp_ret < 0) {
                    return tmp_ret;
                }
            } else {
                /* check for multi-file input processing via command line */
                if (multi_file_input) {
                    tmp_ret = process_multiple_input_files(ctx, argv[i],i);
                    if (tmp_ret < 0) {
                        return tmp_ret;
                    }
                } else {
                    tmp_ret = process_single_input_file(ctx, argv[i]);
                    if (tmp_ret < 0) {
                        return tmp_ret;
                    }
                }
            }
        }
    }

    if (joy_mode != MODE_OFFLINE) {
        for (ctx_counter=0; ctx_counter < init_data.contexts; ++ctx_counter) {
	    joy_print_flocap_stats_output(ctx_counter);
        }
    }

    /* shutdown everything */
    for (ctx_counter=0; ctx_counter < init_data.contexts; ++ctx_counter) {
        joy_context_cleanup(ctx_counter);
    }
    joy_shutdown();
    return 0;
}


/**
 * \fn int process_pcap_file (int index, char *file_name, char *filter_exp, bpf_u_int32 *net, struct bpf_program *fp)
 * \brief process pcap packet data from a given file
 * \param index of the context to use
 * \param file_name name of the file with pcap data in it
 * \param filter_exp filter to use
 * \param net
 * \param fp
 * \return -1 could not open pcap file error
 * \return -2 could not parse filter error
 * \return -3 could not install filter
 * \return 0 success
 */
int process_pcap_file (int index, char *file_name, const char *filtr_exp, bpf_u_int32 *net, struct bpf_program *fp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int more = 1;
    uint64_t idx = index;

    joy_log_info("reading pcap file %s", file_name);

    handle = pcap_open_offline(file_name, errbuf);
    if (handle == NULL) {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", file_name, errbuf);
        return -1;
    }

    if (filtr_exp) {

        /* compile the filter expression */
        if (pcap_compile(handle, fp, filtr_exp, 0, *net) == -1) {
            fprintf(stderr, "error: could not parse filter %s: %s\n",
                    filtr_exp, pcap_geterr(handle));
            return -2;
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, fp) == -1) {
            fprintf(stderr, "error: could not install filter %s: %s\n",
                    filtr_exp, pcap_geterr(handle));
            return -3;
        }
    }

    while (more) {
        /* Loop over all packets in capture file */
        more = pcap_dispatch(handle, NUM_PACKETS_IN_LOOP, joy_libpcap_process_packet, (unsigned char *)idx);
        /* Print out expired flows */
        joy_print_flow_data(index, JOY_EXPIRED_FLOWS);
    }

    joy_log_info("all flows processed");

    /* Cleanup */
    if (filtr_exp) {
        pcap_freecode(fp);
    }

    pcap_close(handle);
    joy_print_flow_data(index, JOY_ALL_FLOWS);
    return 0;
}
