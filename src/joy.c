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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#ifdef WIN32
#include "win_types.h"
#include "Ws2tcpip.h"
#else 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>    
#include <netinet/in.h>
#endif

#include <limits.h>  
#include <getopt.h>
#include <unistd.h>   
#include <pthread.h>    

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
#include "updater.h"    /* updater thread for classifer and label subnets */
#include "ipfix.h"    /* IPFIX cleanup */
#include "pcap.h"

enum operating_mode {
    mode_none = 0,
    mode_offline = 1,
    mode_online = 2,
    mode_ipfix_collect_online = 3
};

/* some globals defined in p2f.c */

extern enum SALT_algorithm salt_algo;

extern radix_trie_t rt;

extern struct flocap_stats stats;

extern struct timeval time_window;

extern struct timeval active_timeout;

extern unsigned int active_max;

extern unsigned short compact_bd_mapping[16];

/* configuration state */

extern unsigned int bidir;

extern unsigned int include_zeroes;

extern unsigned int byte_distribution;

extern char *compact_byte_distribution;

extern unsigned int report_entropy;

extern unsigned int report_idp;

extern unsigned int report_hd;

extern unsigned int include_classifier;

extern unsigned int nfv9_capture_port;

extern unsigned int ipfix_collect_port;

extern unsigned int ipfix_collect_online;

extern unsigned int ipfix_export_port;

extern unsigned int ipfix_export_remote_port;

extern char *ipfix_export_remote_host;

extern char *ipfix_export_template;

extern char *aux_resource_path;

extern zfile output;

extern FILE *info;

extern unsigned int records_in_file;

extern unsigned int verbosity;

define_all_features_config_extern_uint(feature_list)

/*
 * config is the global configuration 
 */
extern struct configuration config;



/* BEGIN utility functions */
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
    unsigned char friendly_name[IFNAMSIZ];
    unsigned char ip_addr[INET6_ADDRSTRLEN];
    unsigned char active;
};

static unsigned int interface_list_get(struct intrface ifl[IFL_MAX]) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	unsigned int num_ifs = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	//if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return num_ifs;
	}

	/* Print the list */
	fprintf(info, "\nInterfaces\n");
	fprintf(info, "==========\n");
	for (d = alldevs; d; d = d->next) {
		char ip_string[INET6_ADDRSTRLEN];
		pcap_addr_t *dev_addr = NULL; //interface address that used by pcap_findalldevs()

		/* check if the device is suitable for live capture */
		for (dev_addr = d->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
                       if ((dev_addr->addr->sa_family == AF_INET || dev_addr->addr->sa_family == AF_INET6) && dev_addr->addr && dev_addr->netmask) {
                                memset(ip_string, 0x00, INET6_ADDRSTRLEN);
                                if (dev_addr->addr->sa_family == AF_INET6) {
                                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)dev_addr->addr)->sin6_addr, ip_string, INET6_ADDRSTRLEN);
                                } else {
                                        inet_ntop(AF_INET, &((struct sockaddr_in *)dev_addr->addr)->sin_addr, ip_string, INET_ADDRSTRLEN);
                                }
				memset(&ifl[num_ifs], 0x00, sizeof(struct intrface));
				snprintf((char*)ifl[num_ifs].name, INTFACENAMESIZE, "%s", d->name);
				snprintf((char*)ifl[num_ifs].friendly_name, IFNAMSIZ, "intf%d", num_ifs);
				snprintf((char*)ifl[num_ifs].ip_addr, INET6_ADDRSTRLEN, "%s", (unsigned char*)ip_string);
				ifl[num_ifs].active = IFF_UP;
				fprintf(info, "Interface: %s\n", ifl[num_ifs].friendly_name);
				fprintf(info, "  IP Address: %s\n", ifl[num_ifs].ip_addr);
				++num_ifs;
			}
		}
	}

	if (num_ifs == 0) {
		fprintf(info, "No suitable interfaces found.\n\n");
	}

	pcap_freealldevs(alldevs);
	return num_ifs;
}

#if 0
static char *raw_to_string (const void *raw, unsigned int len, char *outstr) {
    const unsigned char *raw_char = raw;
    while (len--) {
        sprintf(outstr, "%02x", *raw_char);
        raw_char++;
        outstr++;
    }
    return outstr;
}
#endif


/* END utility functions */

pcap_t *handle;		

/*
 * sig_close() causes a graceful shutdown of the program after recieving 
 * an appropriate signal
 */
static void sig_close (int signal_arg) {

    if (handle) {
      pcap_breakloop(handle);
    }
    flocap_stats_output(info);
    /*
     * flush remaining flow records, and print them even though they are
     * not expired
     */
    flow_record_list_print_json(NULL);
    zclose(output);  
    fprintf(info, "got signal %d, shutting down\n", signal_arg); 
    exit(EXIT_SUCCESS);
}


#if 0
/*
 * sig_reload() 
 */
static void sig_reload (int signal_arg) {

    if (handle) {
        pcap_breakloop(handle);
    }
    fprintf(info, "got signal %d, printing out stats and configuration\n", signal_arg); 
    flocap_stats_output(info);
    config_print(info, &config);
}
#endif

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
	   "Data feature options\n"
           "  bpf=\"expression\"           only process packets matching BPF \"expression\"\n" 
           "  zeros=1                    include zero-length data (e.g. ACKs) in packet list\n" 
           "  bidir=1                    merge unidirectional flows into bidirectional ones\n" 
           "  dist=1                     include byte distribution array\n" 
           "  cdist=F                    include compact byte distribution array using the mapping file, F\n" 
           "  entropy=1                  include byte entropy\n" 
           "  http=1                     include HTTP data\n" 
           "  exe=1                      include information about host process associated with flow\n" 
           "  classify=1                 include results of post-collection classification\n" 
           "  num_pkts=N                 report on at most N packets per flow (0 <= N < %d)\n" 
           "  type=T                     select message type: 1=SPLT, 2=SALT\n" 
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


/*
 * note: NUM_PACKETS_BETWEEN_STATS_OUTPUT *must* be a multiple of
 * NUM_PACKETS_IN_LOOP, in order for stats output to periodically take
 * place
 */
#define GET_ALL_PACKETS 0
#define NUM_PACKETS_IN_LOOP 5
#define NUM_PACKETS_BETWEEN_STATS_OUTPUT 10000
#define MAX_RECORDS 2147483647
#define MAX_FILENAME_LEN 1024

/**
 \fn int main (int argc, char **argv)
 \brief main entry point for joy
 \param argc command line argument count
 \param argv command line arguments
 \return o
 */
int main (int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE]; 
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;		
    char *filter_exp = "ip or vlan";	
    struct bpf_program fp;	
    int i;
    int c;
    int opt_count = 0;
    int tmp_ret;
    char *ifile = NULL;
    unsigned int file_count = 0;
    char filename[MAX_FILENAME_LEN];   /* output file */
    char pcap_filename[MAX_FILENAME_LEN*2];   /* output file */
    char *cli_interface = NULL; 
    char *cli_filename = NULL; 
    char *config_file = NULL;
    struct intrface ifl[IFL_MAX];
    char *capture_if = NULL;
	unsigned int num_interfaces = 0;
    unsigned int file_base_len = 0;
    unsigned int num_cmds = 0;
    unsigned int done_with_options = 0;
    struct stat sb;
    DIR *dir;
    struct dirent *ent;
    enum operating_mode mode = mode_none;
    pthread_t upd_thread;
    pthread_t uploader_thread;
    int upd_rc;
    pthread_t ipfix_cts_monitor_thread;
    int cts_monitor_thread_rc;

    /* sanity check sizeof() expectations */
    if (data_sanity_check() != ok) {
        fprintf(stderr, "error: failed data size sanity check\n");
    }

    /* sanity check arguments */
    for (i=1; i<argc; i++) {
        if (strchr(argv[i], '=')) { 
            if (done_with_options) {
	              fprintf(stderr, "error: option (%s) found after filename (%s)\n", argv[i], argv[i-1]);
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
     * set configuration from command line arguments that contain
     * LHS=RHS commands, then update argv/argc so that those arguments
     * are not subjected to any further processing
     */
    num_cmds = config_set_from_argv(&config, argv, argc);
    argv += num_cmds;
    argc -= num_cmds;
  
    /* process command line options */
    while (1) {
        int option_index = 0;
        struct option long_options[] = {
            {"help",  no_argument,         0, 'h' },
            {"xconfig", required_argument, 0, 'x' },
            {0,         0,                 0,  0  }
        };

        c = getopt_long(argc, argv, "hx:",
		            long_options, &option_index);
        if (c == -1)
            break;
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

    if (config_file) {
        /*
         * read in configuration from file; note that if we don't read in
         * a file, then the config structure will use the static defaults
         * set when it was declared
         */
        config_set_from_file(&config, config_file);
    } 
    if (config_file || (num_cmds != 0)) {
        /*
         * set global variables as needed, if we got some configuration
         * commands from the config_file or from command line arguments
         */
        bidir = config.bidir;
        include_zeroes = config.include_zeroes;
        byte_distribution = config.byte_distribution;
        compact_byte_distribution = config.compact_byte_distribution;
        report_entropy = config.report_entropy;
        report_hd = config.report_hd;
        include_classifier = config.include_classifier;
        report_idp = config.idp;
        salt_algo = config.type;
        nfv9_capture_port = config.nfv9_capture_port;
        ipfix_collect_port = config.ipfix_collect_port;
        ipfix_collect_online = config.ipfix_collect_online;
        ipfix_export_port = config.ipfix_export_port;
        ipfix_export_remote_port = config.ipfix_export_remote_port;
        ipfix_export_remote_host = config.ipfix_export_remote_host;
        ipfix_export_template = config.ipfix_export_template;
        aux_resource_path = config.aux_resource_path;
        verbosity = config.verbosity;

        set_config_all_features(feature_list)

        if (config.bpf_filter_exp) {
            filter_exp = config.bpf_filter_exp;
        }
    }

    /*
     * allow some command line variables to override the config file
     */
    if (cli_filename) {
        /*
         * output filename provided on command line supersedes that
         * provided in the config file
         */
        config.filename = cli_filename;
    } 
    if (cli_interface) {
        /*
         * interface provided on command line supersedes that provided
         * in the config file
         */
        config.intface = cli_interface;
    }

    if (config.ipfix_collect_port && config.ipfix_export_port) {
        /*
         * Simultaneous IPFIX collection and exporting is not allowed
         */
        fprintf(info, "error: ipfix collection and exporting not allowed at same time\n");
        return -1;
    }

    if (config.ipfix_collect_online && !(config.ipfix_collect_port)) {
        /*
         * Cannot use online collection when the overall Ipfix collect feature is not enabled.
         */
        fprintf(info, "error: must enable IPFIX collection via ipfix_collect_port "
                      "to use ipfix_collect_online\n");
        return -1;
    }

    if (config.filename) {
        strncpy(filename, config.filename, MAX_FILENAME_LEN);
    }

    /*
     * set the operating mode to online or offline 
     */
    if (config.intface != NULL && strcmp(config.intface, NULL_KEYWORD)) {
        /* Network interface sniffing using Pcap */
        if (config.ipfix_collect_port) {
            /* Ipfix collection does not use interface sniffing */
            fprintf(info, "error: ipfix collection and interface monitoring not allowed at same time\n");
            return -1;
        }
        mode = mode_online;
    } else if (config.ipfix_collect_online) {
        /* Ipfix live collecting process */
        mode = mode_ipfix_collect_online;
    } else {
        /* Static Pcap file consumption */
        mode = mode_offline;
    }
    
    /*
     * if we are doing a live capture, get interface list, and set "info"
     * output stream to log file
     */
    if (mode == mode_online) {

        if (config.logfile && strcmp(config.logfile, NULL_KEYWORD)) {
            info = fopen(config.logfile, "a");
            if (info == NULL) {
	              fprintf(stderr, "error: could not open log file %s\n", config.logfile);
	              return -1;
            }
            fprintf(stderr, "writing errors/warnings/info/debug output to %s\n", config.logfile);
        }
    
        /*
         * cheerful message to indicate the start of a new run of the
         * daemon
         */
        fprintf(info, "--- %s initialization ---\n", argv[0]);
        flocap_stats_output(info);

        num_interfaces = interface_list_get(ifl);
    } else {
        info = stderr;
    }

    /*
     * report on running configuration (which may depend on the command
     * line, the config file, or both)
     */
    config_print(info, &config);

    if (config.params_file) {
        char params_splt[LINEMAX];
        char params_bd[LINEMAX];
        int num;
        num = sscanf(config.params_file, "%[^=:]:%[^=:\n#]", params_splt, params_bd);
        if (num != 2) {
            fprintf(info, "error: could not parse command \"%s\" into form param_splt:param_bd\n", config.params_file);
            exit(1);
        } else {
            /*
             * if no URL specified, then process local files 
             * otherwise, if we have a URL, then the updater process
             * will handle the model updates.
             */
            if (config.params_url == NULL) {
                fprintf(info, "updating classifiers from supplied model(%s)\n", config.params_file);
                update_params(SPLT_PARAM_TYPE,params_splt);
                update_params(BD_PARAM_TYPE,params_bd);
            }
        }
    }

    if (config.compact_byte_distribution) {
        FILE *fp;
        int count = 0;
        unsigned short b_value, map_b_value;

        memset(compact_bd_mapping, 0, sizeof(compact_bd_mapping));

        fp = fopen(compact_byte_distribution, "r");
        if (fp != NULL) {
            while (fscanf(fp, "%hu\t%hu", &b_value, &map_b_value) != EOF) {
	                compact_bd_mapping[b_value] = map_b_value;
	                count++;
	                if (count >= 256) {
	                    break;
	                }
            }
            fclose(fp);
        } else {
            fprintf(info, "error: could not open file %s\n", compact_byte_distribution);
            exit(1);
        }
    }

    /*
     * configure labeled subnets (which uses a radix trie to identify
     * addresses that match subnets associated with labels)
     */  
    if (config.num_subnets > 0) {
        attr_flags subnet_flag;
        enum status err;

        rt = radix_trie_alloc();
        if (rt == NULL) {
            fprintf(info, "could not allocate memory\n");
        }
        err = radix_trie_init(rt);
        if (err != ok) {
            fprintf(stderr, "error: could not initialize subnet labels (radix_trie)\n");
        }
        for (i=0; i<config.num_subnets; i++) {
            char label[LINEMAX], subnet_file[LINEMAX];
            int num;
      
            num = sscanf(config.subnet[i], "%[^=:]:%[^=:\n#]", label, subnet_file);
            if (num != 2) {
	              fprintf(info, "error: could not parse command \"%s\" into form label:subnet\n", config.subnet[i]);
	              exit(1);
            }
      
            subnet_flag = radix_trie_add_attr_label(rt, label);
            if (subnet_flag == 0) {
	              fprintf(info, "error: count not add subnet label %s to radix_trie\n", label);
	              exit(1);
            }
      
            err = radix_trie_add_subnets_from_file(rt, subnet_file, subnet_flag, info);
            if (err != ok) {
	              fprintf(info, "error: could not add labeled subnets from file %s\n", subnet_file);
	              exit(1);
            }
        }
        fprintf(info, "configured labeled subnets (radix_trie)\n");
    
    }

    if (config.anon_addrs_file != NULL) {
        if (anon_init(config.anon_addrs_file, info) == failure) {
            fprintf(info, "error: could not initialize anonymization subnets from file %s\n", 
	                config.anon_addrs_file); 
            return -1;
        }
    }

    if (config.anon_http_file != NULL) {
        if (anon_http_init(config.anon_http_file, info, mode_anonymize, ANON_KEYFILE_DEFAULT) == failure) {
            fprintf(info, "error: could not initialize HTTP anonymization from username file %s\n", 
	                config.anon_http_file); 
            return -1;
        }
    }

    if (config.filename != NULL) {
        char *outputdir;
    
        /*
         * set output directory 
         */
        if (config.outputdir) {
            outputdir = config.outputdir;
        } else {
            outputdir = ".";
        }

        /*
         * generate an "auto" output file name, based on the MAC address
         * and the current time, if we are "auto" configured
         */
        if (strncmp(config.filename, "auto", strlen("auto")) == 0) {

            if (mode == mode_online || mode == mode_ipfix_collect_online) {
	               time_t now = time(0);   
	               struct tm *t = localtime(&now);
	
                       snprintf(filename, MAX_FILENAME_LEN, "%s/flocap-h%d-m%d-s%d-D%d-M%d-Y%d", outputdir,
                           t->tm_hour, t->tm_min, t->tm_sec, t->tm_mday, t->tm_mon, t->tm_year + 1900);
           } else {
	               fprintf(info, "error: cannot use \"output = auto\" with no interface specified; use -o or -l options\n");
	               return usage(argv[0]);
           }
           fprintf(info, "auto generated output filename: %s\n", filename);
      
        } else {    
            /* set output file based on command line or config file */
      
            if (cli_filename) {
	               strncpy(filename, config.filename, MAX_FILENAME_LEN);
            } else {
	               char tmp_filename[MAX_FILENAME_LEN];
	
	               strncpy(tmp_filename, filename, MAX_FILENAME_LEN);
	               snprintf(filename,  MAX_FILENAME_LEN, "%s/%s", outputdir, tmp_filename);
            }
        }
        file_base_len = strlen(filename);
        if (config.max_records != 0) {
            snprintf(filename + file_base_len, MAX_FILENAME_LEN - file_base_len, zsuffix("%d"), file_count);
        }
        output = zopen(filename, "w");
        if (output == NULL) {
            fprintf(info, "error: could not open output file %s (%s)\n", filename, strerror(errno));
            return -1;
        }
    } else {
        output = zattach(stdout, "w");
    }
  
    if (ifile != NULL) {
        opt_count--;
        argv[1+opt_count] = ifile; 
    }

    if (config.report_tls) {
        /*
         * Load the TLS fingerprints into memory
         * for use in any mode.
         */
        if (tls_load_fingerprints()) {
            fprintf(info, "info: could not load tls_fingerprint.json file\n");
	    //            return -1;
        }
    }

    if (mode == mode_online) {   /* live capture */
        int linktype;

        /*
         * sanity check: we can't be in both offline mode and online mode
         * simultaneously
         */
        if ((argc-opt_count > 1) || (ifile != NULL)) {
            fprintf(info, "error: both interface (%s) and pcap input file (%s) specified\n",
	                    config.intface, argv[1+opt_count]);
            return usage(argv[0]);
        }

        anon_print_subnets(info);
    
        signal(SIGINT, sig_close);     /* Ctl-C causes graceful shutdown */
        signal(SIGTERM, sig_close);
        // signal(SIGHUP, sig_reload);
        // signal(SIGTSTP, sig_reload);
        //signal(SIGQUIT, sig_reload);   /* Ctl-\ causes an info dump      */

        /*
         * set capture interface as needed
         */
        if (strncmp(config.intface, "auto", strlen("auto")) == 0) {
            capture_if = (char*)ifl[0].name;
            fprintf(info, "starting capture on interface %s\n", ifl[0].friendly_name);
		}
		else {
			int i;
			for (i = 0; i < num_interfaces; ++i) {
				if (STRNCASECMP((char*)ifl[i].friendly_name, config.intface, strlen((char*)ifl[i].friendly_name)) == 0) {
					capture_if = (char*)ifl[i].name;
					break;
				}
			}
        }

		if (capture_if == NULL) {
			fprintf(info, "could not find specified capture device: %s\n", config.intface);
			return -1;
		}

        errbuf[0] = 0;
        handle = pcap_open_live(capture_if, 65535, config.promisc, 10000, errbuf);
        if (handle == NULL) {
            fprintf(info, "could not open device %s: %s\n", capture_if, errbuf);
            return -1;
        }
        if (errbuf[0] != 0) {
            fprintf(stderr, "warning: %s\n", errbuf);
        }

        /* verify that we can handle the link layer headers */
        linktype = pcap_datalink(handle);
        if (linktype != DLT_EN10MB) {
            fprintf(info, "device %s has unsupported linktype (%d)\n", 
	                capture_if, linktype);
            return -2;
        }
    
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

        /*
         * start up the updater thread
         *   updater is only active during live capture runs
         */
         upd_rc = pthread_create(&upd_thread, NULL, updater_main, (void*)&config);
         if (upd_rc) {
	            fprintf(info, "error: could not start updater thread pthread_create() rc: %d\n", upd_rc);
	            return -6;
         }

        /*
         * start up the uploader thread
         *   uploader is only active during live capture runs
         */
         if (config.upload_servername) {
             upd_rc = pthread_create(&uploader_thread, NULL, uploader_main, (void*)&config);
             if (upd_rc) {
	         fprintf(info, "error: could not start uploader thread pthread_create() rc: %d\n", upd_rc);
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
        config_print_json(output, &config);

        while(1) {
            struct timeval time_of_day, inactive_flow_cutoff;

            /* loop over packets captured from interface */
            pcap_loop(handle, NUM_PACKETS_IN_LOOP, process_packet, NULL);
      
            joy_log_info("PCAP processing loop done");

            if (config.report_exe) {
	              /*
	               * periodically obtain host/process flow data
                   * PP: Not implemented for WIN32. Need to handle
	               */ 
	              if (get_host_flow_data() != 0) {
	                  joy_log_warn("Could not obtain host/process flow data\n");
	              }
           }

           /*
            * periodically report on progress
            */
           if ((flocap_stats_get_num_packets() % NUM_PACKETS_BETWEEN_STATS_OUTPUT) == 0) {
	              flocap_stats_output(info);
           }

           /* print out inactive flows */
#ifdef WIN32
		   DWORD t;
		   t = timeGetTime();
		   time_of_day.tv_sec = t / 1000;
		   time_of_day.tv_usec = t % 1000;
#else
		   gettimeofday(&time_of_day, NULL);
#endif
           timer_sub(&time_of_day, &time_window, &inactive_flow_cutoff);

           flow_record_list_print_json(&inactive_flow_cutoff);

           if (config.filename) {
	
	              /* rotate output file if needed */
	              if (config.max_records && (records_in_file > config.max_records)) {

	                  /*
	                   * write JSON postamble
	                   */
	                  zclose(output);
	                  if (config.upload_servername) {
	                      upload_file(filename);
	                  }

	                  // printf("records: %d\tmax_records: %d\n", records_in_file, config.max_records);
	                  file_count++;
	                  if (config.max_records != 0) {
	                      snprintf(filename + file_base_len, MAX_FILENAME_LEN - file_base_len, zsuffix("%d"), file_count);
	                  }
	                  output = zopen(filename, "w");
	                  if (output == NULL) {
	                      perror("error: could not open output file");
	                      return -1;
	                  }
	                  records_in_file = 0;
	              }
      
	              /*
	               * flush out buffered debug/info/log messages on the "info" stream
	               */
	              fflush(info);
           }
           // fflush(output);
        }

        if (filter_exp) {
            pcap_freecode(&fp);
        }

        pcap_close(handle);
 

    } else if (mode == mode_ipfix_collect_online) {
        /* IPFIX live collecting process */
        signal(SIGINT, sig_close);     /* Ctl-C causes graceful shutdown */
        signal(SIGTERM, sig_close);
        //signal(SIGQUIT, sig_reload);   /* Ctl-\ causes an info dump      */

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

        flow_record_list_init();

        ipfix_collect_main();

        flow_record_list_print_json(NULL);
        fflush(info);
    } else { /* mode = mode_offline */

        if ((argc-opt_count <= 1) && (ifile == NULL)) {
            fprintf(stderr, "error: missing pcap file name(s)\n");
            return usage(argv[0]);
        }

        config_print_json(output, &config);
  
        flow_record_list_init();
        flocap_stats_timer_init();

        for (i=1+opt_count; i<argc; i++) {
    
            if (stat(argv[i], &sb) == 0 && S_ISDIR(sb.st_mode)) {
	                if ((dir = opendir(argv[i])) != NULL) {

	                    while ((ent = readdir(dir)) != NULL) {
	                        if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) {
	                            strcpy(pcap_filename, argv[i]);
	                            if (pcap_filename[strlen(pcap_filename)-1] != '/') {
		                                strcat(pcap_filename, "/");
	                            }
	                            strcat(pcap_filename, ent->d_name);
	                            tmp_ret = process_pcap_file(pcap_filename, filter_exp, &net, &fp);
	                            if (tmp_ret < 0) {
		                                return tmp_ret;
	                            }
	                        }
	                    }

	                    closedir(dir);
	                } else {
	                    /* error opening directory*/
	                    printf("Error opening directory: %s\n", argv[i]);
	                    return -1;
	                }

            } else {
	                tmp_ret = process_pcap_file(argv[i], filter_exp, &net, &fp);
	                if (tmp_ret < 0) {
	                   return tmp_ret;
	                }
            }
        }
    }

    flocap_stats_output(info);
    // config_print(info, &config);

    if (config.ipfix_export_port) {
        /* Flush any unsent exporter messages in Ipfix module */
        ipfix_export_flush_message();
    }
    /* Cleanup any leftover memory, sockets, etc. in Ipfix module */
    ipfix_module_cleanup();

    zclose(output);

    return 0;
}


/**
 * \fn int process_pcap_file (char *file_name, char *filter_exp, bpf_u_int32 *net, struct bpf_program *fp)
 * \brief process pcap packet data from a given file
 * \param file_name name of the file with pcap data in it
 * \param filter_exp filter to use
 * \param net 
 * \param fp
 * \return -1 could not open pcap file error
 * \return -2 could not parse filter error
 * \return -3 could not install filter
 * \return 0 success
 */
int process_pcap_file (char *file_name, char *filter_exp, bpf_u_int32 *net, struct bpf_program *fp) {
    char errbuf[PCAP_ERRBUF_SIZE]; 

    joy_log_info("reading pcap file %s", file_name);

    handle = pcap_open_offline(file_name, errbuf);    
    if (handle == NULL) { 
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", file_name, errbuf); 
        return -1;
    }   
	
    if (filter_exp) {
	  
        /* compile the filter expression */
        if (pcap_compile(handle, fp, filter_exp, 0, *net) == -1) {
            fprintf(stderr, "error: could not parse filter %s: %s\n",
	                filter_exp, pcap_geterr(handle));
            return -2;
        }
    
        /* apply the compiled filter */
        if (pcap_setfilter(handle, fp) == -1) {
            fprintf(stderr, "error: could not install filter %s: %s\n",
	              filter_exp, pcap_geterr(handle));
            return -3;
        }
    }
  
    /* loop over all packets in capture file */
    pcap_loop(handle, GET_ALL_PACKETS, process_packet, NULL);

    /* cleanup */
  
    joy_log_info("all flows processed");
  
    if (filter_exp) {
        pcap_freecode(fp);
    }
  
    pcap_close(handle);
  
    flow_record_list_print_json(NULL);
    flow_record_list_free();

    return 0;
}

