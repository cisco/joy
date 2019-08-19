/*
 * af_packet_v3.h
 */

#ifndef AF_PACKET_V3
#define AF_PACKET_V3

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>

#include <sys/mman.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h> /* the L2 protocols */
#include "joy_api.h"

/* ported in to compile within JOY context */

/*
 * struct mercury_config holds the configuration information for a run
 * of the program
 */
struct mercury_config {
    char *read_filename;            /* base name of pcap file to read, if any         */
    char *write_filename;           /* base name of pcap file to write, if any        */
    char *fingerprint_filename;     /* base name of fingerprint file to write, if any */
    char *capture_interface;        /* base name of interface to capture from, if any */
    int filter;                     /* indicates that packets should be filtered      */
    int flags;                      /* flags for open()                               */
    char *mode;                     /* mode for fopen()                               */
    int fanout_group;               /* identifies fanout group used by sockets        */
    float buffer_fraction;          /* fraction of phys mem used for RX_RING buffers  */
    int num_threads;                /* number of worker threads                       */
    uint64_t rotate;                /* number of records per file rotation, or 0      */
    char *user;                     /* username of account used for privilege drop   */
};

/* Information about each packet on the wire */
struct packet_info {
  struct timespec ts;   /* timestamp */
  uint32_t caplen;     /* length of portion present */
  uint32_t len;        /* length this packet (off wire) */
};

typedef void (*frame_handler_func)(void *userdata,
                                   struct packet_info *pi,
                                   uint8_t *eth);

struct pcap_file {
    int fd;
    int flags;
    unsigned int byteswap; /* boolean, indicates if swap needed after read */
    size_t buf_len;        /* number of bytes in buffer                    */
    unsigned char *w;      /* pointer to first emtpy byte in buffer        */
    unsigned char *buf_end; /* pointer to end of buffer                    */
    unsigned char *buffer; /* buffer used for disk i/o                     */
};

struct json_file {
    FILE *file;
    int64_t record_countdown;
    int64_t max_records;
    uint32_t file_num;
    char outfile_name[MAX_FILENAME_LEN];
    const char *mode;
};

struct joy_hndlr_ctx {
    uint64_t thread_id;
    uint64_t packet_cnt;
};

/*
 * struct frame_handler 'object' includes the function pointer func
 * and the context passed to that function, which may be either a
 * struct pcap_file or a FILE depending on the function to which
 * 'func' points
 *
 */
union frame_handler_context {
    struct pcap_file pcap_file;
    struct json_file json_file;
    struct joy_hndlr_ctx joy_data;
};
struct frame_handler {
    frame_handler_func func;
    union frame_handler_context context;
};

/* end of ported in items */

/* The struct that describes the limits on allocating ring memory */
struct ring_limits {
  uint64_t af_desired_memory;
  uint32_t af_ring_limit;
  uint32_t af_framesize;
  uint32_t af_blocksize;
  uint32_t af_min_blocksize;
  uint32_t af_target_blocks;
  uint32_t af_min_blocks;
  uint32_t af_blocktimeout;
  int af_fanout_type;
};


typedef void (*packet_callback_t)(const struct packet_info *,
				  const uint8_t *);
/*
 * Our stats tracking function will get a pointer to a struct
 * that has the info it needs to track stats for each thread
 * and a place to store those stats
 */
struct stats_tracking {
  struct thread_storage *tstor;
  int num_threads;
  uint64_t received_packets;
  uint64_t received_bytes;
  uint64_t socket_packets;
  uint64_t socket_drops;
  uint64_t socket_freezes;
  int *t_start_p;             /* The clean start predicate */
  pthread_cond_t *t_start_c;  /* The clean start condition */
  pthread_mutex_t *t_start_m; /* The clean start mutex */
};

/*
 * struct thread_storage stores information about each thread
 * including its thread id and socket file handle
 */
struct thread_storage {
    packet_callback_t p_callback; /* The packet callback function */
    struct frame_handler handler;
    int tnum;                 /* Thread Number */
    pthread_t tid;            /* Thread ID */
    int sockfd;               /* Socket owned by this thread */
    const char *if_name;      /* The name of the interface to bind the socket to */
    uint8_t *mapped_buffer;   /* The pointer to the mmap()'d region */
    struct tpacket_block_desc **block_header; /* The pointer to each block in the mmap()'d region */
    struct tpacket_req3 ring_params; /* The ring allocation params to setsockopt() */
    struct stats_tracking *statst;   /* A pointer to the struct with the stats counters */
    int *t_start_p;             /* The clean start predicate */
    pthread_cond_t *t_start_c;  /* The clean start condition */
    pthread_mutex_t *t_start_m; /* The clean start mutex */
};


int af_packet_bind_and_dispatch(//const char *if_name,
				//packet_callback_t p_callback,
				struct mercury_config *cfg,
				const struct ring_limits *rlp);

int af_packet_start_processing(struct mercury_config *cfg);

void ring_limits_init(struct ring_limits *rl, float frac);

#endif /* AF_PACKET_V3 */
