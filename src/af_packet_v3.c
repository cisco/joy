/*
 * ring_fanout_capture.c
 *
 * test program for AF_PACKET, RX_RING, and FANOUT
 *
 */

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
#include <pwd.h>
#include <grp.h>

#include "safe_lib.h"
#include "af_packet_v3.h"
#include "utils.h"

/*
 * drop_root_privileges() returns 0 on success and -1 on failure
 */
enum status drop_root_privileges(const char *username, const char *directory) {
    gid_t gid;
    uid_t uid;
    const char *new_username;
    struct passwd *userdata = NULL;

    if (username == NULL) {

        /*
         * if we are not root, we have nothing to do
         */
        if (getuid() != 0) {
            return status_ok;
        }

        /*
         * set new user's UID, GID, and username from environment variables
         */
        uid = getuid();
        if (uid == 0) {
            const char *sudo_uid = getenv("SUDO_UID");
            if (sudo_uid == NULL) {
                printf("environment variable `SUDO_UID` not found\n");
                return status_err;
            }
            errno = 0;
            uid = (uid_t) strtoll(sudo_uid, NULL, 10);
            if (errno) {
                perror("error converting SUDO_UID to int");
                return status_err;
            }
        }

        gid = getgid();
        if (gid == 0) {
            const char *sudo_gid = getenv("SUDO_GID");
            if (sudo_gid == NULL) {
                printf("environment variable SUDO_GID not found\n");
                return status_err;
            }
            errno = 0;
            gid = (gid_t) strtoll(sudo_gid, NULL, 10);
            if (errno) {
                perror("error converting SUDO_GID to int");
                return status_err;
            }
        }

        new_username = getenv("SUDO_USER");
        if (new_username == NULL) {
            printf("environment variable `SUDO_USER` not found\n");
            return status_err;
        }

    } else {
        userdata = getpwnam(username);
        if (userdata) {
            new_username = userdata->pw_name;
            gid = userdata->pw_gid;
            uid = userdata->pw_uid;
        } else {
            printf("%s: could not find user '%.32s'", strerror(errno), username);
            return status_err;
        }
    }


    /*
     * set gid, uid and groups
     */
    if (initgroups(new_username, gid)) {
        perror("error setting groups");
        return status_err;
    }
    if (setgid(gid)) {
        perror("error setting GID");
        return status_err;
    }
    if (setuid(uid)) {
        perror("error setting UID");
        return status_err;
    }

    /*
     * check to make sure that we achieved our goals
     */
    if (setuid(0) == 0 || seteuid(0) == 0) {
        printf("failed to drop root privileges\n");
        return status_err;
    }

    /*
     * change working directory to a non-root one, if asked
     */
    if (directory) {
      if (chdir(directory) != 0) {
        perror("error changing current working directory");
        return status_err;
      }
    }

    return status_ok;
}


/*
 * == Signal handling ==
 *
 * We need the stats tracking thread to end before we stop processing
 * packets or else we run the risk of exiting the packet processing
 * loops and then later measuring "false" drops on those sockets right
 * at the end.  To that end, the stats tracking will watch
 * sig_close_flag and the packet worker threads will watch
 * sig_close_workers.
 */
int sig_close_flag = 0; /* Watched by the stats tracking thread */
int sig_close_workers = 0; /* Packet proccessing var */

extern void sig_close(int signal_arg);

extern void joy_handler_function(void *handler_ctx, struct packet_info *pi, uint8_t *eth);

/* A dummy callback function that just discards packet info */
void dummy_callback(const struct packet_info *pi, const uint8_t *packet) {
  (void)pi;
  (void)packet;
  return;
}

/*
 * packet_fprintf(packet, length) prints out the flow key of the
 * ethernet/ipv4 packet at the location passed in.
 *
 */
void print_packet(const struct packet_info *pi, const uint8_t *packet) {
  double when = pi->ts.tv_sec + (pi->ts.tv_nsec / 1000000000.0);
  unsigned int l3_proto = (((uint8_t *)packet)[12] << 8) | ((uint8_t *)packet)[13];
  packet += 14;
  uint32_t *ip = (uint32_t *)packet;
  uint8_t uint32s_in_header = (((uint8_t *)packet)[0] & 0x0f);
  uint32_t *src_addr = ip + 3;
  uint32_t *dst_addr = ip + 4;
  uint8_t  *src_addr_char = (uint8_t *)src_addr;
  uint8_t  *dst_addr_char = (uint8_t *)dst_addr;
  uint32_t *tcp = ip + uint32s_in_header;
  uint16_t *src_port = (uint16_t *)tcp;
  uint16_t *dst_port = src_port + 1;

  if (l3_proto != 0x0800 || pi->caplen < 44) {
    fprintf(stderr, "not an ipv4/[tcp,udp] packet\n");
    return;
  }

  const char *format __attribute__((unused))= "%u.%u.%u.%u, %u.%u.%u.%u, %u, %u, %u\n";
  const char *json_format = "{\"time\":\"%f\",\"sa\":\"%u.%u.%u.%u\",\"da\":\"%u.%u.%u.%u\",\"sp\":%u,\"dp\":%u,\"len\":%u}\n";

  fprintf(stderr, json_format,
	  when,
	  src_addr_char[0],
	  src_addr_char[1],
	  src_addr_char[2],
	  src_addr_char[3],
	  dst_addr_char[0],
	  dst_addr_char[1],
	  dst_addr_char[2],
	  dst_addr_char[3],
	  ntohs(*src_port),
	  ntohs(*dst_port),
	  pi->caplen);
}



void af_packet_stats(int sockfd, struct stats_tracking *statst) {
  int err;
  struct tpacket_stats_v3 tp3_stats;

  socklen_t tp3_len = sizeof(tp3_stats);
  err = getsockopt(sockfd, SOL_PACKET, PACKET_STATISTICS, &tp3_stats, &tp3_len);
  if (err) {
    perror("error: could not get packet statistics");
  }

  if (statst != NULL) {
    statst->socket_packets += tp3_stats.tp_packets;
    statst->socket_drops += tp3_stats.tp_drops;
    statst->socket_freezes += tp3_stats.tp_freeze_q_cnt;
  }
}


int get_interface_number_by_device_name(int socketfd, const char *interface_name) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), interface_name, sizeof(ifr.ifr_name)) != 0) {
    printf("error: problem with interface name\n");
    return -1;
  }
  
  if (ioctl(socketfd, SIOCGIFINDEX, &ifr) == -1) {
    perror("ioctl interface index error");
    return -1;
  }

  return ifr.ifr_ifindex;
}


void process_all_packets_in_block(struct tpacket_block_desc *block_hdr,
				  struct stats_tracking *statst,
				  struct frame_handler *handler) {
  int num_pkts = block_hdr->hdr.bh1.num_pkts, i;
  unsigned long byte_count = 0;
  struct tpacket3_hdr *pkt_hdr;
  //struct timespec ts;
  struct packet_info pi;

  pkt_hdr = (struct tpacket3_hdr *) ((uint8_t *) block_hdr + block_hdr->hdr.bh1.offset_to_first_pkt);
  for (i = 0; i < num_pkts; ++i) {
    byte_count += pkt_hdr->tp_snaplen;

    /* Grab the times */
    pi.ts.tv_sec = pkt_hdr->tp_sec;
    pi.ts.tv_nsec = pkt_hdr->tp_nsec;

    pi.caplen = pkt_hdr->tp_snaplen;
    pi.len = pkt_hdr->tp_snaplen; // Is this right??

    uint8_t *eth = (uint8_t *)pkt_hdr + pkt_hdr->tp_mac;
    //print_packet(&pi, eth);
    //pc(&pi, eth);

    handler->func(&handler->context, &pi, eth);
    
    pkt_hdr = (struct tpacket3_hdr *) ((uint8_t *)pkt_hdr + pkt_hdr->tp_next_offset);
  }

  /* Atomic operations
   * https://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Atomic-Builtins.html
   */
  __sync_add_and_fetch(&(statst->received_packets), num_pkts);
  __sync_add_and_fetch(&(statst->received_bytes), byte_count);
}


void *stats_thread_func(void *statst_arg) {

    struct stats_tracking *statst = (struct stats_tracking *)statst_arg;

  /* The stats thread is one of the first to get started and it has to wait
   * for the other threads otherwise we'll be tracking bogus stats
   * until they get up to speed
   */
  int err;
  err = pthread_mutex_lock(statst->t_start_m);
  if (err != 0) {
    fprintf(stderr, "%s: error locking clean start mutex for stats thread\n", strerror(err));
    exit(255);
  }
  while (*(statst->t_start_p) != 1) {
    err = pthread_cond_wait(statst->t_start_c, statst->t_start_m);
    if (err != 0) {
      fprintf(stderr, "%s: error waiting on clean start condition for stats thread\n", strerror(err));
      exit(255);
    }
  }
  err = pthread_mutex_unlock(statst->t_start_m);
  if (err != 0) {
    fprintf(stderr, "%s: error unlocking clean start mutex for stats thread\n", strerror(err));
    exit(255);
  }

  while (sig_close_flag == 0) {
    int thread = 0;
    uint64_t packets_before = statst->received_packets;
    uint64_t bytes_before = statst->received_bytes;
    uint64_t socket_packets_before = statst->socket_packets;
    uint64_t socket_drops_before = statst->socket_drops;
    uint64_t socket_freezes_before = statst->socket_freezes;

    sleep(1);
    for (thread = 0; thread < statst->num_threads; thread++) {
      af_packet_stats(statst->tstor[thread].sockfd, statst);
    }

    uint64_t pps = statst->received_packets - packets_before;
    uint64_t bps = statst->received_bytes - bytes_before;
    uint64_t spps = statst->socket_packets - socket_packets_before;
    uint64_t sdps = statst->socket_drops - socket_drops_before;
    uint64_t sfps = statst->socket_freezes - socket_freezes_before;

    fprintf(stderr,
	    "Per second stats: "
	    "recieved packets %8lu; recieved bytes %10lu; "
	    "socket packets %8lu; socket drops %8lu; socket freezes %2lu\n",
	    pps, bps, spps, sdps, sfps);
  }

  return NULL;
}


/*
 * The function af_packet_rx_ring_fanout_capture() sets up an
 * AF_PACKET socket with a memory-mapped RX_RING and FANOUT, then
 * performs a packet capture.  Reference docs:
 *
 *  http://yusufonlinux.blogspot.ru/2010/11/data-link-access-and-zero-copy.html
 *  https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
 */

int create_dedicated_socket(struct thread_storage *thread_stor, int fanout_arg) {
  unsigned int i;
  int err;
  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sockfd == -1) {
      fprintf(stderr, "%s: could not create AF_PACKET socket for thread %d\n", strerror(errno), thread_stor->tnum);
    return -1;
  }
  /* Now store this socket file descriptor in the thread storage */
  thread_stor->sockfd = sockfd;

  /*
   * set AF_PACKET version to V3, which is more performant, as it
   * reads in blocks of packets, not single packets
   */
  int version = TPACKET_V3;
  err = setsockopt(sockfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
  if (err) {
    perror("could not set socket to tpacket_v3 version");
    return -1;
  }

  /*
   * get the number for the interface on which we want to capture packets
   */
  int interface_number = get_interface_number_by_device_name(sockfd, thread_stor->if_name);
  if (interface_number == -1) {
    fprintf(stderr, "Can't get interface number by interface name (%s) for thread %d\n", thread_stor->if_name, thread_stor->tnum);
    return -1;
  }

  /*
   * set interface to PROMISC mode
   */
  struct packet_mreq sock_params;
  memset(&sock_params, 0, sizeof(sock_params));
  sock_params.mr_type = PACKET_MR_PROMISC;
  sock_params.mr_ifindex = interface_number;
  err = setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&sock_params, sizeof(sock_params));
  if (err) {
    fprintf(stderr, "could not enable promiscuous mode for thread %d\n", thread_stor->tnum);
    return -1;
  }

  /*
   * set up RX_RING
   */
  fprintf(stderr, "Requesting PACKET_RX_RING with %u bytes (%d blocks of size %d) for thread %d\n",
	  thread_stor->ring_params.tp_block_size * thread_stor->ring_params.tp_block_nr,
	  thread_stor->ring_params.tp_block_nr, thread_stor->ring_params.tp_block_size, thread_stor->tnum);
  err = setsockopt(sockfd, SOL_PACKET, PACKET_RX_RING, (void*)&(thread_stor->ring_params), sizeof(thread_stor->ring_params));
  if (err == -1) {
    perror("could not enable RX_RING for AF_PACKET socket");
    return -1;
  }

  /*
   * each thread has its own mmaped buffer
   */
  uint8_t *mapped_buffer = (uint8_t*)mmap(NULL, thread_stor->ring_params.tp_block_size * thread_stor->ring_params.tp_block_nr,
					  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
					  sockfd, 0);
  if (mapped_buffer == MAP_FAILED) {
      fprintf(stderr, "%s: mmap failed for thread %d\n", strerror(errno), thread_stor->tnum);
    return -1;
  }

  /* Now store this mmap()'d region in the thread storage */
  thread_stor->mapped_buffer = mapped_buffer;

  /*
   * The start of each block is a struct tpacket_block_desc so make
   * array of pointers to the start of each block struct
   */
  struct tpacket_block_desc **block_header = (struct tpacket_block_desc**)malloc(thread_stor->ring_params.tp_block_nr * sizeof(struct tpacket_hdr_v1 *));
  if (block_header == NULL) {
    fprintf(stderr, "error: could not allocate block_header pointer array for thread %d\n", thread_stor->tnum);
  }

  /* Now store this block pointer array the thread storage */
  thread_stor->block_header = block_header;


  for (i = 0; i < thread_stor->ring_params.tp_block_nr; ++i) {
    block_header[i] = (struct tpacket_block_desc *)(mapped_buffer + (i * thread_stor->ring_params.tp_block_size));
  }

  /*
   * bind to interface
   */
  struct sockaddr_ll bind_address;
  memset(&bind_address, 0, sizeof(bind_address));
  bind_address.sll_family = AF_PACKET;
  bind_address.sll_protocol = htons(ETH_P_ALL);
  bind_address.sll_ifindex = interface_number;
  err = bind(sockfd, (struct sockaddr *)&bind_address, sizeof(bind_address));
  if (err) {
    fprintf(stderr, "could not bind interface %s to AF_PACKET socket for thread %d\n", thread_stor->if_name, thread_stor->tnum);
    return -1;
  }

  /*
   * set up fanout (each thread gets some portion of packets)
   */


  err = setsockopt(sockfd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
  if (err) {
    perror("error: could not configure fanout");
    return -1;
  }

  return 0;
}


int af_packet_rx_ring_fanout_capture(struct thread_storage *thread_stor) {

  unsigned int b;
  int err;
  /* At this point this thread is ready to go
   * but we need to wait for all the other threads to be ready too
   * so we'll wait on a condition broadcast from the main thread to
   * let us know we can go
   */
  err = pthread_mutex_lock(thread_stor->t_start_m);
  if (err != 0) {
    fprintf(stderr, "%s: error locking clean start mutex for thread %lu\n", strerror(err), thread_stor->tid);
    exit(255);
  }
  while (*(thread_stor->t_start_p) != 1) {
    err = pthread_cond_wait(thread_stor->t_start_c, thread_stor->t_start_m);
    if (err != 0) {
      fprintf(stderr, "%s: error waiting on clean start condition for thread %lu\n", strerror(err), thread_stor->tid);
      exit(255);
    }
  }
  err = pthread_mutex_unlock(thread_stor->t_start_m);
  if (err != 0) {
    fprintf(stderr, "%s: error unlocking clean start mutex for thread %lu\n", strerror(err), thread_stor->tid);
    exit(255);
  }

  /* get local copies from the thread_stor struct so we can skip
   * pointer dereferences each time we access one
   */
  int sockfd = thread_stor->sockfd;
  struct tpacket_block_desc **block_header = thread_stor->block_header;
  struct stats_tracking *statst = thread_stor->statst;
  //packet_callback_t p_callback = thread_stor->p_callback;
  struct frame_handler *handler = &thread_stor->handler;
  
  /* We got the clean start all clear so we can get started but
   * while we were waiting our socket was filling up with packets
   * and drops were accumulating so we need to return everything to
   * the kernel
   */
  uint32_t thread_block_count = thread_stor->ring_params.tp_block_nr;
  af_packet_stats(sockfd, NULL); // Discard bogus stats
  for (b = 0; b < thread_block_count; b++) {
    if ((block_header[b]->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
      continue;
    }
    else {
      block_header[b]->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }
  }
  af_packet_stats(sockfd, NULL); // Discard bogus stats

  fprintf(stderr, "Thread %d with thread id %lu started...\n", thread_stor->tnum, thread_stor->tid);

  /*
   * The kernel keeps a pointer to one of the blocks in the ringbuffer
   * (starting at 0) and every time the kernel fills a block and
   * returns it to userspace (by setting block_status to
   * TP_STATUS_USER) the kernel increments (modulo the number of
   * blocks) the block pointer.
   *
   * The tricky & undocumented bit is that if the kernel's block
   * pointer ever ends up pointing at a block that isn't marked
   * TP_STATUS_KERNEL the kernel will freeze the queue and discard
   * packets until the block it is pointing at is returned back to the
   * kernel.  See kernel-src/net/packet/af_packet.c for details of the
   * queue freezing behavior.
   *
   * This means that in a worst-case scenario, only a single block in
   * the ringbuffer could be marked for userspace and the kernel could
   * get stuck on that block and throw away packets even though the
   * entire rest of the ringbuffer is free to use.  The kernel DOES
   * NOT go hunt for free blocks to use if the current one is taken.
   *
   * The following loop tries to keep the current block (cb) pointed
   * to the block that the kernel is about to return, and then
   * increment to the next block the kernel will return, and so
   * forth. If for some reason they get out of sync, the kernel can
   * get stuck and freeze the queue while we can get stuck trying to
   * check the wrong block to see if it has returned yet.
   *
   * To address this case, we count how many times poll() has returned
   * saying data is ready (pstreak) but we haven't gotten any new
   * data.  If this happens a few times in a row it likely means we're
   * checking the wrong block and the kernel has frozen the queue and
   * is stuck on another block.  The fix is to increment our block
   * pointer to go find the block the kernel is stuck on.  This will
   * quickly move this thread and the kernel back into sync.
   */

  struct pollfd psockfd;
  memset(&psockfd, 0, sizeof(psockfd));
  psockfd.fd = sockfd;
  psockfd.events = POLLIN | POLLERR;
  psockfd.revents = 0;

  int pstreak = 0;
  int polret;
  unsigned int cb = 0;
  while (sig_close_workers == 0) {

    if ((block_header[cb]->hdr.bh1.block_status & TP_STATUS_USER) == 0) {

      polret = poll(&psockfd, 1, 1000); /* Let poll wait up to a second */
      if (polret < 0) {
	perror("poll returned error");
      } else if (polret > 0) {
	pstreak++; /* This wasn't a timeout */
      }

      /* If poll() has returned but we haven't found any data... */
      if (pstreak > 2) {
	cb = (cb + 1) % thread_block_count; /* Go find the block the kernel is stuck on */
      }
      continue;
    }

    /* We found data! */
    pstreak = 0; /* Reset the poll streak tracking */
    process_all_packets_in_block(block_header[cb], statst, handler);
    block_header[cb]->hdr.bh1.block_status = TP_STATUS_KERNEL;

    cb = (cb + 1) % thread_block_count;
  }

  fprintf(stderr, "Thread %d with thread id %lu exiting...\n", thread_stor->tnum, thread_stor->tid);
  return 0;
}


void *packet_capture_thread_func(void *arg)  {
  struct thread_storage *thread_stor = (struct thread_storage *)arg;

  if (af_packet_rx_ring_fanout_capture(thread_stor) < 0) {
    fprintf(stdout, "error: could not perform packet capture\n");
    exit(255);
  }
  return NULL;
}


int af_packet_bind_and_dispatch(struct mercury_config *cfg,
				const struct ring_limits *rlp) {
  int thread = 0;
  int err;
  int num_threads = cfg->num_threads;
  int fanout_arg = ((getpid() & 0xffff) | (rlp->af_fanout_type << 16));

  /* We need all our threads to get a clean start at the same time or
   * else some threads will start working before other threads are ready
   * and this makes a mess of drop counters and gets in the way of
   * dropping privs and other such things that need to happen in a
   * coordinated manner. We pass a pointer to these via the thread
   * storage struct.
   */
  int t_start_p = 0;
  pthread_cond_t t_start_c  = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t t_start_m = PTHREAD_MUTEX_INITIALIZER;

  struct stats_tracking statst;
  memset(&statst, 0, sizeof(statst));
  statst.num_threads = num_threads;
  statst.t_start_p = &t_start_p;
  statst.t_start_c = &t_start_c;
  statst.t_start_m = &t_start_m;

  struct thread_storage *tstor;  // Holds the array of struct thread_storage, one for each thread
  tstor = (struct thread_storage *)malloc(num_threads * sizeof(struct thread_storage));
  if (!tstor) {
    perror("could not allocate memory for strocut thread_storage array\n");
  }
  statst.tstor = tstor; // The stats thread needs to know how to access the socket for each packet worker

  /* Now that we know how many threads we will have, we need
   * to figure out what our ring parameters will be */
  uint32_t thread_ring_size;
  if (rlp->af_desired_memory / num_threads > rlp->af_ring_limit) {
    thread_ring_size = rlp->af_ring_limit;
    fprintf(stderr, "Notice: desired memory exceedes %x memory for %d threads\n", rlp->af_ring_limit, num_threads);
  } else {
    thread_ring_size = rlp->af_desired_memory / num_threads;
  }

  /* If the number of blocks is fewer than our target
   * decrease the block size to increase the block count
   */
  uint32_t thread_ring_blocksize = rlp->af_blocksize;
  while (((thread_ring_blocksize >> 1) >= rlp->af_min_blocksize) &&
	 (thread_ring_size / thread_ring_blocksize < rlp->af_target_blocks)) {
    thread_ring_blocksize >>= 1; /* Halve the blocksize */
  }
  uint32_t thread_ring_blockcount = thread_ring_size / thread_ring_blocksize;
  if (thread_ring_blockcount < rlp->af_min_blocks) {
    fprintf(stderr, "Error: only able to allocate %u blocks per thread (minimum %u)\n", thread_ring_blockcount, rlp->af_min_blocks);
    exit(255);
  }

  /* blocks must be a multiple of the framesize */
  if (thread_ring_blocksize % rlp->af_framesize != 0) {
    fprintf(stderr, "Error: computed thread blocksize (%u) is not a multiple of the framesize (%u)\n", thread_ring_blocksize, rlp->af_framesize);
    exit(255);
  }

  if ((uint64_t)num_threads * (uint64_t)thread_ring_blockcount * (uint64_t)thread_ring_blocksize < rlp->af_desired_memory) {
    fprintf(stderr, "Notice: requested memory %lu will be less than desired memory %lu\n",
	    (uint64_t)num_threads * (uint64_t)thread_ring_blockcount * (uint64_t)thread_ring_blocksize, rlp->af_desired_memory);
  }

  /* Fill out the ring request struct */
  struct tpacket_req3 thread_ring_req;
  memset(&thread_ring_req, 0, sizeof(thread_ring_req));
  thread_ring_req.tp_block_size = thread_ring_blocksize;
  thread_ring_req.tp_frame_size = rlp->af_framesize;
  thread_ring_req.tp_block_nr = thread_ring_blockcount;
  thread_ring_req.tp_frame_nr = (thread_ring_blocksize * thread_ring_blockcount) / rlp->af_framesize;
  thread_ring_req.tp_retire_blk_tov = rlp->af_blocktimeout;
  thread_ring_req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
  
  /* Get all the thread storage ready and allocate the sockets */
  for (thread = 0; thread < num_threads; thread++) {
    /* Init the thread storage for this thread */
    //tstor[thread].p_callback = p_callback;
      tstor[thread].tnum = thread;
      tstor[thread].tid = 0;
      tstor[thread].sockfd = -1;
      tstor[thread].if_name = cfg->capture_interface;
      tstor[thread].statst = &statst;
      tstor[thread].t_start_p = &t_start_p;
      tstor[thread].t_start_c = &t_start_c;
      tstor[thread].t_start_m = &t_start_m;
      tstor[thread].handler.func = joy_handler_function;
      tstor[thread].handler.context.joy_data.thread_id = thread;

      memcpy(&(tstor[thread].ring_params), &thread_ring_req, sizeof(thread_ring_req));

      err = create_dedicated_socket(&(tstor[thread]), fanout_arg);

      if (err != 0) {
	  fprintf(stderr, "error creating dedicated socket for thread %d\n", thread);
	  exit(255);
      }
  }

  /* drop privileges from root to normal user */
  if (drop_root_privileges(cfg->user, NULL) != status_ok) {
      return status_err;
  }
  printf("dropped root privileges\n");

  /* Start up the threads */
  pthread_t stats_thread;
  err = pthread_create(&stats_thread, NULL, stats_thread_func, &statst);
  if (err != 0) {
    perror("error creating stats thread");
  }

  for (thread = 0; thread < num_threads; thread++) {
    pthread_attr_t thread_attributes;
    err = pthread_attr_init(&thread_attributes);
    if (err) {
      fprintf(stderr, "%s: error initializing attributes for thread %u\n", strerror(err), thread);
      exit(255);
    }

    err = pthread_create(&(tstor[thread].tid), &thread_attributes, packet_capture_thread_func, &(tstor[thread]));
    if (err) {
      fprintf(stderr, "%s: error creating af_packet capture thread %u\n", strerror(err), thread);
      exit(255);
    }
  }

  /* At this point all threads are started but they're waiting on
     the clean start condition
  */
  t_start_p = 1;
  err = pthread_cond_broadcast(&(t_start_c)); // Wake up all the waiting threads
  if (err != 0) {
    printf("%s: error broadcasting all clear on clean start condition\n", strerror(err));
    exit(255);
  }

  /* Wait for the stats thread to close (which only happens on a sigint/sigterm) */
  pthread_join(stats_thread, NULL);

  /* stats tracking closed, let the packet processing workers know */
  sig_close_workers = 1;

  /* wait for each thread to exit */
  for (thread = 0; thread < num_threads; thread++) {
    pthread_join(tstor[thread].tid, NULL);
  }

  /* free up resources */
  for (thread = 0; thread < num_threads; thread++) {
    free(tstor[thread].block_header);
    munmap(tstor[thread].mapped_buffer, tstor[thread].ring_params.tp_block_size * tstor[thread].ring_params.tp_block_nr);
    close(tstor[thread].sockfd);
  }
  free(tstor);

  fprintf(stderr, "--\n"
	  "%lu packets captured\n"
	  "%lu bytes captured\n"
	  "%lu packets seen by socket\n"
	  "%lu packets dropped\n"
	  "%lu socket queue freezes\n",
	  statst.received_packets, statst.received_bytes, statst.socket_packets, statst.socket_drops, statst.socket_freezes);

  return 0;
}

#define RING_LIMITS_DEFAULT_FRAC 0.01

void ring_limits_init(struct ring_limits *rl, float frac) {

    if (frac < 0.0 || frac > 1.0 ) { /* sanity check */
	frac = RING_LIMITS_DEFAULT_FRAC;
    }
    
    /* This is the only parameter you should need to change */
    rl->af_desired_memory = sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) * frac;
    //rl->af_desired_memory = 128 * (uint64_t)(1 << 30);  /* 8 GiB */
    printf("mem: %lu\tfrac: %f\n", rl->af_desired_memory, frac); 

    /* Don't change any of the following parameters without good reason */
    rl->af_ring_limit     = 0xffffffff;      /* setsockopt() can't allocate more than this so don't even try */
    rl->af_framesize      = 2  * (1 << 10);  /* default in docs is 2 KiB, don't go lower than this */
    rl->af_blocksize      = 4  * (1 << 20);  /* 4 MiB (MUST be a multiple of af_framesize) */
    rl->af_min_blocksize  = 64 * (1 << 10);  /* 64 KiB is the smallest we'd ever want to go */
    rl->af_target_blocks  = 64;              /* Fewer than this and we'll decrease the block size to get more blocks */
    rl->af_min_blocks     = 8;               /* 8 is a reasonable absolute minimum */
    rl->af_blocktimeout   = 100;             /* milliseconds before a block is returned partially full */
    rl->af_fanout_type    = PACKET_FANOUT_HASH;

}
