#ifndef _MLVPN_H
#define _MLVPN_H

#include "includes.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <math.h>
#include <ev.h>

/* Many thanks Fabien Dupont! */
#ifdef HAVE_LINUX
 /* Absolutely essential to have it there for IFNAMSIZ */
 #include <sys/types.h>
 #include <netdb.h>
 #include <linux/if.h>
#endif

#include <arpa/inet.h>

#ifdef HAVE_VALGRIND_VALGRIND_H
 #include <valgrind/valgrind.h>
#else
 #define RUNNING_ON_VALGRIND 0
#endif

#ifdef HAVE_DECL_RES_INIT
 #include <netinet/in.h>
 #include <arpa/nameser.h>
 #include <resolv.h>
#endif

#ifdef HAVE_FILTERS
 #include <pcap/pcap.h>
#endif

#include "pkt.h"
#include "buffer.h"
#include "timestamp.h"

#define MLVPN_MAXHNAMSTR 256
#define MLVPN_MAXPORTSTR 6

/* Number of packets in the queue. Each pkt is ~ 1520 */
/* 1520 * 128 ~= 24 KBytes of data maximum per channel VMSize */
#define PKTBUFSIZE 1024*4

/* tuntap interface name size */
#ifndef IFNAMSIZ
 #define IFNAMSIZ 16
#endif
#define MLVPN_IFNAMSIZ IFNAMSIZ

/* How frequently we check tunnels */
#define MLVPN_IO_TIMEOUT_DEFAULT 0.25
/* What is the maximum retry timeout */
#define MLVPN_IO_TIMEOUT_MAXIMUM 60.0
/* In case we can't open the tunnel, retry every time with previous
 * timeout multiplied by the increment.
 * Example:
 * 1st try t+0: bind error
 * 2nd try t+1: bind error
 * 3rd try t+2: bind error
 * 4rd try t+4: dns error
 * ...
 * n try t+60
 * n+1 try t+60
 */
#define MLVPN_IO_TIMEOUT_INCREMENT 2

#define NEXT_KEEPALIVE(now, t) (now + MLVPN_IO_TIMEOUT_DEFAULT)
/* Protocol version of mlvpn
 * version 0: mlvpn 2.0 to 2.1 
 * version 1: mlvpn 2.2+ (add reorder field in mlvpn_proto_t)
 */
#define MLVPN_PROTOCOL_VERSION 2

struct mlvpn_options_s
{
    /* use ps_status or not ? */
    int change_process_title;
    /* process name if set */
    char process_name[1024];
    /* where is the config file */
    char control_unix_path[MAXPATHLEN];
    char control_bind_host[MLVPN_MAXHNAMSTR];
    char control_bind_port[MLVPN_MAXHNAMSTR];
    char config_path[MAXPATHLEN];
    /* tunnel configuration for the status command script */
    char ip4[24];
    char ip6[128]; /* Should not exceed 45 + 3 + 1 bytes */
    char ip4_gateway[16];
    char ip6_gateway[128];
    char ip4_routes[4096]; /* Allow about 200 routes minimum */
    char ip6_routes[8192]; /* Allow about 80 routes minimum */
    int mtu;
    int config_fd;
    /* log verbosity */
    int verbose;
    int debug;
    /* User change if running as root */
    char unpriv_user[128];
    int cleartext_data;
    int root_allowed;
    uint32_t reorder_buffer_size;
    uint32_t fallback_available;
};

struct mlvpn_status_s
{
    int fallback_mode;
    int connected;
    int initialized;
    time_t start_time;
    time_t last_reload;
};

enum chap_status {
    MLVPN_DISCONNECTED,
    MLVPN_AUTHSENT,
    MLVPN_AUTHOK,
    MLVPN_LOSSY
};

LIST_HEAD(rtunhead, mlvpn_tunnel_s) rtuns;

typedef struct mlvpn_tunnel_s
{
    LIST_ENTRY(mlvpn_tunnel_s) entries;
    char *name;           /* tunnel name */
    char bindaddr[MLVPN_MAXHNAMSTR]; /* packets source */
    char bindport[MLVPN_MAXPORTSTR]; /* packets port source (or NULL) */
    char binddev[MLVPN_IFNAMSIZ];    /* bind to specific device */
    uint32_t bindfib;     /* FIB number to use */
    char destaddr[MLVPN_MAXHNAMSTR]; /* remote server ip (can be hostname) */
    char destport[MLVPN_MAXPORTSTR]; /* remote server port */
    int id;               /* Unique ID which will be shared between tunnel end
                             points (e.g. port number) */
    int fd;               /* socket file descriptor */
    int server_mode;      /* server or client */
    int disconnects;      /* is it stable ? */
    int conn_attempts;    /* connection attempts */
    int fallback_only;    /* if set, this link will be used when all others are down */
    uint32_t loss_tolerence; /* How much loss is acceptable before the link is
                              * discarded */
    double sent_loss;   /* loss as reported by far end */
    uint64_t loss_cnt;
    uint64_t loss_event;
    double loss_av;    /* our average loss */
    uint64_t seq;
//    uint64_t expected_receiver_seq;
    uint64_t saved_timestamp;
    uint64_t saved_timestamp_received_at;
    uint64_t seq_last;
    uint64_t seq_vect;
//    uint64_t last_seen;
    int rtt_hit;
    double srtt;
    double srtt_av;
    double srtt_av_d;
    double srtt_av_c;
    double srtt_raw;
    double rttvar;
    double weight;        /* For weight round robin */
    uint32_t flow_id;
    uint64_t sentpackets; /* 64bit packets sent counter */
    uint64_t recvpackets; /* 64bit packets recv counter */
    uint64_t sentbytes;   /* 64bit bytes sent counter */
    uint64_t recvbytes;   /* 64bit bytes recv counter */
    int64_t permitted;  /* how many bytes we can send */
    uint32_t quota; /* how many bytes per second we can send */
    uint32_t reorder_length_preset;  /* minimum  packets this tunnel can re-order */
    uint32_t reorder_length;  /* how many packets this tunnel can re-order */
    uint32_t reorder_length_max;
    uint32_t timeout;     /* configured timeout in seconds */
    uint64_t bandwidth_max;   /* max bandwidth in bytes per second */
    uint64_t bandwidth;   /* current bandwidth in bytes per second */
    uint64_t bandwidth_measured;
    uint64_t bm_data;
    uint64_t bandwidth_out;
//    uint32_t bandwidth_asked;
    mlvpn_pkt_list_t sbuf;    /* send buffer */
    mlvpn_pkt_list_t hpsbuf;  /* high priority buffer */
    struct addrinfo *addrinfo;
    enum chap_status status;    /* Auth status */
    ev_tstamp last_activity;
    ev_tstamp last_connection_attempt;
    ev_tstamp next_keepalive;
    ev_tstamp last_keepalive_ack;
    ev_tstamp last_keepalive_ack_sent;
    ev_io io_read;
    ev_io io_write;
    ev_timer io_timeout;
    ev_check check_ev;
//      ev_idle idle_ev;

    ev_timer send_timer;
    ev_tstamp last_adjust;
    uint64_t bytes_since_adjust;
    double bytes_per_sec;
    int busy_writing;  

    mlvpn_pkt_t *old_pkts[PKTBUFSIZE];
} mlvpn_tunnel_t;

#ifdef HAVE_FILTERS
struct mlvpn_filters_s {
    uint8_t count;
    struct bpf_program filter[255];
    mlvpn_tunnel_t *tun[255];
};
#endif

int mlvpn_config(int config_file_fd, int first_time);
int mlvpn_sock_set_nonblocking(int fd);

int mlvpn_loss_ratio(mlvpn_tunnel_t *tun);
int mlvpn_rtun_wrr_reset(struct rtunhead *head, int use_fallbacks);
void mlvpn_rtun_set_weight(mlvpn_tunnel_t *t, double weight);
mlvpn_tunnel_t *mlvpn_rtun_wrr_choose();
//mlvpn_tunnel_t *mlvpn_rtun_choose(uint32_t len);
mlvpn_tunnel_t *mlvpn_rtun_new(const char *name,
    const char *bindaddr, const char *bindport, const char *binddev, uint32_t bindfib,
    const char *destaddr, const char *destport,
    int server_mode, uint32_t timeout,
    int fallback_only, uint32_t bandwidth,
    uint32_t loss_tolerence, uint32_t quota,
    uint32_t reorder_length);
void mlvpn_rtun_drop(mlvpn_tunnel_t *t);
void mlvpn_rtun_status_down(mlvpn_tunnel_t *t);
#ifdef HAVE_FILTERS
int mlvpn_filters_add(const struct bpf_program *filter, mlvpn_tunnel_t *tun);
mlvpn_tunnel_t *mlvpn_filters_choose(uint32_t pktlen, const u_char *pktdata);
void mlvpn_send_buffer_write(mlvpn_pkt_t *p);
#endif

#include "privsep.h"
#include "log.h"
#include "reorder.h"

#endif
