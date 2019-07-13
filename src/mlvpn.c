/*
 * Copyright (c) 2015, Laurent COUSTET <ed@zehome.com>
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <ev.h>

#include "includes.h"
#include "mlvpn.h"
#include "tool.h"
#include "setproctitle.h"
#include "crypto.h"
#ifdef ENABLE_CONTROL
#include "control.h"
#endif
#include "tuntap_generic.h"

/* Linux specific things */
#ifdef HAVE_LINUX
#include <sys/prctl.h>
#include "systemd.h"
#endif

#ifdef HAVE_FREEBSD
#define _NSIG _SIG_MAXSIG
#include <sys/endian.h>
#endif

#ifdef HAVE_DARWIN
#include <libkern/OSByteOrder.h>
#define be16toh OSSwapBigToHostInt16
#define be32toh OSSwapBigToHostInt32
#define be64toh OSSwapBigToHostInt64
#define htobe16 OSSwapHostToBigInt16
#define htobe32 OSSwapHostToBigInt32
#define htobe64 OSSwapHostToBigInt64
#endif

/* GLOBALS */
struct tuntap_s tuntap;
char *_progname;
static char **saved_argv;
struct ev_loop *loop;
char *status_command = NULL;
char *process_title = NULL;
int logdebug = 0;

static uint64_t data_seq = 0;
ev_tstamp lastsent=0;
uint64_t bandwidthdata=0;
double bandwidth=0;
uint64_t out_resends=0;

static double avtime=3.0; // long enough to make sensible averages

struct resend_data
{
  char r,s;
  uint64_t seqn;
  int tun_id;
  int len;
};

struct mlvpn_status_s mlvpn_status = {
    .start_time = 0,
    .last_reload = 0,
    .fallback_mode = 0,
    .connected = 0,
    .initialized = 0
};
struct mlvpn_options_s mlvpn_options = {
    .change_process_title = 1,
    .process_name = "mlvpn",
    .control_unix_path = "",
    .control_bind_host = "",
    .control_bind_port = "",
    .ip4 = "",
    .ip6 = "",
    .ip4_gateway = "",
    .ip6_gateway = "",
    .ip4_routes = "",
    .ip6_routes = "",
    .mtu = 0,
    .config_path = "mlvpn.conf",
    .config_fd = -1,
    .debug = 0,
    .verbose = 2,
    .unpriv_user = "mlvpn",
    .cleartext_data = 1,
    .root_allowed = 0,
};
#ifdef HAVE_FILTERS
struct mlvpn_filters_s mlvpn_filters = {
    .count = 0
};
#endif

static char *optstr = "c:n:u:hvVD:p:";
static struct option long_options[] = {
    {"config",        required_argument, 0, 'c' },
    {"debug",         no_argument,       0, 2   },
    {"name",          required_argument, 0, 'n' },
    {"natural-title", no_argument,       0, 1   },
    {"help",          no_argument,       0, 'h' },
    {"user",          required_argument, 0, 'u' },
    {"verbose",       no_argument,       0, 'v' },
    {"quiet",         no_argument,       0, 'q' },
    {"version",       no_argument,       0, 'V' },
    {"yes-run-as-root",no_argument,      0, 3   },
    {"permitted",     required_argument, 0, 'p' },
    {0,               0,                 0, 0 }
};

static int mlvpn_rtun_start(mlvpn_tunnel_t *t);
static void mlvpn_rtun_read(EV_P_ ev_io *w, int revents);
static void mlvpn_rtun_write(EV_P_ ev_io *w, int revents);
static void mlvpn_rtun_check_timeout(EV_P_ ev_timer *w, int revents);
static void mlvpn_rtun_send_keepalive(ev_tstamp now, mlvpn_tunnel_t *t);
static void mlvpn_rtun_send_disconnect(mlvpn_tunnel_t *t);
static int mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf);
static void mlvpn_rtun_resend(struct resend_data *d);
static void mlvpn_rtun_request_resend(mlvpn_tunnel_t *loss_tun, uint64_t tun_seqn, int len);
static void mlvpn_rtun_send_auth(mlvpn_tunnel_t *t);
static void mlvpn_rtun_status_up(mlvpn_tunnel_t *t);
static void mlvpn_rtun_tick_connect(mlvpn_tunnel_t *t);
static void mlvpn_rtun_recalc_weight();
static void mlvpn_update_status();
static int mlvpn_rtun_bind(mlvpn_tunnel_t *t);
static void update_process_title();
static void mlvpn_tuntap_init();
static int
mlvpn_protocol_read(mlvpn_tunnel_t *tun,
                    mlvpn_pkt_t *rawpkt,
                    mlvpn_pkt_t *decap_pkt);


static void
usage(char **argv)
{
    fprintf(stderr,
            "usage: %s [options]\n\n"
            "Options:\n"
            " -c, --config [path]   path to config file (ex. /etc/mlvpn.conf)\n"
            " --debug               don't use syslog, print to stdout\n"
            " --natural-title       do not change process title\n"
            " -n, --name            change process-title and include 'name'\n"
            " -h, --help            this help\n"
            " -u, --user [username] drop privileges to user 'username'\n"
            " --yes-run-as-root     ! please do not use !\n"
            " -v --verbose          increase verbosity\n"
            " -q --quiet            decrease verbosity\n"
            " -V, --version         output version information and exit\n"
            " -p, --permitted <tunnel>:<value>[bkm]      Preset tunnel initial permitted bandwidth (Bytes - Default,Kbytes or Mbytes)\n"
            "\n"
            "For more details see mlvpn(1) and mlvpn.conf(5).\n", argv[0]);
    exit(2);
}

void preset_permitted(int argc, char **argv)
{
  mlvpn_tunnel_t *t;
  char tunname[21];
  uint64_t val=0;
  int c;
  char mag=0;
  int filled, option_index;
  optind=0;
    while(1)
    {
        c = getopt_long(argc, argv, optstr, long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
          case 'p':
            filled=sscanf(optarg,"%20[^:]:%lu%c",tunname, &val, &mag);
            if (filled<2) {
              usage(argv);
            }
            if (filled==3) {
              switch (mag) {
                default: usage(argv);
                case 'm': val*=1000;
                case 'k': val*=1000;
                case 'b': break;
              }
            }
            int found=0;
            LIST_FOREACH(t, &rtuns, entries) {
              if (strcmp(t->name,tunname)==0 && t->quota) {
                t->permitted=val;
                found++;
              }
            }
            if (!found) usage(argv);
        }
    }
}

int
mlvpn_sock_set_nonblocking(int fd)
{
    int ret = 0;
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0)
    {
        log_warn(NULL, "fcntl");
        ret = -1;
    } else {
        fl |= O_NONBLOCK;
        if ( (ret = fcntl(fd, F_SETFL, fl)) < 0)
            log_warn(NULL, "Unable to set socket %d non blocking",
               fd);
    }
    return ret;
}

inline static 
void mlvpn_rtun_tick(mlvpn_tunnel_t *tun) {
    tun->last_activity = ev_now(EV_DEFAULT_UC);
}

/* Inject the packet to the tuntap device (real network) */
void mlvpn_rtun_inject_tuntap(mlvpn_pkt_t *pkt)
{
    mlvpn_pkt_t *tuntap_pkt = mlvpn_pktbuffer_write(tuntap.sbuf);
    tuntap_pkt->len = pkt->len;
    memcpy(tuntap_pkt->data, pkt->data, tuntap_pkt->len);
    /* Send the packet back into the LAN */
    if (!ev_is_active(&tuntap.io_write)) {
        ev_io_start(EV_A_ &tuntap.io_write);
    }
}


/* Count the loss on the last 64 packets */
static void
mlvpn_loss_update(mlvpn_tunnel_t *tun, uint64_t seq)
{
  if (seq >= tun->seq_last + 64) {
    /* consider a connection reset. */
    tun->seq_vect = (uint64_t) -1;
    tun->seq_last = seq;
    tun->loss_cnt++;
  } else if (seq > tun->seq_last) {
    /* new sequence number -- recent message arrive */
    int len=0;
    int start=0;
    for (int i=0;i<seq-tun->seq_last;i++) {
      tun->loss_cnt++; // inc the counter, _cnt shoudl be a count of all 'possible' pkt's
      if ((tun->seq_vect & (1ul<<(tun->reorder_length+1)))==0) {
        tun->loss_event++;
        len++;
      } else {
        if (len) {
          log_debug("loss","%s lost %d pkts from %lu new seq %lu last seq %lu vector: %lx (reorder length: %d)",tun->name, len, tun->seq_last+start-(tun->reorder_length+1), seq, tun->seq_last, tun->seq_vect, tun->reorder_length);
          mlvpn_rtun_request_resend(tun, tun->seq_last+start-(tun->reorder_length+1), len);
          len=0;
        }
        start=i+1; // start again (maybe) at the next place, which MAY be a new hole.
      }
      tun->seq_vect<<=1;
    }
    if (len) {
      log_debug("loss","%s lost %d pkts from %lu new seq %lu last seq %lu vector: %lx (reorder length: %d)",tun->name, len, tun->seq_last+start-(tun->reorder_length+1), seq, tun->seq_last, tun->seq_vect, tun->reorder_length);
      mlvpn_rtun_request_resend(tun, tun->seq_last+start-(tun->reorder_length+1), len);
    }
    tun->seq_vect |= 1;
    tun->seq_last = seq;
  } else if (seq >= tun->seq_last - 63) {
    tun->loss_cnt++;
    if ((tun->seq_vect & (1 << (tun->seq_last - seq)))==0) {
      tun->seq_vect |= (1 << (tun->seq_last - seq));
    }
    int d=(tun->seq_last - seq)+1;
    if (tun->reorder_length < (tun->seq_last - seq)) {
      log_debug("loss","Erronious loss %s, found %lu, %d behind reorder length (new RL %d)",tun->name, seq, d-tun->reorder_length,d);
      if (tun->loss_event > 0) tun->loss_event--;
    }
    if (d>63) d=63;
    if (tun->reorder_length <= d) {
      tun->reorder_length = d;
      if (d > tun->reorder_length_max) {
        tun->reorder_length_max=d;
      }
    }
  } else {
    /* consider a wrap round. */
    tun->seq_vect = (uint64_t) -1;
    tun->seq_last = seq;
    tun->loss_cnt++;
  }
}

static void
mlvpn_rtun_recv_data(mlvpn_tunnel_t *tun, mlvpn_pkt_t *inpkt)
{
  mlvpn_reorder_insert( tun, inpkt );
}


/* read from the rtunnel => write directly to the tap send buffer */
static void
mlvpn_rtun_read(EV_P_ ev_io *w, int revents)
{
    mlvpn_tunnel_t *tun = w->data;
    ssize_t len;
    struct sockaddr_storage clientaddr;
    socklen_t addrlen = sizeof(clientaddr);
    mlvpn_pkt_t pkt;
    len = recvfrom(tun->fd, pkt.data,
                   sizeof(pkt.data),
                   MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addrlen);
    if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("net", "%s read error", tun->name);
            mlvpn_rtun_status_down(tun);
        }
    } else if (len == 0) {
        log_info("protocol", "%s peer closed the connection", tun->name);
    } else {
        pkt.len = len;
        mlvpn_pkt_t decap_pkt;

        /* validate the received packet */
        if (mlvpn_protocol_read(tun, &pkt, &decap_pkt) < 0) {
            return;
        }

        tun->recvbytes += len;
        tun->recvpackets += 1;
        tun->bm_data += decap_pkt.len;
        if (tun->quota) {
          if (tun->permitted > (len + 46)) {
            tun->permitted -= (len + 46 /*UDP over Ethernet overhead*/);
          } else {
            tun->permitted = 0;
          }
        }

        if (! tun->addrinfo)
            fatalx("tun->addrinfo is NULL!");

        if ((tun->addrinfo->ai_addrlen != addrlen) ||
                (memcmp(tun->addrinfo->ai_addr, &clientaddr, addrlen) != 0)) {
            if (mlvpn_options.cleartext_data && tun->status >= MLVPN_AUTHOK) {
                log_warnx("protocol", "%s rejected non authenticated connection",
                    tun->name);
                return;
            }
            char clienthost[NI_MAXHOST];
            char clientport[NI_MAXSERV];
            int ret;
            if ( (ret = getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                                    clienthost, sizeof(clienthost),
                                    clientport, sizeof(clientport),
                                    NI_NUMERICHOST|NI_NUMERICSERV)) < 0) {
                log_warn("protocol", "%s error in getnameinfo: %d",
                       tun->name, ret);
            } else {
                log_info("protocol", "%s new connection -> %s:%s",
                   tun->name, clienthost, clientport);
                memcpy(tun->addrinfo->ai_addr, &clientaddr, addrlen);
            }
        }
        log_debug("net", "< %s recv %d bytes (type=%d, seq=%"PRIu64", reorder=%d)",
            tun->name, (int)len, decap_pkt.type, decap_pkt.seq, decap_pkt.reorder);

        if (decap_pkt.type == MLVPN_PKT_DATA || decap_pkt.type == MLVPN_PKT_DATA_RESEND) {
            if (tun->status >= MLVPN_AUTHOK) {
              mlvpn_rtun_tick(tun);
              mlvpn_rtun_recv_data(tun, &decap_pkt);
            } else {
                log_debug("protocol", "%s ignoring non authenticated packet",
                    tun->name);
            }
        } else if (decap_pkt.type == MLVPN_PKT_KEEPALIVE &&
                tun->status >= MLVPN_AUTHOK) {
            log_debug("protocol", "%s keepalive received", tun->name);
            mlvpn_rtun_tick(tun);
            tun->last_keepalive_ack = ev_now(EV_DEFAULT_UC);
            /* Avoid flooding the network if multiple packets are queued */
            if (tun->last_keepalive_ack_sent + MLVPN_IO_TIMEOUT_DEFAULT < tun->last_keepalive_ack) {
                tun->last_keepalive_ack_sent = tun->last_keepalive_ack;
                mlvpn_rtun_send_keepalive(tun->last_keepalive_ack, tun);
            }
            uint32_t bw=0;
            sscanf(decap_pkt.data,"%u", &bw);
            if (bw>0) {
              tun->bandwidth_out=bw;
            }
        } else if (decap_pkt.type == MLVPN_PKT_DISCONNECT &&
                tun->status >= MLVPN_AUTHOK) {
            log_info("protocol", "%s disconnect received", tun->name);
            mlvpn_rtun_status_down(tun);
        } else if (decap_pkt.type == MLVPN_PKT_AUTH ||
                decap_pkt.type == MLVPN_PKT_AUTH_OK) {
          // recieve any quota info, if there is any
          if (decap_pkt.len > 2) {
            int64_t perm=0;
            sscanf(&(decap_pkt.data[2]),"%ld", &perm);
            if (perm > tun->permitted) tun->permitted=perm;
          }
          mlvpn_rtun_send_auth(tun);
        } else if (decap_pkt.type == MLVPN_PKT_RESEND &&
                tun->status >= MLVPN_AUTHOK) {
          mlvpn_rtun_resend((struct resend_data *)decap_pkt.data);
        } else {
          if (tun->status >= MLVPN_AUTHOK) {
            log_warnx("protocol", "Unknown packet type %d", decap_pkt.type);
          }
        }
    }
}

int mlvpn_loss_pack(mlvpn_tunnel_t *t)
{
  if (t->loss_av >= (float)t->loss_tolerence) return 31;
  int v=(int)((t->loss_av * 31.0) / (float)t->loss_tolerence);
  if (t->loss_av>0 && v==0) return 1;
  return v;
}
float mlvpn_loss_unpack(mlvpn_tunnel_t *t, uint16_t v)
{
  return ((float)v * (float)t->loss_tolerence)/31.0;
}


static int
mlvpn_protocol_read(
    mlvpn_tunnel_t *tun, mlvpn_pkt_t *pkt,
    mlvpn_pkt_t *decap_pkt)
{
    unsigned char nonce[crypto_NONCEBYTES];
    int ret;
    uint16_t rlen;
    mlvpn_proto_t proto;
    uint64_t now64 = mlvpn_timestamp64(ev_now(EV_DEFAULT_UC));
    /* Overkill */
    memset(&proto, 0, sizeof(proto));
    memset(decap_pkt, 0, sizeof(*decap_pkt));

    /* pkt->data contains mlvpn_proto_t struct */
    if (pkt->len > sizeof(pkt->data) || pkt->len > sizeof(proto) ||
            pkt->len < (PKTHDRSIZ(proto))) {
        log_warnx("protocol", "%s received invalid packet of %d bytes",
            tun->name, pkt->len);
        goto fail;
    }
    memcpy(&proto, pkt->data, pkt->len);
    rlen = be16toh(proto.len);
    if (rlen == 0 || rlen > sizeof(proto.data)) {
        log_warnx("protocol", "%s invalid packet size: %d", tun->name, rlen);
        goto fail;
    }

    proto.tun_seq = be64toh(proto.tun_seq);
    proto.timestamp = be16toh(proto.timestamp);
    proto.timestamp_reply = be16toh(proto.timestamp_reply);
    proto.flow_id = be32toh(proto.flow_id);
    /* now auth the packet using libsodium before further checks */
#ifdef ENABLE_CRYPTO
    if (mlvpn_options.cleartext_data && (proto.flags == MLVPN_PKT_DATA || proto.flags == MLVPN_PKT_DATA_RESEND)) {
        memcpy(decap_pkt->data, &proto.data, rlen);
    } else {
        sodium_memzero(nonce, sizeof(nonce));
        memcpy(nonce, &proto.tun_seq, sizeof(proto.tun_seq));
        memcpy(nonce + sizeof(proto.tun_seq), &proto.flow_id, sizeof(proto.flow_id));
        if ((ret = crypto_decrypt((unsigned char *)decap_pkt->data,
                                  (const unsigned char *)&proto.data, rlen,
                                  nonce)) != 0) {
            log_warnx("protocol", "%s crypto_decrypt failed: %d",
                tun->name, ret);
            goto fail;
        }
        rlen -= crypto_PADSIZE;
    }
#else
    memcpy(decap_pkt->data, &proto.data, rlen);
#endif
    decap_pkt->len = rlen;
    decap_pkt->type = proto.flags;
    if (proto.version >= 1) {
        decap_pkt->reorder = proto.reorder;
        decap_pkt->seq = be64toh(proto.data_seq);
        mlvpn_loss_update(tun, proto.tun_seq);
                         // use the TUN seq number to
                         // calculate loss
        if (proto.version >=2) {
          tun->sent_loss=mlvpn_loss_unpack(tun, proto.sent_loss);
        } else {
          tun->sent_loss=0;
        }
//        if (decap_pkt->reorder && decap_pkt->seq) {// > tun->last_seen) {
//          tun->last_seen=decap_pkt->seq;
//        }
    } else {
        decap_pkt->reorder = 0;
        decap_pkt->seq = 0;
    }
    if (proto.timestamp != (uint16_t)-1) {
        tun->saved_timestamp = proto.timestamp;
        tun->saved_timestamp_received_at = now64;
    }
    if (proto.timestamp_reply != (uint16_t)-1) {
        uint16_t now16 = mlvpn_timestamp16(now64);
        double R = mlvpn_timestamp16_diff(now16, proto.timestamp_reply);
                  if ((R < 5000) && (tun->seq_vect==(uint64_t)-1)) {  /* ignore large values, e.g. server
                                                                       * was Ctrl-Zed, and while there
                                                                       * are losses, the values will be wrong! */
            tun->srtt_raw=R;
            if (tun->rtt_hit<10) { /* first measurement */
              tun->srtt = 40;//R;
                tun->rttvar = 0;//R / 2;
                tun->rtt_hit ++;
            } else {
                const double alpha = 1.0 / 8.0;
                const double beta = 1.0 / 4.0;
                tun->rttvar = (1 - beta) * tun->rttvar + (beta * fabs(tun->srtt - R));
                tun->srtt = (1 - alpha) * tun->srtt + (alpha * R);
            }
            tun->srtt_av_d+=tun->srtt_raw + (4*tun->rttvar);
            tun->srtt_av_c++;
        }
//        log_debug("rtt", "%ums srtt %ums loss ratio: %d",
//            (unsigned int)R, (unsigned int)tun->srtt, mlvpn_loss_ratio(tun));
    }
    return 0;
fail:
    return -1;
}

void set_reorder(mlvpn_pkt_t *pkt)
{
    // should packet inspect, and only re-order TCP packets !
    // 17 - UDP
    // 6 - TCP
    if ((pkt->type == MLVPN_PKT_DATA || pkt->type == MLVPN_PKT_DATA_RESEND) && pkt->data[9]==6) {
      pkt->reorder = 1;
    } else {
      pkt->reorder = 0;
    }
}

static int
mlvpn_rtun_send(mlvpn_tunnel_t *tun, circular_buffer_t *pktbuf)
{
    unsigned char nonce[crypto_NONCEBYTES];
    ssize_t ret;
    size_t wlen;
    mlvpn_proto_t proto;
    memset(&proto, 0, sizeof(proto));
    mlvpn_pkt_t *pkt = mlvpn_pktbuffer_read(pktbuf);

    set_reorder(pkt);

    // NB, the 'proto.data_seq' should be removed !
    if (pkt->type==MLVPN_PKT_DATA_RESEND) {
      proto.data_seq = pkt->seq;
    } else {
      if (pkt->reorder) {
        proto.data_seq = data_seq++;
      } else {
        proto.data_seq = 0;
      }
      pkt->seq=proto.data_seq;
    }
    
    wlen = PKTHDRSIZ(proto) + pkt->len;


    proto.len = pkt->len;
    proto.flags = pkt->type;

// we should still use this to measure packet loss even if they are UDP packets
// tun seq incrememts even if we resend
    tun->old_pkts_n[tun->seq % PKTBUFSIZE]=tun->seq;
    tun->old_pkts[tun->seq % PKTBUFSIZE]=pkt;
    proto.tun_seq = tun->seq++;

    proto.flow_id = tun->flow_id;
    proto.version = MLVPN_PROTOCOL_VERSION;
    proto.reorder = pkt->reorder;
    proto.sent_loss=mlvpn_loss_pack(tun);

#ifdef ENABLE_CRYPTO
    if (mlvpn_options.cleartext_data && (pkt->type == MLVPN_PKT_DATA || pkt->type == MLVPN_PKT_DATA_RESEND)) {
        memcpy(&proto.data, &pkt->data, pkt->len);
    } else {
        if (wlen + crypto_PADSIZE > sizeof(proto.data)) {
            log_warnx("protocol", "%s packet too long: %u/%d (packet=%d)",
                tun->name,
                (unsigned int)wlen + crypto_PADSIZE,
                (unsigned int)sizeof(proto.data),
                pkt->len);
            return -1;
        }
        sodium_memzero(nonce, sizeof(nonce));
        memcpy(nonce, &proto.tun_seq, sizeof(proto.tun_seq));
        memcpy(nonce + sizeof(proto.tun_seq), &proto.flow_id, sizeof(proto.flow_id));
        if ((ret = crypto_encrypt((unsigned char *)&proto.data,
                                  (const unsigned char *)&pkt->data, pkt->len,
                                  nonce)) != 0) {
            log_warnx("protocol", "%s crypto_encrypt failed: %d incorrect password?",
                tun->name, (int)ret);
            return -1;
        }
        proto.len += crypto_PADSIZE;
        wlen += crypto_PADSIZE;
    }
#else
    memcpy(&proto.data, &pkt->data, pkt->len);
#endif

    
// significant time can have elapsed, so maybe better use the current time
    // rather than... uint64_t now64 = mlvpn_timestamp64(ev_now(EV_DEFAULT_UC));
    uint64_t now64 = mlvpn_timestamp64(ev_time());
    /* we have a recent received timestamp */
    if (tun->saved_timestamp != -1) {
      if (now64 - tun->saved_timestamp_received_at < 1000 ) {
        /* send "corrected" timestamp advanced by how long we held it */
        /* Cast to uint16_t there intentional */
        proto.timestamp_reply = tun->saved_timestamp + (now64 - tun->saved_timestamp_received_at);
        tun->saved_timestamp = -1;
        tun->saved_timestamp_received_at = 0;
      } else {
        proto.timestamp_reply = -1;
        log_debug("rtt","(%s) No timestamp added, time too long! (%lu > 1000)",tun->name, tun->saved_timestamp + (now64 - tun->saved_timestamp_received_at ));
      }
    } else {
      proto.timestamp_reply = -1;
      log_debug("rtt","(%s) No timestamp added, time too long! (%lu > 1000)",tun->name, tun->saved_timestamp + (now64 - tun->saved_timestamp_received_at ));
    }

    proto.timestamp = mlvpn_timestamp16(now64);
    proto.len = htobe16(proto.len);
    proto.tun_seq = htobe64(proto.tun_seq);
    proto.data_seq = htobe64(proto.data_seq);
    proto.flow_id = htobe32(proto.flow_id);
    proto.timestamp = htobe16(proto.timestamp);
    proto.timestamp_reply = htobe16(proto.timestamp_reply);
    ret = sendto(tun->fd, &proto, wlen, MSG_DONTWAIT,
                 tun->addrinfo->ai_addr, tun->addrinfo->ai_addrlen);
    if (ret < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          if (pkt->type!=MLVPN_PKT_AUTH) {
            log_warn("net", "%s write error", tun->name);
            mlvpn_rtun_status_down(tun);
          } // dont report AUTH packet loss, as we know that !
        }
    } else {
        tun->sentpackets++;
        tun->sentbytes += ret;
        if (tun->quota) {
          if (tun->permitted > (ret + 46)) {
            tun->permitted -= (ret + 46 /*UDP over Ethernet overhead*/);
          } else {
            tun->permitted = 0;
          }
        }

        if (wlen != ret)
        {
            log_warnx("net", "%s write error %d/%u",
                tun->name, (int)ret, (unsigned int)wlen);
        } else {
            log_debug("net", "> %s sent %d bytes (size=%d, type=%d, seq=%"PRIu64", reorder=%d)",
                tun->name, (int)ret, pkt->len, pkt->type, pkt->seq, pkt->reorder);
        }
    }

    if (ev_is_active(&tun->io_write) && mlvpn_cb_is_empty(pktbuf)) {
        ev_io_stop(EV_A_ &tun->io_write);
    }
    return ret;
}


static void
mlvpn_rtun_write(EV_P_ ev_io *w, int revents)
{
    mlvpn_tunnel_t *tun = w->data;

    if (! mlvpn_cb_is_empty(tun->hpsbuf)) {
        mlvpn_rtun_send(tun, tun->hpsbuf);
    }

    if (! mlvpn_cb_is_empty(tun->sbuf)) {
        mlvpn_rtun_send(tun, tun->sbuf);
    }

}

mlvpn_tunnel_t *
mlvpn_rtun_new(const char *name,
               const char *bindaddr, const char *bindport, const char *binddev, uint32_t bindfib,
               const char *destaddr, const char *destport,
               int server_mode, uint32_t timeout,
               int fallback_only, uint32_t bandwidth_max,
               uint32_t loss_tolerence, uint32_t quota,
               uint32_t reorder_length)
{
    mlvpn_tunnel_t *new;

    /* Some basic checks */
    if (server_mode)
    {
        if (bindport == NULL)
        {
            log_warnx(NULL,
                "cannot initialize socket without bindport");
            return NULL;
        }
    } else {
        if (destaddr == NULL || destport == NULL)
        {
            log_warnx(NULL,
                "cannot initialize socket without destaddr or destport");
            return NULL;
        }
    }

    new = (mlvpn_tunnel_t *)calloc(1, sizeof(mlvpn_tunnel_t));
    if (! new)
        fatal(NULL, "calloc failed");
    /* other values are enforced by calloc to 0/NULL */
    new->name = strdup(name);
    new->fd = -1;
    new->server_mode = server_mode;
    new->weight = 1;
    new->status = MLVPN_DISCONNECTED;
    new->addrinfo = NULL;
    new->sentpackets = 0;
    new->sentbytes = 0;
    new->recvbytes = 0;
    new->permitted = 0;
    new->quota = quota;
    new->reorder_length= reorder_length;
    new->reorder_length_preset= reorder_length;
    new->reorder_length_max=0;
    new->seq = 0;
//    new->last_seen = 0;
    new->saved_timestamp = -1;
    new->saved_timestamp_received_at = 0;
    new->srtt = 40;
    new->srtt_av=40;
    new->srtt_av_d=0;
    new->srtt_av_c=0;
    new->rttvar = 5;
    new->rtt_hit = 0;
    new->seq_last = 0;
    new->seq_vect = (uint64_t) -1;
    new->loss_cnt=0;
    new->loss_event=0;
    new->loss_av=0;
    new->flow_id = crypto_nonce_random();
    if (bandwidth_max==0) {
      log_warnx("config",
                "Enabling automatic bandwidth adjustment");
      bandwidth_max=10000; // faster lines will go up faster from 10000, slower
                           // ones will drop from here.... it's a compromise
    }
    new->bandwidth_max = bandwidth_max;
    new->bandwidth = bandwidth_max;
    new->bandwidth_measured=0;
    new->bm_data=0;
    new->fallback_only = fallback_only;
    new->loss_tolerence = loss_tolerence;
    if (bindaddr)
        strlcpy(new->bindaddr, bindaddr, sizeof(new->bindaddr));
    if (bindport)
        strlcpy(new->bindport, bindport, sizeof(new->bindport));
    new->bindfib = bindfib;
    if (binddev) {
        strlcpy(new->binddev, binddev, sizeof(new->binddev));
    }
    if (destaddr)
        strlcpy(new->destaddr, destaddr, sizeof(new->destaddr));
    if (destport)
        strlcpy(new->destport, destport, sizeof(new->destport));
    new->sbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    new->hpsbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    mlvpn_rtun_tick(new);
    new->timeout = timeout;
    new->next_keepalive = 0;
    LIST_INSERT_HEAD(&rtuns, new, entries);
    new->io_read.data = new;
    new->io_write.data = new;
    new->io_timeout.data = new;
    ev_init(&new->io_read, mlvpn_rtun_read);
    ev_init(&new->io_write, mlvpn_rtun_write);
    ev_timer_init(&new->io_timeout, mlvpn_rtun_check_timeout,
        0., MLVPN_IO_TIMEOUT_DEFAULT);
    ev_timer_start(EV_A_ &new->io_timeout);
    update_process_title();
    return new;
}

void
mlvpn_rtun_drop(mlvpn_tunnel_t *t)
{
    mlvpn_tunnel_t *tmp;
    mlvpn_rtun_send_disconnect(t);
    mlvpn_rtun_status_down(t);
    ev_timer_stop(EV_A_ &t->io_timeout);
    ev_io_stop(EV_A_ &t->io_read);

    LIST_FOREACH(tmp, &rtuns, entries)
    {
        if (mystr_eq(tmp->name, t->name))
        {
            LIST_REMOVE(tmp, entries);
            if (tmp->name)
                free(tmp->name);
            if (tmp->addrinfo)
                freeaddrinfo(tmp->addrinfo);
            mlvpn_pktbuffer_free(tmp->sbuf);
            mlvpn_pktbuffer_free(tmp->hpsbuf);
            /* Safety */
            tmp->name = NULL;
            break;
        }
    }
    update_process_title();
}


static void
mlvpn_rtun_recalc_weight_srtt()
{
    mlvpn_tunnel_t *t;
    double totalsrtt=0;

    LIST_FOREACH(t, &rtuns, entries)
    {
      totalsrtt+=t->srtt;
    }
    double totalf=0;
      
    LIST_FOREACH(t, &rtuns, entries)
    {
      if (t->srtt > 0)  {
        totalf += totalsrtt / t->srtt;
      }
    }
    LIST_FOREACH(t, &rtuns, entries)
    {
      double st=t->srtt;
      if (st > 0)  {
        // should be 1 / (t->srtt / totalsrtt)
        // e.g. (1 / (srtt / totalsrtt)) * (100 / totalf)
        mlvpn_rtun_set_weight(t, ((totalsrtt * 100) / (st * totalf)));
        if (t->weight < 1) mlvpn_rtun_set_weight(t,1);
        if (t->weight > 100) mlvpn_rtun_set_weight(t,100);
        log_debug("wrr", "%s weight = %f%%", t->name, t->weight);
      } 
    }
}



/* Based on tunnel bandwidth, with priority compute a "weight" value
 * to balance correctly the round robin rtun_choose.
 */
static void
mlvpn_rtun_recalc_weight_prio()
{
  if (bandwidth<=0) {
// When there is no bandwdith, anything that comes through, share out in
// proportion to srtt - this should give us the fastest pickup.
    return mlvpn_rtun_recalc_weight_srtt();
  }

    
  mlvpn_tunnel_t *t;
  double bwneeded=bandwidth * 5; /* do we need headroom e.g. * 1.5*/;
  double bwavailable=0;
  LIST_FOREACH(t, &rtuns, entries) {
    if (t->bandwidth == 0) // bail out, we need to know the bandwidths to share
      return mlvpn_rtun_recalc_weight_srtt();

    if (bwavailable > 2 * bwneeded) {
//      bandwidth_max = (realBW * 8)/1000, and we want it for avtime seconds
        if ((t->quota==0 || t->permitted > (t->bandwidth_max*125*avtime)) && (t->status == MLVPN_AUTHOK)) {
          mlvpn_rtun_set_weight(t, bwneeded/50);
        } else {
          mlvpn_rtun_set_weight(t, 0);
        }
        continue;
    }
    
    double lt=(double)t->loss_tolerence/2.0; // aim at 1/2 the loss at which we will
                                     // declair the tunnel lossy.
    double part = (((lt-t->sent_loss)/lt));

    if (part<0) part=0;
    // effectively, the link is lossy, and will be marked as such later, here,
    // simply remove the weight from the link.

    // Should we limit to e.g. 0.8 of the bandwidth here?
    if ((t->quota == 0) && (t->status == MLVPN_AUTHOK)) {
      mlvpn_rtun_set_weight(t, (t->bandwidth*part));
      bwavailable+=(t->bandwidth*part);
    } else {
      double bw=bwneeded - bwavailable;
      if (bw>0 && (t->quota==0 || t->permitted > (t->bandwidth_max*125*avtime)) && (t->status == MLVPN_AUTHOK)) {
        if (t->bandwidth*part > bw) {
          mlvpn_rtun_set_weight(t, (bw*part));
          bwavailable+=bw*part;
        } else {
          mlvpn_rtun_set_weight(t, (t->bandwidth*part));
          bwavailable+=(t->bandwidth*part);
        }
      } else {
        if ((t->quota==0 || t->permitted > (t->bandwidth_max*125*avtime)) && (t->status == MLVPN_AUTHOK)) {
          mlvpn_rtun_set_weight(t, bwneeded/50);
        } else {
          mlvpn_rtun_set_weight(t, 0);
        }
      }
    }
  }
  
  if (bwavailable==0) {
    return mlvpn_rtun_recalc_weight_srtt();
  }
}



static void
mlvpn_rtun_recalc_weight()
{
  mlvpn_rtun_recalc_weight_prio();
}


static int
mlvpn_rtun_bind(mlvpn_tunnel_t *t)
{
    struct addrinfo hints, *res;
    struct ifreq ifr;
    char bindifstr[MLVPN_IFNAMSIZ+5];
    int n, fd;

    memset(&hints, 0, sizeof(hints));
    /* AI_PASSIVE flag: the resulting address is used to bind
       to a socket for accepting incoming connections.
       So, when the hostname==NULL, getaddrinfo function will
       return one entry per allowed protocol family containing
       the unspecified address for that family. */
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_UNSPEC;
    fd = t->fd;
    hints.ai_socktype = SOCK_DGRAM;

    if (*t->bindaddr) {
      n = priv_getaddrinfo(t->bindaddr, t->bindport, &res, &hints);
      if (n < 0)
      {
        log_warnx(NULL, "%s getaddrinfo error: %s", t->name, gai_strerror(n));
        return -1;
      }
    }

    /* Try open socket with each address getaddrinfo returned,
       until getting a valid listening socket. */
    memset(bindifstr, 0, sizeof(bindifstr));
    if (*t->binddev) {
      snprintf(bindifstr, sizeof(bindifstr) - 1, " on %s", t->binddev);
    }
    log_info(NULL, "%s bind to %s%s",
             t->name, t->bindaddr ? t->bindaddr : "any",
             bindifstr);

    if (*t->binddev) {
      memset(&ifr, 0, sizeof(ifr));
      snprintf(ifr.ifr_name, sizeof(ifr.ifr_name) - 1, t->binddev);
      if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        log_warn(NULL, "failed to bind on interface %s", t->binddev);
      }
    }
    if (*t->bindaddr) {
      n = bind(fd, res->ai_addr, res->ai_addrlen);
      freeaddrinfo(res);
      if (n < 0)
      {
        log_warn(NULL, "%s bind error", t->name);
        return -1;
      }
    }

    return 0;
}

static int
mlvpn_rtun_start(mlvpn_tunnel_t *t)
{
    int ret, fd = -1;
    char *addr, *port;
    struct addrinfo hints, *res;
#if defined(HAVE_FREEBSD) || defined(HAVE_OPENBSD)
    int fib = t->bindfib;
#endif
    fd = t->fd;
    if (t->server_mode)
    {
        addr = t->bindaddr;
        port = t->bindport;
        t->id=atoi(t->bindport);
    } else {
        addr = t->destaddr;
        port = t->destport;
        t->id=atoi(t->destport);
    }

    /* Initialize hints */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    ret = priv_getaddrinfo(addr, port, &t->addrinfo, &hints);
    if (ret < 0 || !t->addrinfo)
    {
        log_warnx("dns", "%s getaddrinfo(%s,%s) failed: %s",
           t->name, addr, port, gai_strerror(ret));
        return -1;
    }

    res = t->addrinfo;
    while (res)
    {
        /* creation de la socket(2) */
        if ( (fd = socket(t->addrinfo->ai_family,
                          t->addrinfo->ai_socktype,
                          t->addrinfo->ai_protocol)) < 0)
        {
            log_warn(NULL, "%s socket creation error",
                t->name);
        } else {
            /* Setting fib/routing-table is supported on FreeBSD and OpenBSD only */
#if defined(HAVE_FREEBSD)
            if (fib > 0 && setsockopt(fd, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) < 0)
#elif defined(HAVE_OPENBSD)
            if (fib > 0 && setsockopt(fd, SOL_SOCKET, SO_RTABLE, &fib, sizeof(fib)) < 0)
            {
                log_warn(NULL, "Cannot set FIB %d for kernel socket", fib);
                goto error;
            }
#endif
            t->fd = fd;
            break;
        }
        res = res->ai_next;
    }

    if (fd < 0) {
        log_warnx("dns", "%s connection failed. Check DNS?",
            t->name);
        goto error;
    }

    /* setup non blocking sockets */
    socklen_t val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(socklen_t)) < 0) {
        log_warn(NULL, "%s setsockopt SO_REUSEADDR failed", t->name);
        goto error;
    }
    if (*t->bindaddr || *t->binddev) {
        if (mlvpn_rtun_bind(t) < 0) {
            goto error;
        }
    }

    /* set non blocking after connect... May lockup the entiere process */
    mlvpn_sock_set_nonblocking(fd);
    mlvpn_rtun_tick(t);
    ev_io_set(&t->io_read, fd, EV_READ);
    ev_io_set(&t->io_write, fd, EV_WRITE);
    ev_io_start(EV_A_ &t->io_read);
    t->io_timeout.repeat = MLVPN_IO_TIMEOUT_DEFAULT;
    return 0;
error:
    if (t->fd > 0) {
        close(t->fd);
        t->fd = -1;
    }
    if (t->io_timeout.repeat < MLVPN_IO_TIMEOUT_MAXIMUM)
        t->io_timeout.repeat *= MLVPN_IO_TIMEOUT_INCREMENT;
    return -1;
}

static void
mlvpn_script_get_env(int *env_len, char ***env) {
    char **envp;
    int arglen;
    *env_len = 8;
    *env = (char **)calloc(*env_len + 1, sizeof(char *));
    if (! *env)
        fatal(NULL, "out of memory");
    envp = *env;
    arglen = sizeof(mlvpn_options.ip4) + 4;
    envp[0] = calloc(1, arglen + 1);
    if (snprintf(envp[0], arglen, "IP4=%s", mlvpn_options.ip4) < 0)
        log_warn(NULL, "snprintf IP4= failed");

    arglen = sizeof(mlvpn_options.ip6) + 4;
    envp[1] = calloc(1, arglen + 1);
    if (snprintf(envp[1], arglen, "IP6=%s", mlvpn_options.ip6) < 0)
        log_warn(NULL, "snprintf IP6= failed");

    arglen = sizeof(mlvpn_options.ip4_gateway) + 12;
    envp[2] = calloc(1, arglen + 1);
    if (snprintf(envp[2], arglen, "IP4_GATEWAY=%s", mlvpn_options.ip4_gateway) < 0)
        log_warn(NULL, "snprintf IP4_GATEWAY= failed");

    arglen = sizeof(mlvpn_options.ip6_gateway) + 12;
    envp[3] = calloc(1, arglen + 1);
    if (snprintf(envp[3], arglen, "IP6_GATEWAY=%s", mlvpn_options.ip6_gateway) < 0)
        log_warn(NULL, "snprintf IP6_GATEWAY= failed");

    arglen = sizeof(mlvpn_options.ip4_routes) + 11;
    envp[4] = calloc(1, arglen + 1);
    if (snprintf(envp[4], arglen, "IP4_ROUTES=%s", mlvpn_options.ip4_routes) < 0)
        log_warn(NULL, "snprintf IP4_ROUTES= failed");

    arglen = sizeof(mlvpn_options.ip6_routes) + 11;
    envp[5] = calloc(1, arglen + 1);
    if (snprintf(envp[5], arglen, "IP6_ROUTES=%s", mlvpn_options.ip6_routes) < 0)
        log_warn(NULL, "snprintf IP6_ROUTES= failed");

    arglen = sizeof(tuntap.devname) + 7;
    envp[6] = calloc(1, arglen + 1);
    if (snprintf(envp[6], arglen, "DEVICE=%s", tuntap.devname) < 0)
        log_warn(NULL, "snprintf DEVICE= failed");

    envp[7] = calloc(1, 16);
    if (snprintf(envp[7], 15, "MTU=%d", mlvpn_options.mtu) < 0)
        log_warn(NULL, "snprintf MTU= failed");
    envp[8] = NULL;
}

static void
mlvpn_free_script_env(char **env)
{
    char **envp = env;
    while (*envp) {
        free(*envp);
        envp++;
    }
    free(env);
}

mlvpn_tunnel_t *best_quick_tun(mlvpn_tunnel_t *not)
{
  mlvpn_tunnel_t *t, *best=NULL;
  LIST_FOREACH(t, &rtuns, entries) {
    if (t->status == MLVPN_AUTHOK &&
        t!=not &&
//        t->sent_loss==0 &&
        t->sent_loss<(double)t->loss_tolerence/4.0 &&
        (!best || mlvpn_cb_length(t->hpsbuf) < mlvpn_cb_length(best->hpsbuf)))
      best=t;
  }
  return best;
}

static void
mlvpn_rtun_status_up(mlvpn_tunnel_t *t)
{
    char *cmdargs[4] = {tuntap.devname, "rtun_up", t->name, NULL};
    char **env;
    int env_len;
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    t->status = MLVPN_AUTHOK;
    t->next_keepalive = NEXT_KEEPALIVE(now, t);
    t->last_activity = now;
    t->last_keepalive_ack = now;
    t->last_keepalive_ack_sent = now;
    t->srtt_av=40;
    t->srtt_av_d=0;
    t->srtt_av_c=0;
    t->loss_av=0;
    t->bm_data=0;
//    mlvpn_pktbuffer_reset(t->sbuf);
//    mlvpn_pktbuffer_reset(t->hpsbuf);
    mlvpn_update_status();
    mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
    mlvpn_script_get_env(&env_len, &env);
    priv_run_script(3, cmdargs, env_len, env);
    if (mlvpn_status.connected > 0 && mlvpn_status.initialized == 0) {
        cmdargs[0] = tuntap.devname;
        cmdargs[1] = "tuntap_up";
        cmdargs[2] = NULL;
        priv_run_script(2, cmdargs, env_len, env);
        mlvpn_status.initialized = 1;
    }
    mlvpn_free_script_env(env);
    update_process_title();
}

void
mlvpn_rtun_status_down(mlvpn_tunnel_t *t)
{
    char *cmdargs[4] = {tuntap.devname, "rtun_down", t->name, NULL};
    char **env;
    int env_len;
    enum chap_status old_status = t->status;
    t->status = MLVPN_DISCONNECTED;
    t->disconnects++;
    t->srtt_av=0;
    t->srtt_av_d=0;
    t->srtt_av_c=0;
    t->srtt_raw=0;
    t->loss_av=100;

    mlvpn_rtun_recalc_weight();

    // Resend anything that was in flight !!!!
    // for the hps, lest just try to resend what we know is outstanding
    while (!mlvpn_cb_is_empty(t->hpsbuf))
    {
      mlvpn_pkt_t *old=mlvpn_pktbuffer_read(t->hpsbuf);
      mlvpn_tunnel_t *tun=best_quick_tun(t);
      if (!tun) break;
      if (mlvpn_cb_is_full(tun->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", tun->name);
      mlvpn_pkt_t *pkt = mlvpn_pktbuffer_write(tun->hpsbuf);
      memcpy(pkt,old,sizeof(mlvpn_pkt_t));
    }
    mlvpn_pktbuffer_reset(t->sbuf);
    mlvpn_pktbuffer_reset(t->hpsbuf);
    // for the normal buffer, lets request resends of all possible packets from
    // the last one we recieved
    mlvpn_rtun_request_resend(t, t->seq_last, PKTBUFSIZE);

    if (ev_is_active(&t->io_write)) {
        ev_io_stop(EV_A_ &t->io_write);
    }

    mlvpn_update_status();
    if (old_status >= MLVPN_AUTHOK)
    {
        mlvpn_script_get_env(&env_len, &env);
        priv_run_script(3, cmdargs, env_len, env);
        /* Re-initialize weight round robin */
        mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
        if (mlvpn_status.connected == 0 && mlvpn_status.initialized == 1) {
            cmdargs[0] = tuntap.devname;
            cmdargs[1] = "tuntap_down";
            cmdargs[2] = NULL;
            priv_run_script(2, cmdargs, env_len, env);
            mlvpn_status.initialized = 0;
        }
        mlvpn_free_script_env(env);
        /* MAYBE flushing the re-order buffer here would be good, as we might
    have a lot of packets in flight which will never arrive, so recovery MAY be
    quicker with a flush...*/
    }
    update_process_title();
}

static void
mlvpn_update_status()
{
    mlvpn_tunnel_t *t;
    mlvpn_status.fallback_mode = mlvpn_options.fallback_available;
    mlvpn_status.connected = 0;
    LIST_FOREACH(t, &rtuns, entries)
    {
        if (t->status >= MLVPN_AUTHOK) {
            if (!t->fallback_only)
                mlvpn_status.fallback_mode = 0;
            mlvpn_status.connected++;
        }
    }
}

static void
mlvpn_rtun_challenge_send(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;

    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", t->name);

    pkt = mlvpn_pktbuffer_write(t->hpsbuf);
    pkt->data[0] = 'A';
    pkt->data[1] = 'U';
    pkt->len = 2;

    // send quota info
    if (t->quota) {
      pkt->len+=sprintf(&(pkt->data[pkt->len]),"%ld",t->permitted) + 1;
    }

    pkt->type = MLVPN_PKT_AUTH;

    t->status = MLVPN_AUTHSENT;
    log_debug("protocol", "%s mlvpn_rtun_challenge_send", t->name);
}

static void
mlvpn_rtun_send_auth(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (t->server_mode)
    {
        /* server side */
        if (t->status == MLVPN_DISCONNECTED || t->status >= MLVPN_AUTHOK)
        {
            mlvpn_rtun_tick(t);
            mlvpn_rtun_status_up(t); // mark this as up, before trying to send
                                     // somethign on it !

            if (mlvpn_cb_is_full(t->hpsbuf)) {
                log_warnx("net", "%s high priority buffer: overflow", t->name);
                mlvpn_cb_reset(t->hpsbuf);
            }
            pkt = mlvpn_pktbuffer_write(t->hpsbuf);
            pkt->data[0] = 'O';
            pkt->data[1] = 'K';
            pkt->len = 2;

            // send quota info
            if (t->quota) {
              pkt->len+=sprintf(&(pkt->data[pkt->len]),"%ld",t->permitted) + 1;
            }

            pkt->type = MLVPN_PKT_AUTH_OK;
            if (t->status < MLVPN_AUTHOK)
                t->status = MLVPN_AUTHSENT;
            log_debug("protocol", "%s sending 'OK'", t->name);
            log_info("protocol", "%s authenticated", t->name);
//            mlvpn_rtun_tick(t);
//            mlvpn_rtun_status_up(t);
            if (!ev_is_active(&t->io_write)) {
                ev_io_start(EV_A_ &t->io_write);
            }
        }
    } else {
        /* client side */
        if (t->status == MLVPN_AUTHSENT) {
            log_info("protocol", "%s authenticated", t->name);
            mlvpn_rtun_tick(t);
            mlvpn_rtun_status_up(t);
        }
    }
}

static void
mlvpn_rtun_request_resend(mlvpn_tunnel_t *loss_tun, uint64_t tun_seqn, int len)
{
    mlvpn_pkt_t *pkt;
    mlvpn_tunnel_t *t=best_quick_tun(loss_tun);
    if (!t) {
      log_debug("resend", "No suitable tunnel to request resend");
      return;
    }
    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", t->name);
    pkt = mlvpn_pktbuffer_write(t->hpsbuf);
    struct resend_data *d=(struct resend_data *)(pkt->data);
    d->r='R';
    d->s='S';
    d->seqn=tun_seqn;
    d->tun_id=loss_tun->id;
    d->len=len;
    pkt->len = sizeof(struct resend_data);

    pkt->type = MLVPN_PKT_RESEND;
    out_resends+=len;
    log_debug("resend", "On %s request resend %lu (lost from tunnel %s)", t->name, tun_seqn, loss_tun->name);
}

static mlvpn_tunnel_t *mlvpn_find_tun(int id)
{
  mlvpn_tunnel_t *t;
  LIST_FOREACH(t, &rtuns, entries) {
    if (t->id==id) return t;
  }
  return NULL;
}

static void
mlvpn_rtun_resend(struct resend_data *d)
{
  mlvpn_pkt_t *pkt;
  mlvpn_tunnel_t *loss_tun=mlvpn_find_tun(d->tun_id);
  if (loss_tun->sent_loss==0) {
    loss_tun->sent_loss++; // We KNOW they had a loss here !
    // Mark it as at least a '1', which will prevent some things from usng the tunnel
  }
  for (int i=0; i<d->len;i++) {
    uint64_t seqn=d->seqn+i;
    if (loss_tun && loss_tun->old_pkts_n[seqn % PKTBUFSIZE] == seqn) {
      mlvpn_pkt_t *old_pkt=loss_tun->old_pkts[seqn % PKTBUFSIZE];
      set_reorder(old_pkt);
      if (old_pkt->reorder) { // refuse to resend UDP packets!
        mlvpn_tunnel_t *t=best_quick_tun(loss_tun);
        if (t) {
          if (mlvpn_cb_is_full(t->hpsbuf))
            log_warnx("net", "%s high priority buffer: overflow", t->name);
          pkt = mlvpn_pktbuffer_write(t->hpsbuf);
          memcpy(pkt, old_pkt, sizeof(mlvpn_pkt_t));
          pkt->type=MLVPN_PKT_DATA_RESEND;
          log_debug("resend", "resend on tunnel %s, packet (tun seq: %lu data seq %lu) previously sent on %s", t->name, seqn, old_pkt->seq, loss_tun->name);
        } else {
          log_debug("resend", "No suitable tunnel, unable to resend (tun seq: %lu data seq %lu)",seqn, old_pkt->seq);
        }
      } else {
        log_debug("resend", "Wont resent packet (tun seq: %lu data seq %lu) of type %d", seqn, old_pkt->seq, (unsigned char)old_pkt->data[6]);
      }
    } else {
      log_debug("resend", "unable to resend seq %lu (Not Found)",seqn);
    }
  }
}

static void
mlvpn_rtun_tick_connect(mlvpn_tunnel_t *t)
{
    ev_tstamp now = ev_now(EV_DEFAULT_UC);
    if (t->server_mode) {
        if (t->fd < 0) {
            if (mlvpn_rtun_start(t) == 0) {
                t->conn_attempts = 0;
            } else {
                return;
            }
        }
    } else {
        if (t->status < MLVPN_AUTHOK) {
            t->conn_attempts++;
            t->last_connection_attempt = now;
            if (t->fd < 0) {
                if (mlvpn_rtun_start(t) == 0) {
                    t->conn_attempts = 0;
                } else {
                    return;
                }
            }
        }
        mlvpn_rtun_challenge_send(t);
    }
}

void mlvpn_calc_bandwidth(uint32_t len)
{
  ev_tstamp now=ev_now(EV_A);

  if (lastsent==0) lastsent=now;
  ev_tstamp diff=now - lastsent;
  bandwidthdata+=len;
  if (diff>avtime) {
    lastsent=now;
    bandwidth=((((double)bandwidthdata*8) / diff))/1000; // kbits/sec
    bandwidthdata=0;
    // what we can do here is add any bandwidth allocation
    // The allocation should be per second.
    // permittedis in bytes.
    mlvpn_tunnel_t *t;
    LIST_FOREACH(t, &rtuns, entries) {
      // permitted is in BYTES per second.
      if (t->quota) {
        t->permitted+=(((double)t->quota * diff)*1000.0)/8.0; // listed in kbps
      }

      // calc the srtt average...
      t->srtt_av = (t->srtt_av_d / t->srtt_av_c);
      // reset so if we get no traffic, we still see a valid srtt
      t->srtt_av_d=t->srtt_raw + (4*t->rttvar);;
      t->srtt_av_c=1;

      // calc measured bandwidth
      t->bandwidth_measured=((((double)(t->bm_data)*8) / diff))/1000; // kbits/sec
      t->bm_data=0;

      if (t->loss_cnt) {
        double current_loss=((double)t->loss_event * 100.0)/ (double)t->loss_cnt;
        t->loss_av=current_loss;//((t->loss_av*3.0)+current_loss)/4.0;
      } else {
        if (t->loss_event || t->status!=MLVPN_AUTHOK) {
          t->loss_av=100.0;
        } else {
          t->loss_av=0;
        }
      }
      t->loss_event=0;
      t->loss_cnt=0;

      // hunt a high watermark with slow drift
//      if (t->srtt_av < target) {
      if (t->sent_loss == 0) {
        if (t->bandwidth_out>t->bandwidth_max) {
          t->bandwidth_max=t->bandwidth_out;
          // we could 'drift' the target here...
        }
//      } else {
//        if (t->bandwidth*2 < t->bandwidth_max && t->bandwidth_max > 10) {
//          t->bandwidth_max *= 0.95;
//        }
      }

//      if (t->srtt_av < target*0.9 && t->bandwidth < t->bandwidth_max) {
      if (t->sent_loss==0) {
        if (t->bandwidth < t->bandwidth_max) {
          t->bandwidth*=1.05;
        }
      } else {
        if (/*t->srtt_av > target*1.1 &&*/ t->bandwidth_out > (t->bandwidth_max/4)) {
          t->bandwidth=t->bandwidth_out * 0.8;//(t->bandwidth*9 + t->bandwidth_out)/10;
          if (t->bandwidth_max > 100) {
            t->bandwidth_max=(t->bandwidth_max*9 + t->bandwidth)/10;
          }
        }
      }

      if (t->seq_vect==(uint64_t)-1  /* !t->loss*/) {
        if (t->reorder_length > t->reorder_length_preset) {
          t->reorder_length--;
        }
      }

    }
    mlvpn_rtun_recalc_weight();
  }
}

mlvpn_tunnel_t *
mlvpn_rtun_choose(uint32_t len)
{
  mlvpn_tunnel_t *tun;
  mlvpn_calc_bandwidth(len);
  tun = mlvpn_rtun_wrr_choose(len);
  return tun;
}

static void
mlvpn_rtun_send_keepalive(ev_tstamp now, mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", t->name);
    else {
        log_debug("protocol", "%s sending keepalive", t->name);
        pkt = mlvpn_pktbuffer_write(t->hpsbuf);
        pkt->type = MLVPN_PKT_KEEPALIVE;
        pkt->len=sprintf(pkt->data,"%u",t->bandwidth_measured) + 1;
    }
    t->next_keepalive = NEXT_KEEPALIVE(now, t);
}

static void
mlvpn_rtun_send_disconnect(mlvpn_tunnel_t *t)
{
    mlvpn_pkt_t *pkt;
    if (mlvpn_cb_is_full(t->hpsbuf))
        log_warnx("net", "%s high priority buffer: overflow", t->name);
    else {
        log_debug("protocol", "%s sending disconnect", t->name);
        pkt = mlvpn_pktbuffer_write(t->hpsbuf);
        pkt->type = MLVPN_PKT_DISCONNECT;
    }
    mlvpn_rtun_send(t, t->hpsbuf);
}

static void
mlvpn_rtun_check_lossy(mlvpn_tunnel_t *tun)
{
  double loss = tun->sent_loss;
  int status_changed = 0;
  ev_tstamp now = ev_now(EV_DEFAULT_UC);
  int keepalive_ok= ((tun->last_keepalive_ack != 0) || (tun->last_keepalive_ack + MLVPN_IO_TIMEOUT_DEFAULT*2 + ((tun->srtt_av/1000.0)*2)) > now);

  if (!keepalive_ok && tun->status == MLVPN_AUTHOK) {
    log_info("rtt", "%s keepalive reached threashold, keepalive recieved %fs ago", tun->name, now-tun->last_keepalive_ack);
    tun->status = MLVPN_LOSSY;
    mlvpn_rtun_request_resend(tun, tun->seq_last, PKTBUFSIZE);
    // We wont mark the tunnel down yet (hopefully it will come back again, and
    // coming back from a loss is quicker than pulling it down etc. However,
    // here, we fear the worst, and will ask for all packets again. Lets hope
    // there are not too many in flight.
    status_changed = 1;
  } else if (loss >= tun->loss_tolerence && tun->status == MLVPN_AUTHOK) {
    log_info("rtt", "%s packet loss reached threashold: %f%%/%d%%",
             tun->name, loss, tun->loss_tolerence);
    tun->status = MLVPN_LOSSY;
    status_changed = 1;
  } else if (keepalive_ok && loss < tun->loss_tolerence && tun->status == MLVPN_LOSSY) {
    log_info("rtt", "%s packet loss acceptable again: %f%%/%d%%",
             tun->name, loss, tun->loss_tolerence);
    tun->status = MLVPN_AUTHOK;
    status_changed = 1;
  }
  /* are all links in lossy mode ? switch to fallback ? */
  if (status_changed) {
    mlvpn_tunnel_t *t;
    LIST_FOREACH(t, &rtuns, entries) {
      if (! t->fallback_only && t->status != MLVPN_LOSSY) {
        mlvpn_status.fallback_mode = 0;
        mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
        return;
      }
    }
    if (mlvpn_options.fallback_available) {
      log_info(NULL, "all tunnels are down or lossy, switch fallback mode");
      mlvpn_status.fallback_mode = 1;
      mlvpn_rtun_wrr_reset(&rtuns, mlvpn_status.fallback_mode);
    } else {
      log_info(NULL, "all tunnels are down or lossy but fallback is not available");
    }
  }
}

static void
mlvpn_rtun_check_timeout(EV_P_ ev_timer *w, int revents)
{
    mlvpn_tunnel_t *t = w->data;
    ev_tstamp now = ev_now(EV_DEFAULT_UC);

    mlvpn_rtun_check_lossy(t);

    if (t->status >= MLVPN_AUTHOK && t->timeout > 0) {
      if ((t->last_keepalive_ack != 0) && (t->last_keepalive_ack + t->timeout + MLVPN_IO_TIMEOUT_DEFAULT + ((t->srtt_av/1000.0)*2)) < now) {
            log_info("protocol", "%s timeout", t->name);
            mlvpn_rtun_status_down(t);
        } else {
            if (now > t->next_keepalive)
                mlvpn_rtun_send_keepalive(now, t);
        }
    }
    if (t->status < MLVPN_AUTHOK) {
        mlvpn_rtun_tick_connect(t);
    }
    if (!ev_is_active(&t->io_write) && ! mlvpn_cb_is_empty(t->hpsbuf)) {
        ev_io_start(EV_A_ &t->io_write);
    }
}


static void
tuntap_io_event(EV_P_ ev_io *w, int revents)
{
    if (revents & EV_READ) {
        mlvpn_tuntap_read(&tuntap);
    } else if (revents & EV_WRITE) {
        mlvpn_tuntap_write(&tuntap);
        /* Nothing else to read */
        if (mlvpn_cb_is_empty(tuntap.sbuf)) {
            ev_io_stop(EV_A_ &tuntap.io_write);
        }
    }
}

static void
mlvpn_tuntap_init()
{
    mlvpn_proto_t proto;
    memset(&tuntap, 0, sizeof(tuntap));
    snprintf(tuntap.devname, MLVPN_IFNAMSIZ-1, "%s", "mlvpn0");
    tuntap.maxmtu = 1500 - PKTHDRSIZ(proto) - IP4_UDP_OVERHEAD;
    log_debug(NULL, "absolute maximum mtu: %d", tuntap.maxmtu);
    tuntap.type = MLVPN_TUNTAPMODE_TUN;
    tuntap.sbuf = mlvpn_pktbuffer_init(PKTBUFSIZE);
    ev_init(&tuntap.io_read, tuntap_io_event);
    ev_init(&tuntap.io_write, tuntap_io_event);
}

static void
update_process_title()
{
    if (! process_title)
        return;
    char title[1024];
    char *s;
    mlvpn_tunnel_t *t;
    char status[32];
    int len;
    memset(title, 0, sizeof(title));
    if (*process_title)
        strlcat(title, process_title, sizeof(title));
    LIST_FOREACH(t, &rtuns, entries)
    {
        switch(t->status) {
            case MLVPN_AUTHOK:
                s = "@";
                break;
            case MLVPN_LOSSY:
                s = "~";
                break;
            default:
                s = "!";
                break;
        }
        len = snprintf(status, sizeof(status) - 1, " %s%s", s, t->name);
        if (len) {
            status[len] = 0;
            strlcat(title, status, sizeof(title));
        }
    }
    setproctitle("%s", title);
}

static void
mlvpn_config_reload(EV_P_ ev_signal *w, int revents)
{
    log_info("config", "reload (SIGHUP)");
    priv_reload_resolver();
    /* configuration file path does not matter after
     * the first intialization.
     */
    int config_fd = priv_open_config("");
    if (config_fd > 0)
    {
        if (mlvpn_config(config_fd, 0) != 0) {
            log_warn("config", "reload failed");
        } else {
            if (time(&mlvpn_status.last_reload) == -1)
                log_warn("config", "last_reload time set failed");
            mlvpn_rtun_recalc_weight();
        }
    } else {
        log_warn("config", "open failed");
    }
}

static void
mlvpn_quit(EV_P_ ev_signal *w, int revents)
{
    mlvpn_tunnel_t *t;
    log_info(NULL, "killed by signal SIGTERM, SIGQUIT or SIGINT");
    LIST_FOREACH(t, &rtuns, entries)
    {
        ev_timer_stop(EV_A_ &t->io_timeout);
        ev_io_stop(EV_A_ &t->io_read);
        if (t->status >= MLVPN_AUTHOK) {
            mlvpn_rtun_send_disconnect(t);
        }
    }
    ev_break(EV_A_ EVBREAK_ALL);
}

int
main(int argc, char **argv)
{
    int i, c, option_index, config_fd;
    struct stat st;
    ev_signal signal_hup;
    ev_signal signal_sigquit, signal_sigint, signal_sigterm;
    extern char *__progname;
#ifdef ENABLE_CONTROL
    struct mlvpn_control control;
#endif
    /* uptime statistics */
    if (time(&mlvpn_status.start_time) == -1)
        log_warn(NULL, "start_time time() failed");
    if (time(&mlvpn_status.last_reload) == -1)
        log_warn(NULL, "last_reload time() failed");

    log_init(1, 2, "mlvpn");

    _progname = strdup(__progname);
    saved_argv = calloc(argc + 1, sizeof(*saved_argv));
    for(i = 0; i < argc; i++) {
        saved_argv[i] = strdup(argv[i]);
    }
    saved_argv[i] = NULL;
    compat_init_setproctitle(argc, argv);
    argv = saved_argv;

    /* Parse the command line quickly for config file name.
     * This is needed for priv_init to know where the config
     * file is.
     *
     * priv_init will not allow to change the config file path.
     */
    while(1)
    {
        c = getopt_long(argc, saved_argv, optstr,
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 1:  /* --natural-title */
            mlvpn_options.change_process_title = 0;
            break;
        case 2:  /* --debug */
            mlvpn_options.debug = 1;
            break;
        case 3:  /* --yes-run-as-root */
            mlvpn_options.root_allowed = 1;
            break;
        case 'c': /* --config */
            strlcpy(mlvpn_options.config_path, optarg,
                    sizeof(mlvpn_options.config_path));
            break;
        case 'D': /* debug= */
            mlvpn_options.debug = 1;
            log_accept(optarg);
            break;
        case 'n': /* --name */
            strlcpy(mlvpn_options.process_name, optarg,
                    sizeof(mlvpn_options.process_name));
            break;
        case 'u': /* --user */
            strlcpy(mlvpn_options.unpriv_user, optarg,
                    sizeof(mlvpn_options.unpriv_user));
            break;
        case 'v': /* --verbose */
            mlvpn_options.verbose++;
            break;
        case 'V': /* --version */
            printf("mlvpn version %s.\n", VERSION);
            _exit(0);
            break;
        case 'q': /* --quiet */
            mlvpn_options.verbose--;
            break;
        case 'p': /* will be checked later, move on */
            break;
        case 'h': /* --help */
        default:
            usage(argv);
        }
    }

    /* Config file check */
    if (access(mlvpn_options.config_path, R_OK) != 0) {
        log_warnx("config", "unable to read config file %s",
            mlvpn_options.config_path);
    }
    if (stat(mlvpn_options.config_path, &st) < 0) {
        fatal("config", "unable to open file");
    } else if (st.st_mode & (S_IRWXG|S_IRWXO)) {
        fatal("config", "file is group/other accessible");
    }

    /* Some common checks */
    if (getuid() == 0)
    {
        void *pw = getpwnam(mlvpn_options.unpriv_user);
        if (!mlvpn_options.root_allowed && ! pw)
            fatal(NULL, "you are not allowed to run this program as root. "
                        "please specify a valid user with --user option");
        if (! pw)
            fatal(NULL, "invalid unprivilged username");
    }

#ifdef HAVE_LINUX
    if (access("/dev/net/tun", R_OK|W_OK) != 0)
    {
        fatal(NULL, "unable to open /dev/net/tun");
    }
#endif

    if (mlvpn_options.change_process_title)
    {
        if (*mlvpn_options.process_name)
        {
            __progname = strdup(mlvpn_options.process_name);
            process_title = mlvpn_options.process_name;
            setproctitle("%s [priv]", mlvpn_options.process_name);
        } else {
            __progname = "mlvpn";
            process_title = "";
            setproctitle("[priv]");
        }
    }

    if (crypto_init() == -1)
        fatal(NULL, "libsodium initialization failed");

    log_init(mlvpn_options.debug, mlvpn_options.verbose, __progname);

#ifdef HAVE_LINUX
    mlvpn_systemd_notify();
#endif

    priv_init(argv, mlvpn_options.unpriv_user);
    if (mlvpn_options.change_process_title)
        update_process_title();

    LIST_INIT(&rtuns);

    /* Kill me if my root process dies ! */
#ifdef HAVE_LINUX
    prctl(PR_SET_PDEATHSIG, SIGCHLD);
#endif

    /* Config file opening / parsing */
    config_fd = priv_open_config(mlvpn_options.config_path);
    if (config_fd < 0)
        fatalx("cannot open config file");
    if (! (loop = ev_default_loop(EVFLAG_AUTO)))
        fatal(NULL, "cannot initialize libev. check LIBEV_FLAGS?");

    /* init the reorder buffer after ev is enabled, but before we have all the
       tunnels */
    mlvpn_reorder_init();

    /* tun/tap initialization */
    mlvpn_tuntap_init();
    if (mlvpn_config(config_fd, 1) != 0)
        fatalx("cannot open config file");

    if (mlvpn_tuntap_alloc(&tuntap) <= 0)
        fatalx("cannot create tunnel device");
    else
        log_info(NULL, "created interface `%s'", tuntap.devname);
    mlvpn_sock_set_nonblocking(tuntap.fd);

    preset_permitted(argc, saved_argv);
    
    ev_io_set(&tuntap.io_read, tuntap.fd, EV_READ);
    ev_io_set(&tuntap.io_write, tuntap.fd, EV_WRITE);
    ev_io_start(loop, &tuntap.io_read);

    priv_set_running_state();

#ifdef ENABLE_CONTROL
    /* Initialize mlvpn remote control system */
    strlcpy(control.fifo_path, mlvpn_options.control_unix_path,
        sizeof(control.fifo_path));
    control.mode = MLVPN_CONTROL_READWRITE;
    control.fifo_mode = 0600;
    control.bindaddr = strdup(mlvpn_options.control_bind_host);
    control.bindport = strdup(mlvpn_options.control_bind_port);
    mlvpn_control_init(&control);
#endif

    /* re-compute rtun weight based on bandwidth allocation */
    mlvpn_rtun_recalc_weight();

    /* Last check before running */
    if (getppid() == 1)
        fatalx("Privileged process died");

    ev_signal_init(&signal_hup, mlvpn_config_reload, SIGHUP);
    ev_signal_init(&signal_sigint, mlvpn_quit, SIGINT);
    ev_signal_init(&signal_sigquit, mlvpn_quit, SIGQUIT);
    ev_signal_init(&signal_sigterm, mlvpn_quit, SIGTERM);
    ev_signal_start(loop, &signal_hup);
    ev_signal_start(loop, &signal_sigint);
    ev_signal_start(loop, &signal_sigquit);
    ev_signal_start(loop, &signal_sigterm);

    ev_run(loop, 0);

    free(_progname);
    return 0;
}
