/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Adapted for mlvpn by Laurent Coustet (c) 2015
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
  IDEAS:

   1/ have a fixed length reorder buffer, controlled by a timer to deliver to the tun/tap.

*/

#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <ev.h>

#include "log.h"

#include "mlvpn.h"

struct pkttailq
{
  mlvpn_pkt_t pkt;
  ev_tstamp timestamp;
  TAILQ_ENTRY(pkttailq) entry;
};



/* The reorder buffer data structure itself */
struct mlvpn_reorder_buffer {
  uint64_t min_seqn;  /**< Lowest seq. number that can be in the buffer */
  int is_initialized;
  int enabled;
  int list_size;
  int list_size_max;
  uint64_t loss;
  uint64_t delivered;
  uint64_t inboundpps;
  uint64_t inboundpkts;
  double ideal_len;
  TAILQ_HEAD(list_t, pkttailq) list, pool;
};
static struct mlvpn_reorder_buffer *reorder_buffer;
static ev_timer reorder_drain_timeout;
extern void mlvpn_rtun_inject_tuntap(mlvpn_pkt_t *pkt);
extern mlvpn_tunnel_t *best_quick_tun();
extern struct ev_loop *loop;

void mlvpn_reorder_drain();

int mlvpn_reorder_length() 
{
  int r=reorder_buffer->list_size_max;
  reorder_buffer->list_size_max=0;
  return r;
}

double mlvpn_total_loss()
{
  float r=0;
  
  if (reorder_buffer->loss) {
    r=((double)reorder_buffer->loss / (double)(reorder_buffer->loss + reorder_buffer->delivered))*100.0;
  }
  reorder_buffer->loss=0;
  reorder_buffer->delivered=0;

  return r;
}
  
void mlvpn_reorder_drain_timeout(EV_P_ ev_timer *w, int revents)
{
    log_debug("reorder", "reorder timeout. Packet loss?");
    struct mlvpn_reorder_buffer *b=reorder_buffer;

    if (!TAILQ_EMPTY(&b->list)) {
//      if (b->min_seqn != TAILQ_LAST(&b->list, list_t)->pkt.seq) {
////        b->min_seqn=TAILQ_LAST(&b->list, list_t)->pkt.seq; // Jump over any hole !!!!
////        b->loss++;
////        printf("Timeout loss\n");
//      }
      mlvpn_reorder_drain();
    }
}

// Called once from main.
void mlvpn_reorder_init()
{
  reorder_buffer=malloc(sizeof(struct mlvpn_reorder_buffer));
  TAILQ_INIT(&reorder_buffer->pool);
  TAILQ_INIT(&reorder_buffer->list);
  ev_init(&reorder_drain_timeout, &mlvpn_reorder_drain_timeout);
  mlvpn_reorder_reset();
}

//called from main, or from config
void
mlvpn_reorder_reset()
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  while (!TAILQ_EMPTY(&b->list)) {
    struct pkttailq *p = TAILQ_FIRST(&b->list);
    TAILQ_REMOVE(&b->list, p, entry);
    TAILQ_INSERT_HEAD(&b->pool, p, entry);
  }
  b->list_size=0;
  b->list_size_max=0;
  b->is_initialized=0;
  b->enabled=0;
  b->inboundpps=0;
  b->inboundpkts=0;
  mlvpn_reorder_adjust_timeout(0.8);
}

void mlvpn_reorder_enable()
{
  reorder_buffer->enabled=1;
}

// t given in ms
void mlvpn_reorder_adjust_timeout(double srtt)
{
  reorder_drain_timeout.repeat = (srtt*7.0)/1000.0;//2.2;// ((reorder_drain_timeout.repeat*9)+ t)/10;
  log_debug("reorder", "adjusting reordering drain timeout to %.0fs", reorder_drain_timeout.repeat );
//  printf("rtt %f\n", reorder_drain_timeout.repeat);

  struct mlvpn_reorder_buffer *b=reorder_buffer;

  b->inboundpps=b->inboundpkts/*/we are called each second*/;
  b->inboundpkts=0;

  /* Ideal size of the reorder buffer is long enough to get a resent back, if we
   have a loss. So (the bandwidth requested/8) /1500 = number of packets / s
   so, outstanding packets :   ((bandwidth/8)/1500) * (srtt)
   e.g inbound packets/s  * srtt
     (NB srtt in seconds (e.g. /1000).
     only problme - we dont know what the incomming bandwidth is !
*/
  b->ideal_len=((b->ideal_len*3.0)+((double)b->inboundpps*srtt*2.0)/1000.0)/4.0;
//  printf("Ideal %f\n",b->ideal_len);

}

void mlvpn_reorder_insert(mlvpn_tunnel_t *tun, mlvpn_pkt_t *pkt)
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  b->inboundpkts++;
  if (pkt->type == MLVPN_PKT_DATA_RESEND) {
    if ((int64_t)(b->min_seqn - pkt->seq) > 0) {
      log_debug("resend","Rejecting (un-necissary ?) resend %lu",pkt->seq);
      return;
    } else {
      log_debug("resend","Injecting resent %lu",pkt->seq);
    }
  } else if (!b->enabled || !pkt->reorder || !pkt->seq || pkt->seq==b->min_seqn)
  {
    if (pkt->seq==b->min_seqn) {
      log_debug("reorder", "Inject TCP packet Just In Time (seqn %lu)", pkt->seq);
      b->min_seqn = pkt->seq+1;
    }
    mlvpn_rtun_inject_tuntap(pkt);
    if (!TAILQ_EMPTY(&b->list))  mlvpn_reorder_drain();
    return;
  }

  if ((!b->is_initialized) ||
      ((int64_t)(b->min_seqn - pkt->seq) > 1000 && pkt->seq < 1000))
  {
    b->min_seqn = pkt->seq;
    b->is_initialized = 1;
    log_debug("reorder", "initial sequence: %"PRIu64"", pkt->seq);
  }

  if (((int64_t)(b->min_seqn - pkt->seq) > 0)) {
    log_debug("reorder", "got old insert %d behind (probably agressive pruning) on %s",(int)(b->min_seqn - pkt->seq), tun->name);
    b->loss++;
//    mlvpn_rtun_inject_tuntap(pkt);
    if (!TAILQ_EMPTY(&b->list))  mlvpn_reorder_drain();
    return;
  }

  struct pkttailq *p;
  if (!TAILQ_EMPTY(&b->pool)) {
    p = TAILQ_FIRST(&b->pool);
    TAILQ_REMOVE(&b->pool, p, entry);
  } else {
    p=malloc(sizeof (struct pkttailq));
  }
  memcpy(&p->pkt, pkt, sizeof(mlvpn_pkt_t));

  p->timestamp = ev_now(EV_DEFAULT_UC);


    
    /*
     * calculate the offset from the head pointer we need to go.
     * The subtraction takes care of the sequence number wrapping.
     * For example (using 16-bit for brevity):
     *  min_seqn  = 0xFFFD
     *  pkt_seq   = 0x0010
     *  offset    = 0x0010 - 0xFFFD = 0x13
     * Then we cast to a signed int, if the subtraction ends up in a large
     * number, that will be seen as negative when casted....
     */
  struct pkttailq *l;
  // we could search from the other end if it's closer?
  TAILQ_FOREACH(l, &b->list, entry) {
    if (pkt->seq == l->pkt.seq) { // replicated packet!
      log_debug("resend","Un-necissary resend %lu",pkt->seq);
      TAILQ_INSERT_TAIL(&b->pool, p, entry);
      mlvpn_reorder_drain();
      return;
    }
    if ((int64_t)(pkt->seq - l->pkt.seq)>0) break;
  }
  if (l) {
    TAILQ_INSERT_BEFORE(l, p, entry);
  } else {
    TAILQ_INSERT_TAIL(&b->list, p, entry);
  }

  b->list_size++;
  if (b->list_size > b->list_size_max) {
    b->list_size_max = b->list_size;
  }
//  if (TAILQ_LAST(&b->list,list_t) && ((int64_t)(b->min_seqn -
//  TAILQ_LAST(&b->list,list_t)->pkt.seq) > 0)) {
//  if (((int64_t)(b->min_seqn - p->pkt.seq) > 0)) {
//    log_debug("reorder", "got old insert %d behind (probably fluctuating RTT)\n",(int)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq));
//    printf("got old insert %d behind (probably fluctuating RTT)\n",(int)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq));
//  }

  mlvpn_reorder_drain(); // now see what canbe drained off
}

void mlvpn_reorder_drain()
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  unsigned int drain_cnt = 0;
  ev_tstamp cut=ev_now(EV_DEFAULT_UC) - (reorder_drain_timeout.repeat);

#if 0
  // If there is no chance of getting a packet (it's older than the latest
  // packet seen on an ACTIVE  tunnel - the maximum reorder_length),
  // then consider it lost
  uint64_t oldest=0;
  if (b->min_seqn != TAILQ_LAST(&b->list,list_t)->pkt.seq)
  {
    mlvpn_tunnel_t *t;
    mlvpn_tunnel_t *ptun;
    LIST_FOREACH(t, &rtuns, entries) {
      if (t->reorder_length
          && t->status >= MLVPN_AUTHOK
          &&  (t->last_activity > ev_now(EV_DEFAULT_UC)-3.0)
// if there has been acivity in the last 3 seconds, we'll assume this tunnel isn't dead.
// better keep all the tunnels 'active' to make sure that there is traffic on all tunnels, so we can prune better !!!!
          ) {
        uint64_t o=(t->last_seen - (t->reorder_length));
        if (!oldest || ((int64_t)(oldest-o))>=0) {
          oldest=o;
          ptun=t;
        }
      }
    }

    if (oldest==0 || (int64_t)(b->min_seqn - oldest)>=0) 
    {
      oldest=b->min_seqn;
    } else {
      printf("Pruning %lu (from %s reorder %d)\n",oldest - b->min_seqn, ptun->name, ptun->reorder_length);
    }
  } else {
    oldest=b->min_seqn;
  }
#endif

/* We should
  deliver all packets in order
    Packets that are 'before' the current 'minium' - drop
    Packets that are 'after' the current 'minimum' hold - till the cut-off time,
      then deliver
    // If we are less than the ideal size, ignore the cut-off and grow till the ideal size.
  */
  while
    (!TAILQ_EMPTY(&b->list) &&
     (((int64_t)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq)>=0)
//      || ((int64_t)(oldest - TAILQ_LAST(&b->list,list_t)->pkt.seq)>=0)
      || (b->list_size > b->ideal_len && (TAILQ_LAST(&b->list,list_t)->timestamp < cut))
//      || b->list_size>200
       ))
    {
      if (!((int64_t)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq)>=0)) {
        log_debug("reorder","Clearing size %d (ideal %f) last %f cut %f", b->list_size, b->ideal_len, TAILQ_LAST(&b->list,list_t)->timestamp, cut);
      }
    struct pkttailq *l = TAILQ_LAST(&b->list,list_t);

// should we drop out-of-order?    
    if (l->pkt.seq == b->min_seqn) {  // normal delivery
      mlvpn_rtun_inject_tuntap(&l->pkt);
      b->delivered++;
      log_debug("reorder","Delivered %lu", l->pkt.seq);
      b->min_seqn=l->pkt.seq+1;
    } else if ((int64_t)(b->min_seqn - l->pkt.seq)<0) { // cut off time reached
      mlvpn_rtun_inject_tuntap(&l->pkt);
      b->delivered++;
      b->loss+=l->pkt.seq - b->min_seqn;
      log_debug("reorder","Lost %d from %lu, Delivered %lu", (int)(l->pkt.seq - b->min_seqn), b->min_seqn,  l->pkt.seq);
      b->min_seqn=l->pkt.seq+1;
    } else {
      b->loss++;
      log_debug("reorder","Lost %lu, (trying to deliver %lu)", l->pkt.seq, b->min_seqn);
    }

    TAILQ_REMOVE(&b->list, l, entry);
    TAILQ_INSERT_TAIL(&b->pool, l, entry);

    b->list_size--;
    drain_cnt++;

  }

  if (TAILQ_EMPTY(&b->list)) {
    ev_timer_stop(EV_A_ &reorder_drain_timeout);
  } else {
    ev_timer_again(EV_A_ &reorder_drain_timeout);
  }
}
  
