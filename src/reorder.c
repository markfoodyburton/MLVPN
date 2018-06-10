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

#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <ev.h>

#include "reorder.h"
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
  int list_size_av;
  int max_size;

  TAILQ_HEAD(list_t, pkttailq) list, pool;
};
static struct mlvpn_reorder_buffer *reorder_buffer;
static ev_timer reorder_drain_timeout;
extern void mlvpn_rtun_inject_tuntap(mlvpn_pkt_t *pkt);
extern struct ev_loop *loop;

void mlvpn_reorder_drain();

void mlvpn_reorder_drain_timeout(EV_P_ ev_timer *w, int revents)
{
    log_debug("reorder", "reorder timeout. Packet loss?");
    printf("reorder timeout\n");
    
    struct mlvpn_reorder_buffer *b=reorder_buffer;

    if (!TAILQ_EMPTY(&b->list)) {
      b->min_seqn=TAILQ_LAST(&b->list, list_t)->pkt.seq; // Jump over any hole !!!!
    }
    printf("list size %d\n",b->list_size);
    mlvpn_reorder_drain();
    printf("list size %d\n",b->list_size);
}

// Called once from main.
void mlvpn_reorder_init()
{
  reorder_buffer=malloc(sizeof(struct mlvpn_reorder_buffer));
  reorder_buffer->max_size=10;
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
  b->list_size_av=10;
  b->is_initialized=0;
  b->enabled=0;
  mlvpn_reorder_adjust_timeout(0.8);
}

void mlvpn_reorder_enable()
{
  reorder_buffer->enabled=1;
}

void mlvpn_reorder_adjust_timeout(double t)
{
  reorder_drain_timeout.repeat = t;// ((reorder_drain_timeout.repeat*9)+ t)/10;
  printf("rtt %f\n", reorder_drain_timeout.repeat);
}

void mlvpn_reorder_insert(mlvpn_pkt_t *pkt)
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  if (!b->enabled || !pkt->reorder) {
    return mlvpn_rtun_inject_tuntap(pkt);
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

  if ((!b->is_initialized) ||
      (abs((int)(b->min_seqn - pkt->seq)) > b->list_size_av*100))
  {
    b->min_seqn = pkt->seq;
    b->is_initialized = 1;
    printf("Init\n");
    log_debug("reorder", "initial sequence: %"PRIu64"", pkt->seq);
  }

    
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
  TAILQ_FOREACH(l, &b->list, entry) {if ((int64_t)(pkt->seq - l->pkt.seq)>0) break;}
  if (l) {
    TAILQ_INSERT_BEFORE(l, p, entry);
  } else {
    TAILQ_INSERT_TAIL(&b->list, p, entry);
  }

  b->list_size++;

  if (TAILQ_LAST(&b->list,list_t) && ((int64_t)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq) > 0)) {
    log_debug("reorder", "got old insert %d behind (probably fluctuating RTT)\n",(int)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq));
    printf("got old insert %d behind (probably fluctuating RTT)\n",(int)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq));
  }

  mlvpn_reorder_drain(); // now see what canbe drained off
}

void mlvpn_reorder_drain()
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  unsigned int drain_cnt = 0;
  ev_tstamp cut=ev_now(EV_DEFAULT_UC) - (reorder_drain_timeout.repeat);

  while
    (!TAILQ_EMPTY(&b->list) &&
         (((int64_t)(b->min_seqn - TAILQ_LAST(&b->list,list_t)->pkt.seq)>=0) ||
//          (b->list_size>((b->list_size_av*3)))
//          (b->list_size > 20)
          (TAILQ_LAST(&b->list,list_t)->timestamp < cut)
           ))
    {
      
    struct pkttailq *l = TAILQ_LAST(&b->list,list_t);

    if ((int64_t)(b->min_seqn - l->pkt.seq)<0) {
      printf("Prune seq %lu min %lu list %d av %d time(from cut) %fs old",l->pkt.seq, b->min_seqn,  b->list_size, b->list_size_av*2, cut - l->timestamp);
      mlvpn_tunnel_t *t;
      LIST_FOREACH(t, &rtuns, entries) {
        printf(" loss on %s=%d ",t->name, mlvpn_loss_ratio(t));
      }
      printf("\n");
    }

    mlvpn_rtun_inject_tuntap(&l->pkt);
    
    TAILQ_REMOVE(&b->list, l, entry);
    TAILQ_INSERT_TAIL(&b->pool, l, entry);

    b->list_size--;
    drain_cnt++;

    if ((int64_t)(b->min_seqn - l->pkt.seq)<=0) {
      b->min_seqn=l->pkt.seq+1;
    }
    
  }
  
  if (drain_cnt > 1) {
    int last=b->list_size_av;
    b->list_size_av = ((b->list_size_av*9) + (b->list_size + drain_cnt) + 5)/10;
    if (b->list_size_av > 64) {
      b->list_size_av = 64;
      if (b->list_size_av != last ) {
        log_info("reorder", "List size reached limit (64)\n");
      }
    } 
    if (b->list_size_av < 4) {
      b->list_size_av = 4;
      if (b->list_size_av != last ) {
        log_debug("reorder", "List size reached limit (4)\n");
      }
    } 
  }

  if (TAILQ_EMPTY(&b->list)) {
    ev_timer_stop(EV_A_ &reorder_drain_timeout);
  } else {
    ev_timer_again(EV_A_ &reorder_drain_timeout);
  }
}
  
