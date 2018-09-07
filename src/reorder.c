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
  int list_size_max;  // used to report only
  uint64_t loss;
  uint64_t delivered;

  ev_tstamp last;
  ev_tstamp diffs;
  int arrived;

  double max_srtt;

  TAILQ_HEAD(list_t, pkttailq) list, pool;
};
static struct mlvpn_reorder_buffer *reorder_buffer;
static ev_timer reorder_drain_timeout;
extern void mlvpn_rtun_inject_tuntap(mlvpn_pkt_t *pkt);
extern struct ev_loop *loop;
static ev_timer reorder_timeout_tick;
extern uint64_t out_resends;
void mlvpn_reorder_reset();

void mlvpn_reorder_drain();

int aolderb(uint64_t a, uint64_t b)
{
  return ((int64_t)(b-a)) > 0;
}
int aoldereqb(uint64_t a, uint64_t b)
{
  return ((int64_t)(b-a)) >= 0;
}


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
  mlvpn_reorder_drain();
}

void mlvpn_reorder_tick(EV_P_ ev_timer *w, int revents)
{


  mlvpn_tunnel_t *t;
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  double max_srtt = 0.0;
  int ts=0;

  int up=0;
  LIST_FOREACH(t, &rtuns, entries)
  {
    if (t->status >= MLVPN_AUTHOK) up++;
    if (t->status == MLVPN_AUTHOK && !t->fallback_only) {
      /* We don't want to monitor fallback only links inside the
       * reorder timeout algorithm
       */
      if (t->srtt_av > max_srtt) {
        max_srtt = t->srtt_av;
        ts=1;
      }
        
    }
  }
  if (up==0) {
    b->is_initialized=0;
  }

  if (ts>0) {
    max_srtt/=ts;
  }
  
  if (max_srtt <= 0) {
    max_srtt=800;
  }

  b->max_srtt=max_srtt;

  if (b->arrived) {
    ev_tstamp av=((b->diffs / (float)b->arrived)/2.0);
    b->diffs=0;
    b->arrived=0;
    if (av > 0 && av < 1) {
      reorder_drain_timeout.repeat=av;
    } else {
      reorder_drain_timeout.repeat=0.01;
    }
  } else {
    reorder_drain_timeout.repeat=0.01;
  }

  log_debug("reorder", "adjusting reordering drain timeout to %.0fms", reorder_drain_timeout.repeat*1000 );
}

// Called once from main.
void mlvpn_reorder_init()
{
  reorder_buffer=malloc(sizeof(struct mlvpn_reorder_buffer));
  TAILQ_INIT(&reorder_buffer->pool);
  TAILQ_INIT(&reorder_buffer->list);
  reorder_drain_timeout.repeat = 0.01;
  mlvpn_reorder_reset();
  ev_init(&reorder_drain_timeout, &mlvpn_reorder_drain_timeout);
  ev_timer_init(&reorder_timeout_tick, &mlvpn_reorder_tick, 0., 1.0);
  ev_timer_start(EV_A_ &reorder_timeout_tick);
  ev_timer_start(EV_A_ &reorder_drain_timeout);
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
  b->last=0;
  b->diffs=0;
  b->arrived=0;
  b->max_srtt=0.1;
}

void mlvpn_reorder_enable()
{
  reorder_buffer->enabled=1;
}

void mlvpn_reorder_insert(mlvpn_tunnel_t *tun, mlvpn_pkt_t *pkt)
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  ev_tstamp now=ev_now(EV_DEFAULT_UC);
  ev_tstamp diff=now - b->last;
  b->last = now;
  b->diffs+=diff;
  b->arrived++;

  if (pkt->type == MLVPN_PKT_DATA_RESEND) {
    if (out_resends>0) out_resends--;
    if (aolderb(pkt->seq, b->min_seqn)) {
      log_debug("resend","Rejecting (un-necissary ?) resend %lu",pkt->seq);
      return;
    } else {
      log_debug("resend","Injecting resent %lu",pkt->seq);
    }
  } else if (!b->enabled || !pkt->reorder || !pkt->seq || pkt->seq==b->min_seqn)
    // if this is a resend, it may  not be marked as reorderable, so we
    // must skip fast delivery
  {
    if (pkt->seq==b->min_seqn) {
      log_debug("reorder", "Inject TCP packet Just In Time (seqn %lu)", pkt->seq);
      b->min_seqn = pkt->seq+1;
    }
    mlvpn_rtun_inject_tuntap(pkt);
    b->delivered++;
    return;
  }

  if ((!b->is_initialized) ||
      ((int64_t)(b->min_seqn - pkt->seq) > 1000 && pkt->seq < 1000))
  {
    b->min_seqn = pkt->seq;
    b->is_initialized = 1;
    log_debug("reorder", "initial sequence: %"PRIu64"", pkt->seq);
  }

  if (aolderb(pkt->seq, b->min_seqn)) {
    log_debug("loss", "got old insert %d behind (probably agressive pruning) on %s",(int)(b->min_seqn - pkt->seq), tun->name);
    b->loss++;
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
      return;
    }
    if (aolderb(l->pkt.seq, pkt->seq)) break;
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

}

void mlvpn_reorder_drain()
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  unsigned int drain_cnt = 0;
  // 2.2 is a good window size
  // 3 * more when we have resends (there and back + processing time etc)
  ev_tstamp cut=ev_now(EV_DEFAULT_UC) - ((double)b->max_srtt/1000.0*(out_resends?6.6:2.2));

/* We should
  deliver all packets in order
    Packets that are 'before' the current 'minium' - drop
    Packets that are 'after' the current 'minimum' hold - till the cut-off time,
      then deliver

  We would love a list that was equal to the number of things we need such
  that (max_srtt*2 + processing, + other things in the resend queue) time can
  pass, and we'll still be able to fill in wih resends...
  Lets call that max_srtt*6.6 (as above)

  But, no point having a length greater than  we could be asking for
  (e.g. that could be found in the pkt list)
*/

  int target_len=(int)(b->max_srtt*6.6/(reorder_drain_timeout.repeat * 1000));
  if (target_len > PKTBUFSIZE*3) target_len=PKTBUFSIZE*3;
  while (!TAILQ_EMPTY(&b->list) &&
         ( aoldereqb(TAILQ_LAST(&b->list,list_t)->pkt.seq, b->min_seqn)
           || (TAILQ_LAST(&b->list,list_t)->timestamp < cut)
           || (b->list_size > target_len)
           ))
  {

    if (!aoldereqb(TAILQ_LAST(&b->list,list_t)->pkt.seq, b->min_seqn) ) {
      log_debug("loss","Clearing size %d last %f  outstanding resends %lu", b->list_size,  TAILQ_LAST(&b->list,list_t)->timestamp,  out_resends);
    }
    struct pkttailq *l = TAILQ_LAST(&b->list,list_t);
    TAILQ_REMOVE(&b->list, l, entry);
    TAILQ_INSERT_TAIL(&b->pool, l, entry);

    b->list_size--;
    drain_cnt++;

    if (l->pkt.seq == b->min_seqn) {  // normal delivery
      mlvpn_rtun_inject_tuntap(&l->pkt);
      b->delivered++;
      log_debug("reorder","Delivered %lu", l->pkt.seq);
      b->min_seqn=l->pkt.seq+1;
      if (b->list_size < target_len) break;
    } else if (aolderb(b->min_seqn, l->pkt.seq)) { // cut off time reached
      mlvpn_rtun_inject_tuntap(&l->pkt);
      b->delivered++;
      b->loss+=l->pkt.seq - b->min_seqn;
      log_debug("loss","Lost %d from %lu, Delivered %lu", (int)(l->pkt.seq - b->min_seqn), b->min_seqn,  l->pkt.seq);
      b->min_seqn=l->pkt.seq+1;
    } else {
      b->loss++;
      log_debug("loss","Lost %lu, (trying to deliver %lu)", l->pkt.seq, b->min_seqn);
    }
  }

}
