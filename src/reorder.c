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
#include "pkt.h"

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
  int arrived;
  double pkts_per_sec;
  uint64_t pkts_sent;

  double max_srtt;

  mlvpn_pkt_list_t list;

  ev_check reorder_drain_check;

};
static struct mlvpn_reorder_buffer *reorder_buffer;
//static ev_timer reorder_drain_check;
extern void mlvpn_rtun_inject_tuntap(mlvpn_pkt_t *pkt);
extern struct ev_loop *loop;
static ev_timer reorder_timeout_tick;
extern uint64_t out_resends;
extern mlvpn_pkt_list_t send_buffer;    /* send buffer */
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
  
void mlvpn_reorder_drain_check(EV_P_ ev_check *w, int revents)
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  ev_tstamp now=ev_now(EV_DEFAULT_UC);
  ev_tstamp diff=now - b->last;
//  printf("%f %lu %f \n", diff, b->pkts_sent, b->pkts_per_sec);
  
  if (b->pkts_sent < b->pkts_per_sec * diff) {
    b->pkts_sent++;
    mlvpn_reorder_drain();
  }
}

void mlvpn_reorder_tick(EV_P_ ev_timer *w, int revents)
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  mlvpn_tunnel_t *t;
  double max_srtt = 0.0;
  int ts=0;

  ev_tstamp now=ev_now(EV_DEFAULT_UC);
  ev_tstamp diff=now - b->last;
  b->last = now;
  b->pkts_sent=0;

  int up=0;
  LIST_FOREACH(t, &rtuns, entries)
  {
    if (t->status >= MLVPN_AUTHOK) up++;
    if (t->status == MLVPN_AUTHOK && !t->fallback_only) {
      /* We don't want to monitor fallback only links inside the
       * reorder timeout algorithm
       */
      if (t->srtt_av > max_srtt) {
        max_srtt += t->srtt_av;
        ts++;
      }
        
    }
  }
  if (up==0 && b->is_initialized) {
    log_warnx("reorder", "No Tunnels hence resetting\n");
    b->is_initialized=0;
  }
  
  if (ts>0) {
    max_srtt/=ts;
  }
  
  if (max_srtt <= 0) {
    max_srtt=800;
  }

  b->max_srtt=max_srtt;

  if (diff) {
    b->pkts_per_sec=((float)b->arrived/diff);
/*      
    ev_tstamp av=((b->diff / (float)b->arrived)/2.0);
    b->arrived=0;
    if (av > 0 && av < 1) {
      reorder_drain_timeout.repeat=av;
    } else {
      reorder_drain_timeout.repeat=0.01;
      }*/
  } else {
    b->pkts_per_sec=(float)b->arrived;
//    reorder_drain_timeout.repeat=0.01;
  }

//  log_debug("reorder", "adjusting reordering drain timeout to %.0fms", reorder_drain_timeout.repeat*1000 );
}

// Called once from main.
void mlvpn_reorder_init()
{
  reorder_buffer=malloc(sizeof(struct mlvpn_reorder_buffer));
  MLVPN_TAILQ_INIT(&reorder_buffer->list);
//  reorder_drain_timeout.repeat = 0.01;
  reorder_buffer->enabled=0;
  mlvpn_reorder_reset();

  ev_check_init(&reorder_buffer->reorder_drain_check, mlvpn_reorder_drain_check);

//  ev_init(&reorder_drain_timeout, &mlvpn_reorder_drain_timeout);
//  ev_timer_start(EV_A_ &reorder_drain_timeout);

  ev_timer_init(&reorder_timeout_tick, &mlvpn_reorder_tick, 0., 1.0);
  ev_timer_start(EV_A_ &reorder_timeout_tick);
}

//called from main, or from config
void
mlvpn_reorder_reset()
{
  log_warnx("reorder", "Reset");
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  while (!MLVPN_TAILQ_EMPTY(&b->list)) {
    mlvpn_pkt_t *p = MLVPN_TAILQ_FIRST(&b->list);
    MLVPN_TAILQ_REMOVE(&b->list, p);
    mlvpn_pkt_release(p);
  }
  b->list_size=0;
  b->list_size_max=0;
  b->is_initialized=0;
  b->last=0;
  b->arrived=0;
  b->pkts_per_sec=1;
  b->pkts_sent=0;
  b->max_srtt=0.1;
}

void mlvpn_reorder_enable()
{
  reorder_buffer->enabled=1;
}

void mlvpn_reorder_insert(mlvpn_tunnel_t *tun, mlvpn_pkt_t *pkt)
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  b->arrived++;

//  printf("received data seq %lu tun seq %lu from tun %s\n", pkt->p.data_seq, pkt->p.tun_seq, tun->name);

  if (pkt->p.type == MLVPN_PKT_DATA_RESEND) {
    if (out_resends>0) out_resends--;
    if (aolderb(pkt->p.data_seq, b->min_seqn)) {
      log_debug("resend","Rejecting (un-necissary ?) resend %lu",pkt->p.data_seq);
      mlvpn_pkt_release(pkt);
      return;
    } else {
      log_debug("resend","Injecting resent %lu",pkt->p.data_seq);
    }
  } else if (!b->enabled || !pkt->p.reorder || !pkt->p.data_seq || pkt->p.data_seq==b->min_seqn)
    // if this is a resend, it may  not be marked as reorderable, so we
    // must skip fast delivery
  {
    if (pkt->p.data_seq==b->min_seqn) {
      log_debug("reorder", "Inject TCP packet Just In Time (seqn %lu)", pkt->p.data_seq);
      b->min_seqn = pkt->p.data_seq+1;
    }
    mlvpn_rtun_inject_tuntap(pkt); // this will deliver and free the packet
    b->delivered++;
    return;
  }

  if ((!b->is_initialized) ||
      ((int64_t)(b->min_seqn - pkt->p.data_seq) > 1000 && pkt->p.data_seq < 1000))
  {
    b->min_seqn = pkt->p.data_seq;
    b->is_initialized = 1;
    log_debug("reorder", "initial sequence: %"PRIu64"", pkt->p.data_seq);
  }

  if (aolderb(pkt->p.data_seq, b->min_seqn)) {
    log_debug("loss", "got old insert %d behind (probably agressive pruning) on %s",(int)(b->min_seqn - pkt->p.data_seq), tun->name);
    b->loss++;
    mlvpn_pkt_release(pkt);
    return;
  }

  pkt->timestamp = ev_now(EV_DEFAULT_UC);

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
  mlvpn_pkt_t *l;
  // we could search from the other end if it's closer?
  MLVPN_TAILQ_FOREACH(l, &b->list) {
    if (pkt->p.data_seq == l->p.data_seq) { // replicated packet!
      log_debug("resend","Un-necissary resend %lu",pkt->p.data_seq);
      mlvpn_pkt_release(pkt);
      return;
    }
    if (aolderb(l->p.data_seq, pkt->p.data_seq)) break;
  }
  if (l) {
    MLVPN_TAILQ_INSERT_BEFORE(&b->list, l, pkt);
  } else {
    MLVPN_TAILQ_INSERT_TAIL(&b->list, pkt);
  }

  b->list_size++;
  if (b->list_size > b->list_size_max) {
    b->list_size_max = b->list_size;
  }

  if (!ev_is_active(&b->reorder_drain_check)) {
    ev_check_start(EV_A_ &b->reorder_drain_check);
  }
}

void mlvpn_reorder_drain()
{
  struct mlvpn_reorder_buffer *b=reorder_buffer;
  unsigned int drain_cnt = 0;
  // 2.2 is a good window size
  // 3 * more when we have resends (there and back + processing time etc)
//  ev_tstamp cut=ev_now(EV_DEFAULT_UC) -  ((double)b->max_srtt/1000.0*(out_resends?6.6:2.2));
  ev_tstamp cut=ev_now(EV_DEFAULT_UC) -  (MLVPN_IO_TIMEOUT_DEFAULT*(out_resends?2:1));

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

  int clearall=0;
//  int target_len=(int)(b->max_srtt*2.2/(reorder_drain_timeout.repeat * 1000));
  int target_len=(b->pkts_per_sec*1000.0) / (b->max_srtt*2.2);
  if (target_len > PKTBUFSIZE*5) target_len=PKTBUFSIZE*5;
  while (!MLVPN_TAILQ_EMPTY(&b->list) &&
         ( aoldereqb(MLVPN_TAILQ_LAST(&b->list)->p.data_seq, b->min_seqn)
           || (MLVPN_TAILQ_LAST(&b->list)->timestamp < cut)
           || (b->list_size > target_len)
           || clearall
           ))
  {

    if (!aoldereqb(MLVPN_TAILQ_LAST(&b->list)->p.data_seq, b->min_seqn) ) {
      log_debug("loss","Clearing size %d last %f  outstanding resends %lu", b->list_size,  MLVPN_TAILQ_LAST(&b->list)->timestamp,  out_resends);
      mlvpn_tunnel_t *t;
      LIST_FOREACH(t, &rtuns, entries)
      {
        printf("%s last tun seq %lu seq vec %lx\n",t->name,t->seq_last, t->seq_vect);
      }
//      clearall=1;
    }
    mlvpn_pkt_t *l = MLVPN_TAILQ_LAST(&b->list);
    MLVPN_TAILQ_REMOVE(&b->list, l);

    b->list_size--;
    drain_cnt++;

    if (l->p.data_seq == b->min_seqn) {  // normal delivery
      mlvpn_rtun_inject_tuntap(l);
      b->delivered++;
      log_debug("reorder","Delivered data seq %lu (tun seq %lu)", l->p.data_seq, l->p.tun_seq);
      b->min_seqn=l->p.data_seq+1;
      if (b->list_size < target_len && !clearall) break;
    } else if (aolderb(b->min_seqn, l->p.data_seq)) { // cut off time reached
      mlvpn_rtun_inject_tuntap(l);
      b->delivered++;
      b->loss+=l->p.data_seq - b->min_seqn;
      log_debug("loss","Lost %d from %lu, Delivered %lu (tun seq %lu)", (int)(l->p.data_seq - b->min_seqn), b->min_seqn,  l->p.data_seq, l->p.tun_seq);
      b->min_seqn=l->p.data_seq+1;
    } else {
      mlvpn_pkt_release(l);
      b->loss++;
      log_debug("loss","Lost %lu, (trying to deliver %lu) (tun seq %lu)", l->p.data_seq, b->min_seqn, l->p.tun_seq);
    }
  }
  if (clearall) {
    while(!MLVPN_TAILQ_EMPTY(&send_buffer)) {
      // we shoudl only throw away TCP packets!
      mlvpn_pkt_release(MLVPN_TAILQ_POP_LAST(&send_buffer));
    }
  }  


  if (out_resends > b->list_size) out_resends=b->list_size;

  if (MLVPN_TAILQ_EMPTY(&b->list)) {
    if (ev_is_active(&b->reorder_drain_check)) {
      ev_check_stop(EV_A_ &b->reorder_drain_check);
    }
  }

}
