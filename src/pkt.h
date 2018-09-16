#ifndef _MLVPN_PKT_H
#define _MLVPN_PKT_H

#include <stdint.h>
#include <ev.h>
#include "crypto.h"

#define DEFAULT_MTU 1500

enum {
    MLVPN_PKT_AUTH,
    MLVPN_PKT_AUTH_OK,
    MLVPN_PKT_KEEPALIVE,
    MLVPN_PKT_DATA,
    MLVPN_PKT_DATA_RESEND,
    MLVPN_PKT_DISCONNECT,
    MLVPN_PKT_RESEND
};


/* packet sent on the wire. 20 bytes headers for mlvpn */
typedef struct {
    uint16_t len;
    uint16_t version: 4; /* protocol version */
    uint16_t type: 6;   /* protocol options */
    uint16_t reorder: 1; /* do reordering or not */
    uint16_t sent_loss: 5;  /* loss as reported from far end */
    uint16_t timestamp;
    uint16_t timestamp_reply;
    uint32_t flow_id;
    uint64_t tun_seq;     /* Stream sequence per flow (for crypto) */
    uint64_t data_seq;    /* data packets global sequence */
    char data[DEFAULT_MTU];
} __attribute__((packed)) mlvpn_proto_t;

typedef struct mlvpn_pkt_t
{
  mlvpn_proto_t p;
  ev_tstamp timestamp;
  uint16_t len; // wire read length
  TAILQ_ENTRY(mlvpn_pkt_t) entry;
} mlvpn_pkt_t;

typedef struct mlvpn_pkt_list_t 
{
  TAILQ_HEAD(list_t, mlvpn_pkt_t) list;
  uint64_t length;
  uint64_t max_size;
} mlvpn_pkt_list_t;

#define MLVPN_TAILQ_INIT(lst_) do{TAILQ_INIT(&((lst_)->list));(lst_)->length=0;}while(0)
#define MLVPN_TAILQ_INSERT_HEAD(lst_, l) do{TAILQ_INSERT_HEAD(&((lst_)->list), l, entry);(lst_)->length++;}while(0)
#define MLVPN_TAILQ_INSERT_TAIL(lst_, l) do{TAILQ_INSERT_TAIL(&((lst_)->list), l, entry);(lst_)->length++;}while(0)
#define MLVPN_TAILQ_INSERT_AFTER(lst_, elm, l) do{TAILQ_INSERT_AFTER(&((lst_)->list), elm, l, entry);(lst_)->length++;}while(0)
#define MLVPN_TAILQ_INSERT_BEFORE(lst_, elm, l) do{TAILQ_INSERT_BEFORE(elm, l, entry);(lst_)->length++;}while(0)
#define MLVPN_TAILQ_REMOVE(lst_, l) do{TAILQ_REMOVE(&((lst_)->list), l, entry);(lst_)->length--;}while(0)
#define MLVPN_TAILQ_FOREACH(l, lst_) TAILQ_FOREACH(l, &((lst_)->list), entry)
#define MLVPN_TAILQ_FOREACH_REVERSE(l, lst_) TAILQ_FOREACH(l, &((lst_)->list), list_t, entry)
#define MLVPN_TAILQ_EMPTY(lst_) TAILQ_EMPTY(&((lst_)->list))
#define MLVPN_TAILQ_FIRST(lst_) TAILQ_FIRST(&((lst_)->list))
#define MLVPN_TAILQ_LAST(lst_) TAILQ_LAST(&((lst_)->list), list_t)
#define MLVPN_TAILQ_LENGTH(lst_) ((lst_)->length)
static inline mlvpn_pkt_t *MLVPN_TAILQ_POP_LAST(mlvpn_pkt_list_t *lst)
{
  mlvpn_pkt_t *l = MLVPN_TAILQ_LAST(lst);
  if (l) MLVPN_TAILQ_REMOVE(lst, l);
  return l;
}


mlvpn_pkt_t *mlvpn_pkt_get();
void mlvpn_pkt_release(mlvpn_pkt_t *p);

                                        
#define PKTHDRSIZ(pkt) (sizeof(pkt)-sizeof(pkt.data))
#define ETH_OVERHEAD 24
#define IPV4_OVERHEAD 20
#define TCP_OVERHEAD 20
#define UDP_OVERHEAD 8

#define IP4_UDP_OVERHEAD (IPV4_OVERHEAD + UDP_OVERHEAD)

#endif
