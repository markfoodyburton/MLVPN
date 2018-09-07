#include "mlvpn.h"

extern void mlvpn_rtun_choose();

int
mlvpn_tuntap_generic_read(u_char *data, uint32_t len)
{
  mlvpn_pkt_t *pkt=mlvpn_send_buffer_write(len);
  if (pkt) {
    pkt->len = len;
    /* TODO: INEFFICIENT COPY */
    memcpy(pkt->data, data, pkt->len);
    
    return pkt->len;
  }
  return 0;
}
