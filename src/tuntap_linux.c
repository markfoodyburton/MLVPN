#include "includes.h"

#include <err.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <linux/if.h>

#include "buffer.h"
#include "tuntap_generic.h"
#include "tool.h"
#include "pkt.h"

mlvpn_pkt_t *spair=NULL;
mlvpn_pkt_t *mlvpn_tuntap_read(struct tuntap_s *tuntap)
{
  if (!spair) spair=mlvpn_pkt_get();
  mlvpn_pkt_t *p=spair;
  ssize_t ret;
  ret = read(tuntap->fd, &(p->p.data), DEFAULT_MTU);
  
  if (ret<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) {
    return NULL;
  }
  
  if (ret < 0) {
    /* read error on tuntap is not recoverable. We must die. */
    fatal("tuntap", "unrecoverable read error");
  } else if (ret == 0) { /* End of file */
    fatalx("tuntap device closed");
  } else if (ret > tuntap->maxmtu)  {
    log_warnx("tuntap",
              "cannot send packet: too big %d/%d. truncating",
              (uint32_t)ret, tuntap->maxmtu);
    ret = tuntap->maxmtu;
  }
  log_debug("tuntap", "%s < recv %zd bytes",
            tuntap->devname, ret);
  spair=NULL; // we've used this one now.
  p->p.len=ret; // data length
  p->p.type=MLVPN_PKT_DATA;

  return p;
}

int
mlvpn_tuntap_write(struct tuntap_s *tuntap, mlvpn_pkt_t *pkt)
{
    ssize_t ret;
//    mlvpn_pkt_t *pkt;

//    /* Safety checks */
//    if (MLVPN_TAILQ_EMPTY(&tuntap->sbuf)) {
//      log_warnx("tuntap","tuntap_write called with empty buffer");
//      return -1;
//    }
    
//    pkt = MLVPN_TAILQ_POP_LAST(&tuntap->sbuf);
    ret = write(tuntap->fd, pkt->p.data, pkt->p.len);
    mlvpn_pkt_release(pkt);
    if (ret < 0)
    {
        log_warn("tuntap", "%s write error", tuntap->devname);
    } else {
        if (ret != pkt->p.len)
        {
            log_warnx("tuntap", "%s write error: %zd/%d bytes sent",
               tuntap->devname, ret, pkt->len);
        } else {
            log_debug("tuntap", "%s > sent %zd bytes",
               tuntap->devname, ret);
        }
    }
    return ret;
}

int
mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    int fd;

    if ((fd = priv_open_tun(tuntap->type,
                            tuntap->devname, tuntap->maxmtu)) <= 0 )
        fatalx("failed to open /dev/net/tun read/write");
    tuntap->fd = fd;
    return fd;
}

/* WARNING: called as root
 *
 * Really open the tun device.
 * returns tun file descriptor.
 *
 * Compatibility: Linux 2.4+
 */
int
root_tuntap_open(int tuntapmode, char *devname, int mtu)
{
    struct ifreq ifr;
    int fd, sockfd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        warn("failed to open /dev/net/tun");
    } else {
        memset(&ifr, 0, sizeof(ifr));
        if (tuntapmode == MLVPN_TUNTAPMODE_TAP)
            ifr.ifr_flags = IFF_TAP;
        else
            ifr.ifr_flags = IFF_TUN;

        /* We do not want kernel packet info (IFF_NO_PI) */
        ifr.ifr_flags |= IFF_NO_PI;

        /* Allocate with specified name, otherwise the kernel
         * will find a name for us. */
        if (*devname)
            strlcpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

        /* ioctl to create the if */
        if (ioctl(fd, TUNSETIFF, &ifr) < 0)
        {
            /* don't call fatal because we want a clean nice error for the
             * unprivilged process.
             */
            warn("open tun %s ioctl failed", devname);
            close(fd);
            return -1;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        /* set tun MTU */
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            warn("socket creation failed");
        } else {
            ifr.ifr_mtu = mtu;
            if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0)
            {
                warn("unable to set tun %s mtu=%d", devname, mtu);
                close(fd);
                close(sockfd);
                return -1;
            }
            close(sockfd);
        }
    }
    /* The kernel is the only one able to "name" the if.
     * so we reread it to get the real name set by the kernel. */
    if (fd > 0) {
        strlcpy(devname, ifr.ifr_name, MLVPN_IFNAMSIZ);
    }
    return fd;
}

