#include "mlvpn.h"

/* Fairly big no ? */
#define MAX_TUNNELS 128

struct mlvpn_wrr {
    int len;
    mlvpn_tunnel_t *tunnel[MAX_TUNNELS];
    double tunval[MAX_TUNNELS];
};

static struct mlvpn_wrr wrr = {
    0,
    {NULL},
    {0}
};

double big=0;

static int wrr_min_index()
{
    int min_index = -1;
    int i;
    double min = 0;

    for(i = 0; i < wrr.len; i++)
    {
      if (wrr.tunnel[i]->quota==0 || wrr.tunnel[i]->permitted>1500) {
        if ((min_index==-1 || wrr.tunval[i] < min) && (wrr.tunnel[i]->status == MLVPN_AUTHOK)) {
          min = wrr.tunval[i];
          min_index = i;
        }
      }
    }
    return min_index;
}

/* initialize wrr system */
int mlvpn_rtun_wrr_reset(struct rtunhead *head, int use_fallbacks)
{
    mlvpn_tunnel_t *t;
    wrr.len = 0;
    LIST_FOREACH(t, head, entries)
    {
        if (t->fallback_only != use_fallbacks) {
            continue;
        }
        /* Don't select "LOSSY" tunnels, except if we are in fallback mode */
        if ((t->fallback_only && t->status >= MLVPN_AUTHOK) ||
            (t->status == MLVPN_AUTHOK))
        {
            if (wrr.len >= MAX_TUNNELS)
                fatalx("You have too many tunnels declared");
            wrr.tunnel[wrr.len] = t;
            wrr.tunval[wrr.len] = 0.0;
            wrr.len++;
        }
    }

    return 0;
}

void mlvpn_rtun_set_weight(mlvpn_tunnel_t *t, double weight)
{
  if (t->weight!=weight) {
//    if (weight<1)
//      t->weight=1;
//    else
      t->weight=weight;

/*    if (weight>t->weight) {
//      t->weight=weight;
      t->weight=((t->weight * 3.0) + weight)/4.0;
    } else {
      t->weight=((t->weight * 19.0) + weight)/20.0;
    }
//    printf("weight %f %f\n",weight, t->weight);
    
    for (int i = 0; i< wrr.len; i++) {
      wrr.tunval[i] = 0.0;
      }*/
  }
}

mlvpn_tunnel_t *
mlvpn_rtun_wrr_choose()
{

  int idx = wrr_min_index();
  if (idx == -1) return NULL; // no valid tunnels!
  double srtt_av=0;
  for (int i = 0; i< wrr.len; i++) {
    srtt_av+=wrr.tunnel[i]->srtt_av;
  }
  srtt_av/=wrr.len;
  if (srtt_av < 1) srtt_av=1;
  
  if (wrr.tunval[idx]<=0 || wrr.tunval[idx] > 1000000) {
    for (int i = 0; i< wrr.len; i++) {
      if (wrr.tunnel[i]->weight) {
        wrr.tunval[i]=1 / wrr.tunnel[i]->weight;
      } else {
        wrr.tunval[i]=wrr.len; // handle initial setup fairly
      }
    }
  } else {
// simply basing things on the SRTT doesn't work, as the srtt is often
// similar, even though te tunnel can haldle more!
// e.g. this doesn't work   wrr.tunval[idx]+=wrr.tunnel[idx]->srtt_raw;

    double d=(wrr.tunnel[idx]->srtt_raw / srtt_av);
    if (wrr.tunnel[idx]->weight<=2) {
        wrr.tunval[idx]+=d;
    } else {
      if (wrr.tunnel[idx]->srtt_raw > srtt_av * 2) {
        wrr.tunval[idx]+=d / (wrr.tunnel[idx]->weight/2);
        idx = wrr_min_index();
        if (idx == -1) return NULL; // no valid tunnels!
//      wrr.tunval[idx]+=1; // lock it out for a bit (but '1' is too long)
      } else {
        // Try to 'pull' towards the average srtt
        wrr.tunval[idx]+=d / wrr.tunnel[idx]->weight;
      }
    }
  }

  return wrr.tunnel[idx];
}
