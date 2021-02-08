// TODO: remove workaround necessary for GitHub Actions/bcc Dec 2020
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>

// TODO: default policy, for copro should be TX, for standalone probably PASS.
#define DEFAULT_XDP     XDP_PASS

struct arppay_t {
  u8 ar_sha[ETH_ALEN];
  u8 ar_sip[4];
  u8 ar_tha[ETH_ALEN];
  u8 ar_tip[4];
};

struct isat_t {
  u8 target_mac[ETH_ALEN];
  u8 target_ip[16];
  u8 target_iplen;
  u64 observed_ktime;
};

// https://fntlnz.wtf/post/bpf-ring-buffer-usage/
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

static __always_inline struct arphdr *parsehdr(void *data, void *data_end, u16 *eth_type) {
  struct ethhdr *eth = data;
  if ((void*)eth + sizeof(*eth) <= data_end) {
    *eth_type = ntohs(eth->h_proto);
    if (*eth_type == ETH_P_8021Q || *eth_type == ETH_P_8021AD) {
      if ((void*)eth + sizeof(*eth) + sizeof(struct vlan_hdr) <= data_end) {
        struct vlan_hdr *vlan_hdr = (void*)eth + sizeof(*eth);
        *eth_type = ntohs(vlan_hdr->h_vlan_encapsulated_proto);
        return (void*)vlan_hdr + sizeof(*vlan_hdr);
      }
    } else {
      return data + sizeof(*eth);
    }
  }
  return NULL;
}

static __always_inline void update_isat(void *srcmac, void *destip, u8 iplen) {
  struct isat_t *isat_p = buffer.ringbuf_reserve(sizeof(struct isat_t));
  if (isat_p) {
    isat_p->observed_ktime = bpf_ktime_get_ns();
    memcpy(&(isat_p->target_mac), srcmac, ETH_ALEN);
    memcpy(&(isat_p->target_ip), destip, iplen);
    isat_p->target_iplen = iplen;
    buffer.ringbuf_submit(isat_p, 0);
  }
}

int arpwatch_ebpf(struct xdp_md *ctx) {
  struct isat_t isat;
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;
  u16 eth_type = 0;
  void *hdr = parsehdr(data, data_end, &eth_type);
  if (eth_type == ETH_P_ARP) {
    struct arphdr *arp_hdr = hdr;
    if (arp_hdr && (void*)arp_hdr + sizeof(*arp_hdr) + sizeof(struct arppay_t) <= data_end) {
      u16 op = ntohs(arp_hdr->ar_op);
      if (op == ARPOP_REPLY) {
        struct arppay_t *arp_pay = (void*)arp_hdr + sizeof(*arp_hdr);
	update_isat(&(arp_pay->ar_tha), &(arp_pay->ar_tip), sizeof(arp_pay->ar_tip));
	update_isat(&(arp_pay->ar_sha), &(arp_pay->ar_sip), sizeof(arp_pay->ar_sip));
      }
    }
  } else if (eth_type == ETH_P_IPV6) {
    struct ipv6hdr *ipv6_hdr = hdr;
    if (ipv6_hdr && (void*)ipv6_hdr + sizeof(*ipv6_hdr) <= data_end) {
      struct ethhdr *eth = data;
      update_isat(&(eth->h_source), &(ipv6_hdr->saddr.s6_addr), sizeof(ipv6_hdr->saddr.s6_addr));
    }
  }
	
  return DEFAULT_XDP;
}
