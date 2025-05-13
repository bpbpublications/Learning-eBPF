#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/kernel.h>
#include <linux/string.h>

#define SRC_MAC 0x000000000001
#define DST_MAC 0x000000000002
#define DST_IFINDEX 2

SEC("lwt_xmit")
int rewrite_and_redirect(struct __sk_buff *skb) {
  __u64 smac = SRC_MAC, dmac = DST_MAC;
  int ret, ifindex = DST_IFINDEX;
  struct ethhdr ehdr;

  ret = bpf_skb_change_head(skb, 14, 0);
  if (ret < 0) {
    return BPF_DROP;
  }

  ehdr.h_proto = bpf_htons(ETH_P_IP);
  memcpy(&ehdr.h_source, &smac, 6);
  memcpy(&ehdr.h_dest, &dmac, 6);

  ret = bpf_skb_store_bytes(skb, 0, &ehdr, sizeof(ehdr), 0);
  if (ret < 0) {
    return BPF_DROP;
  }

  return bpf_redirect(ifindex, 0);
}