#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int drop_non_tcp_udp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end)
    return XDP_ABORTED;

  // Check if we have an IP packet
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_DROP;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return XDP_ABORTED;

  if (iph->protocol == IPPROTO_ICMP) {
    return XDP_DROP;
  }
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    return XDP_PASS;
  }
  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
