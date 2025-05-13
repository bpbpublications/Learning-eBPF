#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <stddef.h>

SEC("xdp")
int drop_non_rfc1918(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;

  if (data + sizeof(*eth) > data_end) {
    return XDP_ABORTED;
  }

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    return XDP_PASS;
  }

  struct iphdr *iph = data + sizeof(*eth);

  if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
    return XDP_ABORTED;
  }

  __u32 src_ip = bpf_ntohl(iph->saddr);
  if ((src_ip & 0xFF000000) != 0x0A000000 &&
      (src_ip & 0xFFF00000) != 0xAC100000 &&
      (src_ip & 0xFFFF0000) != 0xC0A80000) {
    return XDP_DROP;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
