#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

SEC("action")
int drop_icmp_randomly(struct __sk_buff *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;

  if (data + sizeof(*eth) > data_end) {
    return TC_ACT_OK;
  }

  if (eth->h_proto == __bpf_constant_htons(ETH_P_IP)) {
    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)ip + sizeof(*ip) > data_end) {
      return TC_ACT_OK;
    }

    if (ip->protocol == IPPROTO_ICMP) {
      __u32 random_value = bpf_get_prandom_u32();
      if (random_value % 100 < 7) { // Drop with 7% probability
        return TC_ACT_SHOT;
      }
    }
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
