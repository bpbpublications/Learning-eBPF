#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/kernel.h>
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u8));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, 256); // Assuming protocol numbers are within 0-255
} protocol_counts SEC(".maps");

SEC("lwt_in")
int count_protocols(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  __u8 protocol = 0;

  if (skb->protocol == __bpf_constant_htons(ETH_P_IP)) {
    struct iphdr *iph = data;
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
      return BPF_OK;
    }
    protocol = iph->protocol;
  } else {
    return BPF_OK;
  }

  __u64 *count = bpf_map_lookup_elem(&protocol_counts, &protocol);
  if (count) {
    (*count)++;
  } else {
    __u64 initial_count = 1;
    bpf_map_update_elem(&protocol_counts, &protocol, &initial_count, BPF_ANY);
  }
  return BPF_OK;
}

char _license[] SEC("license") = "GPL";