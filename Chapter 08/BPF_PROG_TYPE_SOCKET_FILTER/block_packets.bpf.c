#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN 14

SEC("socket")
int dns_filter(struct __sk_buff *skb) {
  __u16 eth_type;
  __u8 ip_protocol;
  __u16 udp_dport;

  // Check Ethernet type
  if (bpf_skb_load_bytes(skb, 12, &eth_type, sizeof(eth_type)) < 0) {
    return 0; // Drop if incomplete
  }
  if (__bpf_ntohs(eth_type) != ETH_P_IP) {
    return 1; // Pass if not IP
  }
  // Check IP protocol
  if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
                         &ip_protocol, sizeof(ip_protocol)) < 0) {
    return 0; // Drop if incomplete
  }
  if (ip_protocol != IPPROTO_UDP) {
    return 1; // Pass if not UDP
  }
  // Check UDP destination port
  if (bpf_skb_load_bytes(skb,
                         ETH_HLEN +
                             sizeof(struct iphdr) /* Assuming no options */ +
                             offsetof(struct udphdr, dest),
                         &udp_dport, sizeof(udp_dport)) < 0) {
    return 0; // Drop if incomplete
  }
    if (__bpf_ntohs(udp_dport != 53)) {
      return 1; // Pass if not DNS port
    }
    return -1;
}

char _license[] SEC("license") = "GPL";
