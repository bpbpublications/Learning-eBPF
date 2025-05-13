#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

SEC("tc")
int process_packet(struct __sk_buff *skb) {
  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;

  if (skb->len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    return -1;
  }
  eth_header = (struct ethhdr *)(long)skb->data;
  ip_header = (struct iphdr *)(long)(skb->data + sizeof(struct ethhdr));

  if ((void *)(ip_header + 1) > (void *)(long)skb->data_end) {
    return -1;
  }

  if (ip_header->protocol == IPPROTO_TCP) {
    tcp_header = (struct tcphdr *)(long)(skb->data + sizeof(struct ethhdr) +
                                         sizeof(struct iphdr));
    return bpf_ntohs(tcp_header->dest); // Return the destination port
  }
  return -1; // Default return if not TCP
}

// Required license declaration
char _license[] SEC("license") = "GPL";
