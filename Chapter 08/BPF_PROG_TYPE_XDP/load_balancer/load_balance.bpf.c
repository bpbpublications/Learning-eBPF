#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>  // Include for ICMP header
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_TCP 6  // Manually define IPPROTO_TCP if it's not available
#define IPPROTO_ICMP 1  // ICMP protocol number
SEC("xdp")
int load_balancer(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

  // Only process IPv4 packets
  if (eth->h_proto != __constant_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = (struct iphdr *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return XDP_DROP;

  // Check for protocol (ICMP, TCP)
  if (ip->protocol == IPPROTO_ICMP) {
    // Handle ICMP packets, pass them along
    bpf_printk("ICMP packet received\n");
    return XDP_PASS; // Pass ICMP traffic without load balancing
  }

  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS; // Pass non-TCP traffic (e.g., ICMP, UDP)
  }

  // Parse the TCP header
  struct tcphdr *tcp =
      (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
  if ((void *)(tcp + 1) > data_end)
    return XDP_DROP;

  // Check if destination port is 8080
  if (bpf_ntohs(tcp->dest) != 8080) {
    bpf_printk("TCP packet NOT destined for port 8080\n");
    return XDP_PASS; // Only load balance traffic for port 8080
  }

  bpf_printk("Load balancing TCP traffic for port 8080\n");

  // Load balancing logic
  int choice = bpf_get_prandom_u32() % 2; // Randomly choose between 0 and 1

  if (choice == 0) {
    ip->daddr = bpf_htonl(
      0x7f000001); // 127.0.0.1 (localhost:5000) 0x7F000001.
    tcp->dest = bpf_htons(5000); // Set destination port to 5000
    bpf_printk("Sending packet to 5000");
  } else {
    ip->daddr = bpf_htonl(0x7f000001); // 127.0.0.1 (localhost:6000)
    tcp->dest = bpf_htons(6000);       // Set destination port to 6000
    bpf_printk("Sending packet to 6000");
  }

  // Recalculate IP checksum
  ip->check = 0;
  ip->check =
      bpf_csum_diff(NULL, 0, (__be32 *)&ip->saddr, sizeof(ip->saddr), 0);
  ip->check = bpf_csum_diff(NULL, 0, (__be32 *)&ip->daddr, sizeof(ip->daddr),
                            ip->check);

  // Recalculate TCP checksum
  tcp->check = 0;
  tcp->check =
      bpf_csum_diff((__be32 *)&ip->saddr, sizeof(ip->saddr),
                    (__be32 *)&ip->daddr, sizeof(ip->daddr),
                    bpf_csum_diff((__be32 *)&tcp->source, sizeof(tcp->source),
                                  (__be32 *)tcp, sizeof(struct tcphdr), 0));

  // Return the packet to be transmitted with the updated destination
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
