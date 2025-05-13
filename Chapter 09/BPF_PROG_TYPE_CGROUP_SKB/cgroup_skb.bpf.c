// #include <stddef.h>
// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/in.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define ALLOWED_IP __builtin_bswap32(0x08080808) // 8.8.8.8
#define DNS_PORT 53                              // DNS port 53
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff) {
  __u16 frag_off;

  bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off,
                     2);
  frag_off = __bpf_ntohs(frag_off);
  return frag_off & (IP_MF | IP_OFFSET);
}

SEC("cgroup_skb/ingress")
int ingress_filter(struct __sk_buff *skb) {
  __u8 ip = 0;
  __u16 dst_port = 0;
  __u16 src_port = 0;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (skb->protocol == htons(ETH_P_IP)) {
    if (data + sizeof(struct iphdr) > data_end) {
      return 0;
    }
    struct iphdr *ip = data;
    bpf_printk("Packet from: %u.%u.%u.%u to: %u.%u.%u.%u", (ip->saddr & 0xFF),
               (ip->saddr >> 8 & 0xFF), (ip->saddr >> 16 & 0xFF),
               (ip->saddr >> 24 & 0xFF), (ip->daddr & 0xFF),
               (ip->daddr >> 8 & 0xFF), (ip->daddr >> 16 & 0xFF),
               (ip->daddr >> 24 & 0xFF));
    if (ip->saddr == ALLOWED_IP) {
      if (ip->protocol == IPPROTO_ICMP) {
        return 1;
      } else if (ip->protocol == IPPROTO_TCP) {
        if (data + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
          return 0;
        }
        struct tcphdr *tcp = data + sizeof(struct iphdr);
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
      } else if (ip->protocol == IPPROTO_UDP) { // UDP
        if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
          return 0;
        }
        struct udphdr *udp = data + sizeof(struct iphdr);
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
      }

      if (src_port == 53 || dst_port == 53) {
        bpf_printk("DNS Packet (TCP/UDP) - Source Port: %u, Dest Port: %u",
                   src_port, dst_port);
        // Do something with the DNS packet, e.g., return 1 to drop it
        return 1; // Example: Drop the packet
      }
    }
  }

  // // Allow only packets from 8.8.8.8 (Ingress)
  // bpf_printk("Packet from: %u.%u.%u.%u to: %u.%u.%u.%u",
  //     (ip->saddr & 0xFF), (ip->saddr >> 8 & 0xFF),
  //     (ip->saddr >> 16 & 0xFF), (ip->saddr >> 24 & 0xFF),
  //     (ip->daddr & 0xFF), (ip->daddr >> 8 & 0xFF),
  //     (ip->daddr >> 16 & 0xFF), (ip->daddr >> 24 & 0xFF));
  // if (ip->saddr == ALLOWED_IP) {
  //     // Allow ICMP (ping) from 8.8.8.8
  //     if (ip->protocol == IPPROTO_ICMP)
  //         return 1;

  //     // Allow DNS (UDP/TCP 53) from 8.8.8.8
  //     if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP) {
  //         struct udphdr *udp = udphdr(skb);
  //         if (udp->source == __builtin_bswap16(DNS_PORT))
  //             return 1;
  //     }
  // }

  // Deny everything else
  return 0;
}

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
  return 1;
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // // Ensure we have an Ethernet header
  // struct ethhdr *eth = data;
  // // if ((void *)(eth + 1) > data_end)
  // //     bpf_printk("Break 4");
  // //     return 0;

  // // Ensure we have an IP packet
  // if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
  //     bpf_printk("Break 5");
  //     return 0;

  // struct iphdr *ip = (struct iphdr *)(eth + 1);
  // if ((void *)(ip + 1) > data_end)
  //     bpf_printk("Break 6");
  //     return 0;

  // bpf_printk("Packet from: %u.%u.%u.%u to: %u.%u.%u.%u",
  //     (ip->saddr & 0xFF), (ip->saddr >> 8 & 0xFF),
  //     (ip->saddr >> 16 & 0xFF), (ip->saddr >> 24 & 0xFF),
  //     (ip->daddr & 0xFF), (ip->daddr >> 8 & 0xFF),
  //     (ip->daddr >> 16 & 0xFF), (ip->daddr >> 24 & 0xFF));
  // // Allow only packets to 8.8.8.8 (Egress)
  // if (ip->daddr == ALLOWED_IP) {
  //     // Allow ICMP (ping) to 8.8.8.8
  //     if (ip->protocol == IPPROTO_ICMP)
  //         return 1;

  //     // Allow DNS (UDP/TCP 53) to 8.8.8.8
  //     if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP) {
  //         struct udphdr *udp = (struct udphdr *)(ip + 1);
  //         if ((void *)(udp + 1) > data_end)
  //             bpf_printk("Break 7");
  //             return 0;

  //         if (udp->dest == __builtin_bswap16(DNS_PORT))
  //             return 1;
  //     }
  // }

  // Deny everything else
  bpf_printk("Break 8");
  return 1;
}

char _license[] SEC("license") = "GPL";
