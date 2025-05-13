#include "xdp_firewall.skel.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_PACKET_SIZE 1500
#define ETH_P_IP 0x0800

struct ethhdr *build_ethernet_header(void *packet, unsigned char *src_mac,
                                     unsigned char *dst_mac) {
  struct ethhdr *eth = (struct ethhdr *)packet;
  memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  memcpy(eth->h_source, src_mac, ETH_ALEN);
  eth->h_proto = bpf_htons(ETH_P_IP);
  return eth;
}

struct iphdr *build_ip_header(void *packet, uint32_t src_ip, uint32_t dst_ip) {
  struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
  ip->version = 4;
  ip->ihl = 5;
  ip->tot_len = bpf_htons(sizeof(struct iphdr));
  ip->id = bpf_htons(54321);
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->saddr = bpf_htonl(src_ip);
  ip->daddr = bpf_htonl(dst_ip);
  return ip;
}

static inline __u32 ip_from_string(const char *ip_str) {
  __u32 ip = 0;
  int ret = inet_pton(AF_INET, ip_str, &ip);
  if (ret != 1) {
    return 0;
  }
  return bpf_htonl(ip);
}

int test_xdp_program(struct xdp_firewall_bpf *skel, unsigned char *src_mac,
                     unsigned char *dst_mac, uint32_t src_ip) {
  unsigned char packet[TEST_PACKET_SIZE] = {0};
  build_ethernet_header(packet, src_mac, dst_mac);
  build_ip_header(packet, src_ip, 0xC0A80001);

  LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = packet,
              .data_size_in =
                  sizeof(struct ethhdr) + sizeof(struct iphdr) + 20 // Example
  );

  int ret = bpf_prog_test_run_opts(
      bpf_program__fd(skel->progs.drop_non_rfc1918), &opts);
  return opts.retval;
}

int main() {
  struct xdp_firewall_bpf *skel;
  int err;

  skel = xdp_firewall_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = xdp_firewall_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF program\n");
    return 1;
  }

  unsigned char src_mac[ETH_ALEN] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
  unsigned char dst_mac[ETH_ALEN] = {0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x5f};
  __u32 src_ip;

  // Test with RFC1918 IP address 10.0.0.1
  int ret =
      test_xdp_program(skel, src_mac, dst_mac, ip_from_string("10.0.0.1"));
  if (ret == XDP_PASS) {
    printf("[PASSED]: RFC1918 IP 10.0.0.1 allowed\n");
  } else {
    printf("[FAILED]: RFC1918 IP 10.0.0.1 should be allowed, got %d\n", ret);
  }

  // Test with non-RFC1918 IP address 8.8.8.8
  ret = test_xdp_program(skel, src_mac, dst_mac, ip_from_string("8.8.8.8"));
  if (ret == XDP_DROP) {
    printf("[PASSED]: Non-RFC1918 IP 8.8.8.8 dropped\n");
  } else {
    printf("[FAILED]: Non-RFC1918 IP 8.8.8.8 should be dropped, got %d\n", ret);
  }

  // Test a boundary address (lowest in 172.16.0.0/12 range)
  ret = test_xdp_program(skel, src_mac, dst_mac, ip_from_string("172.16.0.0"));
  if (ret == XDP_PASS) {
    printf("[PASSED]: RFC1918 IP 172.16.0.0 allowed\n");
  } else {
    printf("[FAILED]: RFC1918 IP 172.16.0.0 should be allowed, got %d\n", ret);
  }

  xdp_firewall_bpf__destroy(skel);
  return 0;
}