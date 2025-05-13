#include <arpa/inet.h> // For DNS-related functions
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h> // for if_nametoindex
#include <netinet/in.h>
#include <netinet/ip.h> // Include this line to define struct iphdr
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ETH_HEADER_SIZE sizeof(struct ethhdr)
#define IP_HEADER_SIZE sizeof(struct iphdr)
#define UDP_HEADER_SIZE sizeof(struct udphdr)

#include "block_packets.skel.h" // Assuming your BPF program is in block_packets.bpf.c

// DNS header structure (simplified)
struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

int main(int argc, char **argv) {
  struct block_packets_bpf *skel;
  int sock, prog_fd, err;
  struct sockaddr_ll sll;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return -1;
  }

  const char *ifname = argv[1];

  // 1. Create a raw socket (PF_PACKET)
  sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    fprintf(stderr, "cannot create raw socket: %s\n", strerror(errno));
    return -1;
  }

  // 2. Bind the socket to the interface
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_nametoindex(ifname);
  if (sll.sll_ifindex == 0) {
    fprintf(stderr, "Resolving device name to index for %s: %s\n", ifname,
            strerror(errno));
    close(sock);
    return -1;
  }
  sll.sll_protocol = htons(ETH_P_ALL); // Capture all protocols
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    fprintf(stderr, "bind to %s: %s\n", ifname, strerror(errno));
    close(sock);
    return -1;
  }

  // 3. Open and load the BPF skeleton
  skel = block_packets_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    close(sock);
    return 1;
  }

  // 4. Get the file descriptor of the BPF program
  prog_fd = bpf_program__fd(skel->progs.dns_filter);

  // 5. Attach the BPF program to the socket using setsockopt
  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
    err = -3;
    fprintf(stderr, "Failed to attach to raw socket: %s\n", strerror(errno));
    goto cleanup;
  }

  printf("BPF program attached successfully to %s!\n", ifname);

  // 6. Packet processing loop (example)
  char buffer[4096];
  ssize_t packet_len;

  printf("Press Ctrl+C to exit...\n");
  while (1) {
    packet_len = recv(sock, buffer, sizeof(buffer), 0);
    if (packet_len == -1) {
      perror("recv");
      break;
    }

    struct ethhdr *eth_hdr = (struct ethhdr *)buffer;
    struct iphdr *ip_hdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    if (ip_hdr->protocol == IPPROTO_UDP) {
      struct udphdr *udp_hdr =
          (struct udphdr *)(buffer + sizeof(struct ethhdr) + (ip_hdr->ihl * 4));
      if (ntohs(udp_hdr->dest) == 53) {
        struct dns_hdr *dns_hdr =
            (struct dns_hdr *)(buffer + sizeof(struct ethhdr) +
                               (ip_hdr->ihl * 4) + sizeof(struct udphdr));

        if (!(ntohs(dns_hdr->flags) & 0x8000)) {
          printf("  DNS Request:\n");

          unsigned char *p = buffer + sizeof(struct ethhdr) +
                             (ip_hdr->ihl * 4) + sizeof(struct udphdr) +
                             sizeof(struct dns_hdr);
          char name[256];
          int i = 0;
          while (*p != 0) {
            int len = *p++;
            for (int j = 0; j < len; j++) {
              name[i++] = *p++;
            }
            name[i++] = '.';
          }
          name[i - 1] = '\0';

          uint16_t qtype = ntohs(*(uint16_t *)p);
          p += 2;
          uint16_t qclass = ntohs(*(uint16_t *)p);

          printf("    Name: %s\n", name);
          printf("    Type: %u\n", qtype);
          printf("    Class: %u\n", qclass);
        }
      }
    }
  }

cleanup:
  block_packets_bpf__destroy(skel);
  close(sock);
  return 0;
}
