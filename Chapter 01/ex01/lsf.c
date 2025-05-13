#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  int sockfd, ret, iface_idx;
  struct sock_fprog filter;
  /* IP and TCP */
  struct sock_filter code[] = {
      {0x28, 0, 0, 0x0000000c}, {0x15, 0, 3, 0x00000800},
      {0x30, 0, 0, 0x00000017}, {0x15, 0, 1, 0x00000006},
      {0x6, 0, 0, 0x00040000},  {0x6, 0, 0, 0x00000000},
  };
  sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sockfd == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }
  filter.len = sizeof(code) / sizeof(code[0]);
  filter.filter = code;
  ret =
      setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
  if (ret == -1) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }
  char buffer[4096];
  ssize_t len;
  struct ethhdr *eth_hdr;
  struct iphdr *ip_hdr;
  struct tcphdr *tcp_hdr;
  while (1) {
    len = recv(sockfd, buffer, sizeof(buffer), 0);
    if (len == -1) {
      perror("recv");
      exit(EXIT_FAILURE);
    }
    eth_hdr = (struct ethhdr *)buffer;

    ip_hdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    tcp_hdr = (struct tcphdr *)(buffer + sizeof(struct ethhdr) +
                                sizeof(struct iphdr));

    if (ntohs(eth_hdr->h_proto) == ETH_P_IP &&
        ip_hdr->protocol == IPPROTO_TCP) {
      printf(
          "Received TCP packet from %s:%d to %s:%d\n",
          inet_ntoa(*(struct in_addr *)&ip_hdr->saddr), ntohs(tcp_hdr->source),
          inet_ntoa(*(struct in_addr *)&ip_hdr->daddr), ntohs(tcp_hdr->dest));
    }
  }
  close(sockfd);
}