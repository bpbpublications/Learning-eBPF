#include "bpf_insn.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/if.h>
#include <netinet/tcp.h> // For struct tcphdr and TCP flags
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER)                                              \
  (offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))
#endif
char bpf_log_buf[BPF_LOG_BUF_SIZE];

int main() {
  int sock_fd = -1, prog_fd;
  struct sockaddr_ll sll;

  struct bpf_insn prog[] = {
      BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
      BPF_LD_ABS(BPF_B,
                 ETH_HLEN + offsetof(struct iphdr,
                                     protocol)), // Load IP protocol into R0
      BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, IPPROTO_TCP, 2), // Jump if TCP
      BPF_MOV64_IMM(BPF_REG_0, 0),                     // Drop if not TCP
      BPF_EXIT_INSN(),
      BPF_MOV64_IMM(BPF_REG_0, 2048), // Accept if TCP
      BPF_EXIT_INSN(),
  };
  size_t insns_cnt = ARRAY_SIZE(prog);
  LIBBPF_OPTS(bpf_prog_load_opts, opts, .log_buf = bpf_log_buf,
              .log_size = BPF_LOG_BUF_SIZE, );
  prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", prog,
                          insns_cnt, &opts);
  if (prog_fd < 0) {

    goto cleanup;
  }

  int sock;
  sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                htons(ETH_P_ALL));
  if (sock < 0) {
    fprintf(stderr, "cannot create raw socket\n");
    return -1;
  }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_nametoindex("wlp114s0");
  if (sll.sll_ifindex == 0) {
    fprintf(stderr, "bpf: Resolving device name to index: %s\n",
            strerror(errno));
    close(sock);
    return -1;
  }
  sll.sll_protocol = htons(ETH_P_ALL);
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    fprintf(stderr, "bind to %s: %s\n", "wlp114s0", strerror(errno));
    close(sock);
    return -1;
  }
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl F_GETFL failed");
    return -1;
  }
  flags &= ~O_NONBLOCK;
  if (fcntl(sock, F_SETFL, flags) == -1) {
    perror("fcntl F_SETFL failed");
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) <
      0) {
    perror("setsockopt(SO_ATTACH_FILTER)");
    goto cleanup;
  }

  struct ethhdr *eth_hdr;
  struct iphdr *ip_hdr;
  struct tcphdr *tcp_hdr;
  char buffer[4096];
  ssize_t packet_len;

  while (1) {
    packet_len = recv(sock, buffer, sizeof(buffer), 0);
    if (packet_len == -1) {
      perror("recv");
      exit(EXIT_FAILURE);
    }

    eth_hdr = (struct ethhdr *)buffer;
    /* Parse IP header */
    ip_hdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    if (ip_hdr->protocol == IPPROTO_TCP) {
      tcp_hdr = (struct tcphdr *)(buffer + sizeof(struct ethhdr) +
                                  sizeof(struct iphdr));

      char source_ip[INET_ADDRSTRLEN];
      char dest_ip[INET_ADDRSTRLEN];

      inet_ntop(AF_INET, &(ip_hdr->saddr), source_ip, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ip_hdr->daddr), dest_ip, INET_ADDRSTRLEN);

      printf("Source IP: %s, Source Port: %d, Dest IP: %s, Dest Port: %d, "
             "Protocol: TCP\n",
             source_ip, ntohs(tcp_hdr->source), dest_ip, ntohs(tcp_hdr->dest));
    }
  }

cleanup:
  return 0;
}
