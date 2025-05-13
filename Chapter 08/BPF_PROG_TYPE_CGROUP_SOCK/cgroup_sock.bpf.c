#include <sys/socket.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>

SEC("cgroup/sock_create")
int block_v4_icmp(struct bpf_sock *ctx) {
  // block PF_INET, SOCK_RAW, IPPROTO_ICMP sockets
  if (ctx->family == AF_INET && ctx->type == SOCK_DGRAM &&
      ctx->protocol == IPPROTO_ICMP)
    return 0;
  return 1;
}

char LICENSE[] SEC("license") = "GPL";