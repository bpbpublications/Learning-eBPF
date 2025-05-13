#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#define SOL_TCP 6


SEC("sockops")
int modify_buffers(struct bpf_sock_ops *skops) {
  int bufsize = 30000;
  int rv = 0;
  int op;
  op = (int)skops->op;

  switch (op) {
  case BPF_SOCK_OPS_TCP_CONNECT_CB:
  case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    rv =
        bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    rv +=
        bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    break;
  default:
    rv = -1;
  }
  skops->reply = rv;
  return 1;
}

char LICENSE[] SEC("license") = "GPL";
