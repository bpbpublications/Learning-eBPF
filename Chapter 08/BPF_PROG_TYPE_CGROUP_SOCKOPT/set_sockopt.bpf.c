#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>

#define SO_RCVBUF 8
#define SO_DEBUG 1

SEC("cgroup/setsockopt")
int setsockopt_handler(struct bpf_sockopt *ctx) {
  bpf_printk("setsockopt called: level=%d, optname=%d\n", ctx->level,
             ctx->optname);

  // Allow SO_RCVBUF (socket receive buffer size)
  if (ctx->optname == SO_RCVBUF) {
    bpf_printk("Allowing SO_RCVBUF setsockopt call.\n");
    return 1; // Allow
  }
  // Deny SO_DEBUG (debugging option)
  if (ctx->optname == SO_DEBUG) {
    bpf_printk("Blocking SO_DEBUG setsockopt call.\n");
    return 0; // Deny
  }
  return 1; // Allow all other options by default
}

char LICENSE[] SEC("license") = "GPL";
