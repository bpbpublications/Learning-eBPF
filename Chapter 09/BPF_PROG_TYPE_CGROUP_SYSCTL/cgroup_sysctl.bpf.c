#include <stdint.h>
#include <string.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/stddef.h>

/* Max supported length of sysctl value string (pow2). */
#define MAX_VALUE_STR_LEN 0x40

/* The sysctl name we're blocking. */
#define IP_FORWARDING_NAME "net/ipv4/ip_forward"

static __always_inline int is_ip_forwarding(struct bpf_sysctl *ctx) {
  char name[64];
  int ret;

  memset(name, 0, sizeof(name));
  ret = bpf_sysctl_get_name(ctx, name, sizeof(name), 0);
  if (ret < 0)
    return 0;

  // Manually compare the bytes of the name to "net/ipv4/ip_forward"
  char ip_forwarding_name[] = "net/ipv4/ip_forward";
  for (int i = 0; i < sizeof(ip_forwarding_name) - 1; ++i) {
    if (name[i] != ip_forwarding_name[i])
      return 0;
  }

  return 1;
}

SEC("cgroup/sysctl")
int sysctl_ip_forwarding(struct bpf_sysctl *ctx) {
  if (ctx->write) {
    // Deny all writes except for "net/ipv4/ip_forward"
    if (is_ip_forwarding(ctx))
      return 1; // Allow the write access to "net/ipv4/ip_forward"
  } else {
    // Allow all reads
    return 1;
  }

  return 0; // Deny all other sysctl operations
}

char _license[] SEC("license") = "GPL";
