#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/version.h>

SEC("cgroup/dev")
int bpf_prog1(struct bpf_cgroup_dev_ctx *ctx) {
  short type = ctx->access_type & 0xFFFF;
  short access = ctx->access_type >> 16;
  char fmt[] = "Access to device: %d:%d attempted\n";
  bpf_trace_printk(fmt, sizeof(fmt), ctx->major, ctx->minor);
  char fmt2[] = "Access Type: %d Access: %d\n";
  bpf_trace_printk(fmt2, sizeof(fmt2), type, access);

  /* Ensure only character devices (char) are allowed */
  if (type != BPF_DEVCG_DEV_CHAR) {
    char fmt3[] = "Not a character device";
    bpf_trace_printk(fmt3, sizeof(fmt3));
    return 0; // Deny if not a character device
  }

  /* Ensure major number is 1 (Character devices: zero, urandom, null, etc.) */
  if (ctx->major != 1) {
    return 0; // Deny if not major 1
  }

  /* Allow only specific minor numbers */
  if (ctx->minor == 3 || ctx->minor == 5 || ctx->minor == 9) {
    return 1; // Allow /dev/null (1:3), /dev/zero (1:5) and /dev/urandom (1:9)
  }

  return 0; // Deny everything else
}

char _license[] SEC("license") = "GPL";
