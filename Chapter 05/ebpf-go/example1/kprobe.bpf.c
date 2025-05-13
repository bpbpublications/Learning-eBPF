// go:build ignore

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/sys_openat2")
int kprobe_clone() {
  const char fmt[] = "Hello, world!\n";
  bpf_trace_printk(fmt, sizeof(fmt));
  return 0;
}
