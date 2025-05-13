#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Defines a hash map called ‘openat_count’ which can contain 8192 entries, has
// a key type of pid_t and a value type of u64.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, u64);
} openat_count SEC(".maps");

SEC("kprobe/__openat2")
int bpf_prog1(struct pt_regs *ctx) {
  // Get the current user-space program PID
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // Check if an entry is in the hash map ‘openat_count’ for the given PID
  u64 *count = bpf_map_lookup_elem(&openat_count, &pid);

  if (count) {
    (*count)++;
  } else {
    u64 val = 1;
    // Create the map entry for the user-space PID
    bpf_map_update_elem(&openat_count, &pid, &val, BPF_ANY);
  }
  return 0;
}

char _license[] SEC("license") = "GPL";