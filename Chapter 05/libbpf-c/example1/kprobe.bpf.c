#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(kprobe_clone, int __syscall_nr, const char *filename,
               const char *const *argv, const char *const *envp) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("Starting kernel function '__x64_sys_execve' (pid = %d)\n", pid);
  return 0;
}

SEC("kretprobe/__x64_sys_execve")
int kretprobe_clone(struct pt_regs *ctx) {

  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("Completed kernel function '__x64_sys_execve' (pid = %d)", pid);
  return 0;
}