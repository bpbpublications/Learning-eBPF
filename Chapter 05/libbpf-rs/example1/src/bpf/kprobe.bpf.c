#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";


SEC("kprobe/__x64_sys_clone")
int BPF_KPROBE(do_sys_clone, struct pt_regs *regs) { 
       const char fmt[] = "Hello, world!\n";
       bpf_trace_printk(fmt, sizeof(fmt));
       return 0;
}

