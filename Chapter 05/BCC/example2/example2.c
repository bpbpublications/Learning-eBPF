#include <linux/ptrace.h>

BPF_HASH(open_count, u32);

int count_sys_open(struct pt_regs *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u64 *count = open_count.lookup(&pid);
  if (count) {
        	    (*count)++;
  } else {
        	    u64 val = 1;
        	    open_count.update(&pid, &val);
  }
  return 0;
}