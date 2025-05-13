from bcc import BPF
from bcc.utils import printb
# Define the eBPF program
bpf_program = """
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>


struct info_t {
    char name;
    int is_ret;
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct bpf_raw_tracepoint_args *ctx) {

    // TP_PROTO(struct pt_regs *regs, long id),
    struct pt_regs *regs = (void *)ctx->args[0];
    int __syscall_nr;
    const char * filename;
    const char *const * argv;
    const char *const * envp;

    u64 id = ctx->args[1]; // syscall ID is in the second argument
    if (id != __NR_execve) {
        return 0;
    }
    bpf_probe_read_kernel_str(&filename, sizeof(filename), &regs[0]);
    bpf_trace_printk("Filename argument: %s \\n", filename);
    return 0;
}
"""

# Load and attach the BPF program
bpf = BPF(text=bpf_program)
bpf.attach_raw_tracepoint(tp="sys_enter", fn_name="trace_execve")

print("Tracing execve syscalls... Press Ctrl+C to exit.")
# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %b" % (ts, task, pid, msg.decode()))
