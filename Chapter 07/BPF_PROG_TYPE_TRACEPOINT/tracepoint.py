from bcc import BPF
from bcc.utils import printb

# Define the BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>

struct syscalls_enter_execve_args {
    int __syscall_nr;
    const char * filename;
    const char *const * argv;
    const char *const * envp;
};

int trace_execve(struct syscalls_enter_execve_args *args) {
    char filename[256] = {};

    long ret = bpf_probe_read_kernel_str(filename, sizeof(filename), (void *)args->filename);

    bpf_trace_printk("File opened: Filename: %s", filename);
    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_program)

# Attach to the tracepoint
b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")

# Print output header
print("Tracing process executions... Press Ctrl+C to stop.")

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %b" % (ts, task, pid, msg))