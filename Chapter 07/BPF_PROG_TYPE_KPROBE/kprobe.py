from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

bpf_prog = """
BPF_HASH(connection_start_times, u32);

int trace_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 start_time = bpf_ktime_get_ns();

    connection_start_times.update(&pid, &start_time);

    return 0;
}

int trace_complete(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 end_time = bpf_ktime_get_ns();
    u64 *start_time;

    start_time = connection_start_times.lookup(&pid); // Correct lookup

    if (start_time) {
        u64 duration = end_time - *start_time;
        if (duration > 0) {
            bpf_trace_printk("%d\\n", duration / 1000);
        }
        connection_start_times.delete(&pid);
    }

    return 0;
}
"""

b = BPF(text=bpf_prog)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_start")
b.attach_kretprobe(event="tcp_send_ack", fn_name="trace_complete")

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "Task", "PID", "Duration(ms)"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(msg)
        ms = float(int(msg, 10)) / 1000
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %8.2f" % (ts, task, pid, ms))