from bcc import BPF
from bcc.utils import printb

prog = """
int readline_enter(void *ctx) {
    bpf_trace_printk("'readline' function called in bash!\\n");
    return 0;
}
"""

b = BPF(text=prog)
b.attach_uprobe(name="/usr/bin/bash", sym="readline", fn_name="readline_enter")

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))