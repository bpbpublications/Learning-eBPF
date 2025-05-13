from bcc import BPF

# define BPF program
kernel_prog = """
int kprobe__sys_clone(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""
prog = BPF(text=kernel_prog)
while 1:
    prog.trace_print()