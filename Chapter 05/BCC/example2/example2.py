from bcc import BPF

bpf = BPF(src_file = "example2.c")

# Attach BPF program to kprobe
bpf.attach_kprobe(event="do_sys_openat2", fn_name="count_sys_open")

# Retrieve the BPF map
open_count_map = bpf.get_table("open_count")

# Sleep to allow tracing
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

print("Process count:")
for pid, count in open_count_map.items():
    print(f"Process ID: {int(pid)}, Count: {count.value}")