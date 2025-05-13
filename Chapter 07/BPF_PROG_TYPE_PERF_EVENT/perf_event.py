from bcc import BPF, PerfType, utils, PerfSWConfig
import time

test = """
#include <uapi/linux/ptrace.h>

BPF_HASH(pfcnt, u32, u64, 10240);

int count_sw_page_faults(struct bpf_perf_event_data *ctx) {  // Use the correct context struct
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 zero = 0;
    __u64 *count = pfcnt.lookup(&pid);

    if (count) {
        *count += 1;
    } else {
        pfcnt.update(&pid, &zero); // Correct: Use .update()
        count = pfcnt.lookup(&pid); // Re-lookup after update

        if (count) {
            *count += 1;
        }
    }
    return 0;
}
"""
b = BPF(text=test)
b.attach_perf_event(
    ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.PAGE_FAULTS,
    fn_name="count_sw_page_faults",
    sample_period=0,  # Sample every event
    sample_freq=1 # sample_freq must be zero when sample_period is not zero
)

while True:
    try:
        time.sleep(2)
        print("Page Fault Counts per PID:")
        for k, v in b["pfcnt"].items():
            print(f"PID {k.value}: {v.value}")
    except KeyboardInterrupt:
        break