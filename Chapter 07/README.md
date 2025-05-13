# Chapter 7 - eBPF observability

## Make sure you've installed...

```bash
$ sudo apt install -y make gcc libpcap-dev
```

```bash
$ sudo add-apt-repository ppa:sthima/oss
$ sudo apt-get update
$ sudo apt-get install libstapsdt0 libstapsdt-dev
$ pip install stapsdt
```

## Examples

1. `BPF_PROG_TYPE_KPROBE` - Demonstration of multiple programs that illustrate the use of kprobes, UDST's, uprobes and ksyscall.
2. `BPF_PROG_TYPE_PERF_EVENT` - Demonstration of capturing page fault events using `perf` events
3. `BPF_PROG_TYPE_TRACEPOINT` - Demonstration of capturing kernel tracepoints by tracing `execve` syscalls.
4. `BPF_PROG_TYPE_RAW_TRACEPOINT` - Demonstration of capturing kernel (raw) tracepoints by tracing `execve` syscalls.
