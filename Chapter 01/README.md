# Chapter 1 - Classic BPF (cBPF)

## Make sure you've installed...

```bash
$ sudo apt install -y make gcc libpcap-dev
```

## Examples

1. `ex01` - Demonstration of a cBPF packet filter using a hard-coded BPF program `ip and tcp`
2. `ex02` - Demonstration of a cBPF packtet filter that allows user input to define a `tcpdump`-like filter.
3. `ex03` - Demonstrates a `seccomp` BPF programthat blocks `openat` syscall on `/etc/passwd`.