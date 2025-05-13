# Chapter 5 - Your first eBPF program

## Make sure you've installed...

Red Hat/Centos BCC tools installation:
```bash
sudo yum install bcc bcc-doc bcc-tools
```

Ubuntu BCC tools installation:
```bash
sudo apt install bpfcc-tools linux-headers-$(uname -r)
```

Amazon Linux (AMI):
```bash
sudo amazon-linux-extras enable BCC
sudo yum install kernel-devel-$(uname -r)
sudo yum install bcc
```

## Examples

1. `BCC` - Demonstration of eBPF programs written in Python using the `BCC` library.
2. `ebpf-go` - Demonstration of eBPF programs written in Go using the `ebpf-go` library.
3. `libbpf-c` - Demonstration of eBPF programs written in C using `libbpf` library.
4. `libbpf-rs` - Demonstration of eBPF programs written in Rust using the `libbpf-rs` library.
