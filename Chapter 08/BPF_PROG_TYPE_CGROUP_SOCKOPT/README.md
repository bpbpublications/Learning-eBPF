# ch08/BPF_PROG_TYPE_CGROUP_SOCKOPT

## Introduction

Demonstration of a BPF program attached to a cgroup that controls what `setsockopt` options can be applied.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

You can see the BPF program output by running `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal window.