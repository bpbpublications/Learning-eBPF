# ch08/BPF_PROG_TYPE_SOCKET_FILTER

## Introduction

Demonstration of a eBPF packet filter using a hard-coded BPF program `ip and tcp`

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
./block_packets
```

As processes on your host make DNS queries, you will see them logged in the user-space program.