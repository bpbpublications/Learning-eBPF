# ch08/BPF_PROG_TYPE_CGROUP_SOCK

## Introduction

Demonstrates running a program on v4 socket create within the cgroup that blocks any `PF_INET` && `SOCK_RAW` && `IPPROTO_ICMP` sockets

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The test program will test opening TCP/ UDP/ ICMP sockets and the BPF program will block the ICMP socket creation.