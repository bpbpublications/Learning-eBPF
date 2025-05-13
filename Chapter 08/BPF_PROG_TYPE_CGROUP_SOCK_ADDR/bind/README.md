# ch08/BPF_PROG_TYPE_CGROUP_SOCK_ADDR

## Introduction

Demonstration of a BPF program that's attached to cgroup that disslows IPv6/ UDP/ RAW sockets.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The `run.sh` program will attempt to `bind()` a set of sockets. Some will be denied by the BPF program.