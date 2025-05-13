# ch08/BPF_PROG_TYPE_NETFILTER

## Introduction

Demonstration of an eBPF program being attached to a `netfilter` hook.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The test program will attach the BPF program to the firewall, test some new connections and then exit.