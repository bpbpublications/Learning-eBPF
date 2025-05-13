# ch08/BPF_PROG_TYPE_LWT_IN

## Introduction

Demonstrates a BPF program attached to a tunnel that counts the number of packets per protocol (IP only).

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
ip route add 10.0.0.2/32 encap bpf in obj <bpf object file> section lwt_in dev <interface>
```