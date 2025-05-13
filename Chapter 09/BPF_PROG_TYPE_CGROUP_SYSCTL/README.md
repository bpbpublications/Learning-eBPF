# ch09/BPF_PROG_TYPE_CGROUP_SYSCTL

## Introduction

This program manages the attached cgroup's access to sysctl's. The program allows the `net/ipv4/ip_forward` sysctl to be modified (written), but denies all other writes. It allows all read requests for sysctl values. The test program `test_program.sh` tries to read and then write to `net/ipv4/ip_forward` (allowed) and then tries to write to five sysctl's (denied) and then read from five sysctl's (allowed).

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```
