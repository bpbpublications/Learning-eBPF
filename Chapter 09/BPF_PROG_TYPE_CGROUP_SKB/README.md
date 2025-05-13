# ch09/BPF_PROG_TYPE_CGROUP_SKB

## Introduction

This program manages the attached cgroup's access to network traffic. The program is attached as an ingress filter and only allows ICMP and DNS (both UDP & TCP) packets from 8.8.8.8. The test program `test_program.sh` attempts to send ICMP packets to 1.1.1.1, 8.8.8.8 and 9.9.9.9 as well as try to resolve `google.com` over both TCP & UDP. Only packets from 8.8.8.8 will be allowed by the ingress filter.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```
