# ch06/xdp_firewall

## Introduction

This program is a XDP firewall that only allows traffic from RFC1918 addresses. The loader program then runs a set of unit-tests using (`bpf_prog_test_run_opts()`) to test the XDP firewall to ensure it drops the correct packets.

## Compiling this program

```bash
cd xdp_firewall
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```
