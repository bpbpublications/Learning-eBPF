# ch08/BPF_PROG_TYPE_SCHED_ACT

## Introduction

Demonstration of a `tc` packet action. This program drops 7% of ICMP traffic.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The test program will initiate a set of pings that will be dropped approximately 7% of the time.