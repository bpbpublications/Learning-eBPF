# ch08/BPF_PROG_TYPE_SOCK_OPS

## Introduction

Demonstration of a BPF program that modifies send and recieve socket buffer sizes.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The test program will launch a Python process which attempt to run `getsockopt` which will trigger the BPF program updating the send & recieve buffer sizes.