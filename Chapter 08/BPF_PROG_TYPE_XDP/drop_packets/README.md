# ch08/BPF_PROG_TYPE_XDP

## Introduction

Demonstration of a XDP program that drops all non-TCP and non-UDP `ip` packets.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh <interface-name>
```

If you run `ping` to any remote host from another terminal window, you'll see that the return response is dropped.