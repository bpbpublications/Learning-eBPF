# ch08/BPF_PROG_TYPE_SK_SKB

## Introduction

Demonstration of a BPF program that bypasses the networking stack to send traffic and uses sockmap instead.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
./sk_skb
```

The test program will start a server that listens for messages and then responds back directly over the attached sockmap instead of the networking stack.