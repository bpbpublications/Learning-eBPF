# ch08/BPF_PROG_TYPE_SCHED_CLS

## Introduction

Demonstration of a `tc` packet classifier.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The test program will attach the BPF program as a `tc` ingress filter and perform packet classification based on the destination port.