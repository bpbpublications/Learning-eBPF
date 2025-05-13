# ch08/BPF_PROG_TYPE_SK_LOOKUP

## Introduction

Demonstration of a BPF program that listens to multiple ports and redirects traffic back to a single process.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The test program will start an server that then will be made available on 3 additional ports.