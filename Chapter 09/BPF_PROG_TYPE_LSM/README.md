# ch09/BPF_PROG_TYPE_LSM

## Introduction

This program allows us to attach BPF programs to Linux Security Module (LSM) hooks. In this example, we attach to the `file_open` hook. The test program (in `run.sh`)

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```
