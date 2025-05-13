# ch09/BPF_PROG_TYPE_CGROUP_DEVICE

## Introduction

This program manages the attached cgroup's access to devices. Allows access to `/dev/null` (1:3), `/dev/zero` (1:5) and `/dev/urandom` (1:9) only and denies access to any other device. The test program (`test_program.sh`) will try to access three devices `/dev/zero` (allowed), `/dev/urandom` (allowed)  `/dev/random` (denied).

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```
