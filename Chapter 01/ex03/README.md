# ch01/ex03

## Introduction

This example implement a cBPF seccomp-BPF filter that implements a filter that denies the `openat` system call from being executed.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
sudo ./seccomp.o
stat /etc/passwd
cat /etc/passwd
```

The `stat` command will be allowed, but the `cat` command will be denied.