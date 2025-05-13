# ch07/BPF_PROG_TYPE_TRACEPOINT

## Introduction

This program uses tracepoints to capture the execution of `execve` syscalls using the `sys_enter_execve` tracepoint.

## Running and/or testing this program

```bash
python3 tracepoint.py
```

You may need to run some commands in a different terminal window on the same host to trigger an `execve` syscall.