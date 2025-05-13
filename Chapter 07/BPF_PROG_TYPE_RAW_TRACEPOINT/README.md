# ch07/BPF_PROG_TYPE_RAW_TRACEPOINT

## Introduction

This program uses raw tracepoints to capture the execution of `execve` syscalls using the `sys_enter_execve` tracepoint. The raw tracepoint eBPF program accesses the raw parameters of the tracepoint as raw tracepoints do not provide a pre-contracted argument struct.

## Running and/or testing this program

```bash
python3 tracepoint.py
```

You may need to run some commands in a different terminal window on the same host to trigger an `execve` syscall.