# ch07/BPF_PROG_TYPE_PERF_EVENT

## Introduction

This program attaches to software `PAGE_FAULT` `perf` events. Everytime a program encounters a page-fault, it increments a counter of each page fault against the process PID. Every two seconds, it will print a list of PIDs with the corresponding number of page faults.

## Running and/or testing this program

```bash
python3 perf_event.py
```
