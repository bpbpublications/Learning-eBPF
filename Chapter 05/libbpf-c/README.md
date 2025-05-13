# ch05/BCC

## Introduction

These two examples demonstrate using the libbpf-c.

## Compiling this program

### example1

```bash
cd example1
make all
```

### example2

```bash
cd example2
make all
```

## Running and/or testing this program

### example1

```bash
./kprobe
```

The BPF program is activated with the `clone` syscall is executed. You may need to run some command line tools in another terminal window to get the BPF program to trigger. When triggered, it will print "Hello, World!" as well as some tracing information.

### example2

```bash
./example2
```

The BPF program is activated when the `openat2` syscall is executed, depending on your operating system, you may need to modify the syscall used. When executed, the process that triggers the syscall will have a counter updated in a BPF map that counts the number of times each PID activated the BPF program.
