# ch05/libbpf-rs

## Introduction

These two examples demonstrate using the Go `ebpf-go` library to write BPF programs.

## Compiling this program

### example1

```bash
cd example1
cargo build
```

### libbpf-rs-example2

```bash
cd libbpf-rs-example2
cargo build
```

## Running and/or testing this program

### example1

```bash
./target/debug/libbpf-rs-example1
```

The BPF program is activated when the `openat2` syscall is executed, depending on your operating system, you may need to modify the syscall used. When triggered, it will print "Hello, World!" as well as some tracing information.

### libbpf-rs-example2

```bash
./target/debug/libbpf-rs-example1
```

The BPF program is activated when the `clone` syscall is executed, depending on your operating system, you may need to modify the syscall used. When executed, the process that triggers the syscall will have a counter updated in a BPF map that counts the number of times each PID activated the BPF program.