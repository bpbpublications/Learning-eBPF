# ch05/ebpf-go

## Introduction

These two examples demonstrate using the Go `ebpf-go` library to write BPF programs.

## Compiling this program

### example1

```bash
cd example1
go mod init github.com/michaelkkehoe/ch05/ebpf-go/example1
go tidy
go generate
```

### example2

```bash
cd example2
go mod init github.com/michaelkkehoe/ch05/ebpf-go/example2
go tidy
go generate
```

## Running and/or testing this program

### example1

```bash
./ebpf-hello

```

The BPF program is activated when the `openat2` syscall is executed, depending on your operating system, you may need to modify the syscall used. When triggered, it will print "Hello, World!" as well as some tracing information.

### example2

```bash
./example2
```

The BPF program is activated when the `clone` syscall is executed, depending on your operating system, you may need to modify the syscall used. When executed, the process that triggers the syscall will have a counter updated in a BPF map that counts the number of times each PID activated the BPF program.