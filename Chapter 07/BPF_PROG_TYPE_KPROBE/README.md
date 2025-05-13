# ch07/BPF_PROG_TYPE_KPROBE

## Introduction

This program type allows the tracing of kprobes, syscalls, uprobes and User Statically Defined Tracepoints (USDTs). See each subheading for more information.

## KPROBE.PY

### Running and/or testing this program

```bash
python3 kprobe.py
```

New connections should regularly be opened by your machine by printed the application, if not, you can try running this on a different terminal window on the same host:

```bash
wget https://www.google.com
```

To open a connection to Google which will be printed by the application.

## KSYSCALL.PY

### Running and/or testing this program

```bash
python3 ksyscall.py
```

You may need to execute some new programs (e.g. ls, cat) in a different terminal window to see the `cat` syscall executed.

## UPROBE.PY

### Running and/or testing this program

```bash
python3 uprobe.py
```

You *will* need to open a separate (`bash`) terminal window and execute commands to trigger the bash `readline` function and the BPF program.

## USDT.PY

### Make sure you've installed...

If you are running Ubuntu...

```bash
sudo add-apt-repository ppa:sthima/oss
sudo apt-get update
sudo apt-get install libstapsdt0 libstapsdt-dev
pip install stapsdt
```

If you are NOT running Ubuntu, see the [Getting Started](https://github.com/linux-usdt/libstapsdt/blob/main/docs/getting-started/getting-started.rst) guide on how to build this package from source and then you can install the Python package

```bash
pip install stapsdt
```

### Running and/or testing this program

In one terminal window run:

```bash
python3 example_usdt_program.py
```

In a second terminal window, run the BPF program:

```bash
python3 usdt.py
```
