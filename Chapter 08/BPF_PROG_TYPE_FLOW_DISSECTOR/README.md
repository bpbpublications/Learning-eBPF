# ch08/BPF_PROG_TYPE_FLOW_DISSECTOR

## Introduction

Demonstration of a custom flow-dissector that is mocked out to perform dissection on IP/OSPF packets.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

The test program will attach the flow dissector via `tc` and run some network connections. You can see what the flow dissector is doing by looking at the program trace output via `sudo cat /sys/kernel/debug/tracing/trace_pipe`.