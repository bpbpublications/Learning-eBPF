# ch08/BPF_PROG_TYPE_XDP

## Introduction

This XDP program intercepts incoming ICMP packets and returns a response.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

You will need to ping the attached interface from another host to ensure you're triggering the BPF program.