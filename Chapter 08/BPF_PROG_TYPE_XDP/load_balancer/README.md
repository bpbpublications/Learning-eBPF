# ch08/BPF_PROG_TYPE_XDP

## Introduction

This XDP program acts a very-basic load-balancer that balances TCP packets between two servers.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh <INTERFACE>
```

You will need to run `curl http://localhost:8080` to execute the BPF code-path. **THE LOAD-BALANCER WILL NOT SEND A RESPONSE**.