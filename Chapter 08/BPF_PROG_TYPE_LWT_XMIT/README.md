# ch08/BPF_PROG_TYPE_LWT_XMIT

## Introduction

This program rewrites the MAC headers of the packet and forward it through the tunnel

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
ip route add xxx.xxx.xxx.xxx/xx encap bpf xmit obj lwt_xmit.o section lwt_xmit dev <interface>
```
