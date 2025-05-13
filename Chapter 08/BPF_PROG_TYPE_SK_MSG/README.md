# ch08/BPF_PROG_TYPE_SK_MSG

## Introduction

Demonstration of dropping messages (via `sendmsg()`) as well as redirecting them to a specific socket if it matches a specific criteria.

## Compiling this program

```bash
make all
```

## Running and/or testing this program

```bash
chmod +x run.sh
sudo ./run.sh
```

This demonstration registers three servers, port 80, 1337 and 1234