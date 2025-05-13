#!/bin/bash

echo "Starting TCP server"
# Start a TCP server (netcat in this example)
nc -l 12345 > /dev/null &
server_pid=$!

echo "Starting TCP Client"
# Start a TCP client (netcat)
nc 127.0.0.1 12345 < /dev/null &
client_pid=$!

# Timeout using a background process and sleep
(sleep 5 && kill $client_pid) & timeout_pid=$!
wait $client_pid || kill $timeout_pid

# Check the BPF program's output (using bpftool or trace-cmd)
sudo cat /sys/kernel/debug/tracing/trace | grep "setsockopt"

# Check SO_SNDBUF size using python script
python3 get_sock_opt.py

# Kill the server
kill $server_pid