#!/bin/bash

# Start the echo server in the background within the network namespace
sudo python3 echo_server.py &
server_pid=$!
echo "Echo server started with PID: $server_pid"

# Get the server's file descriptor using ss, targeting the specific port
server_fd=$(sudo ss -lntp | grep ":65432" | grep "python3" | awk -F'fd=' '{print $2}' | awk -F ')' '{print $1}')


if [ -z "$server_fd" ]; then
    echo "Error: Could not find server FD. Check if server is listening on port 65432."
    sudo ip netns exec sk_lookup_test kill $server_pid
    sudo ip netns exec sk_lookup_test wait $server_pid 2>/dev/null
    sudo ip netns delete sk_lookup_test
    exit 1
fi

echo "Server FD: $server_fd"

# Run the BPF program with the server's PID, FD, and listening port
# sudo ip netns add sk_lookup_test
sudo ./sk_lookup $server_pid $server_fd 65432,8000,8080,8888 &
bpf_pid=$!

# Wait for a few seconds to allow the BPF program to attach and update maps
sleep 5

# # Test the echo server within the network namespace
echo "Testing the echo server..."
echo "Hello, world! to port 65432" | nc -N localhost 65432
echo "Hello, world! to port 8000" | nc -N localhost 8000
echo "Hello, world! to port 8080" | nc -N localhost 8080
echo "Hello, world! to port 8888" | nc -N  localhost 8888


# Check if the BPF program is still running
if ps -p $bpf_pid > /dev/null; then
    echo "BPF program is running."
else
    echo "BPF program has exited unexpectedly."
fi

# # Clean up
echo "Cleaning up..."
# sudo ip netns exec sk_lookup_test kill $server_pid
kill $bpf_pid
# sudo ip netns exec sk_lookup_test wait $server_pid 2>/dev/null
wait $bpf_pid 2>/dev/null

kill $server_pid

# Remove the network namespace
sudo ip netns delete sk_lookup_test