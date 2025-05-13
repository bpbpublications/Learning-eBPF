#!/bin/bash

# Function to start the Python web servers in the background
start_servers() {
    echo "Starting server on port 5000..."
    python3 server_5000.py $INTERFACE &
    SERVER_5000_PID=$!

    echo "Starting server on port 6000..."
    python3 server_6000.py $INTERFACE &
    SERVER_6000_PID=$!
}

# Function to load the XDP program
load_xdp() {
    INTERFACE=$1

    # Ensure the interface is provided
    if [ -z "$INTERFACE" ]; then
        echo "Error: No interface specified."
        echo "Usage: ./run.sh <interface>"
        exit 1
    fi

    # Check if the interface exists
    if ! ip link show "$INTERFACE" &>/dev/null; then
        echo "Error: Interface $INTERFACE not found."
        exit 1
    fi

    # Adjust this path to where you have compiled the BPF program
    XDP_PROG="load_balance.bpf.o"

    # Ensure XDP program exists
    if [ ! -f "$XDP_PROG" ]; then
        echo "BPF program not found: $XDP_PROG"
        exit 1
    fi

    # Load the XDP program onto the specified network interface
    echo "Loading XDP program on interface $INTERFACE..."
    sudo ip link set dev "$INTERFACE" xdp obj $XDP_PROG sec xdp
}

# Function to clean up (kill servers and unload XDP program)
cleanup() {
    echo "Cleaning up..."

    # Kill the servers
    kill $SERVER_5000_PID
    kill $SERVER_6000_PID

    # Wait for the servers to exit
    wait $SERVER_5000_PID
    wait $SERVER_6000_PID

    # Unload the XDP program
    sudo ip link set dev "$INTERFACE" xdp off

    echo "Cleanup complete."
}

# Trap INT (Ctrl+C) and TERM signals to clean up
trap cleanup SIGINT

# Ensure we received the interface as an argument
INTERFACE=$1

# If no interface is provided, exit the script with an error message
if [ -z "$INTERFACE" ]; then
    echo "Error: No network interface specified."
    echo "Usage: ./run.sh <interface>"
    exit 1
fi

# Start the servers and the load balancer
start_servers
load_xdp "$INTERFACE"

# Wait indefinitely for a signal (this will keep the script running)
echo "Servers and load balancer are running on interface $INTERFACE. Press Ctrl+C to stop."
wait
