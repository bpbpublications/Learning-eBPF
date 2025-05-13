#!/bin/bash

# Ensure the script is run with an interface argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 <network_interface>"
    exit 1
fi

IFACE=$1
XDP_PROG="icmp_server.bpf.o"

# Check if the compiled XDP program exists
if [ ! -f "$XDP_PROG" ]; then
    echo "Error: Compiled XDP program '$XDP_PROG' not found!"
    exit 1
fi

echo "[+] Attaching XDP program to $IFACE..."
ip link set dev $IFACE xdp obj $XDP_PROG sec xdp/main
if [ $? -ne 0 ]; then
    echo "[-] Failed to attach XDP program."
    exit 1
fi

# Trap SIGINT (Ctrl+C) and ensure cleanup
cleanup() {
    echo "[+] Detaching XDP program..."
    ip link set dev "$IFACE" xdp off
    echo "[+] Cleanup complete."
    exit 0
}
trap cleanup SIGINT

echo "Ping the attached interface (from a different machine)... Press Ctrl+C to exit."

# Infinite loop
while true; do
    sleep 1
done