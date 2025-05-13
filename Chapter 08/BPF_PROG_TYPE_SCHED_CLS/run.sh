#!/bin/bash

set -e  # Exit on error
set -o pipefail

# Variables
BPF_PROG="process_packet"
INTERFACE="lo"  # Change this to your network interface
BPF_OBJ="sched_cls.bpf.o"


echo "[+] Attaching BPF program to interface $INTERFACE..."
sudo tc qdisc add dev $INTERFACE clsact 2>/dev/null || true
sudo tc filter add dev $INTERFACE ingress bpf obj $BPF_OBJ sec "tc"

echo "[+] Sending test TCP packet using Netcat..."
echo "TestPacket" | nc -w 1 127.0.0.1 8080

# Alternative: Use ping (ICMP test)
echo "[+] Sending test ICMP packet using ping..."
ping -c 1 127.0.0.1 > /dev/null

# Alternative: Use nmap to send TCP SYN packet (if available)
if command -v nmap; then
    echo "[+] Sending test TCP SYN packet using nmap..."
    sudo nmap -p 8080 --send-ip 127.0.0.1
else
    echo "[!] nmap not found, skipping nmap test."
fi

echo "[+] Checking BPF return values via tc filter stats..."
sudo tc -s filter show dev $INTERFACE ingress

echo "[+] Cleaning up..."
sudo tc filter del dev $INTERFACE ingress
sudo tc qdisc del dev $INTERFACE clsact 2>/dev/null || true

echo "[+] Test completed!"
