#!/bin/bash

set -e  # Exit on error
set -o pipefail

# Variables
BPF_PROG="drop_icmp_randomly"
INTERFACE="wlp114s0"  # Change this to your network interface
BPF_OBJ="sched_act.bpf.o"

echo "[+] Cleaning up existing qdisc and filters..."
sudo tc filter del dev $INTERFACE ingress 2>/dev/null || true
sudo tc filter del dev $INTERFACE egress 2>/dev/null || true
sudo tc qdisc del dev $INTERFACE clsact 2>/dev/null || true


echo "[+] Attaching BPF program to interface $INTERFACE..."
sudo tc qdisc add dev $INTERFACE clsact
sudo tc filter add dev $INTERFACE ingress bpf da obj $BPF_OBJ sec action
sudo tc -s filter show dev $INTERFACE ingress


echo "[+] Sending 100 ICMP packets over ~15 seconds..."
ping -c 100 -i 0.15 1.1.1.1

echo "[+] Checking BPF return values via tc filter stats..."
sudo tc -s filter show dev $INTERFACE ingress

echo "[+] Cleaning up..."
sudo tc filter del dev $INTERFACE ingress
sudo tc filter del dev $INTERFACE egress
sudo tc qdisc del dev $INTERFACE clsact 2>/dev/null || true

echo "[+] Test completed!"
