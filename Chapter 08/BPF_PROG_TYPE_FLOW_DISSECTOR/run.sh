#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Simplified BPF flow dissector test using ping and curl

BPF_FILE="flow_dissector.bpf.o"
export TESTNAME=test_flow_dissector

# Create a network namespace
ip netns add test_ns
ip netns exec test_ns ip link set lo up

# Mount BPF file system if not already mounted
if ! mount | grep -q /sys/fs/bpf; then
    mount bpffs /sys/fs/bpf -t bpf
fi

# Load BPF program in namespace
ip netns exec test_ns bpftool prog load $BPF_FILE /sys/fs/bpf/flow_dissector
ip netns exec test_ns bpftool prog attach pinned /sys/fs/bpf/flow_dissector flow_dissector

# Setup network filtering in namespace
ip netns exec test_ns tc qdisc add dev lo ingress

# Test ICMP traffic (ping)
echo "Testing ICMP (ping) in namespace..."
ip netns exec test_ns ping -c 3 8.8.8.8

# Test HTTP traffic (curl)
echo "Testing HTTP (curl) in namespace..."
ip netns exec test_ns curl -s http://www.google.com > /dev/null

# Cleanup
ip netns exec test_ns tc qdisc del dev lo ingress
ip netns exec test_ns bpftool prog detach pinned /sys/fs/bpf/flow_dissector flow_dissector
rm -rf /sys/fs/bpf/flow
ip netns del test_ns

exit 0
