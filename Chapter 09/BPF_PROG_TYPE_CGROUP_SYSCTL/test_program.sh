#!/bin/bash

echo "Testing sysctl access inside cgroup..."

sleep 5

# Function to test read access to sysctl variables
test_sysctl_read() {
    local sysctl_var=$1
    echo "Trying to read sysctl: $sysctl_var..."

    if cat "$sysctl_var" &>/dev/null; then
        echo "[SUCCESS] Read access allowed to $sysctl_var"
    else
        echo "[DENIED] Read access denied to $sysctl_var"
    fi
}

# Function to test write access to sysctl variables
test_sysctl_write() {
    local sysctl_var=$1
    local value=$2
    echo "Trying to write '$value' to sysctl: $sysctl_var..."

    if echo "$value" > "$sysctl_var"; then
        echo "[SUCCESS] Write access allowed to $sysctl_var with value $value"
    else
        echo "[DENIED] Write access denied to $sysctl_var"
    fi
}


# Test read and write for "net/ipv4/ip_forward" (this should be denied)
test_sysctl_read /proc/sys/net/ipv4/ip_forward
test_sysctl_write /proc/sys/net/ipv4/ip_forward 0

# Test benign write operations
test_sysctl_write /proc/sys/kernel/sysrq 1  # Toggle sysrq key behavior
test_sysctl_write /proc/sys/net/core/somaxconn 1024  # Max socket connections
test_sysctl_write /proc/sys/vm/swappiness 60  # Control kernel's swappiness behavior
test_sysctl_write /proc/sys/fs/file-max 100000  # Max file handles
test_sysctl_write /proc/sys/net/ipv4/tcp_max_syn_backlog 2048  # Max TCP SYN backlog

# Test benign read operations
test_sysctl_read /proc/sys/kernel/sysrq
test_sysctl_read /proc/sys/net/core/somaxconn
test_sysctl_read /proc/sys/vm/swappiness 60
test_sysctl_read /proc/sys/fs/file-max 100000
test_sysctl_read /proc/sys/net/ipv4/tcp_max_syn_backlog 2048

sleep 5
