#!/bin/bash

echo "Testing device access inside cgroup..."

sleep 10
test_device() {
    local device=$1
    echo "Trying to read from $device..."

    if dd if="$device" of=/dev/null bs=1 count=1 2>/dev/null; then
        echo "[SUCCESS] Access allowed to $device"
    else
        echo "[DENIED] Access denied to $device"
    fi
}

# Test allowed devices
test_device /dev/zero
test_device /dev/urandom

sleep 10

# Test denied device
test_device /dev/random

sleep 10