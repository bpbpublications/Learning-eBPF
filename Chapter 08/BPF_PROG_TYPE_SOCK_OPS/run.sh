#!/bin/bash

CGROUP_PATH="/sys/fs/cgroup/test_sockops2"
LOADER="./sockops"
TEST_SCRIPT="get_sock_opt.py"
BPF_OBJECT="sockops.bpf.o"

# Function to clean up cgroup and BPF program
cleanup() {
    echo "Cleaning up BPF program and cgroup..."

    # Get the cgroup file descriptor (if exists)
    CGROUP_FD=$(ls $CGROUP_PATH/bpf.progs 2>/dev/null)

    if [ -n "$CGROUP_FD" ]; then
        # Detach the BPF program
        sudo bpftool prog detach "$CGROUP_FD" msg VERBOSE || echo "Failed to detach BPF program."
        echo "BPF program detached."
    else
        echo "No BPF program found attached. Skipping detachment."
    fi

    # Remove processes from the cgroup
    echo 0 | sudo tee "$CGROUP_PATH/cgroup.procs" > /dev/null 2>&1

    # Remove the cgroup
    if sudo rmdir "$CGROUP_PATH"; then
        echo "Cgroup removed successfully."
    else
        echo "Failed to remove cgroup."
    fi

    echo "Cleanup complete."
}

# Ensure script is run with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)."
    exit 1
fi

# Check if loader program exists
if [ ! -f "$LOADER" ]; then
    echo "Loader program '$LOADER' not found. Compile it first."
    exit 1
fi

# Check if BPF object exists
if [ ! -f "$BPF_OBJECT" ]; then
    echo "BPF object file '$BPF_OBJECT' not found. Compile it first."
    exit 1
fi

# Check if test script exists
if [ ! -f "$TEST_SCRIPT" ]; then
    echo "Test script '$TEST_SCRIPT' not found."
    exit 1
fi

# Ensure cleanup before starting
cleanup

echo "Getting buffer sizes before BPF program is executed"
python3 "$TEST_SCRIPT"

echo "Creating cgroup at $CGROUP_PATH..."
mkdir -p "$CGROUP_PATH"

echo "Pushing BPF program into cgroup"
echo $$ | sudo tee $CGROUP_PATH/cgroup.procs


# Start the BPF program loader
echo "Starting BPF program..."
"$LOADER" $CGROUP_PATH

# Run the test script
echo "Running test script..."
python3 "$TEST_SCRIPT"

# Cleanup after test
cleanup
