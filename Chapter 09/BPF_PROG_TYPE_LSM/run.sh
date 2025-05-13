#!/bin/bash

# Ensure script stops on error
set -e

# Start the BPF program in the background
./lsm &
BPF_PID=$!

# Give the BPF program a moment to initialize
sleep 2

echo "Attempting to create file /tmp/test_bpf.txt"
touch /tmp/test_bpf.txt

# Optionally check if the file was created
if [ -f /tmp/test_bpf.txt ]; then
  echo "File successfully created."
else
  echo "Failed to create file."
fi

# Clean up
echo "Killing BPF program (PID: $BPF_PID)"
kill $BPF_PID
wait $BPF_PID 2>/dev/null

# Remove the test file if it was created
rm -f /tmp/test_bpf.txt
