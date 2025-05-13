#!/bin/bash

# Start netfilter in the background
./netfilter &
NF_PID=$!


echo "Netfilter program started."

# Function to test connectivity
test_connection() {
    URL=$1
    EXPECTED_PORT=$2

    echo "Attempting to connect to $URL:$EXPECTED_PORT"
    if curl -s --connect-timeout 3 "$URL" > /dev/null; then
        echo "[SUCCESS] connected to $URL:$EXPECTED_PORT"
    else
        echo "[FAILED] did not connect to $URL:$EXPECTED_PORT"
    fi
}

# Test HTTPS (443) and HTTP (80)
test_connection "https://1.1.1.1" "443"
test_connection "http://1.1.1.1" "80"

# Kill netfilter program
kill $NF_PID
wait $NF_PID 2>/dev/null

echo "Netfilter program stopped."

