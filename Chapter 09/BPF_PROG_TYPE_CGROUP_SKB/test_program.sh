#!/bin/bash

# Test ICMP (ping) and DNS (UDP/TCP) for multiple destinations

echo "Testing network access based on BPF program..."

sleep 2

# List of IP addresses to test for ICMP ping
PING_ADDRESSES=("8.8.8.8" "1.1.1.1" "9.9.9.9")

# List of DNS servers to test for UDP/TCP DNS queries
DNS_SERVERS=("8.8.8.8" "1.1.1.1" "9.9.9.9")

# Function to test ICMP ping
test_ping() {
    local ip=$1
    echo "Testing ICMP ping to $ip..."

    if ping -c 1 "$ip" &>/dev/null; then
        echo "[SUCCESS] ICMP ping to $ip is allowed"
    else
        echo "[DENIED] ICMP ping to $ip is blocked"
    fi
}

# Function to test DNS query (UDP)
test_udp_dns() {
    local server=$1
    echo "Testing UDP DNS query to $server on port 53..."

    if dig @"$server" google.com +short &>/dev/null; then
        echo "[SUCCESS] UDP DNS query to $server is allowed"
    else
        echo "[DENIED] UDP DNS query to $server is blocked"
    fi
}

# Function to test DNS query (TCP)
test_tcp_dns() {
    local server=$1
    echo "Testing TCP DNS query to $server on port 53..."

    if dig @"$server" google.com +tcp +short &>/dev/null; then
        echo "[SUCCESS] TCP DNS query to $server is allowed"
    else
        echo "[DENIED] TCP DNS query to $server is blocked"
    fi
}

# Run ICMP ping tests
for ip in "${PING_ADDRESSES[@]}"; do
    test_ping "$ip"
    sleep 2  # Wait before the next test
done

# Run UDP DNS tests
for server in "${DNS_SERVERS[@]}"; do
    test_udp_dns "$server"
    sleep 2  # Wait before the next test
done

# Run TCP DNS tests
for server in "${DNS_SERVERS[@]}"; do
    test_tcp_dns "$server"
    sleep 2  # Wait before the next test
done

echo "Network access test completed."
