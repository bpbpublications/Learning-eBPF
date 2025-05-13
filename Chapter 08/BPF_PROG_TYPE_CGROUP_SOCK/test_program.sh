#!/bin/bash

# Function to test socket creation and print the result
test_socket() {
  local type="$1"  # tcp, icmp, or udp
  local protocol=""

  case "$type" in
    tcp)
      protocol="tcp"
      ;;
    icmp)
      protocol="icmp"
      ;;
    udp)
      protocol="udp"
      ;;
    *)
      echo "Invalid socket type: $type"
      return 1
      ;;
  esac

  case "$type" in
    icmp)
      if ! ping -c 1 www.google.com > /dev/null 2>&1 ; then # Try a ping
        echo "ICMP (ping) to www.google.com: FAILED (Likely requires root privileges)"
        return 1 # Fail if ping fails
      else
        echo "ICMP (ping) to www.google.com: SUCCESS (Requires root privileges for full functionality)"
        return 0 # Succeed if ping works
      fi
      ;;
    tcp)
      # Use dig with +tcp to resolve www.google.com over TCP
      local ip_address=$(dig +tcp +short www.google.com | head -n 1)

      if [[ -z "$ip_address" ]]; then
        echo "Failed to resolve www.google.com via TCP"
        return 1
      fi

      exec 3<>/dev/tcp/$ip_address/80  # Use port 80 for TCP
      if [ $? -eq 0 ]; then
        echo "TCP socket creation: SUCCESS (using $ip_address via TCP)"
        exec 3>&-  # Close the file descriptor
        return 0
      else
        echo "TCP socket creation: FAILED (using $ip_address via TCP)"
        return 1
      fi
      ;;
    udp)
      # Use dig to resolve www.google.com
      local ip_address=$(dig +short www.google.com | head -n 1)

      if [[ -z "$ip_address" ]]; then
        echo "Failed to resolve www.google.com"
        return 1
      fi

       exec 3<>/dev/udp/$ip_address/53  # Use port 53 for UDP (DNS)
      if [ $? -eq 0 ]; then
        echo "UDP socket creation: SUCCESS (using $ip_address)"
        exec 3>&-  # Close the file descriptor
        return 0
      else
        echo "UDP socket creation: FAILED (using $ip_address)"
        return 1
      fi
      ;;
  esac
}


# Test TCP socket
test_socket tcp

# Test ICMP socket (requires root or sudo for raw sockets)
test_socket icmp

# Test UDP socket
test_socket udp

echo "Testing complete."

exit 0