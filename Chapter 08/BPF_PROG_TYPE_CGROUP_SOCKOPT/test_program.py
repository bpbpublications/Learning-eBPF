#!/usr/bin/python3

import socket
import sys

def test_setsockopt(option, value):
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Try to set a socket option using setsockopt
        sock.setsockopt(socket.SOL_SOCKET, option, value)
        print(f"[SUCCESS] Set option {option} with value {value}")
    except socket.error as e:
        print(f"[FAILED] Could not set option {option}: {e}")

    sock.close()

def main():
    # Testing various socket options
    print("Testing SO_RCVBUF (allowed):")
    test_setsockopt(socket.SO_RCVBUF, 1048576)  # Allowed

    print("\nTesting SO_DEBUG (denied):")
    test_setsockopt(socket.SO_DEBUG, 1)  # Denied

    print("\nTesting SO_KEEPALIVE (allowed):")
    test_setsockopt(socket.SO_KEEPALIVE, 1)  # Allowed

if __name__ == "__main__":
    main()
