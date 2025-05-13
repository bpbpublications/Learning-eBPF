#!/usr/bin/python3

import socket
import subprocess
import os
import signal
import time
import threading

def run_server():
    """Starts a simple TCP server."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("127.0.0.1", 12345))
        server_socket.listen(1)
        print("TCP server started")

        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        # Just receive and discard data
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

        client_socket.close()
        server_socket.close()
        print("Server closed")

    except Exception as e:
        print(f"Server error: {e}")

def run_client():
    """Starts a simple TCP client."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", 12345))
        print("TCP client started")

        time.sleep(2)
        sndbuf = client_socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        print(f"SO_SNDBUF size: {sndbuf}")

        rcvbuf = client_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        print(f"SO_RCVBUF size: {rcvbuf}")

        client_socket.close()
        print("Client closed")

    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    print("Starting TCP server")
    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    time.sleep(0.1) # Give server time to start

    print("Starting TCP client")
    client_thread = threading.Thread(target=run_client)
    client_thread.start()

    # Timeout logic
    def kill_client():
        time.sleep(5)
        if client_thread.is_alive():
            try:
                os.kill(client_thread.ident, signal.SIGTERM) #use thread id
                print("client killed by timeout")
            except Exception as e:
                print(f"Error killing client: {e}")

    timeout_thread = threading.Thread(target=kill_client)
    timeout_thread.start()

    client_thread.join()
    if timeout_thread.is_alive():
        timeout_thread.join()

    try:
        os.kill(server_thread.ident, signal.SIGTERM) #kill server
        print("server killed")
    except Exception as e:
        print(f"Error killing server: {e}")

    server_thread.join()