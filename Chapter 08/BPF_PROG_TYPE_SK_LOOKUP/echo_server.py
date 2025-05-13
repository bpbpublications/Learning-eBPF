import socket
import threading

def handle_client(conn, addr):
    """Handles communication with a single client."""
    print(f"Connected by {addr}")
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
            try:
                print(f"Echoed: {data.decode()}")
            except UnicodeDecodeError:
                print(f"Echoed (binary data): {data}") #Handle binary data

    print(f"Connection from {addr} closed.")

def echo_server(host='0.0.0.0', port=65432):
    """A simple echo server that handles multiple connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of the address.
        s.bind((host, port))
        s.listen()
        print(f"Echo server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()

if __name__ == "__main__":
    echo_server()