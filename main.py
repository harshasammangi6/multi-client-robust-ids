import socket
import threading

# A simple rule-based IDS function
def detect_intrusion(client_data):
    # Example rules for detecting malicious activity
    if "malicious" in client_data.lower():
        return True
    return False

# Function to handle each client
def handle_client(client_socket, client_address):
    print(f"[INFO] Connection established with {client_address}")
    try:
        while True:
            # Receive data from the client
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break

            print(f"[DATA] Received from {client_address}: {data}")

            # Check for intrusion
            if detect_intrusion(data):
                print(f"[ALERT] Intrusion detected from {client_address}!")
                client_socket.send("Intrusion detected!".encode('utf-8'))
            else:
                client_socket.send("Data received.".encode('utf-8'))
    except Exception as e:
        print(f"[ERROR] Error with client {client_address}: {e}")
    finally:
        print(f"[INFO] Closing connection with {client_address}")
        client_socket.close()

# Main server function
def start_server(host='0.0.0.0', port=9999):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[INFO] Server started on {host}:{port}")

    try:
        while True:
            client_socket, client_address = server.accept()
            # Start a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down the server.")
    finally:
        server.close()

if __name__ == "__main__":
    print('This is the main entry point for Multi Client Robust IDS')
    start_server()