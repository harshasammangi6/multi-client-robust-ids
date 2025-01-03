import socket
import threading
import logging
import json
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)

# Load configuration from a JSON file
def load_config(config_file="config.json"):
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            return json.load(file)
    else:
        logging.warning(f"Configuration file {config_file} not found. Using default settings.")
        return {"host": "0.0.0.0", "port": 9999, "blacklist": []}

# A more advanced rule-based IDS function
def detect_intrusion(client_data, blacklist):
    # Example rules for detecting malicious activity
    if any(keyword in client_data.lower() for keyword in blacklist):
        return True
    if len(client_data) > 1024:  # Example: flag unusually large messages
        return True
    return False

# Function to handle each client
def handle_client(client_socket, client_address, blacklist):
    logging.info(f"Connection established with {client_address}")
    try:
        while True:
            # Receive data from the client
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break

            logging.info(f"Received from {client_address}: {data}")

            # Check for intrusion
            if detect_intrusion(data, blacklist):
                logging.warning(f"Intrusion detected from {client_address}!")
                client_socket.send("Intrusion detected!".encode('utf-8'))
            else:
                client_socket.send("Data received.".encode('utf-8'))
    except Exception as e:
        logging.error(f"Error with client {client_address}: {e}")
    finally:
        logging.info(f"Closing connection with {client_address}")
        client_socket.close()

# Main server function
def start_server(config):
    host = config.get("host", "0.0.0.0")
    port = config.get("port", 9999)
    blacklist = config.get("blacklist", [])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    logging.info(f"Server started on {host}:{port}")

    try:
        while True:
            client_socket, client_address = server.accept()
            # Start a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, blacklist))
            client_thread.start()
    except KeyboardInterrupt:
        logging.info("Shutting down the server.")
    finally:
        server.close()

if __name__ == "__main__":
    logging.info('Starting Multi Client Robust IDS')
    config = load_config()
    start_server(config)