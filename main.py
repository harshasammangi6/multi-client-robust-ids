import json

# Function to authenticate clients
def authenticate_client(client_socket, allowed_clients):
    try:
        # Ask for client ID
        client_socket.send("Please provide your client ID:".encode('utf-8'))
        client_id = client_socket.recv(1024).decode('utf-8').strip()

        if client_id in allowed_clients:
            client_socket.send("Authentication successful.".encode('utf-8'))
            logging.info(f"Client {client_id} authenticated successfully.")
            return client_id
        else:
            client_socket.send("Authentication failed.".encode('utf-8'))
            logging.warning(f"Authentication failed for client ID: {client_id}")
            return None
    except Exception as e:
        logging.error(f"Error during client authentication: {e}")
        return None

# Function to handle each client
def handle_client(client_socket, client_address, blacklist, allowed_clients):
    logging.info(f"Connection established with {client_address}")
    try:
        # Authenticate the client
        client_id = authenticate_client(client_socket, allowed_clients)
        if not client_id:
            logging.info(f"Closing connection with {client_address} due to failed authentication.")
            client_socket.close()
            return

        while True:
            # Receive data from the client
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break

            logging.info(f"Received from {client_id} ({client_address}): {data}")

            # Check for intrusion
            if detect_intrusion(data, blacklist):
                logging.warning(f"Intrusion detected from {client_id} ({client_address})!")
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
    allowed_clients = config.get("allowed_clients", [])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    logging.info(f"Server started on {host}:{port}")

    try:
        while True:
            client_socket, client_address = server.accept()
            # Start a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, blacklist, allowed_clients))
            client_thread.start()
    except KeyboardInterrupt:
        logging.info("Shutting down the server.")
    finally:
        server.close()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info('Starting Multi Client Robust IDS')

    # Load configuration
    try:
        config = load_config()
        logging.info("Configuration loaded successfully.")
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        exit(1)

    # Start the server
    try:
        start_server(config)
    except Exception as e:
        logging.error(f"Server encountered an error: {e}")
        exit(1)
        def load_config():
            """
            Load configuration from a JSON file.
            Returns a dictionary containing the configuration.
            """
            config_file = "config.json"
            try:
                with open(config_file, 'r') as file:
                    config = json.load(file)
                return config
            except FileNotFoundError:
                logging.error(f"Configuration file {config_file} not found.")
                raise
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from {config_file}: {e}")
                raise
            import time
from collections import defaultdict

# Dictionary to track client request timestamps
client_request_times = defaultdict(list)

# Function to check rate limiting
def is_rate_limited(client_id, max_requests, time_window):
    """
    Check if a client is exceeding the allowed request rate.
    :param client_id: The ID of the client
    :param max_requests: Maximum allowed requests in the time window
    :param time_window: Time window in seconds
    :return: True if rate-limited, False otherwise
    """
    current_time = time.time()
    request_times = client_request_times[client_id]

    # Remove timestamps outside the time window
    client_request_times[client_id] = [t for t in request_times if current_time - t <= time_window]

    # Check if the number of requests exceeds the limit
    if len(client_request_times[client_id]) >= max_requests:
        return True

    # Add the current timestamp
    client_request_times[client_id].append(current_time)
    return False

# Updated handle_client function with rate limiting
def handle_client(client_socket, client_address, blacklist, allowed_clients):
    logging.info(f"Connection established with {client_address}")
    try:
        # Authenticate the client
        client_id = authenticate_client(client_socket, allowed_clients)
        if not client_id:
            logging.info(f"Closing connection with {client_address} due to failed authentication.")
            client_socket.close()
            return

        while True:
            # Receive data from the client
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break

            logging.info(f"Received from {client_id} ({client_address}): {data}")

            # Check for rate limiting
            if is_rate_limited(client_id, max_requests=5, time_window=10):  # 5 requests per 10 seconds
                logging.warning(f"Rate limit exceeded for {client_id} ({client_address})!")
                client_socket.send("Rate limit exceeded. Please slow down.".encode('utf-8'))
                continue

            # Check for intrusion
            if detect_intrusion(data, blacklist):
                logging.warning(f"Intrusion detected from {client_id} ({client_address})!")
                client_socket.send("Intrusion detected!".encode('utf-8'))
            else:
                client_socket.send("Data received.".encode('utf-8'))
    except Exception as e:
        logging.error(f"Error with client {client_address}: {e}")
    finally:
        logging.info(f"Closing connection with {client_address}")
        # Log the disconnection event
        logging.info(f"Client {client_id} disconnected.")
        client_socket.close()