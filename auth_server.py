import socket
import json
import sys

# Function to load the authoritative server table from the provided JSON file
def load_auth_table(auth_table_file):
    try:
        with open(auth_table_file, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load Auth table: {e}")
        sys.exit(1)

# Function to handle client requests
def handle_client(client_data, client_address, server_socket, auth_table, domain):
    try:
        # Decode the domain query
        data = client_data.decode()
        if not data:
            print("[AUTH] Received empty query.")
            return

        print(f"[AUTH] Received query: '{data}' from {client_address}")

        # Check if the domain is in the table
        if domain in auth_table:
            # If domain is found, check the corresponding server and port
            domain_data = auth_table[domain].get(data, None)
            if domain_data:
                # Format response with server information
                response = f"Domain IP: {domain_data}"
                print(f"[AUTH] Domain IP {domain_data}")
            else:
                response = "Domain not found in authoritative server table."
                print("[AUTH] Domain not found in the authoritative server table.")
        else:
            response = f"Domain {domain} not found in the authoritative server table."
            print(f"[AUTH] Domain '{domain}' not found in the authoritative server table.")

        # Send the response back to the client
        server_socket.sendto(response.encode(), client_address)

    except Exception as e:
        print(f"[AUTH ERROR] {e}")

# Start the authoritative server
def start_server(auth_table_file, domain):
    # Load the authoritative server table
    auth_table = load_auth_table(auth_table_file)

    # Define the fixed port based on domain (mapped in auth_table)
    port_map = {
        "google": 1602,
        "microsoft": 1603,
        "wikipedia": 1604,
        "archive": 1605
    }

    if domain not in port_map:
        print(f"[ERROR] Unknown domain '{domain}'. Valid domains are: 'google', 'microsoft', 'wikipedia', 'archive'.")
        sys.exit(1)

    port = port_map[domain]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", port))
    print(f"[AUTH SERVER] Running on port {port} for domain '{domain}'")

    while True:
        client_data, client_address = server_socket.recvfrom(1024)
        handle_client(client_data, client_address, server_socket, auth_table, domain)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python auth_server.py <auth_table.json> <domain>")
        sys.exit(1)

    auth_table_file = sys.argv[1]  # Path to the auth table JSON file
    domain = sys.argv[2]  # The domain to handle (e.g., 'google', 'microsoft')

    start_server(auth_table_file, domain)
