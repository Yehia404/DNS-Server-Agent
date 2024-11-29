import socket
import json
import sys

# Function to load the TLD table from the provided JSON file
def load_tld_table(tld_table_file):
    try:
        with open(tld_table_file, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load TLD table: {e}")
        sys.exit(1)

# Function to handle client requests
def handle_client(client_data, client_address, server_socket, tld_table, tld):
    try:
        # Decode the domain query
        data = client_data.decode()
        if not data:
            print("[TLD] Received empty query.")
            return

        print(f"[TLD] Received query: '{data}' from {client_address}")

        # Check if the TLD is in the table
        if tld in tld_table:
            # If TLD is found, check the domain
            domain_data = tld_table[tld].get(data, None)
            if domain_data:
                # Format response with server information
                response = f"Redirecting to authoritative server: {domain_data[0]}:{domain_data[1]}"
                print(f"[TLD] Redirecting to authoritative server {domain_data[0]}:{domain_data[1]}")
            else:
                response = "Domain not found in TLD table."
                print("[TLD] Domain not found in the TLD table.")
        else:
            response = f"TLD {tld} not found in the TLD table."
            print(f"[TLD] TLD '{tld}' not found in the TLD table.")

        # Send the response back to the client
        server_socket.sendto(response.encode(), client_address)

    except Exception as e:
        print(f"[TLD ERROR] {e}")

# Start the TLD DNS server
def start_server(tld_table_file, tld):
    # Load the TLD table
    tld_table = load_tld_table(tld_table_file)

    # Define the fixed port based on TLD
    tld_ports = {
        "com": 1500,
        "org": 1600
    }

    if tld not in tld_ports:
        print(f"[ERROR] Unknown TLD '{tld}'. Valid TLDs are: 'com', 'org'.")
        sys.exit(1)

    port = tld_ports[tld]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", port))
    print(f"[TLD SERVER] Running on port {port} for TLD '{tld}'")

    while True:
        client_data, client_address = server_socket.recvfrom(1024)
        handle_client(client_data, client_address, server_socket, tld_table, tld)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python tld_server.py <tld_table.json> <tld>")
        sys.exit(1)

    tld_table_file = sys.argv[1]  # Path to the TLD table JSON file
    tld = sys.argv[2]  # The TLD to use (e.g., 'com' or 'org')
    
    start_server(tld_table_file, tld)
