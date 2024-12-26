import socket
import json
import sys
from config import HOST


def load_tld_table(tld_table_file):
    try:
        with open(tld_table_file, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load TLD table: {e}")
        sys.exit(1)

def handle_client(data, client_address, server_socket,tld_table):
    domain_name = extract_domain_name(data)
    print(f"[TLD] Received query for '{domain_name}'")
    print(tld_table)
    if domain_name in tld_table:
        auth_ip, auth_port = tld_table[domain_name]
        # Forward query to the authoritative server
        server_socket.sendto(data, (auth_ip, auth_port))
        # Receive response from the authoritative server
        response, _ = server_socket.recvfrom(1024)
        # Send the response back to the root server
        server_socket.sendto(response, client_address)
    else:
        print(f"[TLD] Domain '{domain_name}' not found.")
        # Send an error response to the client
        error_response = create_dns_error_response(data)
        server_socket.sendto(error_response, client_address)

def extract_domain_name(data):
    # Same domain name extraction logic as root server
    query = data[12:]
    domain_parts = []
    while True:
        length = query[0]
        if length == 0:
            break
        domain_parts.append(query[1:1 + length].decode())
        query = query[1 + length:]
    return '.'.join(domain_parts)

def create_dns_error_response(query):
    transaction_id = query[:2]
    flags = b'\x81\x83'  # Standard query response, Name Error
    rest = query[4:]
    return transaction_id + flags + rest

def start_tld_server(tld_table_file, tld):

    # Load the TLD table
    tld_table = load_tld_table(tld_table_file)


    tld_data = tld_table[tld]  # Extract the inner table for the given TLD

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
    server_socket.bind((HOST, port))
    print(f"[TLD SERVER] Running on port {port} for TLD '{tld}'")


    while True:
        data, client_address = server_socket.recvfrom(1024)
        handle_client(data, client_address, server_socket,tld_data)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python tld_server.py <tld_table.json> <tld>")
        sys.exit(1)

    tld_table_file = sys.argv[1]  # Path to the TLD table JSON file
    tld = sys.argv[2]  # The TLD to use (e.g., 'com' or 'org')
    
    start_tld_server(tld_table_file, tld)
