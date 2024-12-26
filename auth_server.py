import socket
import json
import sys
from config import HOST


# Function to load the authoritative server table from the provided JSON file
def load_auth_table(auth_table_file):
    try:
        with open(auth_table_file, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load Auth table: {e}")
        sys.exit(1)


def handle_client(data, client_address, server_socket, auth_table):
    domain_name = extract_domain_name(data)
    print(f"[AUTH] Received query for '{domain_name}'")
    if domain_name in auth_table:
        # Create a DNS response
        response = create_dns_response(data, auth_table[domain_name])
        server_socket.sendto(response, client_address)
    else:
        print(f"[AUTH] Domain '{domain_name}' not found.")
        error_response = create_dns_error_response(data)
        server_socket.sendto(error_response, client_address)

def extract_domain_name(data):
    query = data[12:]
    domain_parts = []
    while True:
        length = query[0]
        if length == 0:
            break
        domain_parts.append(query[1:1 + length].decode())
        query = query[1 + length:]
    return '.'.join(domain_parts)

def create_dns_response(query, ip_address):
    transaction_id = query[:2]
    flags = b'\x81\x80'  # Standard query response, No error
    qd_count = b'\x00\x01'  # One question
    an_count = b'\x00\x01'  # One answer
    ns_count = b'\x00\x00'  # No authority records
    ar_count = b'\x00\x00'  # No additional records
    question = query[12:]  # Copy question
    answer_name = b'\xc0\x0c'  # Pointer to the domain name in the question
    answer_type = b'\x00\x01'  # Type A
    answer_class = b'\x00\x01'  # Class IN
    ttl = b'\x00\x00\x00\x3c'  # 60 seconds
    rdlength = b'\x00\x04'  # IPv4 address length
    rdata = socket.inet_aton(ip_address)
    return transaction_id + flags + qd_count + an_count + ns_count + ar_count + question + answer_name + answer_type + answer_class + ttl + rdlength + rdata

def create_dns_error_response(query):
    transaction_id = query[:2]
    flags = b'\x81\x83'  # Standard query response, Name Error
    rest = query[4:]
    return transaction_id + flags + rest

def start_auth_server(auth_table_file, domain):
    # Load the authoritative server table
    auth_table = load_auth_table(auth_table_file)

    domain_data = auth_table[domain]  # Extract the domain-specific data

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
    server_socket.bind((HOST, port))
    print(f"[AUTH SERVER] Running on port {port} for domain '{domain}'")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        handle_client(data, client_address, server_socket, domain_data)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python auth_server.py <auth_table.json> <domain>")
        sys.exit(1)

    auth_table_file = sys.argv[1]  # Path to the auth table JSON file
    domain = sys.argv[2]  # The domain to handle (e.g., 'google', 'microsoft')

    start_auth_server(auth_table_file, domain)
