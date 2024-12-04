import socket
import json
import sys
from config import HOST

# Load Authoritative table from JSON file
def load_auth_table(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load Authoritative table: {e}")
        sys.exit(1)

# Function to parse a DNS query
def parse_dns_query(data):
    qname = []
    index = 12
    length = data[index]
    while length != 0:
        index += 1
        qname.append(data[index:index + length].decode())
        index += length
        length = data[index]

    domain_name = ".".join(qname)
    qtype = int.from_bytes(data[index + 1:index + 3], byteorder='big')
    return domain_name, qtype

# Function to create a DNS response
def create_dns_response(query_id, flags, answers):
    header = query_id + flags + (1).to_bytes(2, 'big') + (len(answers)).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
    response_body = b''.join(answers)
    return header + response_body

# Handle incoming client queries
def handle_client(client_data, client_address, server_socket, auth_table):
    try:
        domain_name, qtype = parse_dns_query(client_data)
        print(f"[AUTH] Received query for domain: {domain_name} with type: {qtype}")

        if domain_name in auth_table:
            ip_address = auth_table[domain_name]
            ip_bytes = socket.inet_aton(ip_address)
            answers = [ip_bytes]
            response = create_dns_response(client_data[:2], b'\x80\x00', answers)
            print(f"[AUTH] Resolved domain {domain_name} to IP {ip_address}")
        else:
            print(f"[AUTH] Domain '{domain_name}' not found in Authoritative table.")
            response = create_dns_response(client_data[:2], b'\x80\x03', [])

        server_socket.sendto(response, client_address)
    except Exception as e:
        print(f"[AUTH ERROR] {e}")

# Start the authoritative server
def start_server(auth_table_file, domain):
    # Load the full Authoritative table
    auth_table = load_auth_table(auth_table_file)

    # Get the specific domain's table from the loaded auth table
    if domain not in auth_table:
        print(f"[ERROR] Domain '{domain}' not found in the Authoritative table.")
        sys.exit(1)
    
    domain_data = auth_table[domain]  # Extract the domain-specific data

    # Define the fixed port based on domain (mapped in domain_data)
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
        client_data, client_address = server_socket.recvfrom(1024)
        handle_client(client_data, client_address, server_socket, domain_data)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python auth_server.py <auth_table.json> <domain>")
        sys.exit(1)

    auth_table_file = sys.argv[1]  # Path to the auth table JSON file
    domain = sys.argv[2]  # The domain to handle (e.g., 'google', 'microsoft')

    start_server(auth_table_file, domain)
