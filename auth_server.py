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

# Function to resolve A, NS, MX, CNAME query types
def resolve_query_type(qtype, domain_data):
    # Retrieve the domain-specific data
    if domain_data:
        if qtype == 1:  # A record
            ip_address = domain_data.get("A")
            print(ip_address)
            if ip_address:
                return socket.inet_aton(ip_address), 4  # 4 bytes for an A record
        elif qtype == 2:  # NS record
            ns_records = domain_data.get("NS", [])
            return b''.join([ns.encode() + b'\x00' for ns in ns_records]), 2
        elif qtype == 15:  # MX record
            mx_records = domain_data.get("MX", [])
            mx_answers = b''.join(
                [(str(mx['priority']).encode() + b' ' + mx['exchange'].encode() + b'\x00') for mx in mx_records]
            )
            return mx_answers, 15
        elif qtype == 5:  # CNAME record
            cname = domain_data.get("CNAME")
            if cname:
                return cname.encode() + b'\x00', 5
    return None, 0

# Handle incoming client queries
def handle_client(client_data, client_address, server_socket, auth_table):
    try:
        domain_name, qtype = parse_dns_query(client_data)
        print(f"[AUTH] Received query for domain: {domain_name} with type: {qtype}")

        print(auth_table)
        print(auth_table[domain_name])
        # Check if the domain exists in the authoritative table for the given domain
        if domain_name in auth_table:
            answers, record_type = resolve_query_type(qtype, auth_table[domain_name])
            print(answers)
            if answers:
                response = create_dns_response(client_data[:2], b'\x80\x00', [answers])
                print(f"[AUTH] Resolved domain {domain_name} to {answers}")
            else:
                print(f"[AUTH] Record type {qtype} not found for domain {domain_name}")
                response = create_dns_response(client_data[:2], b'\x80\x03', [])
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
