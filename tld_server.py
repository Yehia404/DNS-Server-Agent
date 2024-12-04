import socket
import json
import sys
from config import HOST

# Load TLD table from JSON file
def load_tld_table(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load TLD table: {e}")
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
def handle_client(client_data, client_address, server_socket, tld_table):
    try:
        domain_name, qtype = parse_dns_query(client_data)
        print(f"[TLD] Received query for domain: {domain_name} with type: {qtype}")

        if domain_name in tld_table:
            auth_server_ip, auth_server_port = tld_table[domain_name]
            ip_bytes = socket.inet_aton(auth_server_ip)
            port_bytes = auth_server_port.to_bytes(2, 'big')
            answers = [ip_bytes + port_bytes]
            response = create_dns_response(client_data[:2], b'\x80\x00', answers)
            print(f"[TLD] Redirecting to Authoritative server at {auth_server_ip}:{auth_server_port}")
        else:
            print(f"[TLD] Domain '{domain_name}' not found in TLD table.")
            response = create_dns_response(client_data[:2], b'\x80\x03', [])
        
        server_socket.sendto(response, client_address)
    except Exception as e:
        print(f"[TLD ERROR] {e}")

# Start the server based on the provided TLD
def start_server(tld_table_file, tld):
    # Load the full TLD table
    tld_table = load_tld_table(tld_table_file)

    # Get the inner TLD table for the specified TLD (e.g., 'com' or 'org')
    if tld not in tld_table:
        print(f"[ERROR] TLD '{tld}' not found in the TLD table.")
        sys.exit(1)
    
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
        client_data, client_address = server_socket.recvfrom(1024)
        handle_client(client_data, client_address, server_socket, tld_data)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python tld_server.py <tld_table.json> <tld>")
        sys.exit(1)

    tld_table_file = sys.argv[1]  # Path to the TLD table JSON file
    tld = sys.argv[2]  # The TLD to use (e.g., 'com' or 'org')
    
    start_server(tld_table_file, tld)
