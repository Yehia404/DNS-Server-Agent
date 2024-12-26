import socket
from config import HOST, ROOT_PORT

# TLD server mappings
TLD_SERVERS = {
    "com": (HOST, 1500),  # TLD server for .com
    "org": (HOST, 1600),  # TLD server for .org
    # Add more TLDs as needed
}

def handle_client(data, client_address, server_socket):
    # Extract domain name from the DNS query
    domain_name = extract_domain_name(data)
    print(f"[ROOT] Received query for '{domain_name}'")
    tld = domain_name.split('.')[-1]
    
    if tld in TLD_SERVERS:
        tld_ip, tld_port = TLD_SERVERS[tld]
        # Forward query to the TLD server
        print(f"[ROOT] Redirecting to TLD server {tld_ip}:{tld_port}")
        server_socket.sendto(data, (tld_ip, tld_port))
        # Receive response from the TLD server
        response, _ = server_socket.recvfrom(1024)
        # Send the response back to the client
        server_socket.sendto(response, client_address)
    else:
        print(f"[ROOT] TLD '{tld}' not found.")
        # Send an error response to the client
        error_response = create_dns_error_response(data)
        server_socket.sendto(error_response, client_address)

def extract_domain_name(data):
    # Parse the domain name from DNS query
    query = data[12:]  # Skip the DNS header
    domain_parts = []
    while True:
        length = query[0]
        if length == 0:
            break
        domain_parts.append(query[1:1 + length].decode())
        query = query[1 + length:]
    return '.'.join(domain_parts)

def create_dns_error_response(query):
    # Create an error response for the DNS query
    transaction_id = query[:2]
    flags = b'\x81\x83'  # Standard query response, Name Error
    rest = query[4:]  # Copy the rest of the query
    return transaction_id + flags + rest

def start_root_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, ROOT_PORT))
    print(f"[ROOT] Server started on {HOST}:{ROOT_PORT}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        handle_client(data, client_address, server_socket)

if __name__ == "__main__":
    start_root_server()
