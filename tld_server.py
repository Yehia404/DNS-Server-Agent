import socket

# Authoritative server mappings
AUTH_SERVERS = {
    "google.com": ("127.0.0.1", 1600),
    "microsoft.com": ("127.0.0.1",1601),
    # Add more domains as needed
}

def handle_client(data, client_address, server_socket):
    domain_name = extract_domain_name(data)
    print(f"[TLD] Received query for '{domain_name}'")
    if domain_name in AUTH_SERVERS:
        auth_ip, auth_port = AUTH_SERVERS[domain_name]
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

def start_tld_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", port))
    print(f"[TLD] Server started on 127.0.0.1:{port}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        handle_client(data, client_address, server_socket)

if __name__ == "__main__":
    start_tld_server(1500)  # Start TLD server for .com
