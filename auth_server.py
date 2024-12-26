import socket

# Predefined DNS records
DNS_RECORDS = {
    "google.com": "93.184.216.34",
    "microsoft.com": "192.0.2.1",
    # Add more records as needed
}

def handle_client(data, client_address, server_socket):
    domain_name = extract_domain_name(data)
    print(f"[AUTH] Received query for '{domain_name}'")
    if domain_name in DNS_RECORDS:
        # Create a DNS response
        response = create_dns_response(data, DNS_RECORDS[domain_name])
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

def start_auth_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", port))
    print(f"[AUTH] Server started on 127.0.0.1:{port}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        handle_client(data, client_address, server_socket)

if __name__ == "__main__":
    start_auth_server(1600)  # Start authoritative server for example.com
