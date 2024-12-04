import socket
from config import HOST, ROOT_PORT

# Root DNS Table (mapping TLD to server)
root_dns_table = {
    "com": ("127.0.0.1", 1500),  # TLD server for .com
    "org": ("127.0.0.1", 1600),  # TLD server for .org
}

# Function to parse a DNS query
def parse_dns_query(data):
    qname = []
    index = 12  # DNS header is 12 bytes
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

# Function to handle client requests
def handle_client(client_data, client_address, server_socket):
    try:
        domain_name, qtype = parse_dns_query(client_data)
        print(f"[ROOT] Received query for domain: {domain_name} with type: {qtype}")
        tld = domain_name.split(".")[-1]

        if tld in root_dns_table:
            tld_server_ip, tld_server_port = root_dns_table[tld]
            ip_bytes = socket.inet_aton(tld_server_ip)
            port_bytes = tld_server_port.to_bytes(2, 'big')
            answers = [ip_bytes + port_bytes]
            response = create_dns_response(client_data[:2], b'\x80\x00', answers)
            print(f"[ROOT] Redirecting to TLD server at {tld_server_ip}:{tld_server_port}")
            server_socket.sendto(response, client_address)
        else:
            print("[ROOT] TLD not found for query.")
            response = create_dns_response(client_data[:2], b'\x80\x03', [])
            server_socket.sendto(response, client_address)

    except Exception as e:
        print(f"[ROOT ERROR] {e}")

# Start the root DNS server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, ROOT_PORT))
    print(f"[ROOT SERVER] Running on {HOST}:{ROOT_PORT}")

    while True:
        client_data, client_address = server_socket.recvfrom(512)
        handle_client(client_data, client_address, server_socket)

if __name__ == "__main__":
    start_server()
