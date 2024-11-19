import socket
from config import HOST, TLD_PORT

# TLD DNS Table (mapping domain to authoritative DNS server)
tld_dns_table = {
    "com": ("127.0.0.1", 1600),  # Authoritative server for .com
    # "org": ("127.0.0.1", 1700),  # Authoritative server for .org
}

def handle_client(client_data, client_address, server_socket):
    try:
        # Decode the domain query
        data = client_data.decode()
        if not data:
            print("[TLD] Received empty query.")
            return

        print(f"[TLD] Received query: '{data}' from {client_address}")

        # Extract TLD
        domain_parts = data.split(".")
        tld = domain_parts[-1]

        if tld in tld_dns_table:
            authoritative_server, authoritative_port = tld_dns_table[tld]
            response = f"Redirect to authoritative server: {authoritative_server}:{authoritative_port}"
            print(f"[TLD] Redirecting to authoritative server {authoritative_server}:{authoritative_port}")
        else:
            response = "TLD not found"
            print("[TLD] TLD not found for query.")

        # Send response to the client
        server_socket.sendto(response.encode(), client_address)

    except Exception as e:
        print(f"[TLD ERROR] {e}")

# Start the TLD DNS server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, TLD_PORT))
    print(f"[TLD SERVER] Running on {HOST}:{TLD_PORT}")

    while True:
        client_data, client_address = server_socket.recvfrom(1024)
        handle_client(client_data, client_address, server_socket)

if __name__ == "__main__":
    start_server()
