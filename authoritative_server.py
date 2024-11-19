import socket
from config import HOST, AUTHORITATIVE_PORT

# Authoritative DNS Table (mapping domain to IP)
authoritative_dns_table = {
    "example.com": "93.184.216.34",
    "google.com": "142.250.190.78",
    "localhost": "127.0.0.1"
}

def handle_client(client_data, client_address, server_socket):
    try:
        # Decode the domain query
        data = client_data.decode()
        if not data:
            print("[AUTHORITATIVE] Received empty query.")
            return

        print(f"[AUTHORITATIVE] Received query: '{data}' from {client_address}")

        # Resolve domain
        response = authoritative_dns_table.get(data, "Domain not found")
        print(f"[AUTHORITATIVE] Responding with: {response}")

        # Send response back to client
        server_socket.sendto(response.encode(), client_address)

    except Exception as e:
        print(f"[AUTHORITATIVE ERROR] {e}")

# Start the authoritative DNS server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, AUTHORITATIVE_PORT))
    print(f"[AUTHORITATIVE SERVER] Running on {HOST}:{AUTHORITATIVE_PORT}")

    while True:
        client_data, client_address = server_socket.recvfrom(1024)
        handle_client(client_data, client_address, server_socket)

if __name__ == "__main__":
    start_server()
