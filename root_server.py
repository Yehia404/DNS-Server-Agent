import socket
from config import HOST, ROOT_PORT

# Root DNS Table (mapping TLD to server)
root_dns_table = {
    ".com": (HOST, 1500),  # TLD server for .com
    ".org": (HOST, 1600),  # TLD server for .org
}

def handle_client(client_data, client_address, server_socket):
    try:
        # Decode the domain query
        data = client_data.decode()
        if not data:
            print("[ROOT] Received empty query.")
            return

        print(f"[ROOT] Received query: '{data}' from {client_address}")

        # Extract TLD
        domain_parts = data.split(".")
        tld = "." + domain_parts[-1]  # Get the last part (e.g., .com, .org)

        # Check if TLD is valid
        if tld in root_dns_table:
            tld_server, tld_port = root_dns_table[tld]
            response = f"Redirect to TLD server: {tld_server}:{tld_port}"
            print(f"[ROOT] Redirecting to TLD server {tld_server}:{tld_port}")
        else:
            response = "TLD not found"
            print("[ROOT] TLD not found for query.")

        # Send response to the client
        server_socket.sendto(response.encode(), client_address)

    except Exception as e:
        print(f"[ROOT ERROR] {e}")

# Start the root DNS server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, ROOT_PORT))
    print(f"[ROOT SERVER] Running on {HOST}:{ROOT_PORT}")

    while True:
        client_data, client_address = server_socket.recvfrom(1024)
        handle_client(client_data, client_address, server_socket)

if __name__ == "__main__":
    start_server()
