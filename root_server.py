import socket
import threading
from config import HOST, ROOT_PORT

# TLD server mappings
TLD_SERVERS = {
    "com": (HOST, 1500),
    "org": (HOST, 1600),
    "arpa": (HOST, 1700),
    # Add more TLDs as needed
}

def start_root_server():
    # UDP Socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, ROOT_PORT))
    print(f"[ROOT] Server started on {HOST}:{ROOT_PORT} (UDP)")

    # TCP Socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((HOST, ROOT_PORT))
    tcp_socket.listen(5)
    print(f"[ROOT] Server started on {HOST}:{ROOT_PORT} (TCP)")

    # Start threads to handle UDP and TCP
    udp_thread = threading.Thread(target=handle_udp_queries, args=(udp_socket,))
    tcp_thread = threading.Thread(target=handle_tcp_queries, args=(tcp_socket,))

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()

def handle_udp_queries(udp_socket):
    while True:
        data, client_address = udp_socket.recvfrom(512)
        handle_client(data, client_address, udp_socket, protocol='udp')

def handle_tcp_queries(tcp_socket):
    while True:
        client_socket, client_address = tcp_socket.accept()
        threading.Thread(target=handle_tcp_connection, args=(client_socket, client_address)).start()

def handle_tcp_connection(client_socket, client_address):
    try:
        while True:
            # Read the two-byte length field
            length_data = client_socket.recv(2)
            if not length_data:
                break  # Client closed the connection
            message_length = int.from_bytes(length_data, byteorder='big')
            # Read the DNS query message
            data = b''
            while len(data) < message_length:
                chunk = client_socket.recv(message_length - len(data))
                if not chunk:
                    break
                data += chunk
            if not data:
                break
            response = handle_client(data, client_address, None, protocol='tcp')
            if response:
                # Send the two-byte length prefix
                response_length = len(response).to_bytes(2, byteorder='big')
                client_socket.sendall(response_length + response)
    except Exception as e:
        print(f"[ROOT TCP ERROR] {e}")
    finally:
        client_socket.close()

def handle_client(data, client_address, server_socket, protocol='udp'):
    # Extract domain name from the DNS query
    domain_name = extract_domain_name(data)
    print(f"[ROOT][{protocol.upper()}] Received query for '{domain_name}'")
    tld = domain_name.split('.')[-1]

    if tld in TLD_SERVERS:
        tld_ip, tld_port = TLD_SERVERS[tld]
        # Forward query to the TLD server
        print(f"[ROOT] Redirecting to TLD server {tld_ip}:{tld_port}")
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_socket.settimeout(5)
        try:
            forward_socket.sendto(data, (tld_ip, tld_port))
            response, _ = forward_socket.recvfrom(1024)
            if protocol == 'udp':
                server_socket.sendto(response, client_address)
            elif protocol == 'tcp':
                return response
        except Exception as e:
            print(f"[ROOT ERROR] {e}")
            error_response = create_dns_error_response(data)
            if protocol == 'udp':
                server_socket.sendto(error_response, client_address)
            elif protocol == 'tcp':
                return error_response
        finally:
            forward_socket.close()
    else:
        print(f"[ROOT] TLD '{tld}' not found.")
        error_response = create_dns_error_response(data)
        if protocol == 'udp':
            server_socket.sendto(error_response, client_address)
        elif protocol == 'tcp':
            return error_response

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
