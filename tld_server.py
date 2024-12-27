import socket
import json
import sys
from config import HOST
import threading


def load_tld_table(tld_table_file):
    try:
        with open(tld_table_file, "r") as file:
            json_content = file.read()
            json_content = json_content.replace("{{HOST}}", HOST)
            return json.loads(json_content)
    except Exception as e:
        print(f"[ERROR] Failed to load TLD table: {e}")
        sys.exit(1)

def start_tld_server(tld_table_file, tld):
    # Load the TLD table
    tld_table = load_tld_table(tld_table_file)
    tld_data = tld_table[tld]  # Extract the inner table for the given TLD

    # Define the fixed port based on TLD
    tld_ports = {
        "com": 1500,
        "org": 1600,
        "arpa": 1700,
    }

    if tld not in tld_ports:
        print(f"[ERROR] Unknown TLD '{tld}'. Valid TLDs are: {list(tld_ports.keys())}.")
        sys.exit(1)

    port = tld_ports[tld]

    # UDP Socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, port))
    print(f"[TLD SERVER] Running on {HOST}:{port} (UDP) for TLD '{tld}'")

    # TCP Socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((HOST, port))
    tcp_socket.listen(5)
    print(f"[TLD SERVER] Running on {HOST}:{port} (TCP) for TLD '{tld}'")

    # Start threads to handle UDP and TCP
    udp_thread = threading.Thread(target=handle_udp_queries, args=(udp_socket, tld_data))
    tcp_thread = threading.Thread(target=handle_tcp_queries, args=(tcp_socket, tld_data))

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()

def handle_udp_queries(udp_socket, tld_data):
    while True:
        data, client_address = udp_socket.recvfrom(512)
        handle_client(data, client_address, udp_socket, tld_data, protocol='udp')

def handle_tcp_queries(tcp_socket, tld_data):
    while True:
        client_socket, client_address = tcp_socket.accept()
        threading.Thread(target=handle_tcp_connection, args=(client_socket, client_address, tld_data)).start()

def handle_tcp_connection(client_socket, client_address, tld_data):
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
            response = handle_client(data, client_address, None, tld_data, protocol='tcp')
            if response:
                # Send the two-byte length prefix
                response_length = len(response).to_bytes(2, byteorder='big')
                client_socket.sendall(response_length + response)
    except Exception as e:
        print(f"[TLD TCP ERROR] {e}")
    finally:
        client_socket.close()

def handle_client(data, client_address, server_socket, tld_data, protocol='udp'):
    domain_name = extract_domain_name(data)
    print(f"[TLD][{protocol.upper()}] Received query for '{domain_name}'")

    # Find the longest matching domain suffix in tld_data
    matching_domain = None
    for tld_domain in tld_data:
        if domain_name.endswith(tld_domain):
            if not matching_domain or len(tld_domain) > len(matching_domain):
                matching_domain = tld_domain

    if matching_domain:
        auth_ip, auth_port = tld_data[matching_domain]
        print(f"[TLD] Forwarding query for '{domain_name}' to authoritative server {auth_ip}:{auth_port}")
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_socket.settimeout(5)
        try:
            forward_socket.sendto(data, (auth_ip, auth_port))
            response, _ = forward_socket.recvfrom(1024)
            if protocol == 'udp':
                server_socket.sendto(response, client_address)
            elif protocol == 'tcp':
                return response
        except Exception as e:
            print(f"[TLD ERROR] {e}")
            error_response = create_dns_error_response(data)
            if protocol == 'udp':
                server_socket.sendto(error_response, client_address)
            elif protocol == 'tcp':
                return error_response
        finally:
            forward_socket.close()
    else:
        print(f"[TLD] Domain '{domain_name}' not found in TLD data.")
        error_response = create_dns_error_response(data)
        if protocol == 'udp':
            server_socket.sendto(error_response, client_address)
        elif protocol == 'tcp':
            return error_response

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

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python tld_server.py <tld_table.json> <tld>")
        sys.exit(1)

    tld_table_file = sys.argv[1]  # Path to the TLD table JSON file
    tld = sys.argv[2]  # The TLD to use (e.g., 'com' or 'org')

    start_tld_server(tld_table_file, tld)
