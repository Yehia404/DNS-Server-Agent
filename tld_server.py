import socket
import json
import sys
import threading
from config import HOST

RECORD_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    12: 'PTR',
    15: 'MX',
    28: 'AAAA',
}

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
    if tld not in tld_table:
        print(f"[ERROR] TLD '{tld}' not found in TLD table.")
        sys.exit(1)
    tld_data = tld_table[tld]  # Extract the inner table for the given TLD

    # Convert keys in tld_data to lowercase
    tld_data = {domain.lower(): tld_data[domain] for domain in tld_data}

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
        threading.Thread(target=handle_client, args=(data, client_address, udp_socket, tld_data, 'udp')).start()

def handle_tcp_queries(tcp_socket, tld_data):
    while True:
        client_socket, client_address = tcp_socket.accept()
        threading.Thread(target=handle_tcp_connection, args=(client_socket, client_address, tld_data)).start()

def handle_tcp_connection(client_socket, client_address, tld_data):
    try:
        while True:
            # Read the two-byte length field
            length_data = client_socket.recv(2)
            if not length_data or len(length_data) < 2:
                break  # Client closed the connection or invalid length data
            message_length = int.from_bytes(length_data, byteorder='big')
            # Read the DNS query message
            data = b''
            while len(data) < message_length:
                chunk = client_socket.recv(message_length - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) < message_length:
                print(f"[TLD TCP ERROR] Incomplete DNS message from {client_address}")
                break
            # Pass the 'protocol' as 'tcp' to get the response back
            response = handle_client(data, client_address, client_socket, tld_data, 'tcp')
            if response:
                # Send the two-byte length prefix
                response_length = len(response).to_bytes(2, byteorder='big')
                client_socket.sendall(response_length + response)
    except Exception as e:
        print(f"[TLD TCP ERROR] {e}")
    finally:
        client_socket.close()

def handle_client(data, client_address, server_socket, tld_data, protocol='udp'):
    try:
        domain_name, qtype = extract_query_info(data)
    except Exception as e:
        print(f"[TLD ERROR] Format error in query from {client_address}: {e}")
        error_response = create_dns_error_response(data, rcode=1)  # Format Error
        if protocol == 'tcp':
            return error_response
        else:
            send_response(server_socket, error_response, client_address, protocol)
        return  # Exit the function after sending the error response

    domain_name = domain_name.lower()  # Ensure domain name is in lowercase

    print(f"[TLD][{protocol.upper()}] Received query for '{domain_name}' with type {qtype}")

    # Check if the query type is supported
    if qtype not in RECORD_TYPES:
        print(f"[TLD] Query type {qtype} not implemented.")
        error_response = create_dns_error_response(data, rcode=4)  # Not Implemented
        if protocol == 'tcp':
            return error_response
        else:
            send_response(server_socket, error_response, client_address, protocol)
        return

    # Find the closest matching domain
    matching_domain = find_matching_domain(domain_name, tld_data)

    if matching_domain:
        auth_ip_port = tld_data[matching_domain]
        if isinstance(auth_ip_port, list) and len(auth_ip_port) == 2:
            auth_ip, auth_port = auth_ip_port
            # Forward query to the authoritative server
            print(f"[TLD] Forwarding query for '{domain_name}' to authoritative server {auth_ip}:{auth_port}")
            response = forward_query(data, (auth_ip, auth_port), protocol)
            if response:
                if protocol == 'tcp':
                    return response
                else:
                    send_response(server_socket, response, client_address, protocol)
            else:
                print(f"[TLD ERROR] Failed to get response from authoritative server {auth_ip}:{auth_port}")
                error_response = create_dns_error_response(data, rcode=2)  # Server Failure
                if protocol == 'tcp':
                    return error_response
                else:
                    send_response(server_socket, error_response, client_address, protocol)
        else:
            print(f"[TLD ERROR] Invalid authoritative server info for domain '{matching_domain}'")
            error_response = create_dns_error_response(data, rcode=2)  # Server Failure
            if protocol == 'tcp':
                return error_response
            else:
                send_response(server_socket, error_response, client_address, protocol)
    else:
        print(f"[TLD] Domain '{domain_name}' not found in TLD data.")
        error_response = create_dns_error_response(data, rcode=3)  # Name Error
        if protocol == 'tcp':
            return error_response
        else:
            send_response(server_socket, error_response, client_address, protocol)

def forward_query(data, server_address, protocol):
    if protocol == 'udp':
        try:
            forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            forward_socket.settimeout(5)
            forward_socket.sendto(data, server_address)
            response, _ = forward_socket.recvfrom(512)
            return response
        except Exception as e:
            print(f"[TLD ERROR] {e}")
            return None
        finally:
            forward_socket.close()
    elif protocol == 'tcp':
        try:
            with socket.create_connection(server_address, timeout=5) as tcp_socket:
                # Prefix the query with the two-byte length field
                tcp_socket.sendall(len(data).to_bytes(2, byteorder='big') + data)
                # Read the two-byte length field from the response
                length_data = tcp_socket.recv(2)
                if not length_data or len(length_data) < 2:
                    print("[TLD ERROR] Incomplete response from authoritative server over TCP")
                    return None
                message_length = int.from_bytes(length_data, byteorder='big')
                # Read the full DNS response message
                response_data = b''
                while len(response_data) < message_length:
                    chunk = tcp_socket.recv(message_length - len(response_data))
                    if not chunk:
                        break
                    response_data += chunk
                if len(response_data) != message_length:
                    print("[TLD ERROR] Incomplete response data from authoritative server over TCP")
                    return None
                return response_data
        except Exception as e:
            print(f"[TLD ERROR] {e}")
            return None

def send_response(server_socket, response, client_address, protocol):
    if protocol == 'udp':
        # Check if the response needs to be truncated
        if len(response) > 512:
            # Set the TC bit in the flags
            flags = int.from_bytes(response[2:4], byteorder='big')
            flags |= 0x0200  # Set the TC (Truncated) bit
            response = response[:2] + flags.to_bytes(2, byteorder='big') + response[4:]
            # Truncate the response to 512 bytes
            response = response[:512]
        server_socket.sendto(response, client_address)
    elif protocol == 'tcp':
        # For TCP, return the response to be sent by the caller
        return response

def extract_query_info(data):
    try:
        index = 12  # Skip the DNS header
        labels = []
        while True:
            length = data[index]
            if length == 0:
                index += 1
                break
            if (length & 0xC0) == 0xC0:
                # Handle name compression
                pointer = ((length & 0x3F) << 8) | data[index + 1]
                labels_part, _ = parse_labels(data, pointer)
                labels += labels_part
                index += 2
                break
            else:
                index += 1
                labels.append(data[index:index+length].decode())
                index += length
        qtype = int.from_bytes(data[index:index+2], 'big')
        domain_name = '.'.join(labels).lower()  # Convert to lowercase
        return domain_name, qtype
    except (IndexError, UnicodeDecodeError) as e:
        raise Exception(f"Failed to parse query info: {e}")

def parse_labels(data, index):
    labels = []
    try:
        while True:
            length = data[index]
            if length == 0:
                index += 1
                break
            if (length & 0xC0) == 0xC0:
                pointer = ((length & 0x3F) << 8) | data[index + 1]
                sub_labels, _ = parse_labels(data, pointer)
                labels.extend(sub_labels)
                index += 2
                break
            else:
                index += 1
                labels.append(data[index:index+length].decode().lower())  # Convert label to lowercase
                index += length
    except IndexError:
        raise Exception("Incomplete or malformed label")
    return labels, index

def find_matching_domain(domain_name, tld_data):
    parts = domain_name.split('.')
    for i in range(len(parts)):
        sub_domain = '.'.join(parts[i:]).lower()  # Ensure sub_domain is in lowercase
        if sub_domain in tld_data:
            return sub_domain
    return None

def create_dns_error_response(query, rcode):
    transaction_id = query[:2]
    # Extract flags from query
    flags_query = query[2:4]
    qr = 1 << 15  # Response flag
    opcode = (flags_query[0] & 0x78) << 8  # Opcode from query
    aa = 1 << 10  # Authoritative Answer
    rd = (flags_query[1] & 0x01) << 8  # Recursion Desired
    ra = 0  # Recursion Available (TLD server does not provide recursion)
    z = 0  # Reserved
    # Build flags
    flags = qr | opcode | aa | rd | ra | rcode
    flags_bytes = flags.to_bytes(2, byteorder='big')
    qd_count = query[4:6]  # Copy QDCOUNT from query
    an_count = b'\x00\x00'  # No answers
    ns_count = b'\x00\x00'
    ar_count = b'\x00\x00'
    header = transaction_id + flags_bytes + qd_count + an_count + ns_count + ar_count
    question = query[12:]  # Include the Question Section
    return header + question

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python tld_server.py <tld_table.json> <tld>")
        sys.exit(1)

    tld_table_file = sys.argv[1]  # Path to the TLD table JSON file
    tld = sys.argv[2]  # The TLD to use (e.g., 'com', 'org', 'arpa')

    try:
        start_tld_server(tld_table_file, tld)
    except KeyboardInterrupt:
        print("\n[TLD] Server shutting down.")
        sys.exit(0)
    except Exception as e:
        print(f"[TLD ERROR] {e}")
        sys.exit(1)