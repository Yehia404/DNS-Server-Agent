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

def load_auth_table(auth_table_file):
    try:
        with open(auth_table_file, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load Auth table: {e}")
        sys.exit(1)

def start_auth_server(auth_table_file, domain):
    # Load the authoritative server table
    auth_table_complete = load_auth_table(auth_table_file)

    if domain not in auth_table_complete:
        print(f"[ERROR] Domain '{domain}' not found in auth table.")
        sys.exit(1)

    auth_table = auth_table_complete[domain]

    # Convert keys in auth_table to lowercase
    auth_table = {domain_name.lower(): records for domain_name, records in auth_table.items()}

    port_map = {
        "google": 1602,
        "microsoft": 1603,
        "wikipedia": 1604,
        "arpa": 1606,
        # Add more domains and ports as needed
    }

    if domain not in port_map:
        print(f"[ERROR] Unknown domain '{domain}'. Valid domains are: {list(port_map.keys())}.")
        sys.exit(1)

    port = port_map[domain]

    # UDP Socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, port))
    print(f"[AUTH SERVER] Running on {HOST}:{port} (UDP) for domain '{domain}'")

    # TCP Socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((HOST, port))
    tcp_socket.listen(5)
    print(f"[AUTH SERVER] Running on {HOST}:{port} (TCP) for domain '{domain}'")

    # Start threads to handle UDP and TCP
    udp_thread = threading.Thread(target=handle_udp_queries, args=(udp_socket, auth_table))
    tcp_thread = threading.Thread(target=handle_tcp_queries, args=(tcp_socket, auth_table))

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()

def handle_udp_queries(udp_socket, auth_table):
    while True:
        data, client_address = udp_socket.recvfrom(512)
        threading.Thread(target=handle_client, args=(data, client_address, udp_socket, auth_table, 'udp')).start()

def handle_tcp_queries(tcp_socket, auth_table):
    while True:
        client_socket, client_address = tcp_socket.accept()
        threading.Thread(target=handle_tcp_connection, args=(client_socket, client_address, auth_table)).start()

def handle_tcp_connection(client_socket, client_address, auth_table):
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
            response = handle_client(data, client_address, None, auth_table, 'tcp')
            if response:
                # Send the two-byte length prefix
                response_length = len(response).to_bytes(2, byteorder='big')
                client_socket.sendall(response_length + response)
    except Exception as e:
        print(f"[AUTH TCP ERROR] {e}")
    finally:
        client_socket.close()

def handle_client(data, client_address, server_socket, auth_table, protocol='udp'):
    try:
        domain_name, qtype = extract_query_info(data)
    except Exception as e:
        print(f"[AUTH ERROR] Format error in query from {client_address}: {e}")
        error_response = create_dns_error_response(data, rcode=1)  # Format Error
        send_response(server_socket, error_response, client_address, protocol)
        return

    domain_name = domain_name.lower()  # Ensure domain name is in lowercase

    print(f"[AUTH][{protocol.upper()}] Received query for '{domain_name}' with type {qtype}")

    # Check if the query type is supported
    if qtype not in RECORD_TYPES:
        print(f"[AUTH] Query type {qtype} not implemented.")
        error_response = create_dns_error_response(data, rcode=4)  # Not Implemented
        send_response(server_socket, error_response, client_address, protocol)
        return

    # Policy example: Refuse queries for certain domains or clients
    # refused_domains = ['blocked.example.com']
    # if domain_name in refused_domains:
    #     print(f"[AUTH] Refusing query for '{domain_name}'")
    #     error_response = create_dns_error_response(data, rcode=5)  # Refused
    #     send_response(server_socket, error_response, client_address, protocol)
    #     return

    if domain_name in auth_table:
        records = auth_table[domain_name]
        answers = [r for r in records if r['type'] == RECORD_TYPES[qtype]]
        if answers:
            response = create_dns_response(data, answers, qtype)
            send_response(server_socket, response, client_address, protocol)
        else:
            print(f"[AUTH] No {RECORD_TYPES[qtype]} record found for '{domain_name}'")
            error_response = create_dns_error_response(data, rcode=3)  # Name Error
            send_response(server_socket, error_response, client_address, protocol)
    else:
        print(f"[AUTH] Domain '{domain_name}' not found.")
        error_response = create_dns_error_response(data, rcode=3)  # Name Error
        send_response(server_socket, error_response, client_address, protocol)

def send_response(server_socket, response, client_address, protocol):
    if protocol == 'udp':
        server_socket.sendto(response, client_address)
    elif protocol == 'tcp':
        # For TCP, the response should be returned to the caller
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

def encode_domain_name(domain_name):
    labels = domain_name.rstrip('.').split('.')
    encoded = b''
    for label in labels:
        length = len(label)
        encoded += bytes([length]) + label.encode()
    encoded += b'\x00'  # End with null byte
    return encoded

def create_dns_response(query, records, qtype):
    transaction_id = query[:2]
    # Extract flags from query
    flags_query = query[2:4]
    qr = 1 << 15  # Response flag
    opcode = (flags_query[0] & 0x78) << 8  # Opcode from query
    aa = 1 << 10  # Authoritative Answer
    rd = (flags_query[1] & 0x01) << 8  # Recursion Desired
    ra = 0  # Recursion Available (Authoritative server does not provide recursion)
    z = 0  # Reserved
    rcode = 0  # No error
    # Build flags
    flags = qr | opcode | aa | rd | ra | rcode
    flags_bytes = flags.to_bytes(2, byteorder='big')

    qd_count = b'\x00\x01'  # One question
    an_count = len(records).to_bytes(2, byteorder='big')  # Number of answers
    ns_count = b'\x00\x00'  # No authority records
    ar_count = b'\x00\x00'  # No additional records

    header = transaction_id + flags_bytes + qd_count + an_count + ns_count + ar_count
    question = query[12:]  # Copy question

    answers = b''
    for record in records:
        answer = b'\xc0\x0c'  # Pointer to domain name in question
        answer += qtype.to_bytes(2, byteorder='big')
        answer += b'\x00\x01'  # Class IN
        ttl = record.get('ttl', 300)
        answer += ttl.to_bytes(4, byteorder='big')

        if record['type'] == 'A':
            rdata = socket.inet_aton(record['value'])
            rdlength = len(rdata).to_bytes(2, byteorder='big')
        elif record['type'] == 'AAAA':
            rdata = socket.inet_pton(socket.AF_INET6, record['value'])
            rdlength = len(rdata).to_bytes(2, byteorder='big')
        elif record['type'] == 'PTR':
            ptr_name = encode_domain_name(record['value'])
            rdlength = len(ptr_name).to_bytes(2, byteorder='big')
            rdata = ptr_name
        elif record['type'] == 'NS':
            ns_name = encode_domain_name(record['value'])
            rdlength = len(ns_name).to_bytes(2, byteorder='big')
            rdata = ns_name
        elif record['type'] == 'CNAME':
            cname = encode_domain_name(record['value'])
            rdlength = len(cname).to_bytes(2, byteorder='big')
            rdata = cname
        elif record['type'] == 'MX':
            preference = record.get('preference', 10).to_bytes(2, byteorder='big')
            exchange = encode_domain_name(record['value'])
            rdlength = (len(preference) + len(exchange)).to_bytes(2, byteorder='big')
            rdata = preference + exchange
        else:
            continue  # Skip unsupported record types

        answer += rdlength + rdata
        answers += answer

    return header + question + answers

def create_dns_error_response(query, rcode):
    transaction_id = query[:2]
    # Extract flags from query
    flags_query = query[2:4]
    qr = 1 << 15  # Response flag
    opcode = (flags_query[0] & 0x78) << 8  # Opcode from query
    aa = 1 << 10  # Authoritative Answer
    rd = (flags_query[1] & 0x01) << 8  # Recursion Desired
    ra = 0  # Recursion Available (Authoritative server does not provide recursion)
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
        print("[ERROR] Usage: python auth_server.py <auth_table.json> <domain>")
        sys.exit(1)

    auth_table_file = sys.argv[1]  # Path to the auth table JSON file
    domain = sys.argv[2]  # The domain to handle (e.g., 'google', 'microsoft', 'wikipedia', 'arpa')

    start_auth_server(auth_table_file, domain)