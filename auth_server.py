import socket
import json
import sys
from config import HOST

RECORD_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    12: 'PTR',    # Add PTR record type
    15: 'MX',
    28: 'AAAA',   # Add AAAA record type
    # Add more types if needed
}

def load_auth_table(auth_table_file):
    try:
        with open(auth_table_file, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load Auth table: {e}")
        sys.exit(1)

def handle_client(data, client_address, server_socket, auth_table):
    domain_name, qtype = extract_query_info(data)
    print(f"[AUTH] Received query for '{domain_name}' with type {qtype}")
    record_type = RECORD_TYPES.get(qtype, None)
    print(f"[AUTH] Record type: {record_type}")
    if not record_type:
        print(f"[AUTH] Unsupported query type: {qtype}")
        error_response = create_dns_error_response(data)
        server_socket.sendto(error_response, client_address)
        return

    if domain_name in auth_table:
        records = auth_table[domain_name]
        answers = [r for r in records if r['type'] == record_type]
        if answers:
            response = create_dns_response(data, answers, qtype)
            server_socket.sendto(response, client_address)
        else:
            print(f"[AUTH] No {record_type} record found for '{domain_name}'")
            error_response = create_dns_error_response(data)
            server_socket.sendto(error_response, client_address)
    else:
        print(f"[AUTH] Domain '{domain_name}' not found.")
        error_response = create_dns_error_response(data)
        server_socket.sendto(error_response, client_address)

def extract_query_info(data):
    query_section = data[12:]
    index = 0
    domain_parts = []

    while True:
        length = query_section[index]
        if length == 0:
            index += 1
            break
        domain_parts.append(query_section[index+1:index+1+length].decode())
        index += length + 1

    domain_name = '.'.join(domain_parts)

    # Extract query type and class
    qtype = int.from_bytes(query_section[index:index+2], 'big')
    qclass = int.from_bytes(query_section[index+2:index+4], 'big')

    return domain_name, qtype

def encode_domain_name(domain_name):
    parts = domain_name.split('.')
    encoded = b''
    for part in parts:
        length = len(part)
        encoded += bytes([length]) + part.encode()
    encoded += b'\x00'  # Null byte to end the domain name
    return encoded



def create_dns_response(query, records, qtype):
    transaction_id = query[:2]
    flags = b'\x81\x80'  # Standard query response, No error
    qd_count = b'\x00\x01'  # One question
    an_count = len(records).to_bytes(2, byteorder='big')  # Number of answers
    ns_count = b'\x00\x00'  # No authority records
    ar_count = b'\x00\x00'  # No additional records

    header = transaction_id + flags + qd_count + an_count + ns_count + ar_count
    question = query[12:]  # Copy question

    answers = b''
    for record in records:
        answer = b'\xc0\x0c'  # Pointer to domain name in question
        answer += qtype.to_bytes(2, byteorder='big')
        answer += b'\x00\x01'  # Class IN
        answer += b'\x00\x00\x00\x3c'  # TTL: 60 seconds

        if record['type'] == 'A':
            rdata = socket.inet_aton(record['value'])
            rdlength = b'\x00\x04'  # IPv4 address length
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
            preference = b'\x00\x05'  # MX preference value
            exchange = encode_domain_name(record['value'])
            rdlength = (len(preference) + len(exchange)).to_bytes(2, byteorder='big')
            rdata = preference + exchange
        else:
            continue  # Skip unsupported record types

        answer += rdlength + rdata
        answers += answer

    return header + question + answers

def create_dns_error_response(query):
    transaction_id = query[:2]
    flags = b'\x81\x83'  # Standard query response, Name Error
    rest = query[4:]
    return transaction_id + flags + rest

def start_auth_server(auth_table_file, domain):
    # Load the authoritative server table
    auth_table_complete = load_auth_table(auth_table_file)

    if domain not in auth_table_complete:
        print(f"[ERROR] Domain '{domain}' not found in auth table.")
        sys.exit(1)

    auth_table = auth_table_complete[domain]

    port_map = {
        "google": 1602,
        "microsoft": 1603,
        "arpa": 1606,
        # Add more domains and their ports as needed
    }

    if domain not in port_map:
        print(f"[ERROR] Unknown domain '{domain}'. Valid domains are: {list(port_map.keys())}.")
        sys.exit(1)

    port = port_map[domain]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, port))
    print(f"[AUTH SERVER] Running on port {port} for domain '{domain}'")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        handle_client(data, client_address, server_socket, auth_table)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[ERROR] Usage: python auth_server.py <auth_table.json> <domain>")
        sys.exit(1)

    auth_table_file = sys.argv[1]  # Path to the auth table JSON file
    domain = sys.argv[2]  # The domain to handle (e.g., 'google', 'microsoft')

    start_auth_server(auth_table_file, domain)