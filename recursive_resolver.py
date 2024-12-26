# recursive_resolver.py
import socket
import time
import struct
from config import HOST, ROOT_PORT

RECURSOR_PORT = 53  # Port on which the recursive resolver will listen


def start_recursive_resolver():
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_socket.bind((HOST, RECURSOR_PORT))
    print(f"[RECURSIVE RESOLVER] Listening on {HOST}:{RECURSOR_PORT}")
    
    cache = {}
    
    while True:
        data, client_address = resolver_socket.recvfrom(512)
        handle_query(data, client_address, resolver_socket, cache)

def handle_query(data, client_address, resolver_socket, cache):
    domain_name, qtype = extract_query_info(data)
    cache_key = (domain_name, qtype)
    current_time = time.time()
    
    # Check if the response is in the cache
    if cache_key in cache:
        cache_entry = cache[cache_key]
        if cache_entry['expires_at'] > current_time:
            print(f"[CACHE HIT] Serving '{domain_name}' type {qtype} from cache.")
            # Update the transaction ID to match the client's query
            response = data[:2] + cache_entry['response'][2:]
            resolver_socket.sendto(response, client_address)
            return
        else:
            # Cache entry has expired
            print(f"[CACHE EXPIRED] Removing '{domain_name}' type {qtype} from cache.")
            del cache[cache_key]
    
    # Cache miss, perform recursive resolution
    print(f"[CACHE MISS] Performing recursive resolution for '{domain_name}' type {qtype}")
    response = perform_recursive_resolution(data, ('localhost', ROOT_PORT))
    if response:
        # Extract TTL from the response
        ttl = extract_ttl(response)
        if ttl:
            expires_at = current_time + ttl
            cache[cache_key] = {'response': response, 'expires_at': expires_at}
            print(f"[CACHE STORE] Caching '{domain_name}' type {qtype} for {ttl} seconds.")
        else:
            print("[WARNING] No TTL found in response; not caching.")
        resolver_socket.sendto(response, client_address)
    else:
        print(f"[ERROR] Could not resolve '{domain_name}' type {qtype}.")
        error_response = create_dns_error_response(data)
        resolver_socket.sendto(error_response, client_address)

def extract_query_info(data):
    # Parse the DNS query to extract the domain name and query type
    index = 12  # Start after the header
    domain_parts = []
    while True:
        length = data[index]
        if length == 0:
            index += 1
            break
        index += 1
        domain_parts.append(data[index:index+length].decode())
        index += length
    domain_name = '.'.join(domain_parts)
    qtype = int.from_bytes(data[index:index+2], 'big')
    qclass = int.from_bytes(data[index+2:index+4], 'big')
    return domain_name, qtype

def perform_recursive_resolution(query_data, server_address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)
    try:
        current_server = server_address
        while True:
            client_socket.sendto(query_data, current_server)
            response_data, addr = client_socket.recvfrom(512)
            
            # Check for an answer in the response
            answer_count = int.from_bytes(response_data[6:8], 'big')
            if answer_count > 0:
                # Found the answer
                return response_data
            else:
                # No answer, check for referral in the additional section
                additional_count = int.from_bytes(response_data[10:12], 'big')
                if additional_count > 0:
                    # Parse the additional section to get the next server
                    next_server = extract_next_server_address(response_data)
                    if next_server:
                        print(f"[RECURSIVE RESOLVER] Querying next server: {next_server}")
                        current_server = (next_server, 53)  # Port 53 is standard for DNS servers
                        continue
                    else:
                        print("[RECURSIVE RESOLVER] No valid additional records found.")
                        return None
                else:
                    print("[RECURSIVE RESOLVER] No answers or additional records.")
                    return None
    except socket.timeout:
        print("[RECURSIVE RESOLVER] Timeout during recursive resolution.")
        return None
    finally:
        client_socket.close()

def extract_ttl(response):
    index = 12  # Skip the header
    # Skip the question section
    while response[index] != 0:
        index += response[index] + 1
    index += 5  # Skip the null byte and QTYPE (2 bytes) and QCLASS (2 bytes)

    # Now at the beginning of the answer section
    answer_count = int.from_bytes(response[6:8], 'big')
    if answer_count == 0:
        return None  # No answer section
    index += 2  # Name (compressed pointer, 2 bytes)
    index += 2  # Type (2 bytes)
    index += 2  # Class (2 bytes)
    ttl = int.from_bytes(response[index:index+4], 'big')
    return ttl

def create_dns_error_response(query):
    transaction_id = query[:2]
    flags = b'\x81\x83'  # Standard query response, with RCODE=3 (Name Error)
    rest = query[4:6] + b'\x00\x00\x00\x00\x00\x00'  # Zero out counts
    return transaction_id + flags + rest

def extract_next_server_address(response):
    # Extract the IP address of the next server from the additional records
    # This function assumes that the next server's IP address is in an A record in the additional section
    index = 12  # Start after the header
    # Skip the question section
    while response[index] != 0:
        index += response[index] + 1
    index += 5  # Skip the null byte and QTYPE (2 bytes) and QCLASS (2 bytes)

    # Skip answer and authority sections
    answer_count = int.from_bytes(response[6:8], 'big')
    authority_count = int.from_bytes(response[8:10], 'big')
    additional_count = int.from_bytes(response[10:12], 'big')

    # Skip answer records
    for _ in range(answer_count):
        index = skip_record(response, index)

    # Skip authority records
    for _ in range(authority_count):
        index = skip_record(response, index)

    # Parse additional records to find the next server's IP
    for _ in range(additional_count):
        start_index = index
        index = skip_name(response, index)
        rtype = int.from_bytes(response[index:index+2], 'big')
        index += 2  # Type
        index += 2  # Class
        ttl = int.from_bytes(response[index:index+4], 'big')
        index += 4  # TTL
        rdlength = int.from_bytes(response[index:index+2], 'big')
        index += 2  # RDLENGTH
        if rtype == 1:  # A record
            rdata = response[index:index+rdlength]
            ip_address = socket.inet_ntoa(rdata)
            return ip_address
        index += rdlength  # Move to the next record
    return None

def skip_name(response, index):
    # Helper function to skip over a domain name in the response
    if response[index] & 0xC0 == 0xC0:
        # Name is a pointer
        index += 2
    else:
        while response[index] != 0:
            length = response[index]
            index += length + 1
        index += 1  # Skip the null byte
    return index

def skip_record(response, index):
    # Helper function to skip over a resource record
    index = skip_name(response, index)
    index += 2  # Type
    index += 2  # Class
    index += 4  # TTL
    rdlength = int.from_bytes(response[index:index+2], 'big')
    index += 2  # RDLENGTH
    index += rdlength  # RDATA
    return index

if __name__ == "__main__":
    start_recursive_resolver()