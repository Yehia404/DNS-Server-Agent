import socket
import time
import threading
import random
from config import HOST, ROOT_PORT

RECURSOR_PORT = 53

def start_recursive_resolver():
    # UDP Socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, RECURSOR_PORT))
    print(f"[RECURSIVE RESOLVER] Listening on {HOST}:{RECURSOR_PORT} (UDP)")

    # TCP Socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((HOST, RECURSOR_PORT))
    tcp_socket.listen(5)
    print(f"[RECURSIVE RESOLVER] Listening on {HOST}:{RECURSOR_PORT} (TCP)")

    cache = {}

    # Start threads to handle UDP and TCP
    udp_thread = threading.Thread(target=handle_udp_queries, args=(udp_socket, cache))
    tcp_thread = threading.Thread(target=handle_tcp_queries, args=(tcp_socket, cache))

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()

def handle_udp_queries(udp_socket, cache):
    while True:
        data, client_address = udp_socket.recvfrom(512)
        threading.Thread(target=handle_query, args=(data, client_address, udp_socket, cache, 'udp')).start()

def handle_tcp_queries(tcp_socket, cache):
    while True:
        client_socket, client_address = tcp_socket.accept()
        threading.Thread(target=handle_tcp_connection, args=(client_socket, client_address, cache)).start()

def handle_tcp_connection(client_socket, client_address, cache):
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
            # Pass the 'protocol' as 'tcp' to get the response back
            response = handle_query(data, client_address, client_socket, cache, 'tcp')
            if response:
                # Send the two-byte length prefix
                response_length = len(response).to_bytes(2, byteorder='big')
                client_socket.sendall(response_length + response)
    except Exception as e:
        print(f"[TCP ERROR] {e}")
    finally:
        client_socket.close()

def handle_query(data, client_address, socket, cache, protocol='udp'):
    try:
        domain_name, qtype = extract_query_info(data)
    except Exception as e:
        print(f"[ERROR] Format error in query from {client_address}: {e}")
        error_response = create_dns_error_response(data, rcode=1)  # Format Error
        send_response(socket, error_response, client_address, protocol)
        return

    domain_name = domain_name.lower()  # Ensure domain name is in lowercase

    print(f"[RECURSIVE RESOLVER][{protocol.upper()}] Received query for '{domain_name}' with type {qtype}")

    # Check if the query type is supported
    supported_qtypes = [1, 2, 5, 12, 15, 28]  # List of supported QTYPEs
    if qtype not in supported_qtypes:
        print(f"[ERROR] Query type {qtype} not implemented.")
        error_response = create_dns_error_response(data, rcode=4)  # Not Implemented
        send_response(socket, error_response, client_address, protocol)
        return

    cache_key = (domain_name, qtype)
    current_time = time.time()

    # Check if the response is in the cache
    if cache_key in cache:
        cache_entry = cache[cache_key]
        if cache_entry['expires_at'] > current_time:
            print(f"[CACHE HIT] Serving '{domain_name}' type {qtype} from cache.")
            # Update the transaction ID and flags to match the client's query
            response = update_transaction_id(cache_entry['response'], data[:2], data[2])
            send_response(socket, response, client_address, protocol)
            if protocol == 'tcp':
                return response
            return
        else:
            # Cache entry has expired
            print(f"[CACHE EXPIRED] Removing '{domain_name}' type {qtype} from cache.")
            del cache[cache_key]

    # Cache miss, perform recursive resolution
    print(f"[CACHE MISS] Performing recursive resolution for '{domain_name}' type {qtype}")
    response = perform_recursive_resolution(data, (HOST, ROOT_PORT))
    if response:
        # Extract RCODE from the response
        rcode = response[3] & 0x0F
        if rcode == 0:
            # Extract TTL from the response
            ttl = extract_ttl(response)
            if ttl:
                expires_at = current_time + ttl
                cache[cache_key] = {'response': response, 'expires_at': expires_at}
                print(f"[CACHE STORE] Caching '{domain_name}' type {qtype} for {ttl} seconds.")
            else:
                print("[WARNING] No TTL found in response; not caching.")
        else:
            print(f"[RECURSIVE RESOLVER] Received error code {rcode} from upstream server.")

        # Update the transaction ID to match the client's query
        response = update_transaction_id(response, data[:2], data[2])
        send_response(socket, response, client_address, protocol)
        if protocol == 'tcp':
            return response
    else:
        print(f"[ERROR] Could not resolve '{domain_name}' type {qtype}.")
        error_response = create_dns_error_response(data, rcode=2)  # Server Failure
        send_response(socket, error_response, client_address, protocol)
        if protocol == 'tcp':
            return error_response

def send_response(socket, response, client_address, protocol):
    if protocol == 'udp':
        if len(response) > 512:
            # Set the TC bit
            flags = int.from_bytes(response[2:4], byteorder='big')
            flags |= 0x0200  # Set the TC (Truncated) bit
            response = response[:2] + flags.to_bytes(2, byteorder='big') + response[4:]
            # Truncate the response to 512 bytes
            response = response[:512]
        socket.sendto(response, client_address)
    elif protocol == 'tcp':
        # For TCP, the response should be returned to the caller
        return response

def extract_query_info(data):
    # Parse the DNS query to extract the domain name and query type
    index = 12  # Start after the DNS header
    domain_parts = []
    try:
        length = data[index]
    except IndexError:
        raise ValueError("Invalid DNS query: Insufficient data for domain name.")
    while length != 0:
        if (length & 0xC0) == 0xC0:
            # Name compression pointer
            pointer = ((length & 0x3F) << 8) | data[index + 1]
            index = pointer
            length = data[index]
            continue
        else:
            index += 1
            domain_parts.append(data[index:index + length].decode())
            index += length
            try:
                length = data[index]
            except IndexError:
                raise ValueError("Invalid DNS query: Unexpected end of data while parsing domain name.")
    index += 1  # Skip the null byte
    qtype = int.from_bytes(data[index:index+2], 'big')
    domain_name = '.'.join(domain_parts).lower()  # Convert to lowercase
    return domain_name, qtype

def perform_recursive_resolution(query_data, server_address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)
    try:
        current_server = server_address
        queried_servers = set()
        retries = 3
        while True:
            if current_server in queried_servers:
                print(f"[RECURSIVE RESOLVER] Detected a loop while querying {current_server}.")
                return create_dns_error_response(query_data, rcode=2)  # Server Failure
            queried_servers.add(current_server)
            try:
                # Update the transaction ID to a random value
                transaction_id = random.randint(0, 65535).to_bytes(2, byteorder='big')
                query_with_id = transaction_id + query_data[2:]
                client_socket.sendto(query_with_id, current_server)
                response_data, addr = client_socket.recvfrom(512)
                # Validate the response transaction ID
                if response_data[:2] != transaction_id:
                    print("[RECURSIVE RESOLVER] Transaction ID mismatch.")
                    continue
                # Check for an error in the response
                rcode = response_data[3] & 0x0F
                if rcode != 0:
                    print(f"[RESOLVER ERROR] Received error code {rcode} from server {current_server}")
                    return response_data  # Return the error response

                answer_count = int.from_bytes(response_data[6:8], 'big')
                if answer_count > 0:
                    # Found the answer
                    return response_data
                else:
                    # No answer, check for referral in the authority section
                    authority_count = int.from_bytes(response_data[8:10], 'big')
                    if authority_count > 0:
                        next_servers = extract_nameservers(response_data)
                        if next_servers:
                            next_server_ip = resolve_nameserver(next_servers[0])
                            if next_server_ip:
                                print(f"[RECURSIVE RESOLVER] Querying next server: {next_server_ip}")
                                current_server = (next_server_ip, 53)
                                continue
                            else:
                                print("[RECURSIVE RESOLVER] Could not resolve IP of next nameserver.")
                                return create_dns_error_response(query_data, rcode=2)  # Server Failure
                        else:
                            print("[RECURSIVE RESOLVER] No valid nameservers found in authority section.")
                            return create_dns_error_response(query_data, rcode=3)  # Name Error
                    else:
                        print("[RECURSIVE RESOLVER] No answers or authority records.")
                        return create_dns_error_response(query_data, rcode=3)  # Name Error
            except socket.timeout:
                print(f"[RECURSIVE RESOLVER] Timeout querying server {current_server}. Retrying...")
                retries -= 1
                if retries == 0:
                    print("[RECURSIVE RESOLVER] Maximum retries reached. Server failure.")
                    return create_dns_error_response(query_data, rcode=2)  # Server Failure
            except Exception as e:
                print(f"[RECURSIVE RESOLVER] Exception: {e}")
                return create_dns_error_response(query_data, rcode=2)  # Server Failure
    finally:
        client_socket.close()

def extract_ttl(response):
    index = 12  # Skip the DNS header
    # Skip the question section
    while response[index] != 0:
        index += response[index] + 1
    index += 5  # Skip null byte and QTYPE/QCLASS

    # Now at the beginning of the answer section
    answer_count = int.from_bytes(response[6:8], 'big')
    if answer_count == 0:
        return None  # No answer section
    # For simplicity, extract TTL from the first answer record
    index += 2  # Name (could be a pointer)
    index += 2  # Type
    index += 2  # Class
    ttl = int.from_bytes(response[index:index+4], 'big')
    return ttl

def create_dns_error_response(query, rcode):
    transaction_id = query[:2]

    # Extract RD flag from query (recursion desired)
    rd = query[2] & 0x01

    # Set the flags:
    # - QR (response): 1
    # - Opcode: copied from query
    # - AA (authoritative answer): 0
    # - TC (truncated): 0
    # - RD (recursion desired): copied from query
    # - RA (recursion available): 1 (since resolver supports recursion)
    # - Z (reserved): 0
    # - RCODE: as per the error
    flags = (0x8000 | (rd << 8) | 0x0080 | rcode).to_bytes(2, byteorder='big')

    qd_count = query[4:6]
    an_count = b'\x00\x00'
    ns_count = b'\x00\x00'
    ar_count = b'\x00\x00'

    header = transaction_id + flags + qd_count + an_count + ns_count + ar_count
    question = query[12:]  # Include the Question Section

    return header + question

def update_transaction_id(response, transaction_id, query_flags_byte):
    # Replace the transaction ID in the response
    updated_response = transaction_id + response[2:]

    # Copy RD flag from query and set RA flag
    rd = query_flags_byte & 0x01
    flags = response[2]
    flags &= 0xFE  # Clear RD bit
    flags |= rd    # Set RD bit as per query
    flags |= 0x80  # Set RA bit (Recursion Available)
    updated_response = updated_response[:2] + bytes([flags]) + updated_response[3:]

    return updated_response

def extract_nameservers(response):
    # Extract NS records from the authority section
    index = 12  # Skip the DNS header
    # Skip the question section
    while response[index] != 0:
        index += response[index] + 1
    index += 5  # Null byte and QTYPE/QCLASS

    answer_count = int.from_bytes(response[6:8], 'big')
    authority_count = int.from_bytes(response[8:10], 'big')
    additional_count = int.from_bytes(response[10:12], 'big')

    # Skip answer records
    for _ in range(answer_count):
        index = skip_record(response, index)

    # Extract NS records from authority section
    nameservers = []
    for _ in range(authority_count):
        start_index = index
        name, index = parse_name(response, index)
        rtype = int.from_bytes(response[index:index+2], 'big')
        index += 2  # Type
        index += 2  # Class
        index += 4  # TTL
        rdlength = int.from_bytes(response[index:index+2], 'big')
        index += 2  # RDLENGTH
        if rtype == 2:  # NS record
            ns_name, _ = parse_name(response, index)
            ns_name = ns_name.lower()  # Convert to lowercase
            nameservers.append(ns_name)
        index += rdlength  # Move to the next record
    return nameservers

def resolve_nameserver(ns_name):
    ns_name = ns_name.lower()  # Ensure the nameserver name is in lowercase
    # Simple resolution function to resolve nameserver's IP
    # This function assumes the nameserver name can be resolved via system DNS
    try:
        # Use system resolver to get the IP address
        ip_addresses = socket.gethostbyname_ex(ns_name)[2]
        if ip_addresses:
            return ip_addresses[0]
        else:
            return None
    except Exception as e:
        print(f"[RECURSIVE RESOLVER] Could not resolve nameserver {ns_name}: {e}")
        return None

def parse_name(data, index):
    labels = []
    while True:
        length = data[index]
        if length == 0:
            index += 1
            break
        elif (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[index + 1]
            sub_labels, _ = parse_name(data, pointer)
            labels.extend(sub_labels)
            index += 2
            break
        else:
            index += 1
            label = data[index:index+length].decode()
            labels.append(label)
            index += length
    domain_name = '.'.join(labels).lower()  # Convert to lowercase
    return domain_name, index

def skip_record(response, index):
    # Helper function to skip over a resource record
    _, index = parse_name(response, index)
    index += 2  # Type
    index += 2  # Class
    index += 4  # TTL
    rdlength = int.from_bytes(response[index:index+2], 'big')
    index += 2  # RDLENGTH
    index += rdlength  # RDATA
    return index

if __name__ == "__main__":
    start_recursive_resolver()