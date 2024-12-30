import socket
import threading
from config import HOST, ROOT_PORT

# TLD server mappings
TLD_SERVERS = {
    "com": (HOST, 1500),
    "org": (HOST, 1600),
    "arpa": (HOST, 1700),
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
        threading.Thread(target=handle_client, args=(data, client_address, udp_socket, 'udp')).start()

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
            response = handle_client(data, client_address, None, 'tcp')
            if response:
                # Send the two-byte length prefix
                response_length = len(response).to_bytes(2, byteorder='big')
                client_socket.sendall(response_length + response)
    except Exception as e:
        print(f"[ROOT TCP ERROR] {e}")
    finally:
        client_socket.close()

def handle_client(data, client_address, server_socket, protocol='udp'):
    try:
        # Extract domain name from the DNS query
        domain_name, qtype = extract_query_info(data)
    except Exception as e:
        print(f"[ROOT ERROR] Format error in query from {client_address}: {e}")
        error_response = create_dns_error_response(data, rcode=1)  # Format Error
        send_response(server_socket, error_response, client_address, protocol)
        return

    print(f"[ROOT][{protocol.upper()}] Received query for '{domain_name}' with type {qtype}")

    # Check if the query type is supported
    supported_qtypes = [1, 2, 5, 12, 15, 28]  # A, NS, CNAME, PTR, MX, AAAA
    if qtype not in supported_qtypes:
        print(f"[ROOT] Query type {qtype} not implemented.")
        error_response = create_dns_error_response(data, rcode=4)  # Not Implemented
        send_response(server_socket, error_response, client_address, protocol)
        return

    tld = domain_name.split('.')[-1].lower()  # Ensure TLD is in lowercase

    if tld in TLD_SERVERS:
        tld_ip, tld_port = TLD_SERVERS[tld]
        # Forward query to the TLD server
        print(f"[ROOT] Redirecting to TLD server {tld_ip}:{tld_port}")
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_socket.settimeout(5)
        try:
            forward_socket.sendto(data, (tld_ip, tld_port))
            response, _ = forward_socket.recvfrom(1024)
            send_response(server_socket, response, client_address, protocol)
        except socket.timeout:
            print(f"[ROOT ERROR] Timeout when contacting TLD server {tld_ip}:{tld_port}")
            error_response = create_dns_error_response(data, rcode=2)  # Server Failure
            send_response(server_socket, error_response, client_address, protocol)
        except Exception as e:
            print(f"[ROOT ERROR] {e}")
            error_response = create_dns_error_response(data, rcode=2)  # Server Failure
            send_response(server_socket, error_response, client_address, protocol)
        finally:
            forward_socket.close()
    else:
        print(f"[ROOT] TLD '{tld}' not found.")
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
                # Name compression pointer
                pointer = ((length & 0x3F) << 8) | data[index + 1]
                labels += extract_labels(data, pointer)
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
        raise Exception(f"Failed to parse domain name: {e}")

def extract_labels(data, index):
    labels = []
    while True:
        length = data[index]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            # Handle nested pointers (discouraged but possible)
            pointer = ((length & 0x3F) << 8) | data[index + 1]
            index = pointer
        else:
            index += 1
            labels.append(data[index:index+length].decode())
            index += length
        index += 1
    return [label.lower() for label in labels]  # Convert labels to lowercase

def create_dns_error_response(query, rcode):
    transaction_id = query[:2]
    # Extract flags from query
    flags_query = query[2:4]
    qr = 1 << 15  # Response flag
    opcode = (flags_query[0] & 0x78) << 8  # Opcode from query
    aa = 1 << 10  # Authoritative Answer
    rd = (flags_query[1] & 0x01) << 8  # Recursion Desired
    ra = 0  # Recursion Available (root server does not provide recursion)
    z = 0  # Reserved
    # Build flags
    flags = qr | opcode | aa | rd | ra | rcode
    flags_bytes = flags.to_bytes(2, byteorder='big')
    qd_count = query[4:6]
    an_count = b'\x00\x00'
    ns_count = b'\x00\x00'
    ar_count = b'\x00\x00'
    header = transaction_id + flags_bytes + qd_count + an_count + ns_count + ar_count
    question = query[12:]  # Include the Question Section
    return header + question

if __name__ == "__main__":
    start_root_server()