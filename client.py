import socket
import argparse
from config import HOST, ROOT_PORT

# DNS Query Types
QUERY_TYPES = {
    "A": 1,
    "CNAME": 5,
    "NS": 2,
    "MX": 15
}

# Server details
ROOT_SERVER = (HOST, ROOT_PORT)  # Root server's IP and port

# Function to create a DNS query format
def create_dns_query(domain, query_type):
    query_id = 1234  # Fixed ID for simplicity, can be randomized
    flags = 0x0100  # Standard query
    qdcount = 1  # Number of questions
    ancount = 0  # Number of answers
    nscount = 0  # Number of authority records
    arcount = 0  # Number of additional records

    # Header section
    header = query_id.to_bytes(2, byteorder='big') + \
             flags.to_bytes(2, byteorder='big') + \
             qdcount.to_bytes(2, byteorder='big') + \
             ancount.to_bytes(2, byteorder='big') + \
             nscount.to_bytes(2, byteorder='big') + \
             arcount.to_bytes(2, byteorder='big')

    # Question section
    qname = b''.join(len(part).to_bytes(1, byteorder='big') + part.encode() for part in domain.split('.')) + b'\x00'
    qtype = QUERY_TYPES[query_type].to_bytes(2, byteorder='big')
    qclass = (1).to_bytes(2, byteorder='big')  # Internet class

    question = qname + qtype + qclass
    return header + question

# Function to parse a DNS response
def parse_dns_response(response):
    query_id = int.from_bytes(response[:2], byteorder='big')
    flags = int.from_bytes(response[2:4], byteorder='big')
    qdcount = int.from_bytes(response[4:6], byteorder='big')
    ancount = int.from_bytes(response[6:8], byteorder='big')
    nscount = int.from_bytes(response[8:10], byteorder='big')
    arcount = int.from_bytes(response[10:12], byteorder='big')

    print(f"Response ID: {query_id}")
    print(f"Flags: {flags}")
    print(f"Questions: {qdcount}, Answers: {ancount}, Authority: {nscount}, Additional: {arcount}")

    # Extract the answers if present
    if ancount > 0:
        answers = response[12:]
        return answers
    return None

# Function to query a server
def query_server(query, server_ip, server_port, server_type):
    try:
        # Create socket for UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(query, (server_ip, server_port))
            response, _ = s.recvfrom(1024)
            print(f"{server_type} Server Response:")
            answers = parse_dns_response(response)
            return response, answers
    except Exception as e:
        print(f"[ERROR] {e}")
        return None, None

# Main client function
def resolve_domain(domain, query_type):
    print(f"Resolving domain: {domain} with query type: {query_type}")
    
    # Create DNS query
    dns_query = create_dns_query(domain, query_type)
    
    # Step 1: Query Root Server
    root_response, root_answers = query_server(dns_query, HOST, ROOT_PORT, "Root")
    if root_answers:
        # Extract TLD server info
        tld_server_ip = socket.inet_ntoa(root_answers[:4])  # Decode IP
        tld_server_port = int.from_bytes(root_answers[4:6], 'big')  # Decode port
        print(f"[INFO] Redirected to TLD server at {tld_server_ip}:{tld_server_port}")
        
        # Step 2: Query TLD Server
        tld_response, tld_answers = query_server(dns_query, tld_server_ip, tld_server_port, "TLD")
        if tld_answers:
            # Extract authoritative server info from TLD server's response
            auth_server_ip = tld_answers[:4]
            auth_server_ip = ".".join(map(str, auth_server_ip))
            auth_server_port = int.from_bytes(tld_answers[4:6], 'big')
            
            # Step 3: Query Authoritative Server (only once)
            auth_response, answer = query_server(dns_query, auth_server_ip, auth_server_port, "Authoritative")
            if auth_response:
                print("[INFO] Successfully resolved domain.")
                ip_address = socket.inet_ntoa(answer)
                print(f"Resolved IP address: {ip_address}")
                
                
            else:
                print("[ERROR] No valid response from Authoritative server.")
        else:
            print("[ERROR] No valid response from TLD server.")
    else:
        print("[ERROR] No valid response from Root server.")

# Entry point for the command-line tool
def main():
    parser = argparse.ArgumentParser(description="DNS Resolver Client")
    parser.add_argument("query_type", choices=QUERY_TYPES.keys(), help="Type of query (A, CNAME, NS, MX)")
    parser.add_argument("domain", help="Domain to resolve")

    args = parser.parse_args()

    resolve_domain(args.domain, args.query_type)

if __name__ == "__main__":
    main()
