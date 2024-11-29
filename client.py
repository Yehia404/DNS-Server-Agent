import socket

# Server details
ROOT_SERVER = ("127.0.0.1", 1400)  # Root server's IP and port
TLD_SERVER = ("127.0.0.1", 1500)  # Example TLD server's IP and port
AUTH_SERVER = ("127.0.0.1", 1600)  # Example Authoritative server's IP and port

# Function to send a query to the root server
def query_root_server(domain):
    try:
        # Create socket for UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(domain.encode(), ROOT_SERVER)
            response, _ = s.recvfrom(1024)
            print(f"Root Server Response: {response.decode()}")
            return response.decode()
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

# Function to send a query to the TLD server
def query_tld_server(domain, tld_server_ip, tld_server_port):
    try:
        # Create socket for UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(domain.encode(), (tld_server_ip, tld_server_port))
            response, _ = s.recvfrom(1024)
            print(f"TLD Server Response: {response.decode()}")
            return response.decode()
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

# Function to send a query to the authoritative server
def query_auth_server(domain, auth_server_ip, auth_server_port):
    try:
        # Create socket for UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(domain.encode(), (auth_server_ip, auth_server_port))
            response, _ = s.recvfrom(1024)
            print(f"Authoritative Server Response: {response.decode()}")
            return response.decode()
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

# Main client function
def resolve_domain(domain):
    print(f"Resolving domain: {domain}")
    
    # Step 1: Query Root Server
    root_response = query_root_server(domain)
    if root_response and "Redirect" in root_response:
        # Extract TLD server info from root server's response
        tld_server_ip = root_response.split(":")[1].strip()
        tld_server_port = root_response.split(":")[2]
        tld_server_port = int(tld_server_port)
        
        # Step 2: Query TLD Server
        tld_response = query_tld_server(domain, tld_server_ip, tld_server_port)
        if tld_response and "Redirecting" in tld_response:
            # Extract authoritative server info from TLD server's response
            auth_server_ip= tld_response.split(":")[1].strip()
            auth_server_port = tld_response.split(":")[2]
            auth_server_port = int(auth_server_port)
            
            # Step 3: Query Authoritative Server
            query_auth_server(domain, auth_server_ip, auth_server_port)
        else:
            print("[ERROR] No valid redirection from TLD server.")
    else:
        print("[ERROR] No valid redirection from Root server.")

# Main loop to take user input
def main():
    print("DNS Resolver Client")
    print("Type 'quit' to exit.")
    
    while True:
        domain_to_resolve = input("Enter domain to resolve: ").strip()
        if domain_to_resolve.lower() == 'quit':
            print("Exiting DNS Resolver Client.")
            break
        elif domain_to_resolve:
            resolve_domain(domain_to_resolve)
        else:
            print("Please enter a valid domain or 'quit' to exit.")

# Run the client
if __name__ == "__main__":
    main()
