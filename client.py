import socket
from config import HOST, ROOT_PORT

def query_dns():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.connect((HOST, ROOT_PORT))

        while True:
            # Input domain name to resolve
            domain_name = input("Enter domain name to resolve (or 'exit' to quit): ")
            if domain_name.lower() == 'exit':
                print("[DISCONNECTED] Client closed the connection.")
                break

            # Send query to root server
            client_socket.sendto(domain_name.encode(), (HOST, ROOT_PORT))

            # Receive and handle response from Root DNS
            response = client_socket.recv(1024).decode()  

            if "Redirect to TLD server" in response:
                try:
                    # Extract the TLD server info part from the response
                    tld_server_info = response.split("Redirect to TLD server:")[1].strip()

                    # Extract the IP and port
                    tld_ip, tld_port = tld_server_info.split(":")
                    tld_port = int(tld_port)

                    # Send the same domain query to the TLD server
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tld_socket:
                        tld_socket.sendto(domain_name.encode(), (tld_ip, tld_port))

                        tld_response = tld_socket.recv(1024).decode()

                        if "Redirect to authoritative server" in tld_response:
                            # Extract authoritative server address and port from response
                            authoritative_server_info = tld_response.split("Redirect to authoritative server:")[1].strip()

                            # Extract the IP and port from the authoritative server info
                            authoritative_ip, authoritative_port = authoritative_server_info.split(":")
                            authoritative_port = int(authoritative_port) 

                            # Send the domain query to the authoritative server
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as authoritative_socket:
                                authoritative_socket.sendto(domain_name.encode(), (authoritative_ip, authoritative_port))

                                authoritative_response = authoritative_socket.recv(1024).decode()
                                print(f"Response: {authoritative_response}")
                        else:
                            print("No authoritative server redirect found in TLD response.")
                except ValueError:
                    print("[ERROR] Invalid response format. Expected 'IP:PORT' format.")
            else:
                print("TLD not found in Root DNS response. Please check the configuration.")

if __name__ == "__main__":
    query_dns()
