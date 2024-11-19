import socket

from config import ROOT_HOST, ROOT_PORT

def query_dns():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.connect((ROOT_HOST, ROOT_PORT))

        while True:
            # Input domain name to resolve
            domain_name = input("Enter domain name to resolve (or 'exit' to quit): ")
            if domain_name.lower() == 'exit':
                print("[DISCONNECTED] Client closed the connection.")
                client_socket.close()
                break

            # Send query to server
            client_socket.send(domain_name.encode())

            # Receive and display response
            response = client_socket.recv(1024).decode()
            print(f"Response from Root DNS: {response}")

if __name__ == "__main__":
    query_dns()

