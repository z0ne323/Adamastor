"""List of imported modules"""
import socket

def start_server(host, port):
    """
    Description:
        Create a server that listen for incoming connection, 
        When a client connect, send them the vigenere key we used for the last chall
    Parameters:
        HOST (CONST str): IP address our server is going to listen on (localhost)
        PORT (CONST int): PORT our server is going to listen on (888)
    Returns:
        N/A
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        client_socket.sendall(b'TheSuperSecretKeyOfRodeo')
        client_socket.close()

if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 888

    start_server(HOST, PORT)
