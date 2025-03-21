import socket
import ssl
import toolbox

def start_https_server():
    # Create an SSL context for the server.
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Load the server’s certificate and private key.
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # Create a TCP/IP socket.
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind(('0.0.0.0', 4433))
    bindsocket.listen(5)
    print("Bob's HTTPS server listening on port 4433...")

    while True:
        newsocket, fromaddr = bindsocket.accept()
        print("Accepted connection from", fromaddr)
        try:
            # Wrap the socket with SSL.
            conn = context.wrap_socket(newsocket, server_side=True)
            data = conn.recv(1024)
            message = data.decode()
            print("Received from Alice:", message)
            # Tokenize the received message using the shared toolbox.
            tokens = toolbox.tokenize_message(message)
            print("Bob tokenized message:", tokens)
            # Send a response.
            conn.sendall(b"Hello from Bob!")
        except Exception as e:
            print("Error during connection:", e)
        finally:
            conn.close()

if __name__ == '__main__':
    start_https_server()
