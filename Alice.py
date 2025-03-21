import socket
import ssl
import os
import toolbox

def connect_https_server():
    # Create an SSL context for the client.
    context = ssl.create_default_context()
    # For this demo, we are not verifying the server's certificate.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Message to send.
    message = "Hello from Alice!"
    # Tokenize the message using the shared toolbox.
    tokens = toolbox.tokenize_message(message)
    print("Alice tokenized message:", tokens)

    # Shared key for DPIEnc encryption.
    # In a full implementation, k would be derived from the TLS handshake.
    key = os.urandom(16)  # 128-bit key for demonstration.

    # Encrypt each token using DPIEnc.
    encrypted_tokens = []
    for token in tokens:
        # Generate a new 16-byte salt for this token.
        salt = os.urandom(16)
        s, ct = toolbox.dpienc_encrypt_token(token, key, salt)
        encrypted_tokens.append((s, ct))
    
    # Display encrypted tokens.
    print("Alice encrypted tokens:")
    for s, ct in encrypted_tokens:
        print("Salt:", s.hex(), "Ciphertext:", ct.hex())

    # Connect to Bob's server over HTTPS.
    with socket.create_connection(('localhost', 4433)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:
            print("Alice connected to Bob via HTTPS!")
            # For now, we send the plaintext message over the HTTPS channel.
            # In a full BlindBox implementation, the encrypted tokens would be sent over a separate channel.
            ssock.sendall(message.encode())
            data = ssock.recv(1024)
            print("Received from Bob:", data.decode())

def send_encrypted_tokens():
    shared_key = b'16byteSecretKey!'
    fixed_salt = b'\x00' * 16  # use same fixed salt for testing detection
    
    message = "Hello from Alice! secret!"  # Include "secret!" so we can trigger a match.
    tokens = toolbox.tokenize_message(message)
    
    # Encrypt tokens using DPIEnc with the fixed salt.
    encrypted_tokens = []
    for token in tokens:
        # For detection simulation, use the fixed salt.
        _, ct = toolbox.dpienc_encrypt_token(token, shared_key, fixed_salt)
        encrypted_tokens.append(ct)
    
    # Connect to MB's detection service and send each ciphertext.
    with socket.create_connection(('localhost', 5555)) as sock:
        for ct in encrypted_tokens:
            sock.sendall(ct)  # each ct is 16 bytes
    print("Alice: Encrypted tokens sent to middlebox.")


if __name__ == '__main__':
    connect_https_server()
    send_encrypted_tokens()
