import socket
from toolbox import dpienc_encrypt_token

def start_middlebox_detection():
    # For simulation, use a fixed shared key and fixed salt.
    shared_key = b'16byteSecretKey!'  # 16-byte key (must be exactly 16 bytes)
    fixed_salt = b'\x00' * 16         # 16 zero bytes as salt
    
    # Define a suspicious rule (as provided by the rule generator).
    rule_keyword = "secret!"  # For example, the suspicious token is "secret!"
    
    # Compute the encrypted rule token using DPIEnc.
    # We ignore the salt output because, in detection, MB doesn't receive salts.
    _, rule_ciphertext = dpienc_encrypt_token(rule_keyword, shared_key, fixed_salt)
    
    print("Middlebox: Encrypted rule for '{}': {}".format(rule_keyword, rule_ciphertext.hex()))
    
    # Simulate a search tree as a dictionary.
    # Key: encrypted rule (in hex), Value: counter (number of times matched).
    rule_tree = { rule_ciphertext.hex(): 0 }
    
    # Set up a TCP server for detection on port 5555.
    host = '0.0.0.0'
    port = 5555
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Middlebox detection server listening on port {}...".format(port))
    
    while True:
        conn, addr = server_socket.accept()
        print("Middlebox: Accepted connection from", addr)
        try:
            # Assume each encrypted token is 16 bytes (one AES block)
            while True:
                token_data = conn.recv(16)
                if not token_data:
                    break
                token_hex = token_data.hex()
                print("Middlebox: Received token:", token_hex)
                # Look up the token in the rule tree.
                if token_hex in rule_tree:
                    rule_tree[token_hex] += 1
                    print("Middlebox: Match found for rule '{}'. Count: {}"
                          .format(rule_keyword, rule_tree[token_hex]))
                else:
                    print("Middlebox: No match for token:", token_hex)
        except Exception as e:
            print("Middlebox: Error during connection:", e)
        finally:
            conn.close()

if __name__ == '__main__':
    start_middlebox_detection()
