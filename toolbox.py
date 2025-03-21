from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def dpienc_encrypt_token(token: str, k: bytes, salt: bytes) -> (bytes, bytes):
    """
    Encrypts a token using the DPIEnc encryption scheme.
    
    DPIEnc encryption is defined (in simplified form) as:
       ciphertext = AES_{AES_k(token)}(salt)
    
    This function:
      1. Computes an intermediate value by encrypting the token (after padding) using key k.
      2. Uses the first 16 bytes of that intermediate as a new key to encrypt the salt.
    
    Parameters:
       token: The plaintext token to be encrypted.
       k: The shared secret key (bytes) used to compute AES_k(token).
       salt: A unique salt (bytes) used as input for the second encryption. Must be 16 bytes.
       
    Returns:
       A tuple (salt, ciphertext), where the salt is returned along with the ciphertext.
       
    Note: In a full DPIEnc implementation, the ciphertext would be reduced modulo RS
          to yield a smaller output (e.g., 5 bytes). For prototyping, we return the full block.
    """
    # Compute AES_k(token) using ECB mode.
    cipher1 = AES.new(k, AES.MODE_ECB)
    # Pad the token to AES block size (16 bytes).
    token_padded = pad(token.encode(), AES.block_size)
    intermediate = cipher1.encrypt(token_padded)  # This is AES_k(token)
    
    # Use the first 16 bytes of the intermediate as the key for the second encryption.
    obfuscated_key = intermediate[:16]
    
    # Encrypt the salt with the obfuscated key.
    cipher2 = AES.new(obfuscated_key, AES.MODE_ECB)
    ciphertext = cipher2.encrypt(salt)
    
    return salt, ciphertext

def tokenize_message(message: str, token_size: int = 8) -> list:
    """
    Tokenize the input message using a sliding window approach.
    Each token is a substring of fixed length `token_size`.
    
    Parameters:
        message (str): The input string to tokenize.
        token_size (int): The size of each token (default is 8).
        
    Returns:
        list: A list of token strings.
    """
    tokens = []
    # Create a token for every possible substring of length token_size.
    for i in range(0, len(message) - token_size + 1):
        tokens.append(message[i:i+token_size])
    return tokens

# For quick testing of the module
if __name__ == "__main__":
    sample_message = "This is a sample message for tokenization."
    tokens = tokenize_message(sample_message)
    print("Tokens:", tokens)
