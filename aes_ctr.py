import os
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AES_CTR:
    """
    Implements AES encryption and decryption using Counter (CTR) mode.
    CTR mode turns a block cipher into a stream cipher. It generates the next
    keystream block by encrypting successive values of a "counter".
    """
    def __init__(self):
        self.backend = default_backend()

    def hex_to_bytes(self, hex_string):
        """Converts a hexadecimal string to bytes."""
        hex_string = hex_string.replace(" ", "").replace("0x", "")
        return bytes.fromhex(hex_string)

    def base64_to_bytes(self, base64_string):
        """Converts a base64 string to bytes."""
        return base64.b64decode(base64_string)

    def bytes_to_base64(self, byte_data):
        """Converts bytes to a base64 string."""
        return base64.b64encode(byte_data).decode('utf-8')

    def validate_key(self, key_input, key_format):
        """Validates and converts a key to 16 bytes (128-bit)."""
        try:
            if key_format.lower() == 'hex':
                key_bytes = self.hex_to_bytes(key_input)
            elif key_format.lower() == 'base64':
                key_bytes = self.base64_to_bytes(key_input)
            else:
                raise ValueError("Key format must be 'hex' or 'base64'")

            if len(key_bytes) != 16:
                raise ValueError("Key must be exactly 128 bits (16 bytes)")

            return key_bytes
        except Exception as e:
            raise ValueError(f"Invalid key: {str(e)}")

    def encrypt(self, plaintext, key_input, key_format='hex', nonce=None):
        """
        Encrypts plaintext using AES-CTR mode.

        Args:
            plaintext (str): The text to encrypt.
            key_input (str): The 128-bit key as a hex or base64 string.
            key_format (str): The format of the key ('hex' or 'base64').
            nonce (bytes): A 16-byte nonce. A secure random nonce is generated if not provided.
                           The nonce must not be reused with the same key.

        Returns:
            dict: Contains 'ciphertext' (base64), 'nonce' (base64), and performance metrics.
        """
        start_time = time.time()
        key = self.validate_key(key_input, key_format)

        if nonce is None:
            nonce = os.urandom(16)  # A 128-bit nonce is required for CTR mode.
        elif len(nonce) != 16:
            raise ValueError("Nonce must be exactly 16 bytes for CTR mode")

        plaintext_bytes = plaintext.encode('utf-8')

        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        end_time = time.time()
        encryption_time = end_time - start_time

        return {
            'ciphertext': self.bytes_to_base64(ciphertext),
            'nonce': self.bytes_to_base64(nonce),
            'encryption_time': encryption_time,
            'ciphertext_size': len(ciphertext)
        }

    def decrypt(self, ciphertext_base64, key_input, nonce_base64, key_format='hex'):
        """
        Decrypts ciphertext using AES-CTR mode.

        Args:
            ciphertext_base64 (str): The base64 encoded ciphertext.
            key_input (str): The 128-bit key as a hex or base64 string.
            nonce_base64 (str): The base64 encoded nonce used for encryption.
            key_format (str): The format of the key ('hex' or 'base64').

        Returns:
            dict: Contains 'plaintext' (str) and performance metrics.
        """
        start_time = time.time()
        key = self.validate_key(key_input, key_format)

        ciphertext = self.base64_to_bytes(ciphertext_base64)
        nonce = self.base64_to_bytes(nonce_base64)

        if len(nonce) != 16:
            raise ValueError("Nonce must be exactly 16 bytes")

        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=self.backend
        )

        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        end_time = time.time()
        decryption_time = end_time - start_time

        return {
            'plaintext': plaintext_bytes.decode('utf-8'),
            'decryption_time': decryption_time
        }

    def encrypt_file(self, file_path, key_input, key_format='hex'):
        """Encrypts a file using AES-CTR."""
        with open(file_path, 'rb') as f:
            file_data = f.read()

        start_time = time.time()
        key = self.validate_key(key_input, key_format)
        nonce = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        
        end_time = time.time()
        encryption_time = end_time - start_time

        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'encryption_time': encryption_time,
            'original_size': len(file_data),
            'ciphertext_size': len(ciphertext)
        }

    def decrypt_file(self, ciphertext, nonce, key_input, key_format='hex'):
        """Decrypts file data using AES-CTR."""
        start_time = time.time()
        key = self.validate_key(key_input, key_format)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        end_time = time.time()
        decryption_time = end_time - start_time

        return {
            'plaintext': plaintext,
            'decryption_time': decryption_time
        }

def demo_text_encryption():
    """Demonstrates AES-CTR encryption and decryption with a text string."""
    print("=== AES-CTR Text Encryption Demo ===")
    aes_ctr = AES_CTR()
    plaintext = "This is a secret message for the AES-CTR implementation assignment."
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"  # Standard 128-bit test key

    print(f"Original Plaintext: {plaintext}")
    print(f"Key (Hex): {key_hex}")

    try:
        # Encrypt
        encryption_result = aes_ctr.encrypt(plaintext, key_hex, 'hex')
        print(f"\n--- Encryption Results ---")
        print(f"Ciphertext (Base64): {encryption_result['ciphertext']}")
        print(f"Nonce (Base64): {encryption_result['nonce']}")
        print(f"Encryption Time: {encryption_result['encryption_time']:.6f} seconds")

        # Decrypt
        decryption_result = aes_ctr.decrypt(
            encryption_result['ciphertext'],
            key_hex,
            encryption_result['nonce'],
            'hex'
        )
        print(f"\n--- Decryption Results ---")
        print(f"Decrypted Plaintext: {decryption_result['plaintext']}")
        print(f"Decryption Time: {decryption_result['decryption_time']:.6f} seconds")

        # Verify
        if plaintext == decryption_result['plaintext']:
            print("\nSUCCESS: Original plaintext was recovered successfully!")
        else:
            print("\nERROR: Decrypted text does not match the original!")

    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")

def demo_base64_key():
    """Demonstrates AES-CTR with a base64 encoded key."""
    print("\n=== AES-CTR Base64 Key Demo ===")
    aes_ctr = AES_CTR()
    plaintext = "Validating AES-CTR with a Base64 formatted key."
    key_hex = "000102030405060708090a0b0c0d0e0f"
    key_bytes = bytes.fromhex(key_hex)
    key_base64 = base64.b64encode(key_bytes).decode('utf-8')

    print(f"Plaintext: {plaintext}")
    print(f"Key (Base64): {key_base64}")

    try:
        # Encrypt with base64 key
        enc_res = aes_ctr.encrypt(plaintext, key_base64, 'base64')
        print(f"Ciphertext (Base64): {enc_res['ciphertext']}")
        
        # Decrypt
        dec_res = aes_ctr.decrypt(enc_res['ciphertext'], key_base64, enc_res['nonce'], 'base64')
        print(f"Decrypted Plaintext: {dec_res['plaintext']}")

        if plaintext == dec_res['plaintext']:
            print("SUCCESS: Base64 key format was handled correctly!")
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")

def create_test_file(size_mb=1):
    """Creates a test file of a specified size in MB for performance testing."""
    file_name = f'ai_test_file.txt'
    # Write chunks of data to avoid holding the entire file in memory
    chunk_size = 1024
    num_chunks = size_mb * 1024
    with open(file_name, 'wb') as f:
        for _ in range(num_chunks):
            f.write(os.urandom(chunk_size))
    return file_name

def performance_test():
    """Tests AES-CTR performance by encrypting and decrypting a 1MB file."""
    print("\n=== AES-CTR Performance Test (1MB File) ===")
    aes_ctr = AES_CTR()
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    test_file = create_test_file(1)

    try:
        file_size = os.path.getsize(test_file)
        print(f"Test file created: {test_file} ({file_size / (1024*1024):.2f} MB)")

        # Encrypt file
        encrypt_result = aes_ctr.encrypt_file(test_file, key_hex, 'hex')
        
        # Decrypt file
        decrypt_result = aes_ctr.decrypt_file(
            encrypt_result['ciphertext'],
            encrypt_result['nonce'],
            key_hex,
            'hex'
        )

        # Verify integrity
        with open(test_file, 'rb') as f:
            original_data = f.read()

        if original_data == decrypt_result['plaintext']:
            print("\nSUCCESS: File integrity verified. Original file recovered.")
        else:
            print("\nERROR: File verification failed!")

        return {
            'original_size': encrypt_result['original_size'],
            'ciphertext_size': encrypt_result['ciphertext_size'],
            'encryption_time': encrypt_result['encryption_time'],
            'decryption_time': decrypt_result['decryption_time']
        }

    except Exception as e:
        print(f"Error during performance test: {str(e)}")
        return None
    finally:
        # Clean up the test file
        if os.path.exists(test_file):
            os.remove(test_file)
            print(f"Cleaned up test file: {test_file}")


if __name__ == "__main__":
    print("AES (Advanced Encryption Standard) - Counter (CTR) Mode")
    print("=" * 60)
    
    demo_text_encryption()
    demo_base64_key()
    
    perf_results = performance_test()
    
    if perf_results:
        print("\n--- Performance Summary Table ---")
        print(f"{'Metric':<25} | {'Value'}")
        print("-" * 45)
        print(f"{'Original File Size':<25} | {perf_results['original_size']} bytes")
        print(f"{'Ciphertext Size':<25} | {perf_results['ciphertext_size']} bytes")
        print(f"{'Encryption Time':<25} | {perf_results['encryption_time']:.6f} seconds")
        print(f"{'Decryption Time':<25} | {perf_results['decryption_time']:.6f} seconds")
        total_time = perf_results['encryption_time'] + perf_results['decryption_time']
        print(f"{'Total Time':<25} | {total_time:.6f} seconds")