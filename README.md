# AES Encryption and Analysis using Counter (CTR) Mode

This project provides a Python implementation of the Advanced Encryption Standard (AES) using the Counter (CTR) mode of operation. It includes functionalities for encrypting and decrypting both text strings and files, along with a performance and security analysis of the CTR mode.

## Overview of AES-CTR

The **Advanced Encryption Standard (AES)** is a symmetric block cipher that operates on 128-bit blocks of data. This implementation uses the **Counter (CTR) mode**, which effectively transforms the block cipher into a stream cipher.

The core idea of CTR mode is to generate a unique keystream for each block of data by encrypting a combined **Nonce** (a number used only once) and an incrementing **Counter**. This keystream is then XORed with the plaintext to produce the ciphertext. This process allows for parallel encryption/decryption and eliminates the need for padding.



### How It Works

1.  A unique **Nonce** is combined with a **Counter** (which starts at 0).
2.  This combined (Nonce + Counter) value is encrypted with the AES key to produce a keystream block.
3.  The keystream block is XORed with the plaintext block to create the ciphertext block.
4.  The counter increments for the next block, and the process repeats.

**Encryption:** `Ci = Pi ⊕ AES_key(Nonce || Counter_i)`
**Decryption:** `Pi = Ci ⊕ AES_key(Nonce || Counter_i)`

---

## Features

-   **AES-128 Encryption**: Implements the AES algorithm with a 128-bit key.
-   **CTR Mode**: Securely converts the block cipher into a stream cipher.
-   **Text and File Support**: Capable of encrypting/decrypting both raw text and files of any size.
-   **Secure Nonce Generation**: Uses `os.urandom` to generate a cryptographically secure nonce for each encryption.
-   **Multiple Key Formats**: Accepts keys in both hexadecimal and Base64 formats.
-   **High Performance**: Leverages the parallelizable nature of CTR mode for fast operations.

---

## Security Analysis of CTR Mode

#### Block Dependencies

CTR mode has **no block dependencies**. The encryption of one block is independent of all others. This allows for:
-   **Full Parallelization**: Multiple blocks can be encrypted or decrypted simultaneously, drastically improving performance.
-   **Random Access**: Any block in a file can be decrypted on its own without processing the preceding data.

#### Nonce Usage

The security of CTR mode critically depends on the rule that a **(Key, Nonce) pair must never be reused**. Reusing a pair generates the same keystream, allowing an attacker to perform a simple XOR operation on two ciphertexts to reveal the XOR of the two plaintexts (`C1 ⊕ C2 = P1 ⊕ P2`). This is a catastrophic failure known as the "two-time pad".

#### Error Propagation

CTR mode has excellent error handling. A bit error in a ciphertext block **only corrupts the corresponding bit** in the plaintext. The error does not propagate to other blocks, making it ideal for data transmission over unreliable networks.

---

## Performance Measurement

Performance was measured by encrypting and decrypting a 1MB (1,048,576 bytes) text file.

| Metric              | Value                 |
| ------------------- | --------------------- |
| Original File Size  | 1048576 bytes         |
| Ciphertext Size     | 1048576 bytes         |
| Encryption Time     | 0.001998 seconds      |
| Decryption Time     | 0.0001886 seconds     |
| Total Time          | 0.003864 seconds      |

**Observations:** The ciphertext size is identical to the plaintext because no padding is required. Encryption and decryption speeds are nearly identical, as they perform the same underlying AES operation.

---

## Requirements

The project requires the Python `cryptography` library. You can install it using pip:

```sh
pip install cryptography
