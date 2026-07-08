LYKNCTF 2026 Writeup: Postbox

Challenge Name: Postbox
Category: Crypto
Tags: AES-128-CBC, Padding Oracle Attack, PKCS#7
Flag: LYKNCTF{5c6545ebb3914a988de14d416fbc8c0c}

Overview

In this challenge, we are presented with a small login service via a web application.
Interacting with the endpoints reveals the following:

GET /login: Returns an encrypted session token formatted as JSON, containing an iv and a ciphertext.

POST /decrypt: Allows us to submit a JSON payload with iv and ciphertext to be decrypted by the server.

The /login endpoint gives a helpful note:
"AES-128-CBC token. POST manipulated (iv, ciphertext) to /decrypt to learn if the padding is valid."

Vulnerability Analysis

The challenge explicitly invites us to perform a Padding Oracle Attack.

The system uses AES-128 in Cipher Block Chaining (CBC) mode. In CBC mode, the decryption of a block $C_i$ involves decrypting it with the block cipher (AES) and then XORing the result with the previous ciphertext block $C_{i-1}$ (or the IV for the first block) to get the plaintext $P_i$.

Because AES is a block cipher (16 bytes per block), messages must be padded to a multiple of 16 bytes. The standard padding is PKCS#7, where the value of each added byte is the number of bytes added (e.g., 0x01 or 0x02 0x02).

The vulnerability lies in the /decrypt endpoint. When we submit a modified ciphertext, the server decrypts it. If the resulting plaintext does not end with a valid PKCS#7 padding, the server returns a specific error ({"error": "bad padding"}). If the padding is valid, it processes it differently or doesn't throw that specific error. This binary response acts as an "Oracle", allowing us to deduce the intermediate state of the decryption, byte by byte, without ever knowing the secret key.

Exploitation Challenges

While a standard Padding Oracle attack works in theory, applying it to a real remote server introduced a few hurdles:

Rate Limiting & Connection Drops: Sending thousands of requests rapidly caused the server to drop connections. We bypassed this by implementing a try-except block to catch requests.exceptions.RequestException and added a slight delay (time.sleep(0.5)) to seamlessly retry failed requests.

False Positives: When guessing a padding of 0x01, we might accidentally form a valid padding of 0x02 0x02 if the preceding byte coincidentally matches. We implemented a secondary check to alter the preceding byte (manipulated_prev[byte_idx - 1] ^= 0x01); if the padding remains valid, it's a true 0x01.

Message Integrity: Modifying the IV only corrupts the first block. To correctly attack the padding (which is at the end of the ciphertext), we must modify the block immediately preceding the block we are currently decrypting, and submit the entire sequence up to that point.

Solution (Exploit Script)

Below is the robust, pure-Python script used to extract the flag block by block.

import requests
import sys
import time

URL = "[http://4a67951d-ff21-4e13-9415-917ec4bdb06d.51.79.140.18.nip.io:8080](http://4a67951d-ff21-4e13-9415-917ec4bdb06d.51.79.140.18.nip.io:8080)"
s = requests.Session() # Use session for connection pooling/speed

def get_challenge_data():
    r = s.get(f"{URL}/login")
    data = r.json()
    return bytes.fromhex(data['iv']), bytes.fromhex(data['ciphertext'])

def is_padding_valid(iv, ct):
    while True:
        try:
            r = s.post(f"{URL}/decrypt", json={"iv": iv.hex(), "ciphertext": ct.hex()}, timeout=5)
            # If the server doesn't complain about padding, our guess is correct
            return "bad padding" not in r.text
        except requests.exceptions.RequestException:
            # Handle rate limiting/dropped connections
            time.sleep(0.5)

def padding_oracle_decrypt(iv, ciphertext):
    blocks = [iv] + [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""

    for block_idx in range(1, len(blocks)):
        prev_block = blocks[block_idx - 1]
        curr_block = blocks[block_idx]
        
        intermediate = bytearray(16)
        block_decrypted = bytearray(16)
        
        for pad_val in range(1, 17):
            byte_idx = 16 - pad_val
            
            found = False
            for guess in range(256):
                manipulated_prev = bytearray(prev_block)
                
                # Setup known padding bytes
                for i in range(byte_idx + 1, 16):
                    manipulated_prev[i] = intermediate[i] ^ pad_val
                    
                # Inject our guess
                manipulated_prev[byte_idx] = guess ^ pad_val
                
                # Construct the payload up to the current block
                test_iv = blocks[0] if block_idx > 1 else manipulated_prev
                test_ct = b""
                if block_idx > 1:
                    for i in range(1, block_idx - 1):
                        test_ct += blocks[i]
                    test_ct += manipulated_prev
                    test_ct += curr_block
                else:
                    test_ct = curr_block

                if is_padding_valid(test_iv, test_ct):
                    # Mitigate False Positives for pad_val == 1
                    if pad_val == 1:
                        manipulated_prev[byte_idx - 1] ^= 0x01
                        
                        test_iv_fp = blocks[0] if block_idx > 1 else manipulated_prev
                        test_ct_fp = b""
                        if block_idx > 1:
                            for i in range(1, block_idx - 1):
                                test_ct_fp += blocks[i]
                            test_ct_fp += manipulated_prev
                            test_ct_fp += curr_block
                        else:
                            test_ct_fp = curr_block

                        if not is_padding_valid(test_iv_fp, test_ct_fp):
                            continue 
                            
                    # Successfully found the intermediate byte
                    intermediate[byte_idx] = guess 
                    block_decrypted[byte_idx] = prev_block[byte_idx] ^ intermediate[byte_idx]
                    found = True
                    break
                    
        plaintext += block_decrypted
        print(f"[*] Recovered so far: {plaintext}")

    return plaintext

if __name__ == "__main__":
    iv, ciphertext = get_challenge_data()
    result = padding_oracle_decrypt(iv, ciphertext)
    print(f"\n[+] Full Decrypted Data: {result}")


Results

Executing the script successfully decoded the ciphertext block by block:

[*] Mendekripsi Blok 1...
[*] Plaintext Sementara: b'session: user=gu'
...
[*] Mendekripsi Blok 2...
[*] Plaintext Sementara: b'session: user=guest; role=viewer'
...
[*] Mendekripsi Blok 3...
[*] Plaintext Sementara: b'session: user=guest; role=viewer; flag=LYKNCTF{5'
...
[*] Mendekripsi Blok 4...
[*] Plaintext Sementara: b'session: user=guest; role=viewer; flag=LYKNCTF{5c6545ebb3914a988'
...
[*] Mendekripsi Blok 5...
[*] Plaintext Sementara: b'session: user=guest; role=viewer; flag=LYKNCTF{5c6545ebb3914a988de14d416fbc8c0c}'


The flag is safely extracted from the session data!
