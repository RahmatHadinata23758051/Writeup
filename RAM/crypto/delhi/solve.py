#!/usr/bin/env python3
from pwn import *

# Biar output terminalnya rapi, gak spam log pwntools
context.log_level = 'info'

HOST = '10.42.5.10'
PORT = 1337

IV_HEX = "a52c6283ebe553b0a1962db103364147"
TOKEN_HEX = "b99900dabcf8a858230682b42866bcd54682f74bee28b0f58f5c943385bf55bdb6139dc85cb922bfb640bf21d6ef18b331c79b525e448a4dcd2500770cac740cb7bde0118b163ec4850832e315ed964add24c589dd12d368e007a253d28c7918b51d4f7352389cbd14c12ce77322cb63440116d40f0faca0f07a0942a06d90167ff020e5ea1d67d6d4e6d63284a71021a67f7b7be8ac1c5e5e93a1b4bdff3a7cb7bf61777a0e153af17132ff3d4d833fb90d109514e0ee5533f83c2604060e92818ba56a2691ce139c6d9ee554bdd04cc47f9f8d6ea19eda3bf606d7dea182cab2df99668f5d669a70c39b8f14a33d32b7ce0c8628e59f7ee245d1c27306e092ac4208787772d3e39c8c54506912ee8017f54cb35d9488f60a89c8b510b3ce5038c4e5ee0233dcbdd5bfe5874b84f27308832f78da5c6c40df5a09f1db5746c2d8cda59bed2969804b14822e0d9cb52730d2e683c834ab42ba7215d985cb68ec20079eabcc15f36d5b1a24f5d19b88817c0fcbc55675d9dad7be3fd3b802d3b5010937f42a4cbc0a23fa94a7f83e7b7a"

ERROR_MSG = b"malformed token"
BLOCK_SIZE = 16

iv = bytes.fromhex(IV_HEX)
ciphertext = bytes.fromhex(TOKEN_HEX)

r = remote(HOST, PORT)
# Ngelewatin banner awal sampai muncul prompt '$ '
r.recvuntil(b'$ ')

def oracle(iv_test, ct_test):
    cmd = f"DECRYPT {iv_test.hex()} {ct_test.hex()}".encode()
    r.sendline(cmd)
    
    # Baca semua response sampai ketemu prompt '$ ' lagi
    response = r.recvuntil(b'$ ')
    
    if ERROR_MSG in response:
        return False
    return True

def crack_block(prev_block, curr_block, block_num):
    intermediate = bytearray(BLOCK_SIZE)
    decrypted_block = bytearray(BLOCK_SIZE)
    
    p = log.progress(f'Cracking Block {block_num}')

    for i in range(1, BLOCK_SIZE + 1):
        padding_val = i
        iv_test = bytearray(BLOCK_SIZE)
        
        # Set byte yang udah ketemu
        for j in range(1, i):
            iv_test[-j] = intermediate[-j] ^ padding_val
            
        # Brute force byte saat ini
        for guess in range(256):
            iv_test[-i] = guess
            
            if oracle(iv_test, curr_block):
                # Edge case: byte pertama
                if i == 1:
                    iv_test[-2] ^= 0x01
                    if not oracle(iv_test, curr_block):
                        continue
                
                intermediate[-i] = guess ^ padding_val
                decrypted_block[-i] = prev_block[-i] ^ intermediate[-i]
                
                p.status(f'Byte {16-i}: {chr(decrypted_block[-i]) if 32 <= decrypted_block[-i] <= 126 else hex(decrypted_block[-i])}')
                break
                
    p.success(f'Decrypted: {bytes(decrypted_block)}')
    return bytes(decrypted_block)

def main():
    blocks = [iv] + [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext = b""
    
    log.info(f"Total blocks to crack: {len(blocks) - 1}")
    
    for i in range(1, len(blocks)):
        decrypted_block = crack_block(blocks[i-1], blocks[i], i)
        plaintext += decrypted_block
        
    # Buang padding PKCS#7
    pad_len = plaintext[-1]
    unpadded = plaintext[:-pad_len]
    
    print("\n" + "="*50)
    print("[+] FULL DECRYPTED DATA:")
    print(unpadded.decode(errors='ignore'))
    print("="*50 + "\n")

if __name__ == '__main__':
    main()
