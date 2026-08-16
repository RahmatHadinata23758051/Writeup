#!/usr/bin/env python3

enc_hex = "584e98db7bf03b70414f849e61a13a355549c6dd56e5654c5516b3dc6bec69"
enc = bytes.fromhex(enc_hex)

prefix = b"bushbash"

# Kunci sebenarnya berukuran 8 byte
key = bytes([enc[i] ^ prefix[i] for i in range(8)])

print(f"[+] Key (8 bytes): {key}")

# Dekripsi menggunakan modulo 8
flag = bytes([enc[i] ^ key[i % 8] for i in range(len(enc))])

print(f"[+] FLAG: {flag.decode('utf-8', errors='ignore')}")
