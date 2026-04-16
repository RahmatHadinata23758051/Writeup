def solve():
    # Hex dari secret.txt
    c_hex = "10001d171446010a1c071b0c1d261205061d1c0d"
    c_bytes = bytes.fromhex(c_hex)
    
    # Kunci rahasia dari pesan Acrostic
    key = b"entropy"
    
    print("[*] Mendekripsi secret.txt dengan kunci 'entropy'...")
    
    # Operasi XOR berulang
    flag = bytes([c_bytes[i] ^ key[i % len(key)] for i in range(len(c_bytes))])
    
    print("\n[✔] Brankas Rohan Berhasil Dibongkar:")
    print(f"--> FLAG: {flag.decode(errors='ignore')}")

if __name__ == "__main__":
    solve()
