#!/usr/bin/env python3

ROUNDS = 4
# 32-bit left shift rotation
rot = lambda x, n: ((x << n) & 0xffffffff) | (x >> (32 - n))

# Fungsi Key Generation (Tetap sama)
def aaa(k):
    ks = []
    for i in range(ROUNDS):
        k = rot(k, 3)
        ks.append((k ^ (0x9E3779B9 * (i + 1))) & 0xffffffff) # Golden Ratio
    return ks

# Fungsi F / Feistel Round (Tetap sama)
def bbb(r, k):
    return (rot(r ^ k, 5) * 0x45D9F3B) & 0xffffffff

# Fungsi Dekripsi Blok Feistel
def ccc_decrypt(block, keys):
    l = int.from_bytes(block[:4], "big")
    r = int.from_bytes(block[4:], "big")
    
    # RAHASIA FEISTEL: Putar kunci secara terbalik (reversed)
    for k in reversed(keys):
        l, r = r, l ^ bbb(r, k) 
        
    return r.to_bytes(4, "big") + l.to_bytes(4, "big")

def decrypt(data, key):
    ks = aaa(key)
    return b''.join(ccc_decrypt(data[i:i+8], ks) for i in range(0, len(data), 8))

def main():
    ciphertext = b"9\xbd/\x9588\x0bwo\xce+\xd4*\xd8\xda\x8d\x1f*\xac\x07f\xf1a\x9b\xd7$O\xbdU\\\xe2\xc5"
    
    # Kita tahu base key-nya adalah 0xD4D4A1xx
    base_key = 0xD4D4A100
    
    print("[*] Memulai Brute-Force pada 1 Byte terakhir kunci...")
    
    # Bruteforce 256 kemungkinan terakhir (0x00 sampai 0xFF)
    for i in range(256):
        test_key = base_key + i
        try:
            pt = decrypt(ciphertext, test_key)
            
            # Cek apakah hasil dekripsi mengandung string flag
            if b"jctf{" in pt or b"jerseyctf{" in pt:
                print(f"\n[!] BINGO! Kunci Asli Ditemukan: {hex(test_key)}")
                print("=" * 50)
                print(f"[+] Flag: {pt.decode('utf-8', errors='ignore')}")
                print("=" * 50)
                break
        except Exception:
            pass

if __name__ == "__main__":
    main()
