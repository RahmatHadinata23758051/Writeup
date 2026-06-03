#!/usr/bin/env python3
import hashlib
import itertools
import re

# 1. Parameter S-Box dari output.txt
sbox = [210, 76, 176, 35, 87, 148, 91, 184, 175, 70, 158, 187, 61, 33, 103, 68, 225, 94, 216, 151, 136, 80, 52, 82, 49, 62, 44, 240, 243, 168, 118, 181, 21, 217, 211, 153, 177, 25, 190, 245, 51, 137, 113, 122, 141, 74, 27, 199, 18, 55, 37, 60, 197, 128, 248, 123, 31, 124, 131, 180, 155, 20, 3, 242, 81, 163, 247, 12, 221, 121, 93, 191, 110, 34, 147, 195, 192, 145, 159, 4, 86, 220, 98, 100, 154, 6, 235, 206, 79, 135, 222, 169, 189, 218, 170, 146, 54, 47, 227, 10, 64, 249, 13, 39, 236, 106, 102, 24, 156, 230, 28, 32, 207, 244, 186, 99, 40, 160, 174, 254, 204, 8, 228, 41, 182, 50, 120, 30, 167, 15, 140, 178, 212, 253, 63, 107, 150, 193, 171, 36, 78, 119, 9, 14, 23, 111, 251, 139, 117, 19, 138, 56, 172, 83, 85, 114, 116, 105, 48, 233, 166, 58, 46, 133, 194, 65, 11, 89, 185, 183, 16, 38, 229, 203, 255, 26, 132, 165, 57, 162, 84, 7, 129, 2, 1, 42, 246, 196, 152, 143, 250, 142, 101, 59, 201, 90, 241, 95, 130, 66, 29, 214, 69, 77, 198, 67, 43, 17, 5, 252, 215, 232, 179, 73, 75, 213, 200, 239, 238, 188, 223, 108, 96, 202, 226, 237, 97, 231, 161, 71, 219, 209, 53, 45, 109, 208, 149, 22, 134, 115, 88, 72, 224, 127, 157, 205, 126, 104, 92, 0, 144, 164, 112, 173, 125, 234]

# 2. Persiapan Data (Ciphertext & Known Plaintext)
ct_hex = "f841cff08a6c0640848efc500a1c6a6cf206546e55542912b2f3540ae043933cda69dd45d778ea9701410416413b67f9f57e9feff06caabb3811149b020155a4d469dd93c10bd2c9cc34be7881a66a243a11acc9b10bf1496d206ca9d5d92ce4f6a853d2bba7db40584196503b015bc3"
ct = bytes.fromhex(ct_hex)
known_pt = b"I have a secret, please don't share: "

# 3. Ekstraksi Inverse S-Box
sbox_inv = [0] * 256
for i, v in enumerate(sbox):
    sbox_inv[v] = i

# 4. KPA & Pencarian Kandidat k0
print("[*] Initiating Known Plaintext Attack on k0...")
k0_candidates = []
for i in range(16):
    cands = []
    for k in range(256):
        c0, c1 = ct[i], ct[16+i]
        p0, p1 = known_pt[i], known_pt[16+i]
        
        # Matematika KPA: Eliminasi k1 via XOR
        if sbox[p0 ^ k] ^ sbox[p1 ^ k] == c0 ^ c1:
            # Validasi ekstra jika plaintext blok ke-3 diketahui di indeks ini
            if 32 + i < len(known_pt):
                c2, p2 = ct[32+i], known_pt[32+i]
                if sbox[p0 ^ k] ^ sbox[p2 ^ k] != c0 ^ c2:
                    continue
            cands.append(k)
    k0_candidates.append(cands)

# 5. Rekonstruksi Kunci & Validasi MD5
print("[*] Filtering exact key based on k1=MD5(k0)...")
for k0_tup in itertools.product(*k0_candidates):
    k0 = bytes(k0_tup)
    k1 = hashlib.md5(k0).digest()
    
    # Validasi struktur cipher secara menyeluruh dengan known plaintext
    valid = True
    for i in range(len(known_pt)):
        if ct[i] != sbox[known_pt[i] ^ k0[i % 16]] ^ k1[i % 16]:
            valid = False
            break
            
    if valid:
        print("[+] Master Key (k0) and k1 successfully retrieved!")
        # 6. Dekripsi penuh menggunakan Inverse SBox
        decrypted = bytearray()
        for i in range(len(ct)):
            decrypted.append(sbox_inv[ct[i] ^ k1[i % 16]] ^ k0[i % 16])
        
        flag_str = decrypted.decode(errors='ignore')
        flag_match = re.search(r'(byuctf\{.*?\})', flag_str)
        if flag_match:
            print(f"\n<FLAG>{flag_match.group(1)}</FLAG>")
        break
