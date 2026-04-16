def round_function(block, key):
    res = (block ^ key)
    return ((res << 3) | (res >> 13)) & 0xFFFF

def rev_round_function(out):
    # Inverse dari ROL16 3-bit adalah ROR16 3-bit
    return ((out >> 3) | (out << 13)) & 0xFFFF

def decrypt(ct_int, subkeys):
    # Split CT back to R3 and L3
    r3 = (ct_int >> 16) & 0xFFFF
    l3 = ct_int & 0xFFFF
    
    # Reverse 3 Rounds
    # Round 3: L3=R2, R3 = L2 ^ F(R2, k3) => L2 = R3 ^ F(R2, k3)
    r2 = l3
    l2 = r3 ^ round_function(r2, subkeys[2])
    
    # Round 2: L2=R1, R2 = L1 ^ F(R1, k2) => L1 = R2 ^ F(R1, k2)
    r1 = l2
    l1 = r2 ^ round_function(r1, subkeys[1])
    
    # Round 1: L1=R0, R1 = L0 ^ F(R0, k1) => L0 = R1 ^ F(R0, k1)
    r0 = l1
    l0 = r1 ^ round_function(r0, subkeys[0])
    
    return (l0 << 16) | r0

# Data dari pairs.txt
pairs = [
    (0xfe2a8ed3, 0xb4d1a3c8),
    (0xc7c0dda5, 0x1b13e27b),
    (0x31325c9d, 0x205e9af4),
    (0xbfc385b3, 0x4f7e7fe0),
    (0x7c5b66aa, 0x59104647)
]

print("[*] Finding subkeys...")
found_keys = None

for k3 in range(0x10000):
    # Gunakan pasangan pertama untuk estimasi k1 dan k2
    pt, ct = pairs[0]
    l0, r0 = (pt >> 16), (pt & 0xFFFF)
    r3, l3 = (ct >> 16), (ct & 0xFFFF)
    
    r2 = l3
    r1 = r3 ^ round_function(r2, k3)
    
    # Dari R1 = L0 ^ F(R0, k1) => F(R0, k1) = R1 ^ L0
    k1 = rev_round_function(r1 ^ l0) ^ r0
    
    # Dari R2 = R0 ^ F(R1, k2) => F(R1, k2) = R2 ^ R0
    k2 = rev_round_function(r2 ^ r0) ^ r1
    
    # Validasi dengan pasangan kedua
    pt2, ct2 = pairs[1]
    if decrypt(ct2, [k1, k2, k3]) == pt2:
        found_keys = [k1, k2, k3]
        print(f"[+] Subkeys found: {[hex(k) for k in found_keys]}")
        break

if found_keys:
    print("[*] Decrypting flag...")
    with open("flag.txt", "r") as f:
        encrypted_blocks = f.read().splitlines()
    
    flag = ""
    for block in encrypted_blocks:
        ct_val = int(block, 16)
        pt_val = decrypt(ct_val, found_keys)
        # Convert 32-bit int to 4 chars
        flag += chr((pt_val >> 24) & 0xFF)
        flag += chr((pt_val >> 16) & 0xFF)
        flag += chr((pt_val >> 8) & 0xFF)
        flag += chr(pt_val & 0xFF)
    
    print(f"\nResult: {flag}")
