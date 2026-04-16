def rev_shr(x, n):
    res = 0
    for i in range(64 // n + 1):
        res = x ^ (res >> n)
    return res

def rev_shl(x, n):
    res = 0
    for i in range(64 // n + 1):
        res = x ^ ((res << n) & 0xFFFFFFFFFFFFFFFF)
    return res

# Data dari r2 pxq
keys = [
    0x0e367bd76e4ed795, 0x092cedfc6690c249, 
    0x6ad2c5c0167f5946, 0x59450f31a1dbc7ed
]

# Alamat fungsi Setter (Target GOT)
# Index 0 = nice, 1 = mlockall, 2 = btowc, 3 = setgid
targets = [0x4013f6, 0x4013d0, 0x4013b4, 0x4013a3]

flag = b""
for i in range(4):
    x = targets[i] ^ keys[i]
    # Reverse 4 kali loop enkripsi (Urutan dibalik: shr 17, shl 13, shr 5)
    for _ in range(4):
        x = rev_shr(x, 17)
        x = rev_shl(x, 13)
        x = rev_shr(x, 5)
    flag += x.to_bytes(8, 'little')

print(f"Flag: {flag.decode().strip()}")
