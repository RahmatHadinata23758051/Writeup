def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

c1 = bytes.fromhex("36273f225d4e393b2414025f1030025f1030025f10301907035e145e0c082508520a0930001d081d1012")
c2 = bytes.fromhex("0e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e02")
c3 = bytes.fromhex("180504021805040218050402180504021805040218050402180504021805040218050402180504021805")
c4 = bytes.fromhex("202020204b49263932131d5d06371d5d06371d5d0637060515590b5c1a0f3a0a440d1632161a171f0615")

# 1. Tebak K1 menggunakan awalan "THEM"
known_plain = b"THEM"
k1 = xor(c1[:4], known_plain) # Menghasilkan b"bozo"

# 2. Cari K2
k2 = xor(c2[:4], k1)          # Menghasilkan b"lmao"

# 3. Cari K3
k3 = xor(c3[:4], k2)          # Menghasilkan b"them"

# 4. Panjangkan K3 agar sesuai dengan panjang C4 (42 bytes)
k3_full = (k3 * 11)[:len(c4)]

# 5. Ekstrak Flag
flag = xor(c4, k3_full)
print(flag.decode())
