import hashlib

# Parameter secp256k1 Curve Order (n)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# 1. Rekonstruksi string pesan & hitung hash SHA-256 (z)
# Format -> "sender:recipient:amount"
msg1 = "Suspect:FranklinGothic:21.68"
msg2 = "Suspect:ForeverFlames:45.46"

z1 = int(hashlib.sha256(msg1.encode()).hexdigest(), 16)
z2 = int(hashlib.sha256(msg2.encode()).hexdigest(), 16)

# 2. Ambil nilai r, s1, dan s2 dari DER signature
# Tx 4
r = 0x2CBDA85FC21F5E62F94D8378D2DAD1A05BC5D5522D5A717F2BDF1DF13D558EC7
s1 = 0x4B2F38C18C2A933F81112350AE048F0162FEAAED599F827180944EA3203570DE

# Tx 19
s2 = 0x7DB2D815212AAB6B986D0A403B724AD5FD57d2D9E826BF2893E29D9D179D59F3

# 3. Hitung modular inverse untuk (s1 - s2)
# Di Python 3.8+, kita bisa pakai pow(x, -1, mod)
s_diff_inv = pow((s1 - s2) % n, -1, n)

# 4. Hitung Nonce (k)
k = ((z1 - z2) * s_diff_inv) % n

# 5. Hitung Private Key (d)
r_inv = pow(r, -1, n)
d = (((s1 * k) - z1) * r_inv) % n

# Output hasil dalam lowercase hex tanpa prefix 0x
private_key_hex = hex(d)[2:].zfill(64)
print(f"[-] Nonce (k): {hex(k)}")
print(f"[+] Private Key (d): {private_key_hex}")
print(f"[+] Flag: boroCTF{{{private_key_hex}}}")
