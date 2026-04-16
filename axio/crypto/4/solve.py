# Parameter dari soal
n = 777906542012148850498730003121751874988890557158978824496911598351713414167225645078880983328428031
e = 65537
c = 144356139161948138223986230693417123074375277282306312193570700654678914727096855004234405963188413

# Ekstraksi p, q, r dari penyebut koordinat A, B, C
p = 709231534941570294451065164719981
q = 972341821943706848801163152057887
r = 1128029403835778203409365975795973

print("[*] Memverifikasi n == p * q * r...")
assert n == p * q * r, "Nilai p, q, r tidak cocok dengan n!"
print("[+] Verifikasi berhasil!")

# Menghitung Euler's totient function untuk 3 prime
phi = (p - 1) * (q - 1) * (r - 1)

# Menghitung private key d
d = pow(e, -1, phi)

# Dekripsi ciphertext
m = pow(c, d, n)

# Konversi integer ke bytes (string)
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('ascii', errors='ignore')

print(f"\n[+] BERHASIL!")
print(f"[+] Flag: {flag}")
