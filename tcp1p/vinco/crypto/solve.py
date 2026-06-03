import sys

p = 35284081072728374486849007153546839654940875013389609094660915307083295701580474060292907973770636993150522968387984084332947336268557134344580010713508521025981098629467760482552581281445381946403837
q = 64570647690564781476667232570439846011334740429928324162751606248631345222399933395775606872074849866467596260229803385378478267256680949937335179309873225691680634935313840375939250528093045113835297
n = p * q
e = 65537
ct_hex = "52c92aeccde16b772b5b9358d2580bc11e15881784c75dae04553e66f7b046cfdf498598d1fa8ffa6538d4dabd6575cf9979afcd8ab0cd05dc9f03aa9adac2f7f253c4ffb94643fb65b5a3b201310f467a0875b374211edbbab1220a3b1a18e2554051b5921b3667f40fbcff76c68333cd3ac3ff57c88514aaceba4b66e528d2bec7cb296b87be413f05e1feef74e91c53bb4955c6b7980a4d62ec924db5faf9083c44e89306"
c = int(ct_hex, 16)

def check_and_print(m_val, desc):
    try:
        b = m_val.to_bytes((m_val.bit_length() + 7) // 8, 'big')
        # Cek jika ada string yang lumayan panjang dan bisa dibaca
        clean_text = ''.join([chr(x) if 32 <= x <= 126 else '' for x in b])
        if "TCP" in clean_text or "flag" in clean_text or "{" in clean_text:
            print(f"\n[+] BINGO ({desc}): {clean_text}")
    except:
        pass

print("[*] Mengecek kemungkinan jebakan (Twist) dari soal...")

# 1. Standard Decryption
phi_normal = (p - 1) * (q - 1)
d_normal = pow(e, -1, phi_normal)
m_normal = pow(c, d_normal, n)

# 2. Twist: Double Decryption ("SecondCrypto")
m_double = pow(m_normal, d_normal, n)
check_and_print(m_double, "Double Decryption")

# 3. Twist: Author Mistakes (Salah tulis rumus phi)
phis_to_test = {
    "phi = p * q": p * q,
    "phi = p * q - 1": p * q - 1,
    "phi = (p+1)*(q+1)": (p + 1) * (q + 1)
}

for desc, test_phi in phis_to_test.items():
    try:
        d_test = pow(e, -1, test_phi)
        m_test = pow(c, d_test, n)
        check_and_print(m_test, f"Author Mistake: {desc}")
    except:
        pass

# 4. Dump ke file binary agar bisa dianalisis manual
raw_bytes = m_normal.to_bytes((m_normal.bit_length() + 7) // 8, 'big')
with open("flag.bin", "wb") as f:
    f.write(raw_bytes)

print("\n[+] Decrypt selesai. Jika script tidak mengeprint BINGO, hasil dekripsi telah disimpan di 'flag.bin'.")
