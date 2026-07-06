import json

# 1. Masukkan data ciphertext dari output.txt
guest_cipher_2 = bytes.fromhex(
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2c0890bc6bf92f2a5dd1b971c73dd0277e8fe2257c5f683491068b3b56165507d6965dac860292c79fcf3862200b3cf8c1afd62d2e5586b34c1b9df4dd8d7e1dee634bedbe46d4ce749d41ce8f61118d060becd997309da64e9e5799b1625d333bd783837104cf82f6b1da7a7d613364771111a4688f1d6002b454315f2041d6a77749f11b19"
)

admin_cipher = bytes.fromhex(
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2a1998a671f92f2a5dd1b971c73dd03c6481f014764d6c2aec44c63c6c19444088eb7d86a832ef99d8c03349374c67beeeafda23386380af0d1ea1e5dd9f6962fb744be79551d58d3ce055c78f626cc54124c0c8a62e9ff51eed1ed9ad361e6332c1a09b1e069787a1f19c4b7c2620753f6c06f93595162e0bfe4c"
)


# 2. Rekonstruksi plaintext asli dari guest_2 sesuai format di chall.py
def encode_ticket(ticket):
    return json.dumps(ticket, separators=(",", ":")).encode()


guest_plaintext_2 = encode_ticket(
    {
        "event": "modern-crypto-101",
        "role": "guest",
        "name": "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read",
        "seat": "N-0705",
        "note": "enjoy the workshop",
    }
)

# 3. Pulihkan keystream dengan cara XOR: Ciphertext_Guest ^ Plaintext_Guest
keystream = bytes([c ^ p for c, p in zip(guest_cipher_2, guest_plaintext_2)])

# 4. Dekripsi Admin Ciphertext menggunakan Keystream yang sudah didapatkan
admin_plaintext = bytes([c ^ k for c, k in zip(admin_cipher, keystream)])

print("--- Hasil Dekripsi Tiket Admin ---")
print(admin_plaintext.decode(errors="ignore"))
