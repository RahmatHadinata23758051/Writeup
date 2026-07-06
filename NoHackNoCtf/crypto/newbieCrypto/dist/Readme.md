CTF Writeup: newbie-crypto (NoHackNoCtf)

Kategori: Cryptography

Tingkat Kesulitan: Newbie / Easy

Kerentanan: AES-CTR Keystream Reuse (Many-Time Pad)

Flag: NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}

1. Deskripsi Tantangan

Diberikan sebuah file skrip Python bernama chall.py yang melakukan enkripsi data tamu (guest ticket) dan tiket admin (admin ticket) menggunakan AES mode CTR. Selain itu, diberikan file output.txt yang berisi hasil enkripsi (ciphertext) beberapa tamu dan enkripsi tiket admin yang menyimpan flag.

2. Analisis Kode Sumber (chall.py)

Kerentanan utama dari tantangan ini terletak pada cara inisialisasi cipher AES pada fungsi encrypt:

def encrypt(ticket):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(ticket).hex()


Karakteristik AES-CTR (Counter Mode)

AES-CTR bekerja seperti stream cipher. Ia menghasilkan aliran biner acak yang disebut Keystream ($K$) berdasarkan kunci enkripsi ($KEY$) dan nilai unik sekali pakai ($NONCE$) ditambah dengan counter.

Proses enkripsi dilakukan dengan mengoperasikan XOR antara pesan asli atau plaintext ($P$) dengan keystream ($K$) tersebut:


$$C = P \oplus K$$

Proses dekripsi juga menggunakan operasi matematika yang sama karena sifat XOR:


$$P = C \oplus K$$

Celah Keamanan (Vulnerability)

Pada kode di atas, KEY dan NONCE (b"ticket42") selalu bernilai sama pada setiap pemanggilan fungsi encrypt(). Di dalam AES-CTR, jika pasangan kunci ($KEY$) dan nilai awal ($NONCE$) tidak pernah berubah, maka keystream yang dihasilkan dari posisi bita ke-$0$ hingga ke-$n$ akan selalu identik untuk setiap proses enkripsi.

Kondisi ini disebut sebagai Many-Time Pad (Keystream Reuse).

3. Strategi Eksploitasi

Jika kita mengetahui nilai plaintext ($P$) dan hasil enkripsinya atau ciphertext ($C$), kita dapat dengan mudah memulihkan keystream ($K$) tersebut:


$$K = C \oplus P$$

Setelah kita memulihkan nilai $K$, kita bisa langsung mendekripsi ciphertext milik admin ($C_{\text{admin}}$) untuk mendapatkan plaintext admin ($P_{\text{admin}}$) yang berisi flag:


$$P_{\text{admin}} = C_{\text{admin}} \oplus K$$

Memilih Target Dekripsi

Panjang keystream yang didekripsi sebanding dengan panjang bita terkecil dari pasangan teks yang kita miliki. Oleh karena itu, kita harus menggunakan data tamu dengan nama terpanjang agar bisa memulihkan keystream dengan ukuran yang cukup besar untuk membuka tiket admin.

Kita memilih Guest 2 (guest_cipher_2) yang memiliki nama paling panjang:

Name: "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read"

Seat: "N-0705"

Format tiket JSON untuk Guest 2 adalah:

{"event":"modern-crypto-101","role":"guest","name":"this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read","seat":"N-0705","note":"enjoy the workshop"}


Panjang JSON ini sangat mencukupi untuk memulihkan keystream guna mendekripsi seluruh pesan tiket admin.

4. Script Penyelesaian (Solver)

Berikut adalah script Python otomatis untuk merekonstruksi plaintext, memulihkan keystream, dan mengekstrak flag dari ciphertext milik admin:

import json

# Ciphertext dari output.txt
guest_cipher_2 = bytes.fromhex(
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2c0890bc6bf92f2a5dd1b971c73dd0277e8fe2257c5f683491068b3b56165507d6965dac860292c79fcf3862200b3cf8c1afd62d2e5586b34c1b9df4dd8d7e1dee634bedbe46d4ce749d41ce8f61118d060becd997309da64e9e5799b1625d333bd783837104cf82f6b1da7a7d613364771111a4688f1d6002b454315f2041d6a77749f11b19"
)

admin_cipher = bytes.fromhex(
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2a1998a671f92f2a5dd1b971c73dd03c6481f014764d6c2aec44c63c6c19444088eb7d86a832ef99d8c03349374c67beeeafda23386380af0d1ea1e5dd9f6962fb744be79551d58d3ce055c78f626cc54124c0c8a62e9ff51eed1ed9ad361e6332c1a09b1e069787a1f19c4b7c2620753f6c06f93595162e0bfe4c"
)

# Rekonstruksi Plaintext Guest 2
guest_plaintext_2 = json.dumps({
    "event": "modern-crypto-101",
    "role": "guest",
    "name": "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read",
    "seat": "N-0705",
    "note": "enjoy the workshop"
}, separators=(',', ':')).encode()

# Memulihkan Keystream: K = C ^ P
keystream = bytes([c ^ p for c, p in zip(guest_cipher_2, guest_plaintext_2)])

# Mendekripsi Tiket Admin: P_admin = C_admin ^ K
admin_plaintext = bytes([c ^ k for c, k in zip(admin_cipher, keystream)])

print("--- Hasil Dekripsi Tiket Admin ---")
print(admin_plaintext.decode(errors="ignore"))


5. Hasil & Pembahasan

Setelah menjalankan script di atas, kita mendapatkan data mentah tiket admin sebagai berikut:

{"event":"modern-crypto-101","role":"admin","name":"organizer","seat":"ROOT","note":"priority access granted","flag":"NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}"}


Dari hasil tersebut, diperoleh flag:
NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}
