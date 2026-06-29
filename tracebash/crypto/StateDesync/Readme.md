Writeup: State Desync

Challenge Info

CTF: Tracebash CTF

Category: Crypto

Difficulty: Easy

Points: Unknown

TL;DR

Stream cipher kustom ini menggunakan dua buah seed 8-bit (seed_a dan seed_b) untuk menginisialisasi state internalnya. Karena ukuran total keyspace sangat kecil ($2^8 \times 2^8 = 65.536$ kemungkinan), cipher ini sangat rentan terhadap serangan brute force secara penuh (exhaustive search) untuk memulihkan plaintext.

Analysis

Berdasarkan berkas challenge.py, algoritma enkripsi menggunakan struktur generator stream cipher berbasis dua state internal: state_a dan state_b.

def encrypt(data, seed_a, seed_b):
    state_a = seed_a
    state_b = seed_b
    ...


Meskipun fungsi ini menerapkan mekanisme penambahan langkah pergeseran bit bitwise dinamis (irregular clocking) lewat fungsi custom_sbox dan umpan balik bit LFSR-like, seluruh kompleksitas tersebut tidak berarti karena batasan ukuran variabel seed.

Kedua seed diinput sebagai nilai 8-bit:

Rentang seed_a: $0 - 255$

Rentang seed_b: $0 - 255$

Kombinasi ruang kunci yang dihasilkan hanya sebesar $256 \times 256 = 65.536$. Angka ini dapat diproses oleh CPU modern dalam waktu kurang dari satu detik menggunakan teknik pencarian menyeluruh (brute force). Sifat operasi XOR yang simetris memungkinkan kita mereplikasi generator keystream yang sama untuk membalikkan proses enkripsi menjadi dekripsi (byte ^ keystream_byte).

Exploitation

Eksploitasi dilakukan dengan mengiterasi seluruh kombinasi seed_a dan seed_b dari $0$ sampai $255$. Setiap hasil dekripsi teks dicocokkan dengan pola penanda flag (TBCTF{).

Berikut script otomatis solve.py:

import binascii

def custom_sbox(val):
    return ((val ^ 0x5A) + 0x33) % 256

def decrypt(ciphertext, seed_a, seed_b):
    state_a = seed_a
    state_b = seed_b
    plaintext = bytearray()

    for byte in ciphertext:
        clock_steps = (state_a & 0x0F) + 1
        for _ in range(clock_steps):
            feedback = ((state_b >> 7) ^ (state_b >> 5) ^ (state_b >> 2) ^ (state_b >> 1)) & 1
            state_b = ((state_b << 1) | feedback) & 0xFF

        state_a = custom_sbox(state_a ^ state_b)
        keystream_byte = custom_sbox(state_b) ^ state_a
        plaintext.append(byte ^ keystream_byte)

    return plaintext

ciphertext = binascii.unhexlify("1ad9756e666a336be1388c7d132c0a83aecfb9735366374196e187f78e38ece6")

found = False
for seed_a in range(256):
    for seed_b in range(256):
        decrypted = decrypt(ciphertext, seed_a, seed_b)
        if decrypted.startswith(b"TBCTF{"):
            print(f"[+] Flag: {decrypted.decode('utf-8')}")
            found = True
            break
    if found:
        break


Jalankan script untuk merestorasi flag:

python3 solve.py


Flag: TBCTF{h1dd3n_st4t3_m4chin3_f4il}
