# Inferior Student

**Category:** Reverse  
**CTF:** LYKN CTF 2026  
**Description:** `Nothing Stay`

## Ringkasan

`chall.exe` adalah binary PyInstaller dari `challl.py`. Source Python-nya sengaja dibesarkan dengan identifier Unicode, pemeriksaan anti-debug, ribuan operasi sampah, tujuh payload terenkripsi, dan satu lapisan `marshal` tambahan.

Verifier terakhir ternyata sederhana: input dienkripsi memakai ChaCha20, lalu hasilnya dibandingkan dengan ciphertext statis sepanjang 145 byte. Karena ChaCha20 adalah stream cipher, ciphertext target bisa diproses dengan key dan nonce yang sama untuk mendapatkan flag.

## 1. Struktur loader

Bagian awal source menghitung accumulator anti-debug yang namanya diacak. Nilai normalnya adalah `0`, tetapi akan berubah ketika program mendeteksi beberapa kondisi seperti:

- `sys.gettrace()` aktif;
- debugger Windows terpasang;
- tracing pada Linux;
- module analisis tertentu sudah dimuat;
- waktu eksekusi melewati batas;
- hook pada beberapa fungsi bawaan.

Nilai accumulator dipakai saat membentuk key payload. Jadi menjalankan source langsung di debugger dapat menghasilkan key salah tanpa pesan yang jelas.

Loader menyimpan tujuh tuple dengan struktur:

```python
(seed, salt_byte, nonce, encrypted_payload, expected_sha256)
```

Worker mendekripsinya dengan pola berikut:

```python
key = hashlib.sha256(seed + bytes([salt_byte ^ anti_debug])).digest()[:32]
compressed = ChaCha20.new(key=key, nonce=nonce).decrypt(encrypted_payload)

assert hashlib.sha256(compressed).digest() == expected_sha256
code = marshal.loads(lzma.decompress(compressed))
exec(code, globals())
```

Payload dijalankan melalui beberapa thread. Chunk indeks `3` adalah payload utama; ukurannya jauh lebih besar daripada enam chunk lain yang sebagian besar hanya membentuk state dan decoy.

## 2. Masalah versi bytecode

Code object dihasilkan oleh Python 3.12. Membuka raw `marshal` memakai Python 3.13 membuat field code object terlihat masuk akal, tetapi `co_code` tidak valid untuk interpreter tersebut dan dapat menyebabkan crash.

Analisis dilakukan dengan memuat marshal sebagai bytecode Python 3.12 menggunakan `xdis`, kemudian menjalankan instruction set-nya lewat `x-python`. Beberapa opcode generator Python 3.12 yang belum tersedia ditambahkan secara lokal:

- `RETURN_GENERATOR`;
- `YIELD_VALUE` dengan operand baru;
- `RETURN_CONST` untuk menandai generator selesai;
- `CALL_INTRINSIC_1`;
- `LOAD_FAST_CHECK`.

Setelah chunk utama berjalan, loader membentuk code object kedua sepanjang 316 byte.

## 3. Verifier terakhir

Disassembly code object kedua dapat diringkas menjadi:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

key = bytes([...])          # 32 byte
full_nonce = bytes([...])   # 16 byte
expected = bytes([...])     # 145 byte
candidate = input("flag: ").encode()

cipher = Cipher(
    algorithms.ChaCha20(key, full_nonce),
    mode=None,
).encryptor()

if cipher.update(candidate) == expected:
    print("Correct!")
else:
    print("Wrong!")
```

`cryptography` memakai format nonce ChaCha20 16 byte:

```text
8 byte little-endian initial counter || 8 byte nonce
```

Tidak ada hash atau transformasi irreversible pada input. Operasi yang diperiksa hanya:

```text
ciphertext = plaintext XOR keystream
```

Maka plaintext dapat dipulihkan dengan operasi yang sama:

```text
plaintext = ciphertext XOR keystream
```

## 4. Solver

`solve.py` mengimplementasikan ChaCha20 secara langsung memakai standard library. Tidak perlu menjalankan PE, PyInstaller, atau code object obfuscated.

```bash
python3 solve.py
```

Output:

```text
[+] FLAG: LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}
```

Solver juga mengenkripsi ulang plaintext dan memastikan hasilnya sama persis dengan ciphertext verifier.

## Flag

```text
LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}
```
