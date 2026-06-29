# Writeup: Broken Trust Protocol

## Challenge Info
- **CTF**: Tracebash CTF
- **Category**: Crypto
- **Difficulty**: Easy
- **Points**: Unknown

## TL;DR
Klien jahat menyuntikkan nilai $B = p - 1 \equiv -1 \pmod p$ pada pertukaran kunci Diffie-Hellman. Akibatnya, nilai *shared secret* ($B^a \pmod p$) tereduksi menjadi kelompok subgrup kecil dengan hanya dua kemungkinan nilai: `1` atau `p - 1`. Kunci AES dapat didekripsi dengan melakukan brute force terhadap kedua kemungkinan ini.

## Analysis
Diberikan berkas `protocol.py` network capture dan variabel numerik di `capture.txt`. Dari kode `protocol.py`, terlihat implementasi protokol Diffie-Hellman:

```python
A = pow(g,a,p)

# malicious client sends small subgroup element
B = p-1

shared = pow(B,a,p)
key = sha256(str(shared).encode()).digest()[:16]

Celah keamanan ada pada manipulasi nilai $B$. Protokol Diffie-Hellman yang aman mengharuskan kedua belah pihak memverifikasi bahwa kunci publik pasangan berada dalam subgrup yang valid.Di sini, $B$ diatur menjadi $p - 1$. Secara modular arithmetic:$$B \equiv -1 \pmod p$$Ketika server menghitung shared secret:$$S = B^a \equiv (-1)^a \pmod p$$Nilai $S$ hanya memiliki dua kemungkinan hasil:Jika $a$ genap, $S = 1$Jika $a$ ganjil, $S = p - 1$Setelah mendapatkan shared, kunci enkripsi dibentuk melalui SHA-256 dan digunakan untuk mengenkripsi flag dengan AES-CBC:

key = sha256(str(shared).encode()).digest()[:16]
cipher = AES.new(key,AES.MODE_CBC,iv)

Exploitation
Kita cukup membuat script untuk menguji kedua kemungkinan nilai shared secret (1 dan p - 1), melakukan derivasi kunci AES, dan mendekripsi ciphertext yang ada di capture.txt.

Berikut script otomatis solve.py

flag: TBCTF{Sm4ll_Subgr0up_Att4cks_Ar3_D34dly}


