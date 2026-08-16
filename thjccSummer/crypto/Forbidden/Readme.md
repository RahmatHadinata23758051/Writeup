# Writeup CTF: Forbidden

## Deskripsi Tantangan

Diberikan sebuah endpoint netcat. Saat diakses, server memberikan satu nilai `NONCE`, tiga blok pesan (masing-masing berisi Plaintext, Ciphertext, dan MAC/Tag), serta satu `TARGET` berupa plaintext. Tujuan kita adalah mengenkripsi plaintext `TARGET` tersebut dan membuat MAC yang valid agar diterima oleh server.

Kerentanan utama terletak pada penggunaan nilai `NONCE` yang sama persis untuk mengenkripsi tiga pesan yang berbeda. Ini adalah implementasi kerentanan klasik yang dikenal sebagai **Forbidden Attack** pada AES-GCM.

## Analisis Teori Kriptografi

AES-GCM (Galois/Counter Mode) terdiri dari dua komponen utama: enkripsi berbasis stream cipher (CTR mode) dan autentikasi berbasis fungsi hash universal (GHASH).

### 1. Kerentanan Enkripsi (Keystream Reuse)

Pada mode CTR, ciphertext dihasilkan dengan melakukan operasi XOR antara plaintext dengan keystream. Keystream dihasilkan dari enkripsi nilai counter (yang diturunkan dari Nonce dan Kunci) menggunakan AES.

$$CT = PT \oplus Keystream$$

Karena Nonce tidak berubah pada ketiga pesan, keystream yang dihasilkan juga identik. Hal ini memungkinkan kita untuk memulihkan keystream hanya dengan melakukan XOR antara Plaintext dan Ciphertext dari salah satu pesan yang diberikan.

$$Keystream = PT_1 \oplus CT_1$$

Setelah keystream didapatkan, kita dapat langsung mengenkripsi plaintext TARGET.

$$CT_{target} = PT_{target} \oplus Keystream$$

### 2. Kerentanan Autentikasi (GHASH Key Recovery)

Autentikasi pada GCM dihitung menggunakan fungsi GHASH beroperasi pada Galois Field $GF(2^{128})$ dengan polinomial tak tereduksi $x^{128} + x^7 + x^2 + x + 1$.

Secara matematis, Tag (T) atau MAC dihasilkan dari persamaan:

$$T = GHASH(H, A, C) \oplus S$$

Di mana:

- $H$ adalah Hash Key (nilai turunan dari Kunci master AES).
- $A$ adalah Additional Authenticated Data (pada kasus ini kosong).
- $C$ adalah Ciphertext.
- $S$ adalah Masking Key, dihitung dengan mengenkripsi blok awal (J0) yang diturunkan dari Nonce.

Karena Nonce yang digunakan sama, nilai $S$ akan identik untuk semua pesan. Dalam aritmatika GF(2), operasi penambahan ekuivalen dengan XOR. Jika kita menjumlahkan Tag dari pesan 1 dan pesan 2, nilai $S$ akan saling meniadakan ($S \oplus S = 0$).

$$T_1 + T_2 = (GHASH(H, C_1) + S) + (GHASH(H, C_2) + S)$$

$$T_1 + T_2 = GHASH(H, C_1) + GHASH(H, C_2)$$

Fungsi GHASH pada dasarnya adalah evaluasi polinomial di mana elemen datanya menjadi koefisien dan $H$ adalah variabelnya. Persamaan di atas dapat disusun ulang menjadi persamaan polinomial dengan variabel bebas $X$:

$$P_1(X) = GHASH(X, C_1) + GHASH(X, C_2) + T_1 + T_2 = 0$$

Nilai rahasia $H$ adalah salah satu akar dari polinomial $P_1(X)$. Karena polinomial ini bisa memiliki banyak akar, kita membutuhkan polinomial kedua untuk mencari irisan akarnya. Kita gunakan kombinasi pesan 1 dan pesan 3:

$$P_2(X) = GHASH(X, C_1) + GHASH(X, C_3) + T_1 + T_3 = 0$$

Dengan menggunakan algoritma Euclidean untuk mencari Greatest Common Divisor (GCD) dari $P_1(X)$ dan $P_2(X)$, kita dapat mengeliminasi akar-akar palsu.

$$P_{gcd}(X) = GCD(P_1(X), P_2(X))$$

Akar dari $P_{gcd}(X)$ adalah nilai Hash Key ($H$) yang sebenarnya. Setelah $H$ diketahui, kita bisa mendapatkan kembali nilai Masking Key ($S$) menggunakan salah satu pesan asli:

$$S = T_1 + GHASH(H, C_1)$$

Dengan $H$ dan $S$ di tangan, kita memegang kendali penuh atas komponen autentikasi GCM dan dapat membuat Tag/MAC yang valid untuk $CT_{target}$.

## Eksploitasi

Eksploitasi dilakukan menggunakan SageMath karena kemampuannya dalam menangani operasi polinomial pada field berhingga (Finite Fields) dengan presisi mutlak.

Hal yang perlu diperhatikan dalam implementasi spesifikasi GCM adalah konversi bit. Standar NIST mengharuskan bit direpresentasikan dengan format Little-Endian bit ordering saat dikonversi ke elemen polinomial GF(2^128). Ini ditangani oleh fungsi kustom `bytes_to_elem` dan `elem_to_bytes` pada skrip penyelesaian.

## Script Penyelesaian (SageMath)

```python
import socket
import operator

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('chal.thjcc.org', 12002))

    lines = []
    for _ in range(5):
        buf = b""
        while b"\n" not in buf:
            buf += s.recv(1)
        lines.append(buf.decode().strip())
    
    msg1 = lines[1].split()
    msg2 = lines[2].split()
    msg3 = lines[3].split()
    target_line = lines[4].split()

    pt1, ct1, mac1 = [bytes.fromhex(x) for x in msg1[1:]]
    pt2, ct2, mac2 = [bytes.fromhex(x) for x in msg2[1:]]
    pt3, ct3, mac3 = [bytes.fromhex(x) for x in msg3[1:]]
    target_pt = bytes.fromhex(target_line[1])

    # 1. Recover Keystream
    ks = bytes([operator.xor(a, b) for a, b in zip(pt1, ct1)])
    target_ct = bytes([operator.xor(a, b) for a, b in zip(target_pt, ks[:len(target_pt)])])

    # 2. Setup Finite Field GF(2^128)
    from sage.all import GF, PolynomialRing
    F = GF(2**128, name='a', modulus=PolynomialRing(GF(2), 'x')('x^128 + x^7 + x^2 + x + 1'))
    PR = PolynomialRing(F, name='X')
    X = PR.gen()

    def bytes_to_elem(b):
        num = int.from_bytes(b, 'big')
        num = int('{:0128b}'.format(num)[::-1], 2)
        bits = [(num >> i) & 1 for i in range(128)]
        return F(bits)

    def elem_to_bytes(e):
        coeffs = e.polynomial().list()
        num = sum(int(c) << i for i, c in enumerate(coeffs))
        num = int('{:0128b}'.format(num)[::-1], 2)
        return num.to_bytes(16, 'big')

    def get_ghash_poly(C):
        C_pad = C + b'\x00' * ((16 - len(C) % 16) % 16)
        blocks = [C_pad[i:i+16] for i in range(0, len(C_pad), 16)]
        len_block = (0).to_bytes(8, 'big') + (len(C) * 8).to_bytes(8, 'big')
        blocks.append(len_block)

        poly = PR(0)
        for i, b in enumerate(reversed(blocks)):
            poly += bytes_to_elem(b) * (X**(i+1))
        return poly

    def ghash(H_val, C):
        C_pad = C + b'\x00' * ((16 - len(C) % 16) % 16)
        blocks = [C_pad[i:i+16] for i in range(0, len(C_pad), 16)]
        len_block = (0).to_bytes(8, 'big') + (len(C) * 8).to_bytes(8, 'big')
        blocks.append(len_block)

        Y = F(0)
        for b in blocks:
            Y = (Y + bytes_to_elem(b)) * H_val
        return Y

    # 3. Construct polynomials and find roots
    P1 = get_ghash_poly(ct1) + get_ghash_poly(ct2) + bytes_to_elem(mac1) + bytes_to_elem(mac2)
    P2 = get_ghash_poly(ct1) + get_ghash_poly(ct3) + bytes_to_elem(mac1) + bytes_to_elem(mac3)

    P_gcd = P1.gcd(P2)
    roots = P_gcd.roots()
    H = roots[0][0]

    # 4. Recover S and Forge MAC
    S = bytes_to_elem(mac1) + ghash(H, ct1)
    target_mac_elem = ghash(H, target_ct) + S
    target_mac = elem_to_bytes(target_mac_elem)

    payload = f"{target_ct.hex()} {target_mac.hex()}"
    s.sendall((payload + '\n').encode())

    print(s.recv(1024).decode().strip())

if __name__ == '__main__':
    solve()
```

## Hasil

Setelah skrip dijalankan, server memvalidasi Tag palsu yang dikirim dan mengembalikan flag:

```
THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}
```
