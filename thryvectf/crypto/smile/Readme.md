# :)

## Ringkasan

File `chall.7z` berisi dua file setelah payload internal LZMA didekompresi:

```text id="k7s3w2"
key.enc
chall.enc
```

Tool `7z` tidak wajib digunakan. Format arsip dapat dibaca langsung dengan mengambil stream utama setelah header 7z, mendekompresinya menggunakan LZMA1, kemudian memisahkan hasilnya menjadi `key.enc` dan `chall.enc`.

Proses solve terdiri dari tiga layer:

1. Decode `key.enc` menggunakan Base45 dan Base64 berlapis.
2. Decode `chall.enc` dari hex → emoji → Base100.
3. Mendekripsi hasil Base100 menggunakan **Beaufort cipher** dengan key `FLAMINGO`.

Flag final:

```text id="x4n8p2"
Thryve{th1s_1s_fun_r1ght!}
```

## 1. Decode `key.enc`

Isi `key.enc` hanya menggunakan alfabet:

```text id="d8q5m1"
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:
```

Alfabet tersebut merupakan alfabet **Base45**.

Setelah Base45 di-decode, hasilnya masih berupa string Base64 dengan beberapa layer. Proses decoding dapat dilakukan berulang selama hasil decoding masih berupa data printable dan memiliki bentuk Base64.

Setelah seluruh layer Base64 dibuka, diperoleh:

```text id="v6c2k9"
FLAMINGO
```

Jadi key yang digunakan pada layer cipher terakhir adalah:

```text id="r5m8x3"
FLAMINGO
```

## 2. Decode `chall.enc`

Berbeda dengan `key.enc`, file `chall.enc` berisi representasi hexadecimal dari byte UTF-8 emoji.

Contohnya:

```text id="p3w7n4"
f09f9184f09f919c...
```

Setelah melakukan hex decode, data berubah menjadi rangkaian emoji.

Pola byte:

```text id="y2k6q8"
f0 9f xx yy
```

mengindikasikan encoding **Base100** berbasis emoji.

Rumus decode yang digunakan:

```text id="m8q1v5"
byte = (xx - 0x8f) * 64 + (yy - 0x80) - 55
```

Setelah seluruh emoji didecode menggunakan rumus tersebut, diperoleh ciphertext:

```text id="c4n7z2"
Mejonj{nh1n_1t_vsv_w1ahm!}
```

Hasil ini sudah memiliki struktur yang menyerupai flag, tetapi karakter alfabetnya masih terenkripsi.

## 3. Beaufort Cipher

Dengan key:

```text id="w3p6x9"
FLAMINGO
```

ciphertext tersebut kemudian diuji menggunakan beberapa varian cipher keluarga Vigenère.

Cipher yang menghasilkan plaintext valid adalah **Beaufort cipher**.

Rumus dekripsinya:

```text id="q5m2k7"
P = K - C mod 26
```

Key hanya maju ketika karakter ciphertext berupa huruf. Karakter lain seperti:

* angka
* underscore `_`
* kurung kurawal `{ }`
* tanda baca

tidak mengonsumsi karakter key dan dibiarkan tetap.

Menerapkan Beaufort dengan key `FLAMINGO` menghasilkan:

```text id="n8v4c1"
Thryve{th1s_1s_fun_r1ght!}
```

## Alur Lengkap

Secara ringkas, seluruh proses dapat digambarkan sebagai:

```text
chall.7z
   │
   └── LZMA1 decompress
          │
          ├── key.enc
          │     └── Base45 → Base64 → Base64 → ...
          │                     ↓
          │                 FLAMINGO
          │
          └── chall.enc
                └── Hex decode
                      ↓
                    Emoji
                      ↓
                  Base100
                      ↓
              Mejonj{nh1n_1t_vsv_w1ahm!}
                      ↓
               Beaufort / FLAMINGO
                      ↓
              Thryve{th1s_1s_fun_r1ght!}
```

## Flag

```text id="z6p3w8"
Thryve{th1s_1s_fun_r1ght!}
```

