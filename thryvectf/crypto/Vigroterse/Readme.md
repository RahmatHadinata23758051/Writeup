# Vigroterse — Crypto Writeup

## Informasi Challenge

**Judul:** `Vigroterse`
**Kategori:** Crypto

Ciphertext terdapat di file `chall(1).enc`:

```text id="h3x7q1"
U(_J|0}`(M_*0dj_(S6NQJ9%
```

Deskripsi challenge mengarahkan ke profil Discord Saad untuk menemukan layer enkripsi pertama. Bagian profil yang relevan adalah:

```text id="p6m2w8"
Life imitates life.
"H" ~♡
```

Huruf `H` digunakan sebagai key untuk layer Vigenère.

## 1. Membaca Hint dari Judul

Nama `Vigroterse` dapat dipecah menjadi beberapa petunjuk:

* `Vig` → **Vigenère**
* `rot` → **ROT**
* bagian akhir mengarah ke **reverse**

Dengan demikian, ciphertext kemungkinan melewati beberapa transformasi sederhana secara berurutan: Vigenère, ROT, kemudian pembalikan string.

Karakter ciphertext juga mendukung dugaan penggunaan **ROT47**. ROT13 hanya memproses karakter alfabet, sedangkan ROT47 bekerja pada hampir seluruh printable ASCII, yaitu karakter dari `!` sampai `~`.

## 2. Layer Vigenère

Key yang ditemukan dari profil Discord adalah:

```text id="k9v4s2"
H
```

Dalam Vigenère, alfabet dipetakan sebagai:

```text id="q1m6x8"
A = 0
B = 1
...
H = 7
```

Karena key hanya terdiri dari satu huruf, proses Vigenère tersebut ekuivalen dengan Caesar shift `-7` ketika melakukan dekripsi terhadap karakter alfabet.

Ciphertext awal:

```text id="r5w2n7"
U(_J|0}`(M_*0dj_(S6NQJ9%
```

Setelah didekripsi menggunakan key `H`:

```text id="v8p3c6"
N(_C|0}`(F_*0wc_(L6GJC9%
```

Karakter non-alfabet tidak diubah.

## 3. ROT47

Layer berikutnya adalah ROT47.

ROT47 memutar karakter printable ASCII sebanyak 47 posisi dalam range ASCII 33–126.

Rumus yang digunakan:

```python id="d4k8m1"
chr(33 + ((ord(c) - 33 + 47) % 94))
```

Setelah ROT47 diterapkan terhadap hasil Vigenère:

```text id="x7q2v5"
}W0rM_N1Wu0Y_H40W{evyrhT
```

Hasil ini sudah memiliki pola yang menyerupai flag yang dibalik.

## 4. Reverse

String tersebut kemudian dibalik:

```text id="n6p4z9"
}W0rM_N1Wu0Y_H40W{evyrhT
```

menjadi:

```text id="c3m8w2"
Thryve{W04H_Y0uW1N_Mr0W}
```

Formatnya cocok dengan format flag challenge:

```text id="y5k1q7"
Thryve{...}
```

## Alur Lengkap

Seluruh proses dapat dirangkum sebagai:

```text id="t8v3m6"
Ciphertext
    │
    ├── Vigenère decrypt (key = H)
    │
    ↓
N(_C|0}`(F_*0wc_(L6GJC9%
    │
    ├── ROT47
    │
    ↓
}W0rM_N1Wu0Y_H40W{evyrhT
    │
    ├── Reverse
    │
    ↓
Thryve{W04H_Y0uW1N_Mr0W}
```

## Solver

`solve.py` melakukan seluruh layer secara otomatis:

1. Membaca ciphertext dari file.
2. Melakukan Vigenère decrypt menggunakan key `H`.
3. Menerapkan ROT47.
4. Membalik string.
5. Memvalidasi format `Thryve{...}`.
6. Mencetak flag dengan format `<FLAG>...</FLAG>`.

Jalankan dari folder challenge:

```bash id="m2x7q4"
source /home/nata/ctf_env/bin/activate
python solve.py 'chall(1).enc'
```

Jika environment tersebut tidak tersedia, solver hanya menggunakan Python standard library:

```bash id="k6p3v8"
python3 solve.py 'chall(1).enc'
```

Output:

```text id="w4n9c2"
[+] Ciphertext        : U(_J|0}`(M_*0dj_(S6NQJ9%
[+] Vigenere key      : H
[+] After Vigenere    : N(_C|0}`(F_*0wc_(L6GJC9%
[+] After ROT47       : }W0rM_N1Wu0Y_H40W{evyrhT
[+] After reverse     : Thryve{W04H_Y0uW1N_Mr0W}

<FLAG>Thryve{W04H_Y0uW1N_Mr0W}</FLAG>
```

## Flag

```text id="p7x2m5"
Thryve{W04H_Y0uW1N_Mr0W}
```

