# Johnny Boy — Crypto Writeup

## TL;DR

Empat ZIP bukan ZipCrypto biasa. Semuanya WinZip AES, jadi `unzip` klasik tidak cukup. Nama file ZIP membentuk kalimat `USE JOHN THE RIPPER`, artinya jalurnya password cracking.

Password pertama yang valid adalah `chips` untuk `a_USE.zip`. Dari situ rule dipersempit ke variasi kata yang sama. `d_RIPPER.zip` terbuka dengan `chip!` dan log di dalamnya langsung memuat flag.

Flag:

```text
boroCTF{L@_R11pP3r;}
```

## Recon

File yang diberikan:

```text
a_USE.zip
b_JOHN.zip
c_THE.zip
d_RIPPER.zip
```

Nama arsipnya kalau dibaca berurutan:

```text
USE JOHN THE RIPPER
```

`zipinfo -v` menunjukkan entry terenkripsi dengan method `99`, yaitu WinZip AES:

```text
USE.log     method=AES Encrypted
JOHN.log    method=AES Encrypted
THE.log     method=AES Encrypted
RIPPER.log  method=AES Encrypted
```

Bagian extra field `0x9901` menunjukkan AES strength `03`, berarti AES-256. Tiga entry pertama memakai deflate, sedangkan `RIPPER.log` disimpan tanpa kompresi.

## Analisis format ZIP AES

Layout data entry WinZip AES:

```text
salt | password_verifier | ciphertext | auth_code
```

Untuk AES-256:

```text
salt              = 16 bytes
password verifier = 2 bytes
auth code         = 10 bytes, HMAC-SHA1 truncated
```

Key material dibuat dengan:

```text
PBKDF2-HMAC-SHA1(password, salt, 1000, 66 bytes)
```

Pembagian hasil PBKDF2:

```text
32 bytes AES key
32 bytes HMAC key
2 bytes password verifier
```

Verifier 2 byte hanya filter awal. Kandidat yang lolos verifier masih harus dicek lagi pakai HMAC, karena false positive gampang muncul.

## Cracking

Clue `USE JOHN THE RIPPER` mengarah ke dictionary/rule attack, bukan brute-force buta. Karena setiap tebakan ZIP AES harus melewati PBKDF2, brute-force semua charset bakal boros.

Aku pakai rule kecil:

1. Cek kata umum dari local dictionary/rule list.
2. Validasi kandidat dengan verifier AES-ZIP.
3. Kandidat yang lolos diverifikasi ulang dengan HMAC.
4. Setelah `chips` valid untuk `USE.log`, variasi dekat dari kata itu dicoba untuk ZIP lain.

Hasil penting:

```text
a_USE.zip   -> chips
d_RIPPER.zip -> chip!
```

`USE.log` cuma berisi heartbeat/no-op log:

```text
[2026-02-09 17:20:01] INFO  Idle process heartbeat: System state nominal.
...
[2026-02-09 17:23:11] DEBUG System clock sync: 0.000s offset.
```

`RIPPER.log` berisi flag:

```text
[2026] ALL PASSWORDS HAVE BEEN BREACHED
[2026] SYSADMIN MESSAGE "boroCTF{L@_R11pP3r;}
```

## Solver

Solver tidak bergantung pada `unzip` atau `john`. Script membaca header ZIP, mengambil salt/verifier/ciphertext/auth code, lalu mendekripsi WinZip AES langsung.

Run:

```bash
python3 solve.py
```

Output:

```text
[+] a_USE.zip:USE.log password='chips'
...
[+] d_RIPPER.zip:RIPPER.log password='chip!'
[2026] ALL PASSWORDS HAVE BEEN BREACHED
[2026] SYSADMIN MESSAGE "boroCTF{L@_R11pP3r;}
<FLAG>boroCTF{L@_R11pP3r;}</FLAG>
```
