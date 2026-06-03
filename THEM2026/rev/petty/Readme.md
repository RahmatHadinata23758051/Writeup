# Writeup — 🦀?

## Ringkasan

Challenge memberikan file `crab.exe`, sebuah executable PE64 Windows hasil compile Rust. Dari enumerasi awal terlihat binary tidak menyimpan flag secara plaintext. Namun di bagian `.rdata` ada beberapa string mencurigakan seperti:

- `bruhmemegang.pyc`
- `python3.12`
- `src\main.rs`
- `chall.py`
- `Enter the passphrase:`
- `Access Granted.` / `Access Denied.`

Ini mengarah ke payload Python bytecode yang disembunyikan di dalam binary Rust.

## Analisis

Pertama file dicek dengan:

```bash
file crab.exe
strings -a -n 4 crab.exe | grep -Ei 'pyc|python|passphrase|access|main.rs|chall'
```

Ditemukan area data yang terlihat seperti bytecode ter-obfuscate. Pada offset sekitar `0x2a009`, jika setiap byte di-XOR dengan `0x69`, empat byte pertama berubah menjadi magic Python bytecode:

```text
cb 0d 0d 0a
```

Magic tersebut cocok dengan `.pyc` Python 3.12. Jadi Rust binary menyimpan file `.pyc` yang dienkripsi sederhana dengan XOR `0x69`.

Payload `.pyc` diekstrak dari range berikut:

```text
start = 0x2a009
end   = 0x2ac34
key   = 0x69
```

Setelah bytecode dianalisis, fungsi pentingnya bernama `check_flag(user_input)`. Secara garis besar validasinya:

1. Input diubah ke hex.
2. Hex diberi spasi per byte.
3. String tersebut di-base64.
4. Alphabet base64 standar ditranslasi ke alphabet custom.
5. Setiap karakter hasil custom base64 di-XOR dengan polynomial key.
6. Hasil akhirnya dibandingkan dengan array target sepanjang 196 byte.

Alphabet base64 custom:

```python
STD_ALPHA    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHA = 'HIJKLMNOPQRSTUVWXYZABCDEFGhijklmnopqrstuvwxyzabcdefg6789012345+/'
```

Rumus key per indeks:

```python
key(i) = (13*i^3 + 3*i^2 + 7*i + 420) & 0xff
```

Karena transformasinya reversible, proses solving dilakukan dari target ke belakang:

1. XOR ulang target dengan `key(i)` untuk mendapatkan custom base64.
2. Translate alphabet custom kembali ke alphabet base64 standar.
3. Base64 decode untuk mendapatkan spaced hex.
4. Hapus spasi lalu decode hex menjadi flag asli.

## Solver

Solver final ada di `solve.py`.

Jalankan:

```bash
python3 solve.py
```

Output:

```text
THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}
```

## Flag

```text
THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}
```
