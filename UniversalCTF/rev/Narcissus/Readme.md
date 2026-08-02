# Narcissus

## Ringkasan

`chall.py` meminta password dan mematikan proses jika mendeteksi debugger/tracer. Password dibentuk dari SHA-256 potongan source script sendiri yang di-XOR dengan konstanta 32 byte.

## File Challenge

- `chall.py` — script Python obfuscated dan self-checking.
- `solve.py` — script untuk mereproduksi ekstraksi password.

## Analisis Awal

`file chall.py` mengidentifikasinya sebagai script Python UTF-8 executable. Tidak ada flag plaintext yang berguna pada hasil `strings` karena sebagian besar source adalah angka desimal sangat panjang.

## Analisis Static

Alias `md5` sebenarnya menunjuk ke `hashlib.sha256`:

```python
from hashlib import sha256 as md5
```

Program mencari marker desimal panjang di source menggunakan `.index(...)`, mengambil 28823 karakter mulai dari posisi marker, lalu menghitung digest SHA-256:

```python
llIIllII = md5(withopen__file__[IlIlIlIlIl:IlIlIlIlIl+28823].encode()).digest()
```

Anti-debugging dilakukan melalui `sys.gettrace()`, `sys.getprofile()`, `TracerPid` di `/proc/self/status`, modul debugger Python, dan mode interaktif. Ada juga pemeriksaan panjang source `len(withopen__file__) > 29190`.

## Analisis Dynamic

Input password yang salah membuat proses keluar tanpa pesan. Dengan password hasil decoding, program mencetak:

```text
Password? there you go
```

## Algoritma Validasi atau Encoding

Nilai yang dibandingkan adalah:

```python
lIlIl == ''.join(chr(a ^ b) for a, b in zip(llIIllII, mask))
```

Untuk source challenge ini:

- panjang source: `29184`
- panjang slice yang di-hash: `28823`
- digest SHA-256: `22f697e38eab4673c1dd0c22097345e91482d1e24f6bfd07130fcc8eade0d28d`
- mask: `5795e385f5fc7643968255125c2c74d85fb18ed7015fb634265084bae5d4e6f0`

XOR byte-per-byte menghasilkan password/flag yang valid.

## Penyusunan Solve Script

`solve.py` membaca `chall.py`, menemukan marker dengan regex, menghitung SHA-256 pada slice yang sama, lalu melakukan XOR dengan mask hardcoded.

## Cara Menjalankan

```bash
python3 solve.py
python3 chall.py
```

Masukkan output `solve.py` ketika `chall.py` meminta password.

## Flag

`uctf{W00W_Y0U_11K3_5N4K35_H4H44}`

## Catatan

Self-hash membuat perubahan pada `chall.py` dapat mengubah password. Karena itu `solve.py` tidak memodifikasi source challenge.
