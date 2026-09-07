# Writeup CTF: purgatory

- **Kategori:** Reverse Engineering
- **Tingkat Kesulitan:** Hard
- **Artefak:** `old.beam`, `new.beam`, `purgatory_runner.erl`
- **Platform:** Erlang BEAM / Hot Code Upgrade
- **Flag:** `NNS{50f7_purge_WoUlD_HaV3_Real1Y_54v3d_You_7H3re}`

---

# 1. Deskripsi Tantangan

Challenge menggunakan dua file Erlang BEAM:

```
old.beam
new.beam
```

Validator dijalankan melalui mekanisme hot patch Erlang.

Runner melakukan urutan:

```
1. Load old.beam

2. Spawn worker:
   purgatory:boot()

3. Load new.beam

4. Worker menerima input passphrase

5. Worker mengirim verdict
```

Karena proses upgrade terjadi setelah worker dibuat, sebagian logic tetap berasal dari kode lama, sedangkan external call dapat berpindah ke kode baru.

Tujuan challenge adalah menemukan passphrase valid yang membuat service memberikan verdict:

```
true
```

Jika berhasil, service akan mencetak:

```
os:getenv("FLAG")
```

---

# 2. File Challenge

File yang diberikan:

```
Dockerfile

compose.yaml

entrypoint.sh

purgatory_runner.erl

run.sh

releases/
 ├── old.beam
 └── new.beam
```

---

# 3. Analisis Runner

File:

```
purgatory_runner.erl
```

menunjukkan alur utama:

```erlang
load(old.beam),

Worker = purgatory:boot(),

load(new.beam)
```

Kemudian worker menerima:

```
passphrase>
```

dan melakukan validasi.

Jika hasil validasi:

```erlang
true
```

maka program mencetak:

```erlang
os:getenv("FLAG")
```

Sehingga target reversing bukan mencari flag langsung, tetapi menemukan passphrase yang benar.

---

# 4. Analisis Awal Binary

Identifikasi file:

```
file old.beam

file new.beam
```

menunjukkan keduanya adalah:

```
Erlang BEAM file
```

---

# 5. String Analysis

Hasil:

```bash
strings old.beam
strings new.beam
```

menampilkan atom penting:

```
boot

loop

check

validate

first_half

second_half

mask

lists:nth

bxor

*

+

band

=:=

binary:at
```

Tidak ditemukan flag langsung.

Validator menggunakan:

- byte input
- konstanta hardcoded
- operasi aritmetika
- XOR mask

---

# 6. Analisis Static BEAM

Erlang BEAM menyimpan literal pada chunk:

```
LitT
```

Chunk tersebut berisi tabel validator.

Struktur:

```
{Index, A, B, C}
```

Setiap rule menggunakan fungsi:

```
safe
```

dengan operasi:

\[
((byte \times A)+B)\&0xff=C
\]

atau:

```python
((byte * A) + B) & 0xff == C
```

---

# 7. Analisis First Half

Tabel dari:

```
old.beam
```

menghasilkan rule:

```
{Index,A,B,C}
```

Setelah dibalik, byte yang valid menghasilkan:

```
0ld_c0d3_w1n5
```

Karena worker pertama kali dibuat dari:

```
old.beam
```

maka validasi awal tetap menggunakan:

```
old first_half
```

---

# 8. Analisis Hot Patch

Runner melakukan:

```
load(old.beam)

spawn worker

load(new.beam)
```

Hal penting terdapat pada pemanggilan:

```
purgatory:second_half/2
```

Pemanggilan tersebut merupakan:

```
external call
```

pada module yang sama.

Dalam Erlang hot code loading, external call akan diarahkan ke versi module terbaru.

Akibatnya:

```
first_half
```

tetap dari:

```
old.beam
```

tetapi:

```
second_half
```

berasal dari:

```
new.beam
```

---

# 9. Validasi Sebenarnya

Kombinasi validator yang digunakan:

```
old first_half

+

new second_half

+

old mask
```

Bukan:

```
full old
```

atau:

```
full new
```

---

# 10. Analisis Second Half

Second half menggunakan tabel dari:

```
new.beam
```

Rule:

```python
safe(
    input[i] ^ old_mask[i-13],
    A,
    B,
    C
)
```

atau:

\[
((input[i]\oplus mask)\times A+B)\&255=C
\]

---

# 11. Algoritma Recovery

Passphrase dapat diperoleh karena operasi bersifat deterministik.

Langkah:

1. Extract:
   
```
OLD_FIRST
```

2. Extract:

```
NEW_SECOND
```

3. Extract:

```
OLD_MASK
```

4. Untuk setiap posisi:

```
brute force byte 0..255
```

5. Cari byte yang memenuhi:

```python
((byte*A)+B)&0xff == C
```

6. Susun seluruh karakter.

---

# 12. Hasil Recovery

Hasil pembalikan rule:

```
0ld_c0d3_w1n5_1n_th3_3nd!
```

Passphrase:

```
0ld_c0d3_w1n5_1n_th3_3nd!
```

---

# 13. Solve Script

File:

```
solve_purgatory.py
```

melakukan:

1. Membaca tabel validator.
2. Menyimpan:

```
OLD_FIRST
NEW_SECOND
OLD_MASK
```

3. Membalik rule safe.
4. Membentuk passphrase.
5. Jika diberikan host dan port, mengirim passphrase ke remote service.

Struktur:

```python
#!/usr/bin/env python3


def solve_rule(A, B, C):

    for x in range(256):

        if ((x*A)+B) & 0xff == C:

            return x



first = recover_old_first()

second = recover_new_second()

password = first + second


print(
    password.decode()
)
```

---

# 14. Cara Menjalankan

## Local Recovery

```bash
python3 solve_purgatory.py
```

Output:

```text
passphrase = 0ld_c0d3_w1n5_1n_th3_3nd!
```

---

## Remote Service

```bash
python3 solve_purgatory.py HOST PORT
```

Script mengirim passphrase valid kemudian membaca response.

---

# 15. Flag

Passphrase valid:

```
0ld_c0d3_w1n5_1n_th3_3nd!
```

Setelah dikirim ke remote service:

```
NNS{50f7_purge_WoUlD_HaV3_Real1Y_54v3d_You_7H3re}
```

---

# 16. Kesimpulan

Challenge ini memanfaatkan fitur:

```
Erlang Hot Code Upgrade
```

Kesalahan utama bukan pada algoritma byte validation, tetapi pada asumsi bahwa seluruh logic berasal dari satu versi module.

Karena:

```
old.beam
```

sudah berjalan sebelum patch, tetapi:

```
purgatory:second_half/2
```

merupakan external call, maka fungsi tersebut berpindah ke:

```
new.beam
```

Validator akhir adalah gabungan:

```
old first_half
+
new second_half
+
old mask
```

Dengan melakukan ekstraksi literal BEAM dan membalik operasi byte, passphrase berhasil diperoleh.

Flag:

```
NNS{50f7_purge_WoUlD_HaV3_Real1Y_54v3d_You_7H3re}
```
