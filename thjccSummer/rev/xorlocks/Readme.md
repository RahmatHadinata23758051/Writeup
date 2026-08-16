# Writeup CTF Reverse Engineering — xorlocks

## Informasi Challenge

**Judul:** xorlocks
**Kategori:** Reverse Engineering
**File:** `xorlock`

Challenge memberikan sebuah binary ELF bernama `xorlock`. Program menerima satu argumen berupa password. Jika password salah, program menampilkan:

```text
access denied
```

Jika password benar, program mendekripsi dan mencetak flag.

---

## Recon Awal

Pertama, file dijalankan tanpa argumen:

```bash
./xorlock
```

Output:

```text
usage: ./xorlock <password>
```

Ketika dijalankan dengan input asal:

```bash
./xorlock test
```

Output:

```text
access denied
```

Kemudian dicek menggunakan `strings`:

```bash
strings xorlock
```

Output menarik:

```text
access denied
usage: %s <password>
HT AVS,chd8
\qoOh*>*4
```

Terdapat beberapa string aneh yang kemungkinan merupakan data terenkripsi atau table validasi.

---

## Analisis dengan Radare2

Binary dianalisis menggunakan `radare2`:

```bash
r2 -A xorlock
```

Fungsi utama ditemukan pada:

```text
fcn.00201190
```

Disassembly:

```bash
pdf @ fcn.00201190
```

Pada awal fungsi, program mengecek jumlah argumen:

```asm
cmp edi, 2
jne 0x20123d
```

Artinya program harus dijalankan dengan format:

```bash
./xorlock <password>
```

---

## Cek Panjang Password

Program menghitung panjang `argv[1]` secara manual. Setelah loop selesai, nilai `rcx` dibandingkan dengan `0x15`:

```asm
cmp rcx, 0x15
jne 0x2012ce
```

Karena loop menghitung sampai null byte, nilai `rcx` sama dengan:

```text
strlen(password) + 1
```

Maka:

```text
strlen(password) + 1 = 0x15
strlen(password) = 20
```

Jadi password yang benar harus memiliki panjang **20 karakter**.

---

## Validasi Password

Bagian validasi password berada pada instruksi berikut:

```asm
movzx esi, byte [rax + rdx]
xor sil, 0x5a
add sil, cl
movzx edi, byte [rdx + 0x200150]
cmp sil, dil
jne access_denied
```

Nilai `cl` dimulai dari `0`, lalu bertambah `3` setiap iterasi:

```asm
add cl, 3
```

Sehingga rumus validasi untuk setiap karakter adalah:

```text
((password[i] ^ 0x5a) + 3*i) & 0xff == table[i]
```

Dari rumus tersebut, password bisa dibalik menjadi:

```text
password[i] = ((table[i] - 3*i) & 0xff) ^ 0x5a
```

Table pembanding berada di alamat:

```text
0x200150
```

dan panjangnya 20 byte.

---

## Dekripsi Output Sukses

Setelah password valid, program tidak langsung menyimpan flag plaintext. Program mendekripsi pesan sukses dari data di `.rodata`.

Bagian pentingnya:

```asm
mov eax, 1
mov cl, 0x40

lea edx, [rcx - 0xd]
xor dl, byte [rax + 0x20016f]
mov byte [rsp + rax - 0x21], dl

movzx edx, byte [rax + 0x200170]
xor dl, cl
mov byte [rsp + rax - 0x20], dl

add rax, 2
add cl, 0x1a
```

Loop ini membangun output sepanjang 31 byte. Jadi setelah password benar, flag didekripsi menggunakan XOR sederhana dari data yang berada di sekitar alamat `0x200170`.

---

## Solver

Solver dibuat untuk:

1. Mengambil table password dari alamat `0x200150`.
2. Membalik rumus validasi password.
3. Mengambil data terenkripsi output dari alamat `0x200170`.
4. Mendekripsi pesan sukses.
5. Menjalankan binary dengan password hasil recovery.

```python
#!/usr/bin/env python3
import subprocess
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "./xorlock"

def r2p8(addr, size):
    out = subprocess.check_output(
        ["r2", "-q", "-c", f"p8 {size} @ {addr}", "-c", "q", BIN],
        text=True
    )
    return bytes.fromhex("".join(out.split()))

# Table validasi password
tbl = r2p8("0x200150", 20)

password = bytes(
    (((b - (3 * i)) & 0xff) ^ 0x5a)
    for i, b in enumerate(tbl)
)

print("[+] password =", password.decode(errors="replace"))

# Data terenkripsi untuk output sukses
enc = r2p8("0x200170", 31)

out = []
cl = 0x40

for k in range(16):
    out.append(((cl - 0x0d) & 0xff) ^ enc[2 * k])

    if 1 + 2 * k == 0x1f:
        break

    out.append(enc[2 * k + 1] ^ cl)
    cl = (cl + 0x1a) & 0xff

flag = bytes(out)

print("[+] decrypted output =", flag.decode(errors="replace"))
```

---

## Eksekusi Solver

Jalankan solver:

```bash
python3 solve_xorlock.py ./xorlock
```

Kemudian password hasil recovery digunakan untuk menjalankan binary:

```bash
PW=$(python3 solve_xorlock.py ./xorlock | awk -F'= ' '/password/{print $2}')
./xorlock "$PW"
```

Output:

```text
THJCC{xor_basics_are_not_magic}
```

---

## Flag

```text
THJCC{xor_basics_are_not_magic}
```

---

