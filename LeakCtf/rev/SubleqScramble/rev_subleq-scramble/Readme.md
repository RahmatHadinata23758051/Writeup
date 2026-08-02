# Subleq Scramble — Writeup

**Flag**

```text
L3AK{L4NGT?N'S4NT_SCR4MBL3RRR_10,000}
```

---

## Recon

Challenge diberikan dalam bentuk arsip:

```bash
tar -tzf rev_subleq-scramble.tar.gz
```

Output:

```text
rev_subleq-scramble/data.subleq
```

Setelah diekstrak, file tersebut bukan merupakan format gambar umum.

```bash
file rev_subleq-scramble/data.subleq
stat -c%s rev_subleq-scramble/data.subleq
```

Output penting:

```text
data
6912
```

Ukuran file adalah **6912 byte**, yang berarti dapat dibaca sebagai **3456 word 16-bit little-endian**.

```python
words = struct.unpack("<" + "H" * (len(blob) // 2), blob)
```

Dari isi memory terlihat bahwa bagian awal berisi program **SUBLEQ** dalam bentuk triplet `(a, b, c)`, sedangkan sisanya merupakan data dan state program.

---

## Decoy

Di area memory terdapat string yang tampak seperti flag.

```python
for w in words[195:252]:
    v = s16(w)
    if v < 0:
        print(chr(-v), end="")
```

Output:

```text
Ant out of bounds:
L3AK{it-encrypts-images-not-text}
```

String tersebut hanyalah pesan **error/out-of-bounds**, bukan flag sebenarnya.

Petunjuk dari judul dan deskripsi challenge menyebutkan bahwa program mengenkripsi **image**, lalu melakukan dump terhadap seluruh state. Artinya flag asli harus direkonstruksi dari image yang tersimpan di memory, bukan dari string tersebut.

---

## Layout Memory

Beberapa cell memberikan informasi mengenai posisi buffer image.

| Cell | Value | Keterangan |
|------:|------:|------------|
| 255 | 1 | `dx` akhir |
| 256 | 0 | `dy` akhir |
| 257 | -9999 | konstanta loop (10000 step) |
| 258 | 80 | posisi `x` akhir |
| 259 | 32 | posisi `y` akhir |
| 261 | 84 | lebar image |
| 262 | 38 | tinggi image |
| 263 | 264 | offset awal buffer image |

Buffer image dimulai dari cell **264**.

```
84 × 38 = 3192 cells
264 + 3192 = 3456 cells
```

Jumlah tersebut tepat sama dengan total ukuran memory dump, sehingga seluruh word setelah offset 264 merupakan bitmap biner.

---

## Memahami Program SUBLEQ

Instruksi SUBLEQ dijalankan dalam bentuk triplet:

```text
mem[b] -= mem[a]

if mem[b] <= 0:
    pc = c
else:
    pc += 3
```

Setelah mengikuti alur program, logika utamanya dapat disederhanakan menjadi:

```python
pixel = img[y][x]

if pixel == 0:
    img[y][x] = 1
    dx, dy = -dy, dx
else:
    img[y][x] = 0
    dx, dy = dy, -dx

x -= dx
y -= dy
```

Perilaku ini identik dengan **Langton's Ant**, hanya saja perpindahan posisi menggunakan:

```python
x -= dx
y -= dy
```

bukan:

```python
x += dx
y += dy
```

---

## Reverse State

Memory dump diberikan setelah **10000 langkah**, sehingga proses simulasi harus dibalik.

State akhir:

```text
x  = 80
y  = 32
dx = 1
dy = 0
```

Karena pada proses forward berlaku:

```text
x_new = x_old - dx_new
y_new = y_old - dy_new
```

maka posisi sebelumnya adalah:

```python
prev_x = x + dx
prev_y = y + dy
```

Pixel pada posisi tersebut sudah mengalami flip, sehingga warna sebelumnya dapat diperoleh dengan:

```python
old_color = 1 - img[prev_y][prev_x]
```

Kemudian arah semut dibalik menggunakan aturan invers:

```python
if old_color == 0:
    old_dx, old_dy = dy, -dx
else:
    old_dx, old_dy = -dy, dx
```

Langkah tersebut diulang sebanyak **10000 kali** hingga diperoleh image awal.

---

## Hasil Rekonstruksi

Image hasil reverse menampilkan tulisan berikut:

```text
L3AK{
L4NGT?N'S4NT_
SCR4MBL3RRR_
10,000
}
```

Jika seluruh baris digabung sesuai format flag, diperoleh:

```text
L3AK{L4NGT?N'S4NT_SCR4MBL3RRR_10,000}
```

---

## Flag

```text
L3AK{L4NGT?N'S4NT_SCR4MBL3RRR_10,000}
```
