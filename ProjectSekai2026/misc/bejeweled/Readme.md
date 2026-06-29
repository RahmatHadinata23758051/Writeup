# Bejeweled

## Challenge

**Category:** Misc
**Description:**

> The stage is yours. Clear the board before the final note fades.

Connection:

```bash
socat -,raw,echo=0 tcp:bejeweled.chals.sekai.team:1337
```

Flag:

```text
SEKAI{th3_l4st_d4nc3_By_eana}
```

---

## Overview

Challenge ini menampilkan game Bejeweled berbasis terminal. Pemain harus menukar dua gem yang bersebelahan agar membentuk minimal tiga simbol yang sama secara horizontal atau vertikal.

Target skor bertambah setiap level:

```text
Level 1 → 2500
Level 2 → 5000
Level 3 → 7500
Level 4 → 10000
```

Masalahnya, seluruh permainan harus diselesaikan dalam sekitar 45 detik. Bermain manual tidak cukup cepat, sehingga dibutuhkan autosolver.

---

## Initial Analysis

Ketika service dibuka menggunakan `socat`, server mengirim antarmuka terminal penuh dengan ANSI escape sequence.

Tampilan awal berisi tombol:

```text
[ Start ]
```

Setelah tombol ditekan, muncul board berukuran:

```text
12 baris × 7 kolom
```

Gem yang digunakan:

```text
▲  ♢  ◼  ♣  ♠  ●  ♡
```

Server juga mengaktifkan mouse tracking pada terminal. Artinya input bukan berupa koordinat teks biasa, tetapi event mouse terminal.

Contoh event klik menggunakan SGR mouse protocol:

```python
press = f"\x1b[<0;{x};{y}M"
release = f"\x1b[<0;{x};{y}m"
```

Karena service memakai antarmuka terminal interaktif, solver perlu melakukan dua pekerjaan:

1. Mengemulasikan terminal untuk membaca board.
2. Mengirim event klik mouse untuk menukar gem.

---

## Terminal Emulation

Library `pyte` digunakan untuk memproses ANSI escape sequence dari server.

```python
import pyte

screen = pyte.Screen(80, 25)
stream = pyte.Stream(screen)
stream.feed(data.decode(errors="ignore"))
```

Isi terminal kemudian dapat dibaca melalui:

```python
lines = list(screen.display)
```

Dari setiap baris, solver mencari tujuh simbol gem.

Mapping simbol:

```python
GEMS = {
    "♣": "C",
    "●": "O",
    "♢": "D",
    "♡": "H",
    "♠": "S",
    "▲": "T",
    "◼": "Q",
}
```

Sempat terdapat bug pada parser karena karakter kotak yang muncul adalah:

```text
◼
```

bukan:

```text
■
```

Akibatnya parser hanya mendeteksi enam gem per baris dan gagal mengenali board. Setelah `◼` ditambahkan ke mapping, board berhasil dibaca.

---

## Starting the Game

Tombol `Start` juga harus ditekan menggunakan mouse terminal.

Solver mencoba beberapa mouse protocol karena terminal server dapat menggunakan mode yang berbeda:

* SGR
* X10
* URXVT

Contoh fungsi klik SGR:

```python
def click_sgr(io, x, y):
    io.send(f"\x1b[<0;{x};{y}M".encode())
    io.send(f"\x1b[<0;{x};{y}m".encode())
```

Posisi tombol dicari dari layar virtual:

```python
position = line.find("Start")
```

Setelah board muncul, koordinat terminal setiap gem disimpan. Dengan begitu solver dapat mengubah koordinat board seperti `R4C5` menjadi koordinat terminal sebenarnya.

---

## Finding Valid Moves

Untuk setiap sel, solver mencoba swap ke kanan dan ke bawah.

```python
neighbours = [
    (row, col + 1),
    (row + 1, col),
]
```

Setelah dua gem ditukar secara lokal, solver memeriksa apakah terbentuk rangkaian minimal tiga simbol yang sama.

Pencarian horizontal:

```python
for row in range(ROWS):
    col = 0

    while col < COLS:
        end = col + 1

        while end < COLS and board[row][end] == board[row][col]:
            end += 1

        if end - col >= 3:
            for current in range(col, end):
                matches.add((row, current))

        col = end
```

Pencarian vertikal dilakukan dengan metode yang sama.

Swap dianggap valid apabila salah satu dari dua sel yang ditukar menjadi bagian dari match.

---

## Move Selection

Versi awal solver memilih langkah berdasarkan jumlah gem yang langsung hilang.

```python
score = len(matched_cells) * 100
```

Solver juga memberikan nilai tambahan untuk pola silang karena berpotensi menghasilkan match lebih besar.

```python
if horizontal and vertical:
    score += 500
```

Setiap iterasi:

1. Baca board.
2. Cari seluruh swap valid.
3. Pilih move dengan skor tertinggi.
4. Klik gem pertama.
5. Klik gem kedua.
6. Tunggu board berubah.
7. Ulangi.

Contoh output:

```text
[+] move=001 level=1 score=0 time=1 R8C3<->R9C3
[+] move=002 level=1 score=105 time=1 R3C4<->R3C5
[+] move=003 level=1 score=180 time=2 R3C6<->R4C6
```

---

## Performance Problem

Solver pertama sebenarnya bekerja, tetapi terlalu lambat.

Run awal berhenti pada:

```text
Level: 4
Score: 9450
Time: 44
```

Target terakhir adalah 10000, sehingga solver hanya kekurangan sekitar 550 poin.

Penyebab utama perlambatan:

* Polling terminal terlalu lama.
* `pyte.screen.display` merender seluruh layar setiap iterasi.
* Delay mouse terlalu besar.
* Output setiap move dicetak melalui terminal dan `tee`.

Beberapa interval kemudian diperkecil:

```python
time.sleep(0.01)   → time.sleep(0.002)
game.pump(0.025)   → game.pump(0.008)
```

Ukuran layar virtual juga diperkecil:

```python
TERM_WIDTH = 80
TERM_HEIGHT = 25
```

Selain itu, output solver diarahkan ke file agar render terminal tidak menjadi bottleneck:

```bash
python3 solve.py > run.log 2>&1
```

---

## Connection Issues

Service terkadang menolak koneksi karena banyak percobaan dalam waktu singkat.

Contoh error:

```text
Could not connect to 136.68.41.243 on port 1337
```

DNS service mengarah ke:

```text
136.68.41.243
```

Koneksi diuji langsung menggunakan Python:

```python
import socket

with socket.create_connection(
    ("136.68.41.243", 1337),
    timeout=8,
) as sock:
    print(sock.recv(1024))
```

Output:

```python
b'\x1b[?1049h\x1b[H\x1b[2J'
```

Byte tersebut menunjukkan bahwa service aktif dan sedang mengirim ANSI escape sequence untuk alternate screen.

Agar tidak terkena connection limit, solver menunggu beberapa detik sebelum retry.

---

## Execution

Solver dijalankan menggunakan:

```bash
source /home/nata/ctf_env/bin/activate
pip install pwntools pyte
python3 solve.py > run.log 2>&1
```

Kemudian flag dicari dari log:

```bash
grep -oE 'SEKAI\{[^}]+\}' run.log
```

Setelah solver berhasil melewati skor 10000 sebelum timer habis, server mengirim flag.

---

## Flag

```text
SEKAI{th3_l4st_d4nc3_By_eana}
```

##
