# Angr Management

Kategori: reverse engineering

## Ringkasan

Binary ini adalah maze berbasis control flow. Program selalu mencetak posisi saat ini dengan format `Arrived at N`, lalu membaca angka dari stdin. Kalau angka itu bukan salah satu edge yang valid dari node tersebut, program mencetak `That's not a valid destination` dan keluar.

File lokal berisi flag dummy:

```text
byuctf{test_flag}
```

Jadi targetnya bukan mengambil string dari binary lokal, tapi menemukan rute maze yang benar lalu mengirim rute itu ke service remote.

## Analisis

Proteksi binary:

```text
ELF 64-bit PIE, not stripped
Full RELRO, Canary, NX, PIE
```

Simbol masih tersedia, termasuk `main` dan `get_input`. Fungsi `get_input` memakai `fgets`, lalu `strtol`, sehingga input yang dibutuhkan hanya angka desimal per baris.

Di `main`, tiap node punya pola seperti ini:

```asm
mov    esi, <node_id>
call   printf          ; "Arrived at %d"
call   get_input
cmp    [rbp-0x4], <destination>
je/jmp <block node tujuan>
```

Saya ekstrak semua blok `Arrived at N`, lalu membuat graf dari setiap `cmp input, X` menuju alamat blok target. Ada 624 node normal. Satu edge terakhir tidak menuju node normal, tetapi ke blok yang mencetak flag. Edge tersebut adalah dari node `329` dengan input `624`.

Rute dari node awal `0` ke blok flag:

```text
256 423 495 307 39 250 391 119 105 499 123 104 536 257 608 253 74 365 543 300 571 506 595 192 383 112 17 556 93 318 114 276 18 216 449 414 124 503 71 407 78 285 481 66 381 531 82 337 600 86 230 327 472 393 348 331 14 207 402 548 528 168 530 490 378 408 518 202 87 342 329 624
```

## Eksploitasi

Solver cukup mengirim semua angka rute tersebut, masing-masing dipisah newline, ke service remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output remote:

```text
byuctf{g3t_w1th_th3_c0ntr01_fl0w}
```

## Flag

```text
byuctf{g3t_w1th_th3_c0ntr01_fl0w}
```
