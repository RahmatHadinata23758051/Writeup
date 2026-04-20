# Writeup - rev/squ1rrel-o-tron

Challenge ini keliatannya simpel dari sisi service (`nc ... 5002`): server ngasih `nonce` 32 byte (hex), kita harus balas 16 byte (hex), 5 ronde, timeout 5 detik. Tapi fungsi `F(nonce)`-nya sengaja disembunyikan.

## 1. Enumerasi awal
Di folder challenge ada dua file:
- `linux.pdf`
- `server.py`

`server.py` cuma kasih skeleton dan jelas bahwa targetnya adalah ngitung `want = F(nonce)`.

Petunjuk penting datang dari PDF: file ini bukan PDF biasa, tapi ada JavaScript besar dengan embedded VM Linux (TinyEMU-style).

## 2. Bongkar isi PDF
Saya ekstrak JavaScript utama dari `linux.pdf` dan dapet beberapa file embedded:
- `kernel-riscv32.bin`
- `bbl32.bin`
- `vm_32.cfg`
- root filesystem (`root/files/...`)

Di rootfs ada binary `/root/chall` (ELF RISC-V kecil, stripped). Ini kandidat kuat implementasi `F`.

## 3. Reverse binary `chall`
`chall` baca tepat 64 hex char (32 byte), proses internal, lalu print 32 hex char (16 byte).

Masalahnya: disassembly nunjukkin 2 instruksi RISC-V yang tidak dikenal tool umum (`funct7=126` dan `funct7=127`), jadi kalau dijalankan di `qemu-riscv32` langsung `SIGILL`.

Awalnya ini terlihat buntu, tapi ternyata opcode custom ini bisa direcover dari **decoder CPU di JavaScript emulator** (yang ada di `linux.pdf`).

## 4. Ambil semantik opcode custom dari decoder asm.js
Saya cari blok `case 51` (opcode OP / R-type) di `asm.js` hasil ekstrak PDF.

Dari situ ketemu:
- `funct7=126` (dengan `funct3=0`) dipakai untuk set state internal global: `state = rs1`.
- `funct7=127` (dengan `funct3=0`) melakukan transform nonlinear berbasis:
  - state global
  - operasi rotasi
  - `imul`
  - S-box 256 byte dari memory initializer emulator

S-box-nya saya ambil dari offset memory yang dipakai decoder (`d[10304 + ...]`).

## 5. Rekonstruksi fungsi F di Python
Setelah semantik opcode jelas, saya translasi 1:1 ke Python:
- parse nonce jadi 8 word little-endian
- inisialisasi state dari word pertama
- loop luar 4096 kali (`+0x19f3dc31` sampai `0x3dc31000`)
- loop dalam 8 word dengan konstanta `0x9f0ce81c`
- apply custom op (funct7=127)
- hasil akhir: ambil 16 byte pertama, hex-encode

## 6. Validasi ke service
Solver berhasil lewat semua 5 ronde dan dapat flag:

`squ1rrel{why_run_l1nux_0n_4_pr1nt3r_wh3n_y0u_c4n_run_l1nux_0n_4_pdf}`

## 7. File akhir
- `solve.py` berisi solver final yang langsung konek ke service dan ambil flag.

Jalankan:

```bash
python3 solve.py
```
