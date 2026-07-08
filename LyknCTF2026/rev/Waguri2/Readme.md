# Waguri2

**Category:** Reverse Engineering  
**Flag:** `LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}`

## Ringkasan

File challenge berisi 23.000 nama karakter yang dipisahkan spasi. Hanya ada tujuh token unik, jadi bentuknya cocok dengan Brainfuck tanpa instruksi output (`.`).

Setelah token diterjemahkan, program membaca 34 byte. Sesudah setiap byte terdapat loop yang tidak pernah mengubah sel pengendalinya. Loop tersebut hanya bisa dilewati kalau hasil pemeriksaan byte saat itu sama dengan nol.

Solver mencoba seluruh nilai `0x00` sampai `0xff` pada setiap posisi, menjalankan interpreter sampai loop jebakan berikutnya, lalu menyimpan satu-satunya kandidat yang membuat sel kontrol bernilai nol.

## Pemetaan token

| Token | Brainfuck | Fungsi |
|---|---:|---|
| `usami_shohei` | `>` | Geser pointer ke kanan |
| `natsusawa_saku` | `<` | Geser pointer ke kiri |
| `waguri_kaoruko` | `+` | Tambah nilai sel |
| `tsumugi_rintaro` | `-` | Kurangi nilai sel |
| `yorita_ayato` | `[` | Awal loop |
| `hoshina_subaru` | `]` | Akhir loop |
| `kaoru_hana` | `,` | Baca satu byte input |

Pemetaan ini bisa diturunkan dari struktur token:

- `yorita_ayato` dan `hoshina_subaru` masing-masing muncul 1.310 kali dan membentuk pasangan kurung yang valid.
- `usami_shohei` dan `natsusawa_saku` masing-masing muncul 5.893 kali. Jumlah yang seimbang cocok dengan pergerakan pointer yang selalu kembali ke sel awal.
- `kaoru_hana` muncul 34 kali dan selalu berada di batas antarblok pemeriksaan, sehingga jelas berperan sebagai input.
- Dua token tersisa menjadi operasi `+` dan `-`. Orientasi di atas menghasilkan flag ASCII valid dan pola zeroing Brainfuck yang normal seperti `++[--]`.

## Loop jebakan

Ada tepat 34 loop yang tubuhnya kembali ke pointer awal tanpa menyentuh sel kontrol. Beberapa bentuknya:

```brainfuck
[><]
[>+[-]<]
[>>+[-]<<]
[>>>++[--]<<<]
```

Ambil contoh `[>+[-]<]`:

1. Pointer pindah ke kanan.
2. Sel sementara dinaikkan lalu dikosongkan dengan `[-]`.
3. Pointer kembali ke sel kontrol.
4. Nilai sel kontrol tidak berubah.

Kalau sel kontrol bukan nol, kondisi `[` selalu benar dan loop berulang selamanya. Program hanya lanjut ketika hasil perhitungan sebelum loop tepat nol.

Pemeriksaan semacam ini muncul satu kali setelah masing-masing instruksi input. Artinya setiap karakter dapat dipulihkan secara berurutan tanpa menebak format flag.

## Strategi solver

1. Ubah seluruh nama karakter menjadi source Brainfuck.
2. Bangun jump table untuk seluruh pasangan `[` dan `]`.
3. Analisis setiap loop dan tandai loop yang:
   - pointer akhirnya kembali ke posisi awal; dan
   - tidak pernah mengubah sel pada offset `0`.
4. Jalankan program sampai instruksi input.
5. Untuk posisi saat ini, coba seluruh byte `0..255`.
6. Kandidat valid harus mencapai loop jebakan dengan nilai sel kontrol `0`.
7. Lewati loop tersebut, simpan state tape, lalu lanjut ke input berikutnya.
8. Pastikan selalu ada tepat satu kandidat pada setiap posisi dan program berakhir setelah byte ke-34.

Sel Brainfuck dimodelkan sebagai unsigned 8-bit, jadi operasi `+` dan `-` menggunakan wraparound modulo 256.

## Menjalankan solver

```bash
python3 solve.py 'output(5).txt'
```

Output akhirnya:

```text
[00] 0x4c 'L'
[01] 0x59 'Y'
[02] 0x4b 'K'
...
[33] 0x7d '}'

FLAG: LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}
```

## Flag

```text
LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}
```
