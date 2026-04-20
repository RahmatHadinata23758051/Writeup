# Writeup - Say My Name (rev)

Challenge ini berupa satu file ELF 64-bit bernama `saymyname`.

## 1. Enumerasi awal

Langkah pertama yang saya lakukan:

```bash
ls -la
file saymyname
```

Hasil penting:
- Binary ELF 64-bit, statically linked
- Tidak di-strip (simbol masih ada), jadi reversing jadi jauh lebih mudah

Program saat dijalankan menampilkan:

```text
Say My Name.
Name:
```

Kalau input salah, output:

```text
nah wrong guy
```

## 2. Cari petunjuk dari simbol dan string

Saya cek simbol dan string yang relevan:

```bash
readelf -sW saymyname | rg ' main$|validate|flag|name'
strings -n 4 saymyname | rg 'Say My Name|wrong|flag|CIT\{'
```

Dari sini terlihat:
- Ada fungsi `main`
- Ada fungsi `validate`
- Ada string flag yang terlihat di binary

Karena challenge rev, string flag saja belum cukup. Saya tetap validasi alur program untuk memastikan cara mendapatkannya benar.

## 3. Reversing fungsi main

Saya disassemble `main`:

```bash
objdump -d --no-show-raw-insn -Mintel saymyname --start-address=0x407e0e --stop-address=0x408100
```

Dari disassembly terlihat pola berikut:
1. Program print banner dan prompt
2. Input dibaca dengan `getline`
3. Input dibandingkan dengan string konstan di address `.rodata` (`0x576d00`)
4. Jika sama, panggil `validate` lalu print hasilnya
5. Jika beda, print `nah wrong guy`

Berarti kunci challenge adalah menemukan string pembanding di `.rodata`.

## 4. Ambil string nama yang benar dari .rodata

Saya dump rodata di sekitar alamat yang dipakai `main`:

```bash
objdump -s --start-address=0x576ce0 --stop-address=0x576e20 saymyname
```

Didapat string nama target:

```text
Bartholomew Demetrius Jamarion Kensington Blackwood Montague Devereaux Jackson-Fitzwilliam the XXVII
```

Di area yang sama terlihat juga string sukses yang memuat flag.

## 5. Validasi runtime

Saya jalankan binary dengan nama tersebut:

```bash
./saymyname
```

Input:

```text
Bartholomew Demetrius Jamarion Kensington Blackwood Montague Devereaux Jackson-Fitzwilliam the XXVII
```

Output sukses:

```text
yeah that me. heres your flag CIT{Zn583Umnwd4S}
```

Jadi flag tervalidasi dari jalur eksekusi program.

## 6. Solver otomatis

Saya buat `solve.py` yang:
- Menjalankan binary `saymyname`
- Mengirim nama valid
- Mengekstrak pola `CIT{...}` dari output
- Print flag

Jalankan dengan:

```bash
python3 solve.py
```

Output:

```text
CIT{Zn583Umnwd4S}
```

## Flag

`CIT{Zn583Umnwd4S}`
