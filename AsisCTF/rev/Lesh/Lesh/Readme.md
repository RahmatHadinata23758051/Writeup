# Lesh

## Ringkasan

File `lesh.hex` berisi shellcode x86 Windows dalam bentuk hex ASCII. String flag tidak disimpan langsung sebagai teks. Shellcode membentuk string di stack lewat beberapa `push imm32`, lalu mendekode tiap dword dengan `xor dword ptr [esp+0xc], ecx`.

String pertama yang muncul adalah decoy:

```
ASIS{BorrowwwYourEyess!!!!!}
```

String itu memang terlihat seperti flag, tapi masih diperbaiki oleh beberapa instruksi byte-level setelah proses decode awal. Dua percobaan sebelumnya gagal karena berhenti di string sementara. Klasik sekali: programnya bilang "catch the flag", lalu menaruh ikan plastik di depan muka kita.

## File Challenge

```
lesh.hex  ASCII hex berisi shellcode x86
```

Setelah diubah dari hex ke byte, shellcode diawali pola Windows shellcode umum untuk mencari API melalui PEB. Di bagian awal terlihat pencarian fungsi `Sleep`, lalu di akhir ada pencarian `FatalExit` dan pesan jebakan `SAW FLAG???`.

## Analisis Awal

Konversi hex ke binary menunjukkan shellcode 32-bit. Disassembly awal memperlihatkan resolver API Windows:

```asm
31 d2                 xor edx, edx
b2 30                 mov dl, 0x30
64 8b 12              mov edx, dword ptr fs:[edx]
...
81 3e 53 6c 65 65     cmp dword ptr [esi], 0x65656c53 ; "Slee"
```

Ada trap `jmp $` di offset `0x2a4`:

```asm
0x2a4: eb fe          jmp 0x2a4
```

Jadi shellcode tidak bisa sekadar dijalankan lurus. Trap itu harus dilewati atau diemulasi dengan patch kontrol alur.

## Analisis Static

Bagian pembentuk string utama ada pada rangkaian `push imm32`. Nilai dword yang dipush bukan teks flag langsung. Setelah beberapa push, shellcode menaikkan `esp`, mengisi `ecx`, lalu menjalankan:

```asm
xor dword ptr [esp+0xc], ecx
```

Instruksi ini muncul beberapa kali pada offset berikut:

```
0x0f27
0x0fd7
0x0fe3
0x10a4
0x117e
0x123f
0x124b
```

Jika semua chunk dan key XOR digabungkan, string sementara yang muncul adalah:

```
ASIS{BorrowwwYourEyess!!!!!}
```

String ini bukan flag final.

## Analisis Dynamic

Emulasi jalur eksekusi memperlihatkan bahwa setelah string sementara terbentuk, ada beberapa instruksi kecil yang memperbaiki byte di stack. Instruksi pentingnya:

```asm
0x125a: sub byte ptr [esp-0x5], 0x2a
0x1260: sub byte ptr [esp-0x4], 0x44
0x135d: add byte ptr [esp-0x3], 0x20
0x141f: sub byte ptr [esp-0x2], 0x3f
0x15c7: add byte ptr [esp+0x6], 0x3e
```

Efeknya terhadap string sementara:

```
w -> M
w -> 3
Y -> y
o -> 0
! -> _
```

Setelah semua patch byte diterapkan, string final menjadi:

```
ASIS{BorrowM3y0urEyess_!!!!}
```

## Algoritma Validasi atau Encoding

Tidak ada validasi flag seperti binary crackme biasa. Shellcode hanya membentuk flag di stack sesaat. Algoritmanya:

1. Ambil 7 dword encoded dari instruksi `push imm32`.
2. Ambil 7 dword key dari immediate yang dipakai untuk `ecx`.
3. XOR tiap chunk dengan key untuk membentuk string sementara.
4. Terapkan patch byte dari instruksi stack repair.
5. Ambil hasil akhir sebagai flag.

## Penyusunan Solve Script

`solve.py` membaca `lesh.hex`, mengambil immediate dari offset yang sudah diidentifikasi, menjalankan XOR, lalu menerapkan lima perbaikan byte sesuai instruksi shellcode.

Output script:

```
[transient] ASIS{BorrowwwYourEyess!!!!!}
<FLAG>ASIS{BorrowM3y0urEyess_!!!!}</FLAG>
```

## Cara Menjalankan

```bash
python3 solve.py
```

## Flag

```
ASIS{BorrowM3y0urEyess_!!!!}
```

