# eyes chico

## Ringkasan

Challenge ini berupa PE64 Windows console binary bernama `1983.exe`. Program meminta input dengan prompt `flag>`, lalu mencetak `correct` atau `wrong`.

Flag:

```text
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```

## Analisis

Enumerasi awal menunjukkan binary adalah PE32+ x86-64 hasil build MinGW:

```bash
file 1983.exe
strings -a -n 4 1983.exe
```

String penting yang muncul:

```text
flag>
correct
wrong
```

Disassembly menunjukkan fungsi utama berada di sekitar `0x140002a40`. Fungsi ini tidak langsung membandingkan input dengan string statis. Sebelum membaca input, program menjalankan VM kecil berbasis bytecode dari `.rdata`, mengacak register internal 8 byte, menjalankan beberapa transformasi per-lane, lalu menulis buffer target ke stack.

Bagian pembacaan input berada setelah bytecode VM selesai. Pada alamat `0x140002b94`, program sudah selesai membangun buffer target dan baru akan memanggil `fgets`. Buffer target berada relatif terhadap stack di:

```text
$rsp + 0xbf
```

Panjang input yang diwajibkan adalah `0x71` byte atau 113 karakter. Setelah input dibaca, program membandingkan target hasil VM dengan input:

- 112 byte pertama dibandingkan blok per blok memakai SIMD.
- Byte terakhir dibandingkan lewat operasi XOR tambahan.
- Jika semua byte cocok, program mencetak `correct`.

## Eksploitasi

Karena target flag sudah tersedia di stack sebelum prompt input, cara paling sederhana adalah menghentikan program tepat sebelum `fgets`, lalu dump 113 byte dari `$rsp + 0xbf`.

Breakpoint yang dipakai:

```text
0x140002b94
```

Contoh dump awal:

```text
4d454854
5443213f
33527b46
```

Nilai tersebut adalah dword little-endian, sehingga menjadi:

```text
THEM?!CTF{R3...
```

Script `solve.py` mengotomatisasi langkah ini dengan `winedbg`, mengambil dword dari stack, mengubahnya dari little-endian ke byte string, lalu mencetak 113 byte pertama sebagai flag.

## Verifikasi

Flag hasil ekstraksi dikirim ke binary:

```bash
printf 'THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}\n' | wine ./1983.exe
```

Output:

```text
flag> correct
```
