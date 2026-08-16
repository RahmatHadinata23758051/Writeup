# TeaGod.exe

## Ringkasan

Binary `TeaGod.exe` adalah aplikasi Windows GUI x64. Program menampilkan mekanisme worship/click, lalu membuka window reward. Flag tidak disimpan sebagai string plaintext. Reward dibangun dari tiga blok byte terenkripsi di `.rdata`, lalu didecode saat handler tombol worship pada window `TeaGodNote` dijalankan.

Flag yang didapat:

```
THJCC{h77p5://p4s73b1n.com/R58uv133}
```

## File Challenge

```bash
file TeaGod.exe
```

Hasil penting:

```
TeaGod.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 7 sections
```

Section penting:

```
.text   VA 0x140001000, raw 0x400
.rdata  VA 0x140005000, raw 0x4000
.rsrc   VA 0x14000b000, raw 0x7200
```

## Analisis Awal

String UTF-16 di `.rdata` menunjukkan aplikasi GUI bertema worship:

```
TeaGodMain
TeaGodNote
TeaGodReward
TeaGod Worship Protocol
Worship count:
茶神降臨 // CLICK TO WORSHIP
WORSHIP TEA GOD
REWARD UNLOCKED
Your reward:
COPY
WORSHIP REQUEST
```

Import table juga mengarah ke program GUI WinAPI:

```
CreateWindowExW
DrawTextW
FindResourceW
LoadResource
LockResource
SetClipboardData
SetTimer
KillTimer
```

Resource PE berisi satu `RCDATA` besar yang ternyata PNG, dipakai untuk gambar pada window worship. Resource ini bukan flag langsung.

## Analisis Static

Class window yang terdaftar:

- `TeaGodMain` dengan WndProc di `0x1400017a0`
- `TeaGodNote` dengan WndProc di `0x140001d50`
- `TeaGodReward` dengan WndProc di `0x1400026c0`

Handler penting ada di `TeaGodNote`:

```asm
140001dc0: cmp edx, 0x111        ; WM_COMMAND
140001dcc: movzx eax, r8w
140001dd0: cmp eax, 0x1001       ; tombol WORSHIP TEA GOD
140001ddb: inc dword [0x1400080c8]
```

Setelah tombol note diklik, program masuk ke blok decode reward mulai sekitar `0x140001e74`.

Pointer ke data terenkripsi ada di `.rdata`:

```
0x140005210 -> 0x1400051e6
0x140005218 -> 0x1400051f2
0x140005220 -> 0x1400051fe
```

Tiga byte key per blok berada di:

```
0x140005228: a7 3c d1
```

Tiga blok ciphertext masing-masing 12 byte:

```
0x1400051e6: a9 a7 b3 e9 cc f0 ed 48 44 17 52 28
0x1400051f2: 79 9b 50 94 61 9f b1 4b cf 92 d6 97
0x1400051fe: f6 f4 c6 0a cc bd 04 13 d4 e2 e2 59
```

## Analisis Dynamic

Dynamic analysis tidak wajib untuk mendapatkan flag. Static analysis sudah cukup karena routine decode reward terlihat jelas di disassembly dan seluruh konstanta berada di `.rdata`.

## Algoritma Validasi atau Encoding

Program memakai dua tahap decode.

Tahap pertama dilakukan per blok 12 byte:

```
tmp[i] = ((cipher[i] + add_table[i]) & 0xff) ^ block_key
```

`add_table` dari immediate instruction di loop decode:

```
e7 e0 d9 d2 cb c4 bd b6 af a8 a1 9a
```

Tahap kedua memakai qword yang ditaruh ke stack:

```asm
movabs rax, 0x616e7368655f6368
```

Karena little-endian, byte key-nya menjadi:

```
hc_ehsna
```

Index key dimulai dari `rax = 1`, lalu naik `+3` setiap byte:

```
out[i] = tmp[i] ^ b"hc_ehsna"[rax & 7]
rax += 3
```

Ada XOR tambahan dengan satu byte hasil fungsi `0x140002e10`, tetapi byte itu di-XOR dua kali berturut-turut sehingga saling membatalkan dan tidak memengaruhi output akhir.

Hasil decode 36 byte langsung menjadi flag.

## Penyusunan Solve Script

`solve.py` membaca `TeaGod.exe`, mem-parse section PE sederhana, mengambil pointer table dan key dari VA yang ditemukan di disassembly, lalu menjalankan ulang algoritma decode.

Script tidak membutuhkan library eksternal.

## Cara Menjalankan

```bash
cd /mnt/data
python3 solve.py
```

Output:

```
THJCC{h77p5://p4s73b1n.com/R58uv133}
```

## Flag

```
THJCC{h77p5://p4s73b1n.com/R58uv133}
```

