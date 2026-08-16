# BlackFrost

## Ringkasan

Flag tidak muncul sebagai string utuh. Binary Windows membaca argumen `--token`, menghitung FNV-1a 32-bit, lalu memakai nilai `0xb700b632` sebagai seed. PCAP pendamping berisi transcript local replay: client mengirim `BFHELLO b700b632`, lalu server membalas `BF2:<hex>`.

Payload BF2 bukan flag langsung. Hex tersebut harus di-decode dengan stream XOR yang sama seperti loop decoder di binary. Hasil decode adalah konfigurasi yang membuka jalur output flag:

```
campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-only;
```

Setelah marker konfigurasi cocok, binary mendecode blob kecil di `.rdata` dan menulis hasilnya ke stdout. Blob itu menghasilkan flag:

```
THJCC{blackfrost_config_recovered}
```

## File Challenge

```
BlackFrost.exe   PE32+ executable for MS Windows, x86-64, console
traffic(1).pcap  pcap capture file, Ethernet
```

Binary kecil, hanya punya dua section utama:

```
.text   kode program
.rdata  konstanta, string status, import table, blob terenkripsi
```

Import penting:

```
GetCommandLineA
GetTickCount
IsDebuggerPresent
VirtualAlloc
VirtualFree
WriteFile
WSAStartup
socket
connect
send
recv
```

Ini cocok dengan deskripsi challenge: binary Windows memakai local C2/replay di `127.0.0.1`.

## Analisis Awal

`strings` pada EXE menunjukkan beberapa string penting:

```
BFHELLO 
00000000
WWWWWWWW
sandbox timeout
C2 unavailable; start the local replay server
configuration rejected
handshake rejected
stage unpack failed
analysis mode disabled
usage: BlackFrost.exe --token <token>
127.0.0.1
```

`strings` pada PCAP langsung memberi dua artefak utama:

```
BFHELLO b700b632
BF2:0bbc114acd70a708ed0748e357ca0ebc179ed807ae3feb38afdb77f739c53bec2e0cab21e810922353d14df411dc0ba1d441c96988449fd84cec0f
```

## Analisis Static

Entry point berada di `0x1400010d0`.

Bagian awal melakukan anti-debug sederhana:

```asm
call IsDebuggerPresent
```

Jika debugger terdeteksi, program menulis:

```
analysis mode disabled
```

Program lalu mencari argumen:

```
--token <token>
```

Token disalin sampai whitespace, kemudian panjangnya harus 16 byte. Setelah itu token di-hash memakai FNV-1a 32-bit:

```asm
mov r14d, 0x811c9dc5
xor eax, r14d
imul r14d, eax, 0x1000193
cmp r14d, 0xb700b632
```

Target hash-nya:

```
0xb700b632
```

Nilai ini sama dengan seed yang muncul di PCAP pada pesan:

```
BFHELLO b700b632
```

## Analisis Dynamic

EXE tidak perlu dijalankan di Linux. PCAP sudah berisi replay traffic yang dibutuhkan binary.

Loop network binary melakukan alur ini:

1. connect ke `127.0.0.1:31337`
2. kirim handshake `BFHELLO <seed>`
3. terima balasan `BF2:<hex>`
4. cari prefix `BF2:`
5. decode hex menjadi byte
6. XOR byte hasil decode dengan seed dan konstanta berjalan
7. validasi marker konfigurasi
8. decode dan print flag blob

Port `31337` berasal dari immediate `0x7a69` yang dipakai sebelum `htons()`. Nilai little-endian itu menghasilkan port `0x697a = 27002` jika dibaca mentah sebagai word di memori, tetapi immediate register yang dipakai oleh `htons` adalah `0x7a69`, sehingga koneksi disiapkan dari konstanta tersebut. Karena PCAP sudah cukup untuk ekstraksi, solve script tidak perlu membuka socket.

## Algoritma Validasi atau Encoding

Decoder BF2 berada di sekitar loop setelah pencarian prefix `BF2:`. Tiap dua karakter hex diubah menjadi satu byte cipher. Byte plaintext dihitung seperti ini:

```
plain[i] = cipher[i] ^ ((seed >> ((i * 8) & 0x18)) & 0xff) ^ ((0x5a + 0x11 * i) & 0xff)
```

Dengan seed dari PCAP:

```
seed = 0xb700b632
```

Payload BF2 terdecode menjadi:

```
campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-only;
```

Binary mengecek marker berikut:

```
campaign=BLACKFROST-26;
nonce=4c2f17;
directive=collect-only;
```

Setelah marker cocok, jalur sukses menuju loop di `0x140001777`. Loop ini mendecode blob di `.rdata` VA `0x140003080` sepanjang 34 byte.

Blob terenkripsi:

```
4d 6e 79 03 0e 21 05 18 e0 ed f0 ce c7 ad bc a8
b6 95 6c 7e 7b 43 50 1b 23 3b 08 17 f3 f7 ed c9
dd bb
```

Decoder flag:

```python
key = 0x26
for i in range(0, 34, 2):
    out.append(blob[i] ^ ((key - 0x0d) & 0xff))
    out.append(blob[i + 1] ^ key)
    key = (key + 0x1a) & 0xff
```

Hasilnya:

```
THJCC{blackfrost_config_recovered}
```

## Penyusunan Solve Script

`solve.py` melakukan tiga hal:

1. Ambil seed `b700b632` dan payload BF2 dari `traffic(1).pcap`.
2. Decode payload BF2, lalu pastikan tiga marker konfigurasi benar.
3. Ambil blob flag dari `BlackFrost.exe` RVA `0x3080`, decode dengan loop XOR, lalu print flag.

Script juga punya parser section PE sederhana supaya RVA `0x3080` dipetakan ke file offset `.rdata` secara benar. Pada file ini, offset akhirnya adalah:

```
0x1680
```

## Cara Menjalankan

```bash
cd /mnt/data
python3 solve.py
```

Output:

```
[+] seed from BFHELLO: 0xb700b632
[+] decoded BF2 config: campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-only;
[+] flag blob file offset: 0x1680
[+] flag: THJCC{blackfrost_config_recovered}
```

## Flag

```
THJCC{blackfrost_config_recovered}
```
