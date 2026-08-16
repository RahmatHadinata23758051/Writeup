# Badge Check

## Ringkasan

File utama adalah executable Windows PE64 bernama `badgecheck.exe`. Program ini sangat kecil: entrypoint hanya menulis teks ke stdout menggunakan `WriteFile`, kemudian memanggil `ExitProcess`.

Bagian yang berguna bukan validasi input pada kode program, melainkan resource `.rsrc` yang menyimpan gambar badge dalam format PNG.

Di dalam gambar badge terdapat barcode **PDF417**. Barcode tersebut masih dapat dibaca walaupun badge berstatus `REVOKED`. Hasil decode PDF417 berisi data staf beserta field `FLAG`.

## File Challenge

```text
badgecheck.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 5 sections
```

Hash file:

```text
7107a782a8c80a69a4b45dc304c33cdedc2565a5ae5da4fda28da5e042a2c915  badgecheck.exe
```

File hasil ekstraksi dan solve:

```text
extracted_badge.png
solve.py
```

## Analisis Awal

Enumerasi awal dilakukan menggunakan:

```bash
file *
strings -a ./badgecheck.exe | head -n 100
objdump -x ./badgecheck.exe
objdump -d -M intel ./badgecheck.exe
```

Beberapa temuan penting dari `strings`:

```text
scanning badge...
access denied
KERNEL32.dll
GetStdHandle
WriteFile
ExitProcess
IHDR
IDAT
```

Kemunculan string `IHDR` dan `IDAT` mengindikasikan adanya data PNG yang tertanam di dalam binary.

Flag tidak ditemukan secara langsung melalui `strings`, sehingga flag bukan plain string yang disimpan di PE.

## Analisis Static

Header PE menunjukkan bahwa resource directory aktif:

```text
Entry 2 0000000000005000 00013ab1 Resource Directory [.rsrc]
```

Resource leaf yang relevan:

```text
Leaf: Addr: 0x005058, Size: 0x013a59, Codepage: 0
```

Section `.rsrc` memiliki file offset `0x0c00` dan RVA `0x5000`. Dengan demikian, resource PNG berada pada file offset:

```text
0x0c00 + (0x5058 - 0x5000) = 0x0c58
```

Byte pada offset tersebut diawali dengan signature PNG:

```text
89 50 4e 47 0d 0a 1a 0a
```

Hal ini mengonfirmasi bahwa terdapat file PNG yang tertanam di dalam executable.

### Disassembly Entry Point

Disassembly entrypoint juga sangat sederhana:

```asm
sub    rsp,0x28
mov    ecx,0xfffffff5
call   GetStdHandle
lea    rdx,[rip+0xfe7]
mov    r8d,0x22
call   WriteFile
xor    ecx,ecx
call   ExitProcess
```

Import table hanya memuat:

```text
GetStdHandle
WriteFile
ExitProcess
```

Tidak ditemukan routine yang melakukan validasi terhadap input atau flag. Dengan demikian, fokus analisis dapat dipindahkan sepenuhnya ke resource gambar badge.

## Analisis Dynamic

Dynamic analysis tidak diperlukan untuk memperoleh flag.

Dari disassembly dan `strings` sudah terlihat bahwa binary hanya menampilkan pesan scanner melalui `WriteFile`, kemudian keluar menggunakan `ExitProcess`.

Data yang sebenarnya berguna berada di resource PNG, bukan pada output runtime program.

## Mekanisme Encoding

Tidak terdapat algoritma validasi flag di bagian `.text`.

Mekanisme challenge adalah menyembunyikan data melalui resource gambar:

1. Executable membawa sebuah PNG di section `.rsrc`.
2. PNG diekstrak dari signature PNG hingga chunk `IEND`.
3. Gambar badge berisi barcode PDF417.
4. Barcode PDF417 didecode menggunakan ZXing.
5. Hasil decode berisi informasi staf dan field `FLAG`.

Hasil decode barcode:

```text
USER=STAFF-0241
NAME=MICHAEL RIVERA
DEPT=FACILITIES
STATUS=REVOKED
FLAG=ThryveCTF{badge_revoked_but_still_talks}
```

Menariknya, status badge adalah `REVOKED`, tetapi barcode masih menyimpan flag sehingga data tetap dapat diekstrak.

## Penyusunan Solve Script

`solve.py` melakukan dua tahap utama.

### 1. Ekstraksi PNG

Script membaca `badgecheck.exe`, mencari signature:

```text
89 50 4e 47 0d 0a 1a 0a
```

Setelah menemukan awal PNG, script mengambil data hingga chunk `IEND`, kemudian menyimpannya sebagai:

```text
extracted_badge.png
```

### 2. Decode PDF417

PNG kemudian dibuka sebagai grayscale dan diproses menggunakan local `libZXing.so.3` melalui `ctypes` untuk melakukan decoding format PDF417.

Setelah mendapatkan hasil decode, script mencari pola flag:

```python
re.search(r"ThryveCTF\{[^}\n]+\}", decoded)
```

## Cara Menjalankan

Dari folder challenge:

```bash
python3 solve.py
```

Output:

```text
USER=STAFF-0241
NAME=MICHAEL RIVERA
DEPT=FACILITIES
STATUS=REVOKED
FLAG=ThryveCTF{badge_revoked_but_still_talks}
ThryveCTF{badge_revoked_but_still_talks}
```

## Flag

```text
ThryveCTF{badge_revoked_but_still_talks}
```

