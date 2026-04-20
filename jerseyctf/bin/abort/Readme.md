# Writeup - Abort (JerseyCTF, PWN)

Challenge ini kelihatannya seperti challenge BOF biasa karena ada `read()`, tapi ternyata yang menarik justru ada di validasi logic input, bukan di overflow.

## 1) Initial Recon

Binary info:
- 64-bit ELF, stripped
- No PIE
- NX enabled
- No canary
- Partial RELRO

`checksec` bikin saya awalnya curiga ke ret2win/ROP, tapi setelah lihat ukuran `read`, ternyata tidak ada overwrite RIP.

## 2) Reverse dari Entry Point

Hint challenge benar: mulai dari entry point.

- Entry ada di `0x401130`.
- Register `rdi` untuk `__libc_start_main` diisi `0x401460`, jadi itu fungsi `main`.

Di `0x401460`:
- Set `signal(SIGALRM, handler)`
- `alarm(0x78)` (120 detik)
- Panggil fungsi utama logic di `0x401365`

## 3) Analisis Fungsi Utama (`0x401365`)

Potongan penting:
- Alokasi stack 0x50 byte
- `memset(buf, 0, 0x50)`
- `read(0, buf, 0x50)`

Validasi setelah input:
1. `*(uint32_t*)(buf+0x40)` masuk ke fungsi `0x401216`, hasilnya harus `0x5a7eab95`
2. `*(uint32_t*)(buf+0x44)` masuk ke fungsi `0x401230`, hasilnya harus `0x6fa08e7e`
3. `buf+0x48` dicek oleh fungsi `0x40124a` (6-byte check dengan XOR)

Kalau semua lolos, dipanggil fungsi sukses (`0x401323`) yang akhirnya manggil:

`system("cat flag.txt")`

## 4) Inversi Persamaan

### Check 1 (`0x401216`)
Rumus fungsi:

`f1(x) = (x ^ 0x4b1d3f29) - 0x6e58d392`

Syarat:

`f1(x) == 0x5a7eab95`

Maka:

`x = (0x5a7eab95 + 0x6e58d392) ^ 0x4b1d3f29 = 0x83ca400e`

### Check 2 (`0x401230`)
Rumus fungsi:

`f2(y) = (y - 0x6bdad9ef) ^ 0x6f6f6f6f`

Syarat:

`f2(y) == 0x6fa08e7e`

Maka:

`y = (0x6fa08e7e ^ 0x6f6f6f6f) + 0x6bdad9ef = 0x6caabb00`

### Check 3 (`0x40124a`)
Fungsi compare 6 byte input dengan byte target yang sudah di-hardcode, setelah tiap byte input di-XOR `0x5c`.
Target bytes yang dibandingkan:

`3d 2e 3f 3d 38 39`

Jadi input 6 byte yang benar:

`target ^ 0x5c` -> `b"arcade"`

Tambahan penting: setelah 6 byte itu, byte berikutnya harus `\x00`.
Karena buffer di-`memset(0)` dulu, cukup kirim payload tanpa newline berlebih supaya byte sesudah `arcade` tetap nol.

## 5) Payload Final

Layout payload:
- `0x40` byte padding
- `p32(0x83ca400e)`
- `p32(0x6caabb00)`
- `b"arcade"`

Total panjang: `0x4e` byte (78 byte)

Kenapa bukan `sendline`?
- Kalau pakai newline, ada risiko `\n` masuk ke byte setelah `arcade` yang harusnya `\x00`, check bisa gagal.

## 6) Exploit Script

Script otomatis ada di:
- `exploit.py`

Mode pakai:
- Local: `python3 exploit.py --local`
- Remote: `python3 exploit.py`

## 7) Flag

`jctf{$UccES5Fully_abOrt3D!_cOnGRATUl@t!0ns}`

