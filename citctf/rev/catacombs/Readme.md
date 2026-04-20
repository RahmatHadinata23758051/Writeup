# Catacombs (rev) Writeup

Challenge ini ternyata berupa binary interaktif yang memodelkan **state machine** dengan perintah seperti:
- `step <syscall>`
- `script a b c ...`
- `submit`

Dari output `help` dan `hint`, kita dapat petunjuk penting:
- Dibutuhkan syscall tertentu dengan jumlah tertentu (`openat x2`, `read x2`, `mmap x1`, `ioctl x2`, `futex x1`, `clone x1`, `close x1`)
- `close` harus masuk ke `sanctum` dari `sysproxy`
- Ada constraint urutan (dua `openat` mengapit path fork)

## 1. Enumerasi awal
Binary bisa dijalankan langsung dan menampilkan prompt interaktif.

Perintah `status` menunjukkan state internal (node, steps, accumulator).
Perintah `step` menunjukkan transisi node nyata, contoh:
`hook openat -> node 3 (sepulcher)`

Dari sini jelas bahwa challenge berbentuk graph traversal + validasi akhir saat `submit`.

## 2. Reverse cepat
Dengan disassembly simbol lokal:
- `parseOpName`
- `applyVisibleStep`
- `applyStepCore`
- `validate`

`applyVisibleStep` membaca transisi dari `EDGE_TABLE` di `.rodata`.
Artinya setiap syscall dari node tertentu akan pindah ke node lain secara deterministik.

`validate` sendiri di-obfuscate, jadi pendekatan paling stabil adalah oracle-based: jalankan `submit` dan cek apakah output `ACCESS GRANTED`.

## 3. Pencarian urutan valid
Saya brute-force semua permutasi unik dari multiset syscall sesuai hint (total 328396 kandidat unik dieksplor sebelum ketemu solusi).

Urutan yang valid:
- `openat mmap ioctl read futex clone openat ioctl read close`

Saat dikirim via command `script ...` lalu `submit`, outputnya:
- `ACCESS GRANTED: CIT{3R2rA2J0PdFH}`

## 4. Flag
`CIT{3R2rA2J0PdFH}`

## 5. Solver
Solver final disimpan di `solve.py`.
Solver hanya:
1. Menjalankan binary
2. Mengirim urutan syscall valid
3. `submit`
4. Parsing `CIT{...}` dari output

Jalankan:
```bash
python3 solve.py
```
