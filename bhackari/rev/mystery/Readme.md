# Writeup Mystery CTF

## 1. Initial Enumeration
Challenge ini memberikan dua file:
- `mystery.so`: Sebuah shared library (Python extension module).
- `flag.enc`: Data terenkripsi yang berisi flag.

Dengan menggunakan perintah `nm -D`, kita bisa melihat bahwa `mystery.so` mengekspor fungsi `PyInit_mystery`, yang menunjukkan bahwa ini adalah modul Python.

Setelah mengimpor modul tersebut di Python, kita menemukan beberapa fungsi menarik:
- `easy_access()`: Memberikan flag palsu/troll.
- `get_runtime_info()`: Memberikan informasi runtime (noise dan table0).
- `stage(index, value)`: Fungsi untuk mengirimkan nilai untuk 4 tahapan trial.
- `reveal()`: Fungsi untuk menampilkan flag asli jika ke-4 tahapan sudah diselesaikan dengan benar.

## 2. Reverse Engineering
Analisis disassembly pada fungsi `stage` menunjukkan bahwa setiap tahapan (1-4) divalidasi dengan memanggil fungsi internal tertentu:
- Stage 1 memanggil fungsi di offset `0x31ec`.
- Stage 2 memanggil fungsi di offset `0x3271`.
- Stage 3 memanggil fungsi di offset `0x3304`.
- Stage 4 memanggil fungsi di offset `0x33ef`.

Setiap fungsi pembantu ini bersifat deterministik namun bergantung pada tabel internal yang diinisialisasi saat runtime (berdasarkan hash SHA256 dari file `mystery.so` itu sendiri) dan beberapa nilai lainnya (seperti CRC32 dari file).

## 3. Exploitation Strategy
Karena fungsi-fungsi pembantu tersebut ada di dalam library dan bersifat deterministik, kita bisa langsung memanggilnya menggunakan `ctypes` setelah library dimuat.

Langkah-langkah pada script `solve.py`:
1. Memuat `mystery.so` menggunakan `ctypes`.
2. Menemukan base address library di memory melalui `/proc/self/maps`.
3. Menginisialisasi modul (memanggil `get_runtime_info` untuk memastikan constructor dijalankan).
4. Memanggil ke-4 fungsi pembantu stage secara langsung dengan argument index yang sesuai (1, 2, 3, 4).
5. Mengambil nilai kembalian (expected value) dari masing-masing fungsi tersebut.
6. Mengirimkan nilai-nilai tersebut kembali ke fungsi `mystery.stage()`.
7. Memanggil `mystery.reveal()` untuk mendapatkan flag asli.

## 4. Final Flag
Setelah menjalankan script `solve.py`, kita mendapatkan flag asli:
`bhackariCTF{F1n4lly_th4_My$t3rY_!S_$OlvEd!!!}`
