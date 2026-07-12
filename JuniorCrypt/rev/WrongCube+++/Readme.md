# WrongKube+++

## Ringkas

`WrongKube+++.exe` adalah aplikasi PyInstaller untuk Windows. Modul Python hanya menjadi UI PyQt6; validasi graph dan flag ada di `build\\wrongkube_validator.dll`.

## Analisis

`file WrongKube+++.exe` menunjukkan PE32+ Windows. Footer EXE berisi cookie PyInstaller `MEI\x0c\x0b\x0a\x0b\x0e`, sehingga overlay bisa diparse sebagai CArchive.

TOC archive memuat `build\\wrongkube_validator.dll`. Export `validate_cluster` memproses JSON graph, lalu bila semua witness graph cocok ia menjalankan loop 24 iterasi. Loop tersebut mendekripsi 48 byte dari `.rdata` RVA `0x2d5a0` sebelum memasukkannya ke field `flag` pada respons JSON.

Tidak perlu menyelesaikan semua constraint graph untuk mengambil flag. Ciphertext, konstanta state, dan operasi loop semuanya statis di DLL. `solve.py` mengekstrak DLL langsung dari EXE, mereproduksi loop x86-64 dengan aritmetika 32-bit, lalu mencetak plaintext.

## Solve

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
grodno{wr0ngkub3ppp_4by55_0r4cl3_qu0rum_3xtr3m3}
```

## Flag

```text
grodno{wr0ngkub3ppp_4by55_0r4cl3_qu0rum_3xtr3m3}
```
