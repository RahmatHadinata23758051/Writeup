# From Russia With Love - Writeup

## Ringkasan
Challenge ini terlihat seperti service yang "ngetes" implementasi function `exit()` dari library buatan user. Kuncinya bukan buffer overflow klasik, tapi **code execution by design** lewat proses compile dan dynamic linking.

Flag berhasil didapat:

`jctf{l1nker_m0re_l1k3_stink3r}`

## Analisis Source
File penting di challenge lokal:
- `vuln.c`
- `test.c`

Isi logic `vuln.c` (inti):
1. Service menerima input C source dari user.
2. Disimpan ke `/tmp/libnew.c`.
3. Di-compile jadi shared library `/tmp/libnew.so`.
4. Binary tester di-compile dengan link `-lnew`.
5. Program `/tmp/test` dijalankan.

Sementara `test.c` hanya memanggil:
```c
int main() {
    exit(1);
    fflush(0);
}
```

Artinya, kalau kita kirim shared library dengan symbol `exit`, function itu akan dipakai saat `/tmp/test` dijalankan.

## Kerentanan
Kerentanannya adalah **unsafe untrusted code compilation + execution**.

Service membiarkan user:
- upload source C arbitrary,
- compile jadi `.so`,
- lalu menjalankan program yang memanggil function dari library itu.

Ini langsung memberi primitive RCE (Remote Code Execution) karena kita bisa isi `exit()` dengan command shell apa pun.

## Detail Penting Saat Eksploitasi
Ada satu behavior parsing input yang wajib diperhatikan:

```c
while(fgets(buffer+i, sizeof(buffer), stdin) && buffer[(strlen(buffer)-2)] != '}') {
    i = strlen(buffer);
}
```

Loop berhenti ketika karakter sebelum newline adalah `}`. Kalau payload multi-line biasa, kiriman bisa kepotong saat ketemu `}` lebih cepat.

Solusi paling stabil: kirim payload dalam format **one-line function body** (satu `}` penutup di akhir function), supaya source tidak terpotong.

## Payload Konsep
Kita override `exit()`:
- jalankan shell command `cat /chal/flag.txt` (dan fallback `cat flag.txt`),
- akhiri pakai `_exit(0)`.

Contoh payload C yang dikirim:
```c
#include <unistd.h>
#include <stdlib.h>
void exit(int status){system("/bin/sh -c 'cat /chal/flag.txt 2>/dev/null; cat flag.txt 2>/dev/null'");_exit(0);}
```

## Solver Otomatis
Saya simpan solver di file `solve.py`.

Jalankan:
```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Solver melakukan:
1. Connect ke `from-russia-with-love.aws.jerseyctf.com:9001`
2. Kirim payload C
3. Baca semua output
4. Regex extract flag `jctf{...}`

## Bukti Hasil
Output service menampilkan isi direktori `/chal` dan file flag:
- `/chal/flag.txt`
- value: `jctf{l1nker_m0re_l1k3_stink3r}`

## Lessons Learned
- Tidak semua pwn harus memory corruption; kadang logic deployment/build pipeline sendiri jadi exploit surface.
- Menjalankan code hasil upload user (meski "cuma buat test") adalah high-risk design.
- Dynamic linking symbol override (`exit`, `puts`, dll) bisa jadi jalur eksekusi yang sangat langsung.
