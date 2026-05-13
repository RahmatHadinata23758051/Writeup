# Scheduling

Challenge ini ternyata lebih sederhana daripada narasi “recursive scheduling engine”-nya.

Service `nc 10.42.5.10 1337` tidak meminta input apa pun. Setiap koneksi langsung mengirim sebuah JSON besar berisi daftar employee dan meeting mereka, lalu koneksi ditutup.

## Temuan penting

Setelah beberapa kali enumerasi, ada pola yang konsisten:

- Ada 6 employee.
- Setiap employee punya banyak meeting biasa.
- Setiap employee juga punya 23 meeting dengan field `"encoded": true`.
- Seluruh meeting `encoded` itu identik untuk semua employee.

Contoh awal sequence `encoded`:

- `2026-05-10T09:00` s/d `2026-05-10T10:22` -> 82 menit
- `2026-05-10T13:22` s/d `2026-05-10T14:39` -> 77 menit
- `2026-05-10T17:39` s/d `2026-05-10T18:46` -> 67 menit

Kalau angka-angka durasi ini dibaca sebagai ASCII:

- 82 = `R`
- 77 = `M`
- 67 = `C`

Tiga karakter pertama langsung membentuk `RMC`, jadi asumsi ini sangat kuat.

## Cara solve

Ambil salah satu daftar `encoded` meeting, hitung durasi tiap interval dalam menit, lalu konversi setiap durasi menjadi karakter ASCII.

Durasi lengkapnya:

`[82, 77, 67, 84, 70, 123, 78, 79, 95, 77, 79, 82, 69, 95, 83, 84, 65, 78, 68, 85, 80, 83, 125]`

Hasil decode:

`RMCTF{NO_MORE_STANDUPS}`

## Solver

File [solve.py](/home/nata/ctf/RAM/misc/SchedulingShenanigans/solve.py) akan:

1. Connect ke service
2. Menerima JSON penuh
3. Mengambil meeting `encoded`
4. Mengubah durasi meeting menjadi karakter ASCII
5. Mencetak flag

Jalankan dengan:

```bash
python3 solve.py
```

Output:

```text
RMCTF{NO_MORE_STANDUPS}
```
