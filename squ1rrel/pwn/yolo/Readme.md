# Writeup - squ1rrel pwn/yolo

## Informasi Challenge
- Kategori: `pwn`
- Judul: `pwn/yolo`
- Target: `http://104.197.153.197/`

---

## Recon Awal

Di folder challenge ada file utama:
- `server.py` (Flask app)
- `yolo_status` (ELF 64-bit, SUID root di Dockerfile)

Hasil `checksec` untuk `yolo_status`:
- No PIE
- NX enabled
- No canary
- Partial RELRO

`server.py` punya endpoint penting:
- `POST /api/model/build`

Pada endpoint ini ada alur:
1. upload file `weights` (`.pt`)
2. disimpan ke `/tmp/...pt`
3. dipanggil `torch.load(path, map_location="cpu")`

Ini langsung red flag karena `torch.load` menggunakan pickle dan bisa mengeksekusi code saat deserialisasi object berbahaya.

---

## Static Analysis Binary `yolo_status`

Dari disassembly `main` ditemukan:
- Program baca `/flag.txt` ke heap buffer `calloc(0x80)` (jadi isi flag ada di memori proses).
- Program print status subcommand dengan pola:
  - `snprintf(local_buf, 0x100, "[*] running: %s\n", argv[1])`
  - `printf(local_buf)`  **(BUG format string)**

Karena `printf` dipanggil dengan user-controlled format string, kita bisa baca data stack/arg dengan `%n$...`.

Dengan uji lokal (`./yolo_status '%41$s'`) didapat:
- `%41$s` menunjuk ke pointer heap buffer yang berisi isi `/flag.txt`.
- Output jadi langsung mencetak flag.

Jadi primitive exploit final:
1. RCE via unsafe `torch.load`
2. Dari RCE jalankan `/app/yolo_status '%41$s'`
3. Output response API berisi flag

---

## Exploitation Flow

Saya buat malicious checkpoint `.pt` berisi object dengan `__reduce__`.
Saat di-`torch.load` oleh server, object itu menjalankan:

```python
subprocess.check_output(['/app/yolo_status', '%41$s'])
```

Kemudian hasil command diangkat jadi exception, supaya message exception kembali ke JSON error API.

Server membalas:
- `pretrained validation failed: ... [*] running: squ1rrel{...}`

Dari response itu solver regex flag dan print.

---

## Flag

`squ1rrel{y0u_0nly_fl@g_1nce_5d7fb1a}`

---

## Solver

File solver sudah disimpan:
- `solve.py`

Cara pakai:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Opsional custom URL:

```bash
python3 solve.py --url http://104.197.153.197/api/model/build
```

---

## Catatan Penting

- Challenge ini chain dua bug:
  - insecure deserialization (`torch.load`)
  - format string di binary SUID helper
- Kalau salah satu ditutup, exploit chain putus:
  - `torch.load(..., weights_only=True)` + validasi ketat format
  - ganti `printf(buf)` jadi `printf("%s", buf)`
