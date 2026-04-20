# CTF Writeup — Mnemosyne Lattice (NME-Ω)

**Event:** JerseyCTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `jctf{mnemosyne_remembers_even_when_humans_forget}`

---

## Challenge Description

> Neptune was never a colony; it was Orion's mediation node, built to preserve reference states long after operators were gone. Its degraded interfaces still hold records about the material that made the gate network possible. Explore the system, understand its trust model, and recover what Orion sealed inside the archive.

**Target:** `http://mnemosyne-lattice.aws.jerseyctf.com`

---

## Reconnaissance

### Step 1 — Initial Endpoint Mapping

Akses root mengarah ke `/neptune/`.

```bash
curl -i http://mnemosyne-lattice.aws.jerseyctf.com/
# -> 302 Location: /neptune/
```

Di source HTML `/neptune/` ada komentar internal yang sangat penting:

- JWT `alg=none` diterima di mode degraded
- role diambil dari payload token
- endpoint kunci:
  - `POST /neptune/api/request_new.php`
  - `POST /neptune/api/request_submit.php`
  - `GET /neptune/review.php?id=<request_id>`
  - `GET /neptune/api/captures.php`
- known issues:
  - authority replay leak header internal
  - legacy developer tokens masih dipercaya

### Step 2 — Validate JWT Weakness

Endpoint token mengeluarkan JWT unsigned (`alg: none`).

```bash
curl -s -X POST http://mnemosyne-lattice.aws.jerseyctf.com/neptune/api/request_new.php
```

Ini mengonfirmasi kita bisa forge token sendiri dan mengatur `role` secara arbitrer.

---

## Exploitation

### Step 3 — Forge Role `o-dev` and Trigger Review Replay

Kita forge JWT:

- header: `{"typ":"JWT","alg":"none"}`
- payload: role `o-dev`

Lalu kirim body ke `request_submit.php`, ambil `request_id`, dan akses:

```bash
GET /neptune/review.php?id=<request_id>
```

Pada response review untuk request dengan role `o-dev`, server membocorkan header:

- `X-Operator-Creds: neptune_admin:NPT-AX13-RELAY`
- `X-Authority-Console: /console/login.php`

Ini adalah kredensial authority console.

### Step 4 — Login Authority Console

Gunakan kredensial bocor:

- username: `neptune_admin`
- password: `NPT-AX13-RELAY`

Login berhasil dan diarahkan ke:

`/console/terminal.php`

Terminal ini punya command archive:

- `arhls`
- `arccat`
- `upload`

### Step 5 — Bypass Material Verification

Di public archive ada petunjuk validator private:

- `archives/public/upload.php` mereferensikan `archives/private/upload_filter.php`

Dengan path traversal pada command `arccat`, file private bisa dibaca:

```php
function validateArtifact(string $filename): bool {
    return str_ends_with($filename, '.mnemo');
}
```

Artinya validasi hanya cek suffix nama file `.mnemo`.

Upload file apapun dengan filename berakhiran `.mnemo` lewat command `upload`, maka sealed vault terbuka.

### Step 6 — Read Sealed Flag

Setelah upload sukses:

```bash
arccat archives/sealed/FLAG.txt
```

Output:

`jctf{mnemosyne_remembers_even_when_humans_forget}`

---

## Flag

```txt
jctf{mnemosyne_remembers_even_when_humans_forget}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **JWT none-alg forgery** | Server menerima token unsigned dan percaya claim `role` |
| 2 | **Authorization logic flaw** | Role `o-dev` memicu jalur internal review replay |
| 3 | **Sensitive header disclosure** | Kredensial admin bocor via `X-Operator-Creds` |
| 4 | **Path traversal in archive read** | `arccat archives/public/../private/...` bisa baca file private |
| 5 | **Weak upload validation** | “material verification” hanya cek ekstensi `.mnemo` |

---

## Tools Used

- `curl` — enumerasi endpoint dan eksploitasi HTTP
- Python (`requests`) — automasi full chain exploit
- parsing sederhana regex/header extraction

---

## Attack Flow

```txt
/neptune/ source comment
      │
      ▼
Forge JWT (alg=none, role=o-dev)
      │
      ▼
POST /neptune/api/request_submit.php
      │
      ▼
GET /neptune/review.php?id=<id>
      │
      ▼
Leak: X-Operator-Creds + /console/login.php
      │
      ▼
Login /console/login.php
      │
      ▼
Read validator via traversal (upload_filter.php)
      │
      ▼
Upload file with .mnemo extension
      │
      ▼
arccat archives/sealed/FLAG.txt
      │
      ▼
jctf{mnemosyne_remembers_even_when_humans_forget}
```

---

## Installation

```bash
source /home/nata/ctf_env/bin/activate
pip install requests
python3 solve_mnemosyne.py
```

