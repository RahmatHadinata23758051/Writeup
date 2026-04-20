# CTF Writeup — Uranus Bastion

**Event:** JerseyCTF  
**Category:** Misc  
**Difficulty:** Medium  
**Flag:** `jctf{the_lattice_trusts_the_surface_not_the_soul}`

---

## Challenge Description

> The Uranus Orbital Defense Lattice guards the next hop inward. A decommissioned staging node was recovered after a failed maintenance sync, and its remnants may describe the one shipment profile the lattice still accepts. Reconstruct the protocol, rebuild the accepted coating sample, and slip your payload through the barrier.

**Target:** `http://uranus-bastion.aws.jerseyctf.com:8080/`

---

## Reconnaissance

### Step 1 — Cek Endpoint Awal

```bash
curl -i http://uranus-bastion.aws.jerseyctf.com:8080/
```

Response JSON nunjukin service aktif dan endpoint pentingnya:
- Method: `POST`
- Endpoint: `/upload`
- Rejection reason disembunyikan dari operator remote

Ini berarti kita harus kirim request yang benar dari sisi format/header/body, bukan berharap error message membantu.

### Step 2 — Enumerasi Artefak Lokal

File yang tersedia:
- `maintenance_window.log`
- `transit_manifest.txt`
- `sync_probe.bin`
- folder `payload_fragments/phase_*.hex`

Petunjuk penting yang didapat:
- Origin port maintenance: `42107`
- Forwarded maintenance sector valid: `10.10.42.0/24`
- Parser masih `plain-text mode`
- Fragmen harus di-stitch dengan urutan phase naik
- Coating class: `ALPHA`
- Encoding fragment: `hex`
- SHA256 payload yang diharapkan:
  `42aa6f011ec28d2198f81407ea91217897c712ca214ef859b068b91623d31abe`

### Step 3 — Reverse Header/Protocol dari `sync_probe.bin`

`xxd sync_probe.bin` memperlihatkan string-string penting:
- `/upload`
- `User-Agent`
- `UranusSync/2.4-beta` dan `UranusSync/2.3`
- `X-Forwarded-For`
- `X-Origin-Port`
- `X-Coating-Class`
- `X-Filename`
- `coating_layer_alpha.dat`
- `Content-Type`
- `text/plain`

Ini menguatkan bahwa validasi service berbasis profil request (header + body), bukan cuma body.

---

## Exploitation

### Step 4 — Rekonstruksi Payload dari Fragment

Gabungkan file `phase_*.hex` secara ascending, lalu decode hex menjadi plaintext.

```bash
for f in $(ls payload_fragments/phase_*.hex | sort); do tr -d '\n' < "$f"; done | xxd -r -p
```

Hasil payload:

```text
COATING_LAYER_ALPHA
REFLECTIVITY_INDEX=0.9821
THERMAL_DECAY=STABLE
CORD_MAP=UR-SAT-ALIGN-07
PHASE_OFFSET=0003AF2C
SURFACE_CLASS=ARCHIVAL_SYNC
```

Verifikasi hash:

```bash
sha256sum payload.txt
# 42aa6f011ec28d2198f81407ea91217897c712ca214ef859b068b91623d31abe
```

Hash cocok persis dengan `EXPECTED_SHA256` di manifest.

### Step 5 — Kirim Request Sesuai Profil Trust

Header yang dipakai:
- `User-Agent: UranusSync/2.3`
- `X-Forwarded-For: 10.10.42.77` (masuk subnet 10.10.42.0/24)
- `X-Origin-Port: 42107`
- `X-Coating-Class: ALPHA`
- `X-Filename: coating_layer_alpha.dat`
- `Content-Type: text/plain`

Body: payload hasil rekonstruksi di atas.

Response sukses: service ngasih attachment ZIP `uranus_gate.zip` yang berisi `FLAG.txt`.

### Step 6 — Ambil Flag

```bash
unzip -p uranus_gate.zip FLAG.txt
# jctf{the_lattice_trusts_the_surface_not_the_soul}
```

---

## Flag

```
jctf{the_lattice_trusts_the_surface_not_the_soul}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **Trust Profile Replay** | Gate masih menerima profil maintenance lama jika header/body cocok |
| 2 | **Weak Origin Validation** | Reliance ke `X-Forwarded-For` + `X-Origin-Port` yang bisa dipalsukan klien |
| 3 | **Deterministic Payload Acceptance** | Cukup match format + hash payload untuk lolos inspeksi |

---

## Tools Used

- `curl` — interaksi HTTP service
- `xxd` — lihat isi binary probe dan decode fragment hex
- `sha256sum` — verifikasi payload
- `unzip` — ekstrak artefak response
- Python 3 (`urllib`, `zipfile`) — automasi solver

---

## Attack Flow

```
Artifacts lokal (log + manifest + probe + fragments)
      |
      v
Rekonstruksi protokol header + body canonical
      |
      v
Susun payload dari phase_*.hex (ascending) + verifikasi SHA256
      |
      v
POST /upload dengan maintenance profile yang valid
      |
      v
Dapat uranus_gate.zip
      |
      v
Extract FLAG.txt
      |
      v
jctf{the_lattice_trusts_the_surface_not_the_soul}
```

---

## Installation

```bash
# Dari folder challenge ini
python3 solve.py
```
