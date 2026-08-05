Saya telah menyusun write-up tersebut dalam format yang rapi untuk `README.md` menggunakan gaya dokumentasi GitHub.

# OSINT CTF Write-up — OSHIT

## Ringkasan Challenge

Challenge memberikan satu artefak awal berupa sebuah **invoice** milik **Asterion Field Services W.L.L.**. Dari dokumen tersebut diperoleh beberapa informasi penting sebagai titik awal investigasi.

| Field               | Value                                                                     |
| ------------------- | ------------------------------------------------------------------------- |
| Company             | Asterion Field Services W.L.L.                                            |
| Domain              | `asterion.kali-team.online`                                               |
| Email               | `info@asterion.kali-team.online`                                          |
| Project Reference   | `NQ-441`                                                                  |
| Project Description | Supply, Delivery & Commissioning of Field Support & Maintenance Equipment |

Format flag yang diberikan adalah:

```text
KaliTeam{CONTACT_REGISTRATION_PORTAL_WAREHOUSE_AREA}
```

Flag akhir:

```text
KaliTeam{MAZEN_DARWISH_104728_OPS_C12_SAHAB}
```

---

# 1. Analisis Artefak Awal

Invoice menjadi satu-satunya titik awal investigasi.

Pivot utama yang diperoleh:

* Company : **Asterion Field Services W.L.L.**
* Domain : **asterion.kali-team.online**
* Project : **NQ-441**

Pemeriksaan awal dilakukan menggunakan `curl`.

```bash
curl https://asterion.kali-team.online/
```

Halaman utama dilindungi oleh **Cloudflare Managed Challenge** sehingga hanya menampilkan halaman:

```text
Just a moment...
Enable JavaScript and cookies to continue
```

Karena challenge bertipe **OSINT**, tidak diperlukan usaha untuk melewati Cloudflare. Fokus dialihkan ke pencarian jejak publik lain yang masih berhubungan dengan domain tersebut.

---

# 2. Rabbit Hole Pertama — Passive Reconnaissance

Beberapa sumber OSINT pasif diperiksa:

* Certificate Transparency (`crt.sh`)
* Wayback Machine
* URLScan
* DNS Records

Certificate Transparency:

```bash
curl -s "https://crt.sh/?q=%25.asterion.kali-team.online&output=json"
```

Wayback Machine:

```bash
curl -sG "https://web.archive.org/cdx/search/cdx" \
  --data-urlencode "url=asterion.kali-team.online/*" \
  --data-urlencode "output=json"
```

Semua hasil kosong.

Awalnya diasumsikan arsip lama perusahaan tersedia, namun ternyata infrastruktur challenge relatif baru sehingga belum memiliki rekaman publik.

**Pelajaran:** hasil kosong pada passive reconnaissance tidak berarti target tidak memiliki subdomain aktif.

---

# 3. Enumerasi Subdomain

Enumerasi dilakukan menggunakan **Subfinder**.

```bash
subfinder -silent -all -recursive \
  -d kali-team.online
```

Hasil yang relevan:

```text
asterion.kali-team.online
media.asterion.kali-team.online
ops.asterion.kali-team.online
tenders.asterion.kali-team.online
```

Berbeda dengan domain utama, ketiga subdomain dapat diakses langsung.

```text
media.asterion.kali-team.online
Title: Asterion Project Media

ops.asterion.kali-team.online
Title: Asterion Operations Portal

tenders.asterion.kali-team.online
Title: Infrastructure Procurement Archive
```

Karena domain `kali-team.online` merupakan domain penyelenggara challenge, ruang lingkup investigasi dibatasi hanya pada:

```text
*.asterion.kali-team.online
```

---

# 4. Memetakan Fungsi Setiap Subdomain

| Subdomain                         | Fungsi                          |
| --------------------------------- | ------------------------------- |
| media.asterion.kali-team.online   | Arsip foto proyek               |
| ops.asterion.kali-team.online     | Portal operasi internal         |
| tenders.asterion.kali-team.online | Arsip tender dan dokumen vendor |

Struktur tersebut menunjukkan bahwa setiap komponen flag kemungkinan tersebar pada layanan yang berbeda.

---

# 5. Menemukan Portal Identifier

Halaman operasi diperiksa.

```bash
curl -skL https://ops.asterion.kali-team.online/
```

Potongan HTML:

```html
<form id="login">
...
</form>

<div class="node">PORTAL CODE: OPS</div>
```

JavaScript halaman:

```javascript
document.getElementById('login').addEventListener(
  'submit',
  e => {
    e.preventDefault();
    document.getElementById('alert').style.display = 'block';
  }
);
```

Portal secara eksplisit menampilkan:

```text
PORTAL CODE: OPS
```

Sehingga diperoleh:

```text
PORTAL = OPS
```

### Rabbit Hole — Login Injection

Karena tampilannya menyerupai halaman login, sempat muncul dugaan bahwa challenge memerlukan:

* SQL Injection
* Credential Guessing
* Authentication Bypass
* Hidden API

Namun setelah source diperiksa, form hanya menjalankan:

```javascript
preventDefault()
```

Tidak ada request yang dikirim ke backend.

Kesimpulannya:

* Tidak diperlukan SQL Injection.
* Tidak diperlukan brute force.
* Tidak ada backend autentikasi.

---

# 6. Menemukan Jalur Dokumen Melalui robots.txt

Pemeriksaan dilakukan pada server tender.

```bash
curl -skL https://tenders.asterion.kali-team.online/robots.txt
```

Hasil:

```text
User-agent: *
Disallow: /vendor-docs/
Disallow: /archive/
```

Dua direktori tersembunyi berhasil ditemukan:

```text
/archive/
/vendor-docs/
```

---

# 7. Mendapatkan Authorized Project Contact

Isi direktori `/archive/`:

```text
award_notice_NQ418.pdf
award_notice_NQ427.pdf
award_notice_NQ441.pdf
award_notice_NQ452.pdf
```

Karena proyek yang dicari adalah **NQ-441**, dokumen yang digunakan:

```text
award_notice_NQ441.pdf
```

Diunduh menggunakan:

```bash
curl -fsSL \
https://tenders.asterion.kali-team.online/archive/award_notice_NQ441.pdf \
-o award_notice_NQ441.pdf
```

Ekstraksi PDF:

```bash
pdftotext -layout award_notice_NQ441.pdf -
```

Dokumen menyebutkan:

```text
Authorized Project Contact
Mazen Darwish
```

Sesuai format flag:

```text
CONTACT = MAZEN_DARWISH
```

---

# 8. Mendapatkan Company Registration Number

Direktori `/vendor-docs/` berisi:

```text
vendor_requirements.pdf
safety_compliance_2025.pdf
supplier_prequalification_2025.pdf
payment_terms.pdf
```

Dokumen yang relevan:

```text
supplier_prequalification_2025.pdf
```

Ekstraksi:

```bash
pdftotext -layout supplier_prequalification_2025.pdf -
```

Isi tabel:

| Vendor                  | Vendor ID | Registration No. | Status               |
| ----------------------- | --------- | ---------------- | -------------------- |
| Asterion Field Services | V-204     | 104728           | Temporarily Approved |

Didapat dua angka berbeda:

```text
Vendor ID       : V-204
Registration No.: 104728
```

Karena challenge meminta **company registration number**, maka yang digunakan adalah:

```text
REGISTRATION = 104728
```

### Rabbit Hole — V-204

Awalnya nilai `V-204` sempat dianggap sebagai registration number.

Namun struktur tabel memperjelas:

* `V-204` → Vendor ID
* `104728` → Registration Number

---

# 9. Membuka Arsip Media Proyek

Halaman media menampilkan daftar proyek:

```text
NQ-418
NQ-427
NQ-441
NQ-452
```

Direktori proyek:

```text
/projects/nq-441/
```

Source halaman menunjukkan dua gambar:

```text
/assets/nq441_a.jpg
/assets/nq441_b.jpg
```

Caption:

```text
Delivery image 01
Loading-bay approach and receiving area.

Delivery image 02
Final handover at the assigned warehouse.
```

---

# 10. Menentukan Warehouse Code

## Gambar Pertama

Kode gudang hanya terlihat:

```text
C-1_
```

Tidak cukup jelas untuk digunakan.

---

## Gambar Kedua

Caption:

```text
Final handover at the assigned warehouse.
```

Kode gudang terlihat jelas:

```text
C-12
```

Karena format flag tidak menggunakan tanda baca:

```text
C-12
```

menjadi

```text
C12
```

Sehingga:

```text
WAREHOUSE = C12
```

### Rabbit Hole — C-1 vs C-12

Gambar pertama hanya menunjukkan area penerimaan barang.

Sedangkan gambar kedua memperlihatkan lokasi serah terima akhir dengan kode gudang yang lengkap.

---

# 11. Menentukan Industrial Area

Pada gambar kedua terlihat papan bertuliskan:

```text
SAHAB INDUSTRIAL ESTATE
```

Awalnya beberapa kandidat dicoba:

```text
SAHAB_INDUSTRIAL_ESTATE
SAHAB_INDUSTRIAL_AREA
SAHAB_INDUSTRIAL_CITY
```

Seluruhnya salah.

Challenge meminta:

> The industrial area associated with the final delivery

Yang dimaksud hanyalah nama kawasannya:

```text
SAHAB
```

Sehingga:

```text
AREA = SAHAB
```

### Rabbit Hole Terbesar

Tulisan pada papan sangat jelas sehingga mudah mengira seluruh frasa harus dimasukkan ke flag.

Padahal:

* **SAHAB** → nama area
* **Industrial Estate** → jenis kawasan

---

# 12. Rabbit Hole — Netlify CNAME

DNS menunjukkan seluruh subdomain menggunakan Netlify.

```text
ops
→ stunning-panda-c6bb8d.netlify.app

media
→ roaring-cocada-527669.netlify.app

tenders
→ dapper-frangipane-1f1f5c.netlify.app
```

Awalnya nama deployment Netlify sempat dianggap sebagai identifier portal.

Contoh kandidat:

```text
STUNNING-PANDA-C6BB8D
```

Namun ternyata hanya nama deployment otomatis.

Identifier portal yang benar sudah ditampilkan langsung:

```text
OPS
```

---

# 13. Rabbit Hole — OCR dan EXIF

Metadata gambar diperiksa menggunakan:

```bash
exiftool nq441_a.jpg nq441_b.jpg
```

Hasil hanya berupa metadata JPEG standar.

OCR juga dicoba menggunakan:

```bash
tesseract nq441_b.jpg stdout --psm 11
```

Namun hasil OCR kurang akurat.

Pada akhirnya:

* EXIF tidak mengandung petunjuk.
* OCR tidak diperlukan.
* Informasi dapat diperoleh melalui observasi visual dan caption.

---

# 14. Penyusunan Flag

Seluruh komponen berhasil diperoleh.

| Slot         | Nilai         | Sumber                             |
| ------------ | ------------- | ---------------------------------- |
| CONTACT      | MAZEN_DARWISH | award_notice_NQ441.pdf             |
| REGISTRATION | 104728        | supplier_prequalification_2025.pdf |
| PORTAL       | OPS           | Operations Portal                  |
| WAREHOUSE    | C12           | Foto final handover                |
| AREA         | SAHAB         | Signage lokasi                     |

Format:

```text
KaliTeam{CONTACT_REGISTRATION_PORTAL_WAREHOUSE_AREA}
```

Hasil akhir:

```text
KaliTeam{MAZEN_DARWISH_104728_OPS_C12_SAHAB}
```

---

# 15. Alur Penyelesaian

```text
Invoice
   │
   ├── Domain: asterion.kali-team.online
   └── Project: NQ-441
          │
          ▼
Subdomain Enumeration
          │
          ├── ops.asterion...
          │      └── PORTAL CODE: OPS
          │
          ├── tenders.asterion...
          │      ├── /archive/
          │      │      └── award_notice_NQ441.pdf
          │      │              └── Mazzen Darwish
          │      │
          │      └── /vendor-docs/
          │             └── supplier_prequalification_2025.pdf
          │                     └── Registration No. 104728
          │
          └── media.asterion...
                 └── /projects/nq-441/
                        ├── nq441_a.jpg
                        └── nq441_b.jpg
                               ├── Warehouse C-12 → C12
                               └── Sahab Industrial Estate → SAHAB
```

---

# Final Flag

```text
KaliTeam{MAZEN_DARWISH_104728_OPS_C12_SAHAB}
```

