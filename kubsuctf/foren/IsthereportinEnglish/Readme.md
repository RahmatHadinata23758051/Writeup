# Writeup - Is the report in English?

Challenge ini memberi satu file PDF bernama `KUBSTU_Financial_Report_2025.pdf`. Kesan awalnya sederhana: ada laporan keuangan berbahasa Inggris, ada attachment ZIP, dan bahkan password ZIP juga ditampilkan terang-terangan di isi PDF. Karena itu justru patut curiga bahwa jalur tersebut hanya umpan.

## 1. Recon awal

Langkah pertama adalah identifikasi file dan triage cepat:

```bash
file KUBSTU_Financial_Report_2025.pdf
exiftool KUBSTU_Financial_Report_2025.pdf
pdfinfo KUBSTU_Financial_Report_2025.pdf
strings -a KUBSTU_Financial_Report_2025.pdf | rg "KubSTU\\{|Embedded|Filespec|stream"
```

Hasil penting dari tahap ini:

- File memang PDF 2 halaman.
- Ada warning `Invalid xref table`, jadi struktur PDF tidak sepenuhnya normal.
- `strings` langsung menampilkan banyak sekali flag palsu.
- Ada object `/EmbeddedFile`, artinya PDF memang menyimpan file terlampir.

## 2. Mengecek attachment PDF

Dari object stream terlihat ada data ZIP yang tertanam di PDF. `binwalk` juga mengonfirmasi adanya archive pada offset tertentu.

```bash
binwalk KUBSTU_Financial_Report_2025.pdf
pdftotext KUBSTU_Financial_Report_2025.pdf -
```

Dari teks PDF yang terbaca, diketahui:

- nama archive: `KUBGTU_FINANCIAL_DATA_2025.ZIP`
- password: `FinanceKubSTU2025!`

ZIP kemudian diekstrak:

```bash
dd if=KUBSTU_Financial_Report_2025.pdf of=embedded.zip bs=1 skip=2122 count=577 status=none
unzip -P 'FinanceKubSTU2025!' -p embedded.zip 'confidential_flag.txt/tmpb1ln4mfr.txt'
```

Isi file hasil ekstraksi memang mengandung string berbentuk flag, tetapi jelas merupakan jebakan:

- isi file menyebut akses tidak sah
- formatnya terlalu teatrikal
- ada mismatch ukuran internal
- flag yang muncul bertema `F4k3_Fl4g...`

Jadi attachment bukan sumber flag asli.

## 3. Menemukan lokasi payload sebenarnya

Karena `xref` rusak, struktur mentah PDF perlu diperiksa. Setelah dilihat lebih teliti, object PDF normal berakhir cukup awal, tetapi area `trailer` berisi metadata yang sangat panjang dan tidak wajar.

`qpdf --qdf --object-streams=disable` membantu menunjukkan bahwa trailer memiliki field metadata tambahan:

- `/ArchivePassword`
- `/HiddenAuditData`

Field `/HiddenAuditData (...)` ternyata berisi literal string PDF sangat besar, panjangnya sekitar 77 KB, penuh noise seperti:

- `B64_...`
- `ENC_...`
- `KEY_...`
- `FLAG: KubSTU{TEST_...}`
- `SECRET='KubSTU{DUMMY_...}'`
- berbagai baris palsu lain

Ini menjelaskan kenapa `strings` menghasilkan banyak flag decoy.

## 4. Memilah noise dan menemukan outlier

Alih-alih decode semua token satu per satu, cara yang lebih efektif adalah mencari baris yang formatnya berbeda dari mayoritas filler. Di antara ratusan baris metadata palsu, ada satu baris yang sangat menonjol:

```text
DATA[9376]="S3ViU1RVe1BERl9NM3Q0ZDR0NF9GMHIzbnMxY3NfNGR2NG5jM2RfQ2g0bGwzbmczXzIwMjVfUzNjdXIzX0VtYjNkZDNkX0YxbDNfM25jcnlwdDEwbl9QcjB0MGMwbH0="
```

Berbeda dari token lain, nilai ini tampak seperti Base64 utuh dan rapi. Setelah didecode:

```bash
python3 - <<'PY'
import base64
s='S3ViU1RVe1BERl9NM3Q0ZDR0NF9GMHIzbnMxY3NfNGR2NG5jM2RfQ2g0bGwzbmczXzIwMjVfUzNjdXIzX0VtYjNkZDNkX0YxbDNfM25jcnlwdDEwbl9QcjB0MGMwbH0='
print(base64.b64decode(s).decode())
PY
```

Hasilnya:

```text
KubSTU{PDF_M3t4d4t4_F0r3ns1cs_4dv4nc3d_Ch4ll3ng3_2025_S3cur3_Emb3dd3d_F1l3_3ncrypt10n_Pr0t0c0l}
```

## 5. Inti challenge

Trik challenge ini ada pada tiga lapis distraksi:

1. PDF terlihat normal dan berbahasa Inggris.
2. Ada embedded ZIP dengan password valid, tetapi isinya flag palsu.
3. Metadata PDF menyimpan blob besar `HiddenAuditData` yang dipenuhi ratusan decoy flag.

Flag asli justru berada di metadata trailer, dalam satu baris Base64 yang sengaja disamarkan di antara noise.

## Flag

```text
KubSTU{PDF_M3t4d4t4_F0r3ns1cs_4dv4nc3d_Ch4ll3ng3_2025_S3cur3_Emb3dd3d_F1l3_3ncrypt10n_Pr0t0c0l}
```
