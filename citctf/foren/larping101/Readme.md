# Writeup Forensic - Larping 101

## Informasi Challenge
- Kategori: Forensic
- File: `challenge.pptx`
- SHA1 valid: `e72c9837de62168b2b5cc573a55800ea1e440b42`

## Langkah Analisis

### 1. Initial Recon
Cek tipe file dan hash:
```bash
sha1sum challenge.pptx
file challenge.pptx
```
Hasil menunjukkan file adalah `Microsoft OOXML` (PPTX), artinya sebenarnya arsip ZIP berisi struktur XML dan media.

### 2. Triage Cepat
Cek metadata:
```bash
exiftool challenge.pptx
```
Metadata normal (LibreOffice template), belum ada flag langsung.

Lalu lihat isi internal PPTX:
```bash
unzip -l challenge.pptx
```
Terlihat struktur umum PowerPoint, termasuk folder `ppt/slides/` dan file tambahan `ppt/slides/transitions.xml`.

### 3. Ekstraksi Layer
Ekstrak seluruh isi:
```bash
unzip -q challenge.pptx -d extracted
```

### 4. Pencarian Konten Mencurigakan
Lakukan pencarian keyword dan pattern CTF di hasil ekstraksi:
```bash
rg -n -i "flag|ctf|cit|hidden|secret" extracted
```

Ditemukan temuan penting di:
- `extracted/ppt/slides/transitions.xml` baris berisi string flag.

Verifikasi cepat:
```bash
sed -n '1,120p' extracted/ppt/slides/transitions.xml
```

## Flag
`CIT{l4rp_l4rp_l4rp_s4hur}`

## Kesimpulan
Flag disisipkan pada file XML transisi slide (`transitions.xml`) di dalam paket OOXML PPTX, bukan pada metadata gambar atau konten slide utama. Teknik utamanya adalah membongkar container PPTX lalu melakukan grep/pattern matching pada seluruh artefak XML.
