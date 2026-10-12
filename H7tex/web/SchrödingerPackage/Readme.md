# Schrödinger Package

## Ringkasan

Flag keluar dari endpoint runtime setelah wheel dengan duplicate ZIP member di-upload, diinspeksi, lalu dijalankan.

## Target dan File

Target: `https://web-cc24668d607354f2.web.h7tex.com`

Direktori awal kosong (blankbox). File hasil analisis: `solve.py` dan wheel probe lokal.

## Analisis Awal

API yang terlihat dari UI dan `/openapi.json`:

- `POST /api/packages` untuk upload wheel.
- `POST /api/packages/{artifact_id}/inspection` untuk inspeksi.
- `POST /api/packages/{artifact_id}/runtime` untuk menjalankan package.

Response OpenAPI menyebut `flag` bersifat transient pada response runtime.

## Source Code Review

Kode runner dapat dibaca dari filesystem runtime melalui import side effect. Runner memakai `resolve_module()` untuk memilih module dari archive, kemudian pip meng-install wheel dan mengimpor module tersebut.

Validasi portal membandingkan digest artifact dan inspection, tetapi tidak menolak duplicate filename di ZIP.

## Vulnerability

Ada perbedaan parser:

1. Inspector merekam hash entry module pertama.
2. Runtime menghitung `archive_occurrences > 1` dan memilih entry duplicate terakhir.
3. Installer juga menghasilkan file dari entry terakhir.
4. Portal mengeluarkan flag jika hash inspection berbeda dari hash module ter-install, sedangkan hash entry terpilih sama dengan file ter-install.

Jadi wheel berisi dua entry `schrodinger_dup/__init__.py`: entry pertama benign dan entry kedua dipilih runtime.

## Eksploitasi

Wheel dibuat dengan urutan berikut:

```text
schrodinger_dup/__init__.py          # benign, dicatat inspector
schrodinger_dup-...dist-info/METADATA
schrodinger_dup-...dist-info/WHEEL
schrodinger_dup-...dist-info/RECORD
schrodinger_dup/__init__.py          # duplicate terakhir, dipilih runtime
```

Request penting:

```text
POST /api/packages
POST /api/packages/46f004a5d1e34a25822b9f1318e483cd/inspection
POST /api/packages/46f004a5d1e34a25822b9f1318e483cd/runtime
```

Runtime membuktikan entry kedua dipakai melalui output:

```text
selected duplicate archive entry
Imported schrodinger_dup
```

Response runtime juga mengembalikan field `flag` non-null.

## Solve Script

Jalankan:

```bash
python3 solve.py
```

Script membuat versi package unik setiap kali jalan agar upload dapat diulang, lalu melakukan upload, inspection, runtime, dan validasi format flag.

## Flag

`H7CTF{87d62c44-a4c8-4ebd-86a9-1ef6ce3efbe2}`

Flag berasal langsung dari field `flag` pada response `POST /api/packages/{artifact_id}/runtime`.

## Catatan Stabilitas

Eksploitasi stabil selama service mempertahankan kondisi duplicate ZIP member dan urutan parser tersebut. `solve.py` tidak melakukan scanning; hanya tiga request API terhadap target challenge.
