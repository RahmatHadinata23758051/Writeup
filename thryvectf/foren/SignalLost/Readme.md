# Signal Lost — Forensic Writeup

## Ringkasan

Bundle berisi sepuluh file berekstensi `.jpg`. Sembilan file memang JPEG, tetapi `_e19a0c57-4c8f-4e2c-a113-5bf01af8e2dd.jpg` adalah PDF terenkripsi. Gambar `_2bd3f369-46d0-4a60-9aa1-1f5d4e77d0fb.jpg` memiliki data tambahan setelah marker JPEG `FF D9`.

Flag akhirnya:

```text
Thryve{d0nt_trust_th3_f1l3_ext3ns10n_follow_th3_s1gnal}
```

## 1. Triage awal

```bash
unzip -l chall.zip
file -- *.jpg
```

Output `file` menunjukkan sembilan JPEG normal. Satu file berbeda:

```text
_e19a0c57-4c8f-4e2c-a113-5bf01af8e2dd.jpg: PDF document, version 1.4, 1 page(s)
```

Ekstensi hanya kamuflase. `exiftool` juga menunjukkan file ini password-protected. File JPEG lain tidak mempunyai EXIF atau komentar yang berguna.

## 2. Mencari data setelah gambar

Marker akhir JPEG adalah `FF D9`. Posisi marker dibandingkan dengan ukuran file. Hanya `_2bd3...jpg` yang memiliki 1241 byte setelah EOI. Carving bagian itu menghasilkan:

```text
BEGIN_SIGNAL_BLOB
Mzc3YWJjYWYyNzFj...
END_SIGNAL_BLOB
```

Isi blok bukan langsung archive. Lapisan pertamanya Base64.

## 3. Membuka PDF palsu

PDF memiliki Standard Security Handler revision 3. Password dapat ditemukan offline dengan wordlist lokal:

```bash
pdfcrack -w /usr/share/john/password.lst \
  _e19a0c57-4c8f-4e2c-a113-5bf01af8e2dd.jpg
```

Hasilnya adalah `trustno1`. Ekstrak teks dengan:

```bash
pdftotext -upw trustno1 _e19a0c57-4c8f-4e2c-a113-5bf01af8e2dd.jpg dispatch.txt
```

Pager fragment memberi string:

```text
VFZWQ1RsZ3pVbTlOTVRsT1RraE9ja2xUUlQwPQ==
```

Instruksinya adalah decode tiga kali. Hasil tiap tahap:

```text
1: TVVCTlgzUm9NMTlOTkhOcklTRT0=
2: MUBNX3RoM19NNHNrISE=
3: 1@M_th3_M4sk!!
```

Hasil decode ketiga adalah password arsip.

## 4. Decode signal blob

Data setelah EOI pada `_2bd3...jpg` diambil sampai akhir file, bagian di antara `BEGIN_SIGNAL_BLOB` dan `END_SIGNAL_BLOB` dipilih, lalu whitespace dihapus. Urutan decoding-nya:

```text
Base64 → hex → 7z AES
```

Setelah Base64 dan hex decode, `file` mengenali hasilnya sebagai arsip 7-Zip terenkripsi. Buka dengan:

```bash
7z x -y -p'1@M_th3_M4sk!!' signal_stage2.bin -oextracted_dispatch
```

Arsip menghasilkan `work/vault/README.txt` dan `work/vault/fsociety_final.txt`. README hanya memberi petunjuk bahwa baris terakhir penting. File final berisi:

```text
final dispatch:
Thryve{d0nt_trust_th3_f1l3_ext3ns10n_follow_th3_s1gnal}
```

## Reproduksi

`solve.py` mengulangi proses membuka PDF, mengambil dan decode Base64 tiga kali, carve trailing data JPEG, decode Base64 → hex → 7z, lalu mencari pola `Thryve{...}`.
