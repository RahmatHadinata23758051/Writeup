# Writeup Forensic - The Evil Files

## Informasi Challenge
- Kategori: Forensic
- Judul: The Evil Files
- File artefak: `challenge.pdf`
- SHA1 yang diberikan: `2230cff50d7ae8672ab072d275df7057773f11eb`

## Tujuan
Mencari flag dari artefak forensik yang diberikan.

## Langkah Analisis

### 1) Initial Recon
Pertama saya cek isi folder dan tipe file:

```bash
ls -la
file challenge.pdf
sha1sum challenge.pdf
```

Hasil penting:
- Hanya ada satu file: `challenge.pdf`
- Tipe file valid: PDF 1.7
- SHA1 file **match** dengan yang di soal:
  `2230cff50d7ae8672ab072d275df7057773f11eb`

Artinya artefak tidak korup dan kemungkinan memang file utama challenge.

### 2) Triage Cepat
Saya lakukan ekstraksi metadata dan string ringan:

```bash
exiftool challenge.pdf
strings -n 6 challenge.pdf
```

Metadata menunjukkan file dibuat dengan LibreOffice Writer dan tidak ada indikasi enkripsi.

Lalu saya ekstrak teks PDF secara langsung:

```bash
pdftotext challenge.pdf -
```

Di output teks terlihat header seperti email, dan ada baris:

`CC: CIT{m0j0_eng4g3d}`

Ini sangat kuat sebagai kandidat flag.

### 3) Validasi Tambahan
Untuk memastikan tidak ada artefak tersembunyi lain, saya cek hal-hal umum:

```bash
pdfdetach -list challenge.pdf
pdfimages -list challenge.pdf
binwalk challenge.pdf
```

Temuan:
- Tidak ada embedded file (`0 embedded files`)
- Tidak ada image object yang mencurigakan
- Ada stream zlib normal untuk struktur PDF (wajar)

Terakhir, saya validasi ulang pola flag di hasil text extraction:

```bash
pdftotext challenge.pdf - | rg "CIT\{|CTF\{|FLAG\{" -n
```

Hanya muncul satu flag yang konsisten.

## Flag

```text
CIT{m0j0_eng4g3d}
```

## Solver Otomatis
Saya juga membuat `solve.py` untuk otomatis mengekstrak flag dari PDF.

Jalankan:

```bash
python3 solve.py
```

Atau jika nama file beda:

```bash
python3 solve.py nama_file.pdf
```

Output solver:

```text
<FLAG>CIT{m0j0_eng4g3d}</FLAG>
```

## Catatan
Challenge ini termasuk forensic yang straightforward: flag disisipkan di konten teks dokumen (format mirip header email), bukan lewat stego atau layer enkripsi tambahan.
