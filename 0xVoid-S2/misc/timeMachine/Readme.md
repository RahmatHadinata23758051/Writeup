# Time Machine — CTF Writeup

## Challenge Information

**Category:** MISC / Docker Forensics
**Challenge Name:** Time Machine

**Flag Format:**

```
0xVO1D{...}
```

**Flag:**

```
0xVO1D{h1st0ry_n3v3r_li35}
```

---

## Challenge Description

Diberikan sebuah Docker image:

```bash
docker pull jinx69/timemachine:latest
```

Deskripsi memberikan petunjuk:

> An old container image has been recovered from an unknown source. The contents may reveal more than expected. Explore carefully and uncover the hidden secret.

Kata kunci utama adalah **old container image**, sehingga kemungkinan terdapat informasi tersembunyi pada **layer Docker sebelumnya**.

---

# 1. Pull Docker Image

Pertama download image:

```bash
docker pull jinx69/timemachine:latest
```

Image berhasil diambil dengan beberapa layer.

---

# 2. Analisis Metadata Image

Melihat detail image:

```bash
docker image inspect jinx69/timemachine:latest
```

Ditemukan bahwa image terdiri dari beberapa layer:

```json
"Layers": [
    "sha256:42724...",
    "sha256:dd65...",
    "sha256:fa7b...",
    ...
]
```

Docker image menyimpan filesystem dalam bentuk layer terpisah. Karena challenge bernama **Time Machine**, kemungkinan secret berada pada layer lama.

---

# 3. Melihat History Docker

Selanjutnya melihat history:

```bash
docker history jinx69/timemachine:latest
```

Hasil:

```
/bin/sh -c chown void:void /opt/flag.sh
/bin/sh -c COPY file:8c44ded4244f8ffa…
```

Ditemukan indikasi file:

```
/opt/flag.sh
```

pernah ditambahkan ke image.

Namun saat dijalankan:

```bash
docker run --rm jinx69/timemachine:latest cat /opt/flag.sh
```

hasil:

```
cat: /opt/flag.sh: Permission denied
```

Artinya file masih ada, tetapi tidak dapat dibaca dari container saat ini.

---

# 4. Membaca Petunjuk Tambahan

Melihat file catatan:

```bash
docker run --rm jinx69/timemachine:latest cat /home/player/notes.txt
```

Output:

```
The answers aren't in the present.
```

Kalimat tersebut menjadi petunjuk bahwa flag tidak berada pada kondisi image sekarang, tetapi pada **history/layer sebelumnya**.

---

# 5. Export Docker Image

Docker image diekspor agar seluruh layer dapat dianalisis:

```bash
docker save jinx69/timemachine:latest -o tm.tar
```

Kemudian diekstrak:

```bash
mkdir layers
tar xf tm.tar -C layers
```

Struktur hasil:

```
layers/
 ├── blobs/
 │   └── sha256/
 ├── index.json
 └── manifest.json
```

Folder `blobs/sha256` berisi seluruh layer filesystem.

---

# 6. Ekstraksi Semua Layer

Karena setiap layer berbentuk archive gzip, seluruh layer diekstrak:

```bash
mkdir extracted

for f in blobs/sha256/*; do
    tar -xf "$f" -C extracted 2>/dev/null
done
```

---

# 7. Mencari File Tersembunyi

Kemudian mencari file flag:

```bash
find extracted -name "flag.sh" -o -name "*flag*"
```

Ditemukan:

```
extracted/opt/flag.sh
```

---

# 8. Membaca Flag dari Layer Lama

Isi file:

```bash
cat extracted/opt/flag.sh
```

Output:

```bash
echo "0xVO1D{h1st0ry_n3v3r_li35}"
```

---

# Flag

```
0xVO1D{h1st0ry_n3v3r_li35}
```

