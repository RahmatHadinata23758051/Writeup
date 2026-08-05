# Writeup CTF - The Last Shift

## Informasi Challenge

- **Judul:** The Last Shift
- **Kategori:** OSINT

---

# Ringkasan

Challenge ini meminta empat informasi mengenai seorang volunteer **ByteBridge 2025**, yaitu:

- Nama lengkap
- Volunteer ID
- Zona kerja
- Neighborhood yang berkaitan dengan aktivitas online miliknya

Artefak awal yang diberikan berupa sebuah tangkapan layar (`evidence.png`) dari postingan X (Twitter) yang telah dihapus. Dari gambar tersebut peserta harus melakukan penelusuran OSINT hingga memperoleh identitas volunteer beserta lokasi yang diminta.

---

# File Challenge

Challenge menyediakan satu file:

```text
evidence.png
```

Isi gambar memperlihatkan beberapa petunjuk penting, antara lain:

- Postingan dari akun **nullvoyager1**
- Hashtag **#ByteBridge2025**
- Badge volunteer
- Label **R03** pada flight case
- Jadwal backstage
- Gelas bertuliskan **Nader**

Tulisan pada badge tidak terbaca dengan jelas sehingga diperlukan pencarian informasi tambahan dari sumber lain.

---

# Analisis Awal

Dari gambar diperoleh beberapa petunjuk awal:

```text
Username   : nullvoyager1
Event      : ByteBridge 2025
Nama depan : Nader
Referensi  : R03
```

Petunjuk **R03** menjadi fokus utama karena tampak seperti kode dokumen atau referensi internal yang kemungkinan berkaitan dengan pembagian area volunteer.

---

# Menelusuri Repository GitHub

Pencarian terhadap username **nullvoyager1** mengarah ke sebuah repository GitHub:

```text
https://github.com/nullvoyager1/skyline-parser
```

Repository tersebut tampak seperti proyek Python sederhana. Namun, pada riwayat commit terdapat folder referensi:

```text
assets/reference/
```

Salah satu file yang menarik adalah:

```text
assets/reference/r03.pdf
```

---

# Memulihkan Riwayat Git

Clone repository:

```bash
git clone https://github.com/nullvoyager1/skyline-parser.git
cd skyline-parser
```

Lihat seluruh riwayat commit:

```bash
git --no-pager log --all \
  --graph \
  --decorate \
  --oneline \
  --parents
```

Ditemukan bahwa beberapa commit lama tidak lagi berada pada branch utama.

Salah satu commit dapat dipulihkan menggunakan SHA berikut:

```bash
git fetch origin \
  83791dcad7c5c006f5f889073307d68716aeff60
```

Kemudian buat branch lokal:

```bash
git branch recovered-old \
  83791dcad7c5c006f5f889073307d68716aeff60
```

Untuk melihat seluruh riwayat secara kronologis:

```bash
git --no-pager log --all --reverse \
  --format='%h | parent=%p | %an <%ae> | %aI | %s'
```

Riwayat commit yang berhasil dipulihkan:

```text
205d8d8 initial parser skeleton
2fcf208 add command line entry point
0c2f940 ignore comment lines
557b3bd validate empty fields
6d9461a add second sample capture
83791dc record local benchmark
8ae84dd organize reference fixtures
d787e1d update reference fixtures
62ef8e2 limit csv field splitting
5ace74c record screenshot settings
b4914b9 refresh reference set
ea89e50 add parser tests
18c1826 report input errors cleanly
4488988 document input format
```

---

# Menemukan Dokumen R03

Seluruh isi setiap commit diekstrak menggunakan:

```bash
mkdir -p ../full_history

for sha in $(git rev-list --reverse --all); do
    short=$(git rev-parse --short "$sha")
    mkdir -p "../full_history/$short"

    git archive "$sha" |
        tar -x -C "../full_history/$short"
done
```

Kemudian cari file yang berkaitan dengan **R03**:

```bash
find ../full_history -type f | grep -i 'r03'
```

Hasil:

```text
assets/reference/r03.pdf
```

Dokumen tersebut berisi daftar volunteer beserta pembagian zona kerja.

Informasi yang diperoleh:

```text
Full Name    : Nader Khoury
Volunteer ID : BB25-052
Work Zone    : B3
Portal Handle: naderk_47
```

Dokumen juga menjelaskan bahwa zona **B3** merupakan area:

```text
Media desk and backstage corridor
```

Sampai tahap ini diperoleh sebagian besar format flag:

```text
KaliTeam{NADER_KHOURY_BB25-052_B3_...}
```

---

# Menelusuri Aktivitas Online

Handle yang ditemukan pada dokumen:

```text
naderk_47
```

Digunakan sebagai petunjuk untuk mencari akun media sosial lain milik volunteer.

Pencarian mengarah pada sebuah posting Instagram:

```text
https://www.instagram.com/p/DboxjvbMhAL/
```

Beberapa elemen pada foto sesuai dengan konteks challenge, antara lain:

- Laptop dengan folder **the-last-shift**
- Catatan bertuliskan **The Last Shift**
- Berbagai stiker bertema ASU
- Latar belakang kota Amman

Lokasi aktivitas online tersebut mengarah ke neighborhood:

```text
Jabal Lweibdeh
```

Untuk format flag, nama lokasi dinormalisasi menjadi:

```text
JABAL_LWEIBDEH
```

---

# Penyusunan Flag

Format flag yang diminta:

```text
KaliTeam{FIRST_LAST_VOLUNTEER_ID_ZONE_NEIGHBORHOOD}
```

Hasil yang diperoleh:

```text
FIRST        = NADER
LAST         = KHOURY
VOLUNTEER_ID = BB25-052
ZONE         = B3
NEIGHBORHOOD = JABAL_LWEIBDEH
```

Sehingga flag akhirnya adalah:

```text
KaliTeam{NADER_KHOURY_BB25-052_B3_JABAL_LWEIBDEH}
```

---

# Flag

```text
KaliTeam{NADER_KHOURY_BB25-052_B3_JABAL_LWEIBDEH}
```

---

