# Kira-Notes

**Category:** Forensics  
**Flag:** `NHNC{n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy}`

## Ringkas

Artefak awalnya `places.sqlite` dari Firefox. Dari history ketemu beberapa URL penting: halaman web challenge, file download, dan link Proton Drive public share. Dari situ alurnya pindah ke decrypt share Proton, lalu ke image disk ext4 untuk ambil clue terakhir.

## Langkah Solve

### 1. Ambil pivot dari browser history

`places.sqlite` berisi history yang langsung nunjuk ke resource penting:

- `http://151.158.224.74:31337/`
- `http://151.158.224.74:31337/#guestbook`
- `http://151.158.224.74:31337/dl/notebook-crack.tgz`
- `http://151.158.224.74:31337/dl/eyeswap.bin`
- `https://drive.proton.me/urls/00MNVW0SHG#do4wWWpAQ0Lw`

Link Proton Drive ini jadi jalur utama karena file yang lain cuma petunjuk.

### 2. Dekripsi public share Proton Drive

Dari source map bundle Proton, flow public link-nya bisa direplikasi:

- ambil info share
- auth ke token `00MNVW0SHG`
- pakai password dari fragment `do4wWWpAQ0Lw`
- lanjut SRP handshake
- decrypt share key dan node

Hasilnya folder `Kira-Notes` terbuka dan berisi:

- `noth*****.png`
- `Some Backup 01.png`
- `of.img`

### 3. Analisis disk image

`of.img` dan hasil carving full image menunjukkan partisi ext4 dengan beberapa nama file menarik:

- `I`
- `will`
- `not`
- `let`
- `you`
- `see`
- `it`

Di raw ext4 juga ketemu file tersembunyi lain, termasuk ZIP terenkripsi dan PNG clue. PNG hasil carving menampilkan teks:

`0x0Kira 1337`

### 4. Buka ZIP terenkripsi

`recovered_flag.zip` berisi `flag.txt` dan diproteksi AES. Password-nya diambil dari clue gambar, dengan huruf `k` kecil:

`0x0kira1337`

Ekstraksi:

```bash
7z x -p0x0kira1337 recovered_flag.zip
cat flag.txt
```

Output akhirnya:

```text
NHNC{n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy}
```

