# Writeup - Office Switching

Kategori: `misc`  
Tipe: `OSINT`

Challenge ini kelihatannya sederhana di permukaan karena situs utamanya hanya landing page biasa. Kuncinya justru ada di petunjuk kecil yang tersebar di beberapa tempat dan semuanya masih berada dalam domain target.

## Langkah 1 - Cek halaman utama

Saya mulai dari halaman utama:

```bash
curl -L https://bluepeakcyber.co.uk/
```

Di source HTML ada komentar yang menarik:

```html
<!-- synced footers from internalit.bluepeakcyber -->
```

Komentar ini memberi petunjuk bahwa ada subdomain internal bernama `internalit.bluepeakcyber.co.uk`.

## Langkah 2 - Enumerasi subdomain internal

Setelah dibuka, subdomain itu tidak menampilkan portal asli, hanya halaman maintenance:

```bash
curl -skL https://internalit.bluepeakcyber.co.uk/
```

Halaman itu sendiri belum memberi flag, jadi saya cek file yang sering terlupakan:

```bash
curl -skL https://internalit.bluepeakcyber.co.uk/robots.txt
```

Hasilnya:

```text
User-agent: *
Disallow: /memo.pdf
```

Berarti ada file `memo.pdf` yang sengaja tidak ingin diindeks, dan biasanya itu justru petunjuk penting.

## Langkah 3 - Ambil dan baca memo

Saya download lalu ekstrak teksnya:

```bash
curl -skL https://internalit.bluepeakcyber.co.uk/memo.pdf -o memo.pdf
pdftotext memo.pdf -
```

Isi memo menjelaskan bahwa tim Internal IT sedang menangani masalah DNS, dan beberapa record lama atau sementara sengaja dibiarkan tetap aktif.

Kalimat pentingnya bukan sebuah lokasi langsung, tapi arah investigasinya jelas: **fokus ke DNS**.

## Langkah 4 - Lihat DNS record domain utama

Karena challenge meminta mencari ke mana tim Infrastructure dipindahkan, saya cek TXT record dari domain utama:

```bash
dig +short txt bluepeakcyber.co.uk
```

Output penting:

```text
"Legacy systems have been left running while the new infrastructure is under maintenance. To contact the infrastructure team get in contact with support@coventry.r032.bluepeakcyber.co.uk"
```

Dari sini terlihat bahwa tim Infrastructure sudah mengarah ke host:

```text
coventry.r032.bluepeakcyber.co.uk
```

## Langkah 5 - Cek TXT record host baru

Karena memo sebelumnya memang menekankan adanya record DNS yang sengaja dibiarkan, saya lanjut cek TXT record host tersebut:

```bash
dig +short txt coventry.r032.bluepeakcyber.co.uk
```

Hasilnya langsung berisi flag:

```text
"RMCTF{DN5_1S_PUBLIC}"
```

## Flag

```text
RMCTF{DN5_1S_PUBLIC}
```

## Inti challenge

Challenge ini memancing solver agar tidak berhenti di web page utama. Alurnya:

1. Temukan subdomain internal dari komentar HTML.
2. Temukan `memo.pdf` dari `robots.txt`.
3. Gunakan isi memo sebagai petunjuk bahwa masalah utamanya ada di DNS.
4. Baca TXT record domain utama untuk menemukan lokasi baru tim Infrastructure.
5. Baca TXT record host tersebut untuk mendapatkan flag.

Pendekatan ini cocok dengan judul **Office Switching**, karena "perpindahan kantor" tim ternyata direpresentasikan lewat perpindahan ke host/subdomain baru, bukan lewat halaman web biasa.
