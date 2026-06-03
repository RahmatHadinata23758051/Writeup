# Panic In the Northern Quadrant (part 1/3)

Challenge ini ternyata jauh lebih sederhana daripada kelihatannya di deskripsi. Aku sempat cek beberapa endpoint seperti `download-legacy` dan `backup`, tapi flag part 1 sudah bocor langsung dari halaman utama.

## Ringkasan

Halaman `/` menampilkan potongan source JavaScript untuk "internal use only". Di bagian bawah HTML ada blok script yang dikomentari. Di dalam komentar itu ada fungsi `backup()` yang memanggil endpoint `backup` dengan body hasil `atob(...)`.

Potongan yang menarik:

```js
"body" : atob("dXNlcm5hbWU9c3N0JnBhc3N3b3JkPVRIQ3tzM2N1cjNwNDU1fQ==")
```

Kalau string base64 itu di-decode, hasilnya:

```text
username=sst&password=THC{s3cur3p455}
```

Jadi flag part 1 langsung kelihatan sebagai value `password`.

## Langkah yang dipakai

1. Buka homepage challenge.
2. Lihat source HTML/JavaScript.
3. Cari string base64 yang dipakai oleh fungsi `backup()`.
4. Decode string tersebut.
5. Ambil nilai parameter `password`.

## Solver

Solver ada di file [solve.py](/home/nata/ctf/THCON2026/web/PanicInTheNorthernQuadrant1/solve.py).

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output-nya akan menampilkan username, password, dan flag dalam format submit:

```text
[+] username = sst
[+] password = THC{s3cur3p455}
<FLAG>THC{s3cur3p455}</FLAG>
```

## Catatan

Aku sempat validasi juga bahwa kredensial itu memang dipakai oleh endpoint `backup`, jadi ini bukan string palsu yang sengaja ditaruh buat ngelabui. Tapi untuk solve part 1, decode string di homepage saja sudah cukup.

## Flag

```text
THC{s3cur3p455}
```
