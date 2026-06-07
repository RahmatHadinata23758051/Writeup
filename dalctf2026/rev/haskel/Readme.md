# Haskell2

Challenge ini kelihatan seperti compiler Haskell kecil, tapi ternyata bahasa yang dipakai jauh lebih sederhana.

## Langkah awal

Saya mulai dari enumerasi lokal pada binary `haskel`:

- `file` menunjukkan ini ELF 64-bit PIE yang stripped.
- `strings` langsung ngasih petunjuk keyword bahasa:
  - `remember that`
  - `innocuous`
  - `read file`
  - `for each`
  - `tell me`
- Dari `r2`, terlihat compiler ini bukan interpreter murni. Dia generate C, lalu compile lagi pakai `cc`.

## Grammar yang ketemu

Setelah beberapa percobaan, format bahasa sumbernya kebaca:

- assignment biasa:

```hs2
remember that x is 1
```

- output:

```hs2
tell me x
```

- binding file:

```hs2
innocuous f <- read file "path"
```

- baca isi file per baris:

```hs2
for each line in f tell me line
```

Kalau file hasil `read file` dipakai langsung tanpa `for each`, compiler ngasih semantic error:

- `file values must be consumed by a line iterator`

## Validasi lokal

Saya cek dulu di lokal dengan file contoh seperti `/etc/hostname`.

Program ini berhasil dan generate executable yang mem-print isi file baris demi baris:

```hs2
innocuous x <- read file "/etc/hostname"
for each line in x tell me line
```

## Pencarian flag

Di remote service, `"/flag"` gagal dibaca. Saya lanjut brute force path yang umum:

- `/flag`
- `/app/flag`
- `/home/challenge/flag`
- `/home/challenge/flag.txt`
- dan variasi lain

Lalu saya pakai `/etc/passwd` untuk lihat user yang ada di container. Di sana ada user `challenge` dengan home `/home/challenge`.

Setelah brute lebih luas, path yang benar ternyata:

```text
flag.txt
```

Jadi payload final cukup baca file itu dan print per baris.

## Payload final

```hs2
innocuous f <- read file "flag.txt"
for each line in f tell me line
```

Program ini dikirim ke service sebagai base64, lalu checker menjalankan hasil compile-nya dan mengeluarkan flag.
