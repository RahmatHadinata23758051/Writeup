# Looking through Windows - boroCTF Writeup

Challenge ini adalah tantangan forensik yang melibatkan analisis file VHD (Virtual Hard Disk). Deskripsi challenge memberikan petunjuk bahwa ada rahasia yang disembunyikan dengan cara dihapus.

## Analisis Awal

Pertama, saya memeriksa struktur partisi file `challenge.vhd` menggunakan `mmls`:

```bash
mmls challenge.vhd
```

Hasilnya menunjukkan adanya partisi NTFS yang dimulai pada sektor 128.

## Pemulihan File Terhapus

Menggunakan `fls` dari SleuthKit, saya mencari file yang telah dihapus dalam partisi tersebut secara rekursif:

```bash
fls -r -d -o 128 challenge.vhd
```

Hasilnya menunjukkan dua file yang dihapus di `$RECYCLE.BIN`:
- `$RIFYI8L.zip` (Data file)
- `$IIFYI8L.zip` (Metadata file)

Saya mengekstrak file zip tersebut menggunakan `icat`:

```bash
icat -o 128 challenge.vhd 39-128-1 > recovered.zip
```

## Brute-force Password Zip

Setelah mencoba mengekstrak `recovered.zip`, ternyata file `flag.txt` di dalamnya diproteksi oleh password. Saya menggunakan `fcrackzip` dengan wordlist `rockyou.txt` untuk menemukan passwordnya:

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt recovered.zip
```

Password berhasil ditemukan: `forget92936281`.

## Ekstraksi Flag

Menggunakan password tersebut, saya mengekstrak dan membaca flag:

```bash
unzip -P "forget92936281" recovered.zip
cat flag.txt
```

Flag: `boroCTF{f!l3_f0r3nsics_FTW!!}`
