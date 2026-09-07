# The Temple

## Ringkasan

Flag berada di hard drive virtual yang harus di-mount dari TempleOS lewat noVNC. OS tidak perlu di-install.

## File Challenge

- `flag.png` — screenshot bukti flag setelah drive berhasil di-mount.

## Analisis Awal

Saat boot, pilih `n` untuk pertanyaan install ke hard drive dan pilih `n` untuk tour. Setelah itu muncul prompt `T:/Home>`.

`DrvRep;` awalnya hanya menampilkan RAM drive dan CD/DVD drive. Hard drive virtual belum terdaftar, jadi digunakan perintah `Mount;`.

## Temuan Penting

Pada menu mount:

1. Pilih drive letter `C`.
2. Pilih probe dengan `p`.
3. Pilih device `1`, yaitu `Hard Drive ATA Primary IDE`.

Setelah berhasil, drive `C` muncul sebagai FAT32 dengan model `QEMU HARDDISK`.

## Proses Ekstraksi

Isi root drive diperiksa dengan:

```text
Dir("C:/*");
```

Hasilnya menunjukkan file `FLAG.TXT` berukuran `005C` byte. File dibaca dengan:

```text
Type("C:/FLAG.TXT");
```

Untuk memastikan kapitalisasi flag secara byte-per-byte, isi file juga dicetak sebagai hexadecimal:

```text
U8 *p;I64 n,i;p=FileRead("C:/FLAG.TXT",&n);for(i=0;i<n;i++)Print("%02X",p[i]);
```

Hex tersebut didekode sebagai bytes ASCII. Byte terakhir adalah newline `0A`, bukan bagian dari flag.

## Solve Script

Tidak ada solve script yang diperlukan. Ekstraksi dilakukan langsung melalui console TempleOS di noVNC.

## Cara Menjalankan

1. Buka service challenge melalui noVNC.
2. Boot tanpa install dan tanpa tour (`n`, lalu `n`).
3. Jalankan `Mount;`, pilih `C`, probe `p`, lalu pilih device `1`.
4. Jalankan `Dir("C:/*");` dan baca `C:/FLAG.TXT`.

## Flag

```text
NNS{4_godly_H0ly_5om37hing_som37HiNg_0Perat1N6_5y573m_tHat_run5_1n_ring_0_is_5UcH_a_b3aUtY}
```

## Catatan

Flag case-sensitive. Kandidat sebelumnya salah pada `som37HiNg` dan `b3aUtY`, khususnya huruf `N` dan `Y` yang harus kapital.
