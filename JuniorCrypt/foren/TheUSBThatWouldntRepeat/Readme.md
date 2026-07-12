# The USB That Wouldn't Repeat

Targetnya minta MD5 dari dua acquisition Windows FTK Imager:

- `Flash-firstrun.001`
- `Flash-secondrun.001`

Artefak yang relevan ada di:

- `digitalcorpora/windows7-ftkimager/flash-firstrun.001`
- `digitalcorpora/windows7-ftkimager/flash-firstrun.001.txt`
- `digitalcorpora/windows7-ftkimager/flash-secondrun.001`
- `digitalcorpora/windows7-ftkimager/flash-secondrun.001.txt`
- `usb-non-deterministic-narrative.pdf`

## Langkah yang dipakai

Identifikasi file dulu:

```bash
rtk file usb-non-deterministic-narrative.pdf \
  digitalcorpora/windows7-ftkimager/flash-firstrun.001 \
  digitalcorpora/windows7-ftkimager/flash-secondrun.001 \
  digitalcorpora/windows7-ftkimager/flash-firstrun.001.txt \
  digitalcorpora/windows7-ftkimager/flash-secondrun.001.txt
```

Hasil pentingnya: PDF terbaca normal, sementara `.001` dan `.txt` dikenali sebagai `data`, jadi isi file perlu dibuka langsung.

Cek sidecar FTK:

```bash
rtk sed -n '1,220p' digitalcorpora/windows7-ftkimager/flash-firstrun.001.txt
rtk sed -n '1,220p' digitalcorpora/windows7-ftkimager/flash-secondrun.001.txt
```

Di bagian `[Computed Hashes]` muncul:

- `flash-firstrun.001` -> `09817bced4213360c1cb2749aa375523`
- `flash-secondrun.001` -> `2bdab2c08b5b507876bf2f2d7e548cc5`

Supaya tidak cuma percaya log, hash file `.001` diverifikasi langsung:

```bash
rtk md5sum digitalcorpora/windows7-ftkimager/flash-firstrun.001
rtk md5sum digitalcorpora/windows7-ftkimager/flash-secondrun.001
```

Output verifikasi:

```text
09817bced4213360c1cb2749aa375523  digitalcorpora/windows7-ftkimager/flash-firstrun.001
2bdab2c08b5b507876bf2f2d7e548cc5  digitalcorpora/windows7-ftkimager/flash-secondrun.001
```

Nilai ini cocok dengan log FTK. PDF `usb-non-deterministic-narrative.pdf` menjelaskan kenapa hasil acquisition bisa berbeda antar run: sektor non-deterministic mengembalikan isi command `SCSI READ(10)` yang sedang diproses, jadi image dari akuisisi berbeda bisa menghasilkan hash berbeda walaupun tidak ada write ke USB di antaranya.

## Flag

```text
grodno{09817bced4213360c1cb2749aa375523_2bdab2c08b5b507876bf2f2d7e548cc5}
```
