# Transcendent Renovation

Kategori: Forensics — Windows Jump Lists

## Jawaban service

| No. | Jawaban |
|---:|---|
| 1 | `OLE CF` |
| 2 | `f01b4d95cf55d32a.automaticDestinations-ms` |
| 3 | `\\TSCLIENT\HAUNTEDHOUSE` |
| 4 | `46` |
| 5 | `EC2AB952-7E4D-11F1-89AD-A2DEAD7852AD` |
| 6 | `logging-vm` |
| 7 | `SoulSearching` |

Nomor 7 berasal dari nama lama `SoulSearch`. Sesuai pengumuman panitia, suffix `ing` harus ditambahkan sehingga jawaban yang diterima server adalah `SoulSearching`.

## Analisis artefak

Direktori berisi berkas `.automaticDestinations-ms` dan `.customDestinations-ms`. Signature berkas automatic destination adalah OLE Compound File, sehingga format Jump List yang diminta service adalah `OLE CF`.

Pencarian UTF-16LE menemukan `NoNeedToWonder` di:

```text
AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms
```

Berkas tersebut dibuka sebagai OLE compound file dan berisi stream `DestList` serta stream numerik. Stream `46` berisi embedded Shell Link yang menargetkan:

```text
C:\Users\Administrator\Desktop\NoNeedToWonder
```

Distributed Link Tracker block pada stream tersebut berisi:

```text
Machine identifier       : logging-vm
Droid file identifier    : EC2AB952-7E4D-11F1-89AD-A2DEAD7852AD
Droid volume identifier  : 08D1517C-F0EA-455F-A42A-7788A985FDE1
```

Stream `45` adalah Shell Link ke network location dan menghasilkan:

```text
\\TSCLIENT\HAUNTEDHOUSE
```

Data tambahan stream `46` menyimpan path lama:

```text
C:\Users\Administrator\Desktop\SoulSearch
```

Jadi folder berubah dari `SoulSearch` menjadi `NoNeedToWonder`. Karena answer key service membutuhkan suffix dari pengumuman panitia, jawaban nomor 7 dikirim sebagai `SoulSearching`.

## Submit

Jalankan:

```bash
python solve.py
```

Flag:

```text
L3AK{P4r4n0rm4l_P4r4ll3l_P47h5}
```
