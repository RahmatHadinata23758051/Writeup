# Writeup: Are You Still There?

## Analisis Awal
Pada challenge "Are You Still There?", kita diberikan sebuah file PCAPNG dengan hint di dalam deskripsinya: *"how would you remotely check if a server is online?"*.
Dari hint tersebut, sangat jelas bahwa metode yang umum digunakan untuk mengecek apakah sebuah server sedang online adalah dengan menggunakan perintah `ping`, yang mana memanfaatkan protokol jaringan ICMP (Internet Control Message Protocol).

## Ekstraksi Data
Berbekal informasi tersebut, saya menggunakan tool `tshark` untuk melakukan filter pada paket-paket dengan protokol `icmp`. Saya mengambil payload data dari paket-paket tersebut dengan command:
```bash
tshark -r chall.pcapng -Y "icmp" -T fields -e data
```

Hasil dari command tersebut menampilkan urutan byte dalam format heksadesimal yang berulang (karena tiap pasang mewakili request dan reply):
```text
62797563
74667b54
75727233
745f5233
64336d70
7421306e
5f4c216e
33735f34
72335f4e
30745f52
21643373
7d
```

## Decoding
Langkah terakhir adalah melakukan decoding heksadesimal tersebut kembali menjadi karakter ASCII.
Tiap baris dapat diterjemahkan menjadi bagian dari teks:
- 62797563 -> byuc
- 74667b54 -> tf{T
- 75727233 -> urr3
- 745f5233 -> t_R3
- 64336d70 -> d3mp
- 7421306e -> t!0n
- 5f4c216e -> _L!n
- 33735f34 -> 3s_4
- 72335f4e -> r3_N
- 30745f52 -> 0t_R
- 21643373 -> !d3s
- 7d       -> }

Setelah semua pecahan dirangkai, kita akan mendapatkan string flag secara utuh.

**Flag:** `byuctf{Turr3t_R3d3mpt!0n_L!n3s_4r3_N0t_R!d3s}`
