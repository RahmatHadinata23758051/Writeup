# Chronos - Forensic Challenge

Challenge ini fokus pada analisis **Timing Covert Channel** dalam network capture.

## Analisis
1.  **Initial Recon**: File `chall.pcap` berisi banyak paket TCP SYN yang dikirim dari `10.10.10.5` ke `192.168.1.20`. Semua field paket (port, seq, window size, dll.) bersifat konstan, namun interval waktu antar paket (delays) sangat bervariasi secara teratur.
2.  **Timing Analysis**: Delay antar paket hanya terdiri dari dua nilai: `0.25` detik dan `0.75` detik. Ini adalah indikasi kuat adanya transmisi binary lewat timing.
    - `0.25` detik diinterpretasikan sebagai bit `0`.
    - `0.75` detik diinterpretasikan sebagai bit `1`.
3.  **Decoding**:
    - Deskripsi challenge menyebutkan "bilingual", yang mengisyaratkan adanya dua jenis encoding atau format data.
    - Setelah mengekstrak bitstream, pola `boroCTF{` ditemukan dengan struktur yang unik: Karakter pertama (`b`) direpresentasikan dalam **7 bit**, sedangkan karakter-karakter selanjutnya menggunakan **8 bit** (prefix `0` + 7 bit ASCII).
    - Total bit yang tersedia adalah 311, yang pas dengan 1 karakter (7 bit) + 38 karakter (8 bit) = 39 karakter.

## Eksploitasi
Script `solve.py` mengekstrak timestamp dari PCAP menggunakan `tshark`, menghitung delay, dan mendekode bitstream sesuai dengan pola bit yang ditemukan.

```python
# boroCTF{c0mbobulat3_sp@gh3tti_nep0t1$m}
```

## Flag
<FLAG>boroCTF{c0mbobulat3_sp@gh3tti_nep0t1$m}</FLAG>
