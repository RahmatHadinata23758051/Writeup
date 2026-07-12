# Fear And Horror — Misc

**CTF:** Grodno CTF 2026  
**Kategori:** Misc  
**Artefak:** `chal_steg.pcap`  
**Flag:** `grodno{m3tr0n0m3x}`

## Ringkasan

Flag tidak berada di payload TLS. Data disimpan pada header record PCAP melalui selisih antara panjang frame asli dan panjang frame yang benar-benar disimpan:

```text
symbol = original_length - captured_length
```

Selisihnya selalu `0–7`, jadi setiap paket membawa tepat 3 bit. Setelah sesi sinkronisasi dibuang dan simbol dibaca per kolom, bitstream menghasilkan flag secara langsung.

## 1. Triage PCAP

```bash
file chal_steg.pcap
```

```text
chal_steg.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

Trafiknya didominasi aktivitas Windows biasa. Dua indikator yang paling mencolok:

- `endofyour.ink` mengirim file gzip bernama `Rose.txt`.
- `westvirjin.space` mengarah ke `193.109.69.2` dan menerima koneksi TLS berulang sekitar setiap lima menit.

Resolusi DNS bisa dicek dengan:

```bash
tshark -r chal_steg.pcap \
  -Y 'dns.qry.name == "westvirjin.space" && dns.flags.response == 1' \
  -T fields -e frame.number -e dns.qry.name -e dns.a
```

```text
westvirjin.space    193.109.69.2
```

## 2. Rabbit hole: `Rose.txt.gz`

HTTP stream menuju `endofyour.ink` dapat direkonstruksi menjadi gzip berukuran 408187 byte. Header gzip valid dan filename internalnya `Rose.txt`, tetapi DEFLATE rusak sejak awal:

```text
Error -3 while decompressing data: invalid distance too far back
```

Cookie request memang memuat hostname, username, build Windows, dan beberapa identifier. Percobaan XOR/RC4 dari nilai-nilai itu tidak menghasilkan flag. Artefak ini berguna sebagai distraksi dan konteks malware traffic, tetapi bukan covert channel final.

## 3. Anomali pada record PCAP

Pada koneksi menuju `193.109.69.2:443`, beberapa paket terlihat memiliki TCP checksum salah. Penyebab sebenarnya bukan perubahan payload, tetapi frame disimpan lebih pendek daripada panjang aslinya.

Field yang relevan di classic PCAP:

```text
incl_len  = jumlah byte yang tersimpan di file
orig_len  = panjang frame ketika berada di wire
```

Cek cepat memakai Tshark:

```bash
tshark -r chal_steg.pcap \
  -Y 'ip.addr == 193.109.69.2 && tcp.len > 0' \
  -T fields \
  -e frame.number -e tcp.srcport -e tcp.dstport \
  -e frame.cap_len -e frame.len -e tcp.checksum.status
```

Satu sesi TLS lengkap mempunyai enam posisi paket yang konsisten. Panjang frame aslinya:

```text
237, 1356, 147, 296, 271, 225
```

Untuk setiap posisi tersebut, hitung:

```text
delta = frame.len - frame.cap_len
```

Hasil sembilan sesi lengkap:

```text
client port    p0 p1 p2 p3 p4 p5
49795           3  3  3  3  3  1
49798           1  1  6  5  3  4
49828           0  0  0  0  0  0
49832           6  0  6  0  4  6
49837           7  6  6  7  3  7
49846           1  7  6  1  0  4
49849           1  1  4  0  1  1
49852           5  5  6  6  5  7
49863           7  7  3  0  5  5
```

Baris port `49828` seluruhnya nol. Ini adalah sesi sinkronisasi/heartbeat dan tidak masuk data.

Setelah dibuang, tersisa:

```text
8 sesi × 6 posisi × 3 bit = 144 bit = 18 byte
```

Panjang 18 byte sama dengan panjang flag lengkap.

## 4. Urutan pembacaan

Kesalahan paling gampang adalah membaca matriks per baris. Urutan yang benar adalah **per kolom**:

```text
p0 untuk seluruh sesi data,
p1 untuk seluruh sesi data,
...
p5 untuk seluruh sesi data.
```

Urutan simbolnya:

```text
3 1 6 7 1 1 5 7
3 1 0 6 7 1 5 7
3 6 6 6 6 4 6 3
3 5 0 7 1 0 6 0
3 3 4 3 0 1 5 5
1 4 6 7 4 1 7 5
```

Setiap nilai ditulis sebagai biner 3-bit dan disambungkan:

```text
0110011101110010011011110110010001101110011011110111101101101101
0011001101110100011100100011000001101110001100000110110100110011
0111100001111101
```

Konversi per delapan bit menghasilkan:

```text
67726f646e6f7b6d337472306e306d33787d
```

```text
grodno{m3tr0n0m3x}
```

## 5. Solver

Solver membaca header classic PCAP secara langsung, jadi tidak membutuhkan Scapy atau Dpkt.

```bash
python3 solve.py chal_steg.pcap
```

```text
[+] target C2: 193.109.69.2:443
[+] delta matrix (orig_len - incl_len):
    49795: 3 3 3 3 3 1
    49798: 1 1 6 5 3 4
    49828: 0 0 0 0 0 0
    49832: 6 0 6 0 4 6
    49837: 7 6 6 7 3 7
    49846: 1 7 6 1 0 4
    49849: 1 1 4 0 1 1
    49852: 5 5 6 6 5 7
    49863: 7 7 3 0 5 5
[+] sync row dibuang: client port 49828
[+] decoded hex: 67726f646e6f7b6d337472306e306d33787d
<FLAG>grodno{m3tr0n0m3x}</FLAG>
```

## Flag

```text
grodno{m3tr0n0m3x}
```
