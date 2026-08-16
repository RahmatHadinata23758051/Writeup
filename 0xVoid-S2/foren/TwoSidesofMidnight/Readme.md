# Two Sides of Midnight

## Ringkasan

PCAPNG ini adalah gabungan dua passive tap. Interface 0 bernama `tap-ingress`, sedangkan interface 1 bernama `tap-egress`. Karena kedua tap menangkap traffic yang sama, paket dengan TCP sequence yang sama tidak otomatis berarti payload-nya identik.

Flag ditemukan pada evidence hasil XOR payload stream yang diubah:

`0xV01D{one_sequence_two_realities}`

## 1. Recon

```bash
file two-side-of-midnight.pcapng capture.txt
cat capture.txt
tshark -r two-side-of-midnight.pcapng -T fields \\
  -e frame.interface_id -e frame.interface_name | sort -u
```

Hasilnya menunjukkan PCAPNG valid dan dua interface:

```text
0  tap-ingress
1  tap-egress
```

`capture.txt` memberi konteks bahwa appliance berada di antara kedua tap, diduga mengubah satu binary upload, dan TCP sequence space tetap dipertahankan.

## 2. Menentukan flow yang berubah

Ringkasan TCP menunjukkan empat stream. Tiga stream background memiliki payload yang sama pada interface 0 dan 1. Stream 0 (`10.42.0.19:49173 -> 10.42.0.8:8443`) berbeda.

Contoh perbandingan payload dengan sequence yang sama:

```text
stream 0, seq 1, interface 0:  8a629853ccbe...
stream 0, seq 1, interface 1:  c434c062ccbe...
```

Jadi flow yang dimodifikasi adalah stream 0. Retransmission identik di sisi yang sama dideduplikasi berdasarkan `(interface, stream, TCP sequence, TCP length)`; interface tetap dipakai sebagai identitas capture point.

## 3. Recovery evidence

Payload setiap sisi disusun kembali mengikuti TCP sequence order. Setelah itu, payload ingress dan egress di-XOR byte per byte:

```python
evidence = bytes(a ^ b for a, b in zip(ingress, egress))
```

Hasil XOR berukuran 397 byte. Bagian awalnya adalah marker dan padding internal, lalu terdapat ZIP local header pada offset 20:

```text
4e 56 58 31 00 ... 50 4b 03 04
NVX1.             PK..
```

ZIP berisi dua file:

```text
incident.txt
operator_note.txt
```

Ekstraksi dapat dilakukan dengan:

```bash
unzip -o s0_xor.bin -d recovered
cat recovered/incident.txt
```

`operator_note.txt` mengarahkan analisis ke capture points dan TCP sequence order. `incident.txt` memuat flag.

## 4. Solver

`solve.py` mengulang proses secara otomatis menggunakan `tshark`: membaca payload per interface, mengurutkan sequence, membandingkan stream, melakukan XOR pada stream 0, mencari ZIP, lalu mengekstrak evidence ke direktori `recovered/`.

Jalankan:

```bash
python3 solve.py
```

Output akhirnya:

```text
Flag: 0xV01D{one_sequence_two_realities}
```
