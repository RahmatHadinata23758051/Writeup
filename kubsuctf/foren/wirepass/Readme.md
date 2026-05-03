# Writeup wirepass

Challenge ini kelihatan seperti network forensics biasa, tapi inti jebakannya ada di protokol custom yang dipakai di atas TCP. Di folder challenge hanya ada satu file, `chall.pcap`, jadi langkah pertama saya benar-benar fokus ke triage dasar: identifikasi file, cek string yang langsung terbaca, lalu lihat protokol apa saja yang muncul di capture.

## Recon awal

Dari `strings` dan `tshark`, kelihatan ada banyak traffic umpan: HTTP, FTP, JSON, sampai beberapa login FTP dengan banyak password berbeda. Bagian yang paling menarik justru ada di koneksi custom dengan port non-standar, khususnya:

- stream `70` ke port `9999`
- stream `86` ke port `31337`

Stream `70` sangat penting karena isinya plaintext:

```text
PASS:IcyFl1pp3r$2026
ACK:OK
```

Awalnya saya belum tahu ini password untuk apa, tapi jelas ini harus disimpan.

## Identifikasi payload utama

Stream `86` adalah transfer terbesar dan polanya berbeda dari stream-stream lain. Payload mentahnya diawali dengan magic:

```text
XFERJ
```

Setelah itu ada 16 byte yang kelihatan seperti IV / key material pendek, lalu sisa data biner. Dugaan pertama saya benar: payload itu bukan random murni, melainkan hasil XOR terhadap blok data lain.

Kesalahan terbesar di fase awal adalah asumsi offset saya meleset 1 byte. Saya sempat mencoba:

- IV di offset `5:21`
- body mulai offset `25`

Hasilnya memang mirip ZIP AES, tapi ada banyak header yang korup, nama file berubah sedikit, dan arsip harus direpair manual. Arsip itu bisa dilist, tetapi password terlihat salah.

## Titik balik

Saya lalu brute-force alignment kecil di sekitar offset payload, bukan brute-force password. Dari situ ketemu alignment yang benar:

- IV = `data[4:20]`
- body = `data[24:]`
- plaintext = `body[i] XOR iv[i % 16]`

Dengan alignment ini, hasil decode langsung menjadi ZIP yang bersih:

- header mulai dengan `PK\x03\x04`
- nama file terbaca utuh
- `7z l` bisa membaca arsip tanpa warning

Isi arsip:

- `mission_report.txt`
- `roster.txt`
- `map.txt`

Di titik ini password dari stream `9999` langsung saya uji lagi, dan ternyata memang benar:

```text
IcyFl1pp3r$2026
```

Kesimpulannya, password itu bukan salah, yang salah adalah alignment dekripsi XOR saya di awal.

## Ekstraksi flag

Setelah arsip berhasil diekstrak, file `mission_report.txt` berisi laporan operasi dalam bahasa Rusia. Di bagian bawah dokumen ada satu baris yang jelas merupakan flag:

```text
СЕКРЕТНЫЙ КОД ОПЕРАЦИИ: KubSTU{p1ngu1n_0p_k4p1b4r0v5k_f4ll5}
```

Itulah flag challenge.

## Ringkasan teknis

Alur solve yang final:

1. Ambil raw stream `86` dari PCAP.
2. Decode dengan XOR berulang memakai 16-byte IV pada offset `4:20`.
3. Body dimulai dari offset `24`.
4. Hasilnya adalah ZIP AES valid.
5. Password ZIP diambil dari stream `70`: `IcyFl1pp3r$2026`.
6. Ekstrak `mission_report.txt` dan ambil flag.

## File yang saya simpan

- `solve.py`
  Script final untuk mereproduksi proses ekstraksi dari `chall.pcap`.
- `stream86_alt.bin`
  Arsip ZIP hasil decode yang benar.

## Catatan

Challenge ini bukan menipu lewat kripto berat, tapi lewat offset yang sengaja bikin hasil decode “hampir benar”. Begitu alignment XOR dibetulkan, semua potongan langsung nyambung: stream auth memberi password, stream transfer memberi arsip, dan flag ada di dokumen utama.
