# Writeup: There Will Be Cake (BYUCTF)

## Deskripsi Singkat
Challenge ini memberikan kita sebuah file PCAP (`chall.pcapng`) yang berisi rekaman traffic jaringan. Dari deskripsi soal, kita dikasih tahu bahwa file PCAP ini sebenarnya nyimpen 4 flag untuk 4 challenge yang berbeda:
1. "There will be cake"
2. "Are you still there?"
3. "Alright. Paradox time"
4. "Corrupted Cores"

Karena fokus kita di challenge saat ini adalah **"There Will Be Cake"**, kita harus perhatiin baik-baik hint yang dikasih: 
> *"what is a baked treat similar to a cake that you can find on almost any website?"* (Apa camilan yang dipanggang mirip kue yang bisa kamu temukan di hampir semua website?)

## Analisis & Solusi
Hint tersebut sangat jelas merujuk pada kata **"Cookie"**. Cookie bisa berarti kue kering, tapi di dunia IT, Cookie adalah data sesi yang disimpan oleh browser dari sebuah website.

Jadi, tujuan kita selanjutnya adalah ngecek *traffic* HTTP pada file PCAP buat nyari apakah ada *HTTP Cookie* yang disisipkan. 

1. **Mengekstrak traffic HTTP:**
   Kita bisa pakai Wireshark atau command `tshark` di terminal buat memfilter traffic HTTP aja. 
   ```bash
   tshark -r chall.pcapng -Y "http" -V
   ```
   Kalau kita perhatikan, pada paket ke-15 ada sebuah HTTP Request dengan metode `POST / HTTP/1.1`. Pas dicek bagian header-nya, ada parameter cookie unik yang dikirimkan klien:
   `Cookie: cake=Ynl1Y3Rme1RoM19DNGszXyFzXzRfTCEzX0hUQzU2emVFfQ==`

2. **Decoding Base64:**
   Value dari cookie tersebut, yaitu `Ynl1Y3Rme1RoM19DNGszXyFzXzRfTCEzX0hUQzU2emVFfQ==` sangat ketara kalau itu adalah format encoding *Base64* (terlihat dari susunan karakternya dan adanya `==` sebagai padding di akhir string). Tinggal kita decode aja di terminal:
   ```bash
   echo "Ynl1Y3Rme1RoM19DNGszXyFzXzRfTCEzX0hUQzU2emVFfQ==" | base64 -d
   ```
   Hasil decode-nya langsung ngasih kita teks flag yang dicari:
   `byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}`

## Catatan Ekstra
Flag yang sebelumnya sempet didapat yaitu `byuctf{Th3_P4rt_Wh3r3_H3_K!lls_Y0u}` adalah flag yang salah untuk soal ini karena flag tersebut sebenernya milik challenge **"Corrupted Cores"** (flag itu disembunyikan di dalam *Source IP Address* yang di-spoofing pada paket-paket request ICMP).

Untuk challenge **"There Will Be Cake"**, lokasinya 100% ada di dalem *HTTP Cookie*.

**Flag:** `byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}`
