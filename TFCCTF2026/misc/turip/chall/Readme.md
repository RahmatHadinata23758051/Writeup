# TURIP

## Ringkasan

Service Flask meminta request POST dengan path dan body yang harus persis. Request tersebut juga diperiksa dari hasil capture TCP yang diproses Tulip. Celahnya ada pada perbedaan validasi TCP antara kernel Linux dan reassembler Tulip.

## File Challenge

- `app.py` — endpoint Flask, autentikasi, validasi request, dan pemeriksaan traffic.
- `Dockerfile`, `entrypoint.sh`, `start_capture.sh` — konfigurasi PostgreSQL, tcpdump, dan Tulip.
- `solve.py` — automasi login, packet crafting, request valid, dan polling flag.

## Analisis Awal

`app.py` menetapkan request canonical berikut:

```http
POST /get_flag1337 HTTP/1.1
Content-Type: application/json
Content-Length: 50

{"supersecretkey":"turip_ip_ip","ip":"1337.0.0.1"}
```

`/check` mencari beberapa needle pada client stream hasil capture, termasuk `get_flag1337`, `turip_ip_ip`, dan `1337.0.0.1`. Jadi request normal selalu ditolak oleh pemeriksaan traffic.

## Temuan Penting

Tulip dijalankan dengan `-skipchecksum`, dan source reassembler Tulip hanya menggunakan sequence number untuk reassembly. Tulip tidak memvalidasi apakah nilai ACK masih valid untuk koneksi tersebut.

Linux TCP menolak payload dari segment dengan ACK yang satu angka lebih lama dari ACK yang diharapkan. Segment tersebut tetap terlihat oleh tcpdump dan dikonsumsi Tulip sebagai data pertama. Request valid berikutnya dikirim dengan sequence number yang sama. Kernel menerima dan memproses request valid, sedangkan Tulip menganggapnya overlap dengan data lama lalu membuangnya.

## Proses Ekstraksi

1. Login ke `/auth` menggunakan team token.
2. Buka koneksi TCP normal dan ambil sequence number handshake dari capture lokal.
3. Kirim payload dummy sepanjang request canonical dengan ACK `expected_ack - 1`.
4. Kirim request canonical yang sebenarnya dengan sequence number sama.
5. Baca response yang memiliki header `X-Traffic-Barrier`.
6. Poll `/check` sampai ingestion Tulip selesai dan flag dikembalikan.

YouTube tidak diperlukan untuk proses ini.

## Solve Script

`solve.py` memakai `requests` untuk autentikasi dan polling, lalu Scapy untuk mengirim segment TCP decoy dengan ACK stale. Request valid dikirim oleh socket TCP normal agar checksum dan state kernel valid.

## Cara Menjalankan

```bash
cd /home/nata/ctf/TFCCTF2026/misc/turip/chall
export TOKEN='TEAM_TOKEN_HEX'
sudo env TOKEN="$TOKEN" /home/nata/ctf_env/bin/python solve.py
```

Root diperlukan karena Scapy mengirim packet mentah. Host dan port dapat diganti dengan environment variable `HOST` dan `PORT`.

## Flag

```text
TFCCTF{this_was_discovered_in_the_good_old_days_when_people_still_played_ctf}
```

## Catatan

Flag berasal langsung dari response HTTP `/check` setelah marker traffic terlihat dan pemeriksaan forbidden request data berhasil dilewati.
