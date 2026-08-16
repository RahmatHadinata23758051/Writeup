# Monday Attack - Writeup

## Ringkasan
Artefak yang diberikan bernama `chall.pcapng`, tapi `file` menunjukkan isi ZIP. Setelah diekstrak, didapat `Monday-Attack.pcapng` yang jadi sumber utama analisis.

Target utama analisis:
- host yang ditemukan saat fase awal
- resource HTTP mencurigakan
- port C2
- nama file exfiltrasi
- data ter-encode yang dikirim saat exfil
- flag final yang sengaja ditinggalkan analyst

## Initial Recon

### 1) Identifikasi artefak
```bash
file chall.pcapng
unzip -l chall.pcapng
strings -a -n 6 chall.pcapng
```

Hasilnya:
- `chall.pcapng` sebenarnya ZIP archive
- di dalamnya ada satu file: `Monday-Attack.pcapng`

### 2) Ekstraksi
```bash
unzip chall.pcapng
```

Setelah itu analisis dilakukan pada `Monday-Attack.pcapng`.

## DFIR Analysis

### Q1 - Discovery
Untuk cari host yang ditemukan lebih dulu, saya cek:
- `tshark -z io,phs`
- `tshark -q -z conv,ip`
- urutan frame awal dengan field `ip.src`, `ip.dst`, `dns.qry.name`, `tcp.dstport`

Yang kelihatan penting:
- host `192.168.1.107` melakukan PTR lookup ke `1.56.168.192.in-addr.arpa`
- setelah itu dia mencoba konek ke `192.168.56.1:8080`
- lalu ada sesi HTTP ke `192.168.1.106:8080`

Karena pertanyaan menanyakan sistem yang ditemukan dan kemudian dikomunikasikan, IP yang relevan adalah:

**Jawaban Q1:** `192.168.1.106`

### Q2 - Delivery
Saya filter HTTP request:
```bash
tshark -r Monday-Attack.pcapng -Y http.request -T fields -e frame.number -e ip.src -e ip.dst -e http.request.uri
```

Muncul request berulang:
- `GET /update/ HTTP/1.1`

**Jawaban Q2:** `/update/`

### Q3 - Command & Control
Saya cek conversation TCP:
```bash
tshark -r Monday-Attack.pcapng -q -z conv,tcp
```

Ada beberapa sesi ke `192.168.1.106`, dan port yang konsisten untuk C2 adalah:
- `4444`

Sesi di port ini berisi komunikasi berulang setelah HTTP activity, jadi itu port C2.

**Jawaban Q3:** `4444`

### Q4 - Exfiltration
Saya fokus ke stream C2 di port `4444`, lalu decode payload teksnya.

Payload penting di `tcp.stream 11`:
- `SESSION=8F21A`
- `ACTION=UPLOAD`
- `FILE=employee_backup.zip`
- `SIZE=2048`
- `STATUS=START`
- `STATUS=COMPLETE`

Jadi file target exfiltrasi adalah:

**Jawaban Q4:** `employee_backup.zip`

### Q5 - Encoded Data
Masih di stream exfiltrasi, ada payload base64:

```text
ZHVtbXlfY3RmX2V4ZmlsdHJhdGlvbl9kYXRh
```

Decode:
```bash
python3 - <<'PY'
import base64
s='ZHVtbXlfY3RmX2V4ZmlsdHJhdGlvbl9kYXRh'
print(base64.b64decode(s).decode())
PY
```

Hasil decode:
- `dummy_ctf_exfiltration_data`

**Jawaban Q5:** `dummy_ctf_exfiltration_data`

## Flag Final
Di artefak pembungkus `chall.pcapng`, ada string flag yang bisa ditemukan dari pencarian raw bytes / strings:

```bash
rg -a -n 'Thryve\{' chall.pcapng
```

Hasilnya menunjukkan flag analyst yang ditinggalkan di wrapper archive:

**Flag:** `Thryve{wedyan love you}`

## IOC / Artefak Penting
- Host internal: `192.168.1.107`
- Host discovery / remote target: `192.168.1.106`
- Host lain yang sempat diprobe: `192.168.56.1`
- HTTP URI: `/update/`
- C2 port: `4444`
- File exfil: `employee_backup.zip`
- Encoded data: `dummy_ctf_exfiltration_data`
- Final flag: `Thryve{wedyan love you}`

## Alur Serangan
1. Host `192.168.1.107` melakukan discovery ke jaringan.
2. Setelah itu muncul request HTTP ke `/update/` pada `192.168.1.106:8080`.
3. Setelah HTTP, koneksi berulang ke port `4444` dipakai sebagai C2.
4. Dari sesi C2 terlihat perintah upload file `employee_backup.zip`.
5. Data exfiltrasi dikirim dalam bentuk base64 dan didecode menjadi `dummy_ctf_exfiltration_data`.
6. Flag final ternyata disimpan di bytes wrapper ZIP, bukan di payload utama PCAP.

## Commands yang Dipakai
```bash
file chall.pcapng
unzip -l chall.pcapng
unzip chall.pcapng

# Recon network

tshark -r Monday-Attack.pcapng -q -z io,phs
tshark -r Monday-Attack.pcapng -q -z conv,ip
tshark -r Monday-Attack.pcapng -q -z conv,tcp

# HTTP

tshark -r Monday-Attack.pcapng -Y http.request -T fields -e frame.number -e ip.src -e ip.dst -e http.request.uri

# C2 stream

tshark -r Monday-Attack.pcapng -Y 'tcp.stream==11' -T fields -e frame.number -e data

# Raw flag search

rg -a -n 'Thryve\{' chall.pcapng
```
