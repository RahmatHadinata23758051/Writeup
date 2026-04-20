# Writeup - Mars Dominion (Forensics)

Challenge ini memberikan bundle artefak campuran:
- `orionhq-incident.pcap`
- EVTX dari `WS01-SHIPLINK`, `DC01-SHIPLINK`, `DC01-ORIONHQ`
- `bloodhound-collection.zip`

Tujuan: mengikuti alur kompromi dari foothold awal sampai trust boundary terakhir, lalu merangkai override-key fragments yang tersebar.

## 1) Initial Recon

Pertama saya identifikasi file:

```bash
ls -la
file * DC01-ORIONHQ/* DC01-SHIPLINK/* WS01-SHIPLINK/*
```

Hasil penting:
- Ada 1 file PCAP dan banyak EVTX (Security, Sysmon, PowerShell, Application, dsb).
- BloodHound zip berisi dump AD object JSON.

## 2) Triage PCAP

Saya mulai dari lalu lintas protokol utama:

```bash
tshark -r orionhq-incident.pcap -q -z io,phs
```

Terlihat dominan: SMB2, DCERPC (termasuk DRSUAPI), DNS.

Lalu saya cari DNS query:

```bash
tshark -r orionhq-incident.pcap -Y "dns" -T fields -e frame.number -e dns.qry.name -e dns.a
```

Temuan krusial:
- `sync-gate.amN0ZntuYXZf.ops.c2.silent-dominion.net`

Label `amN0ZntuYXZf` saya decode base64:

```bash
python3 - << 'PY'
import base64
print(base64.b64decode('amN0ZntuYXZf').decode())
PY
```

Hasil:
- `jctf{nav_`

Ini jelas fragmen awal flag.

## 3) Triage EVTX untuk fragmen lanjutan

### a) Fragmen dari shortcut name (WS01 Application)

Dari event Application di WS01, ada jejak:
- `\\gate-archive\shared\ops\lease-756e31745f7761735f.lnk`

Bagian hex `756e31745f7761735f` di-decode ASCII menjadi:
- `un1t_was_`

### b) Fragmen dari PowerShell payload (DC01-SHIPLINK)

Pada artefak PowerShell/Sysmon DC01-SHIPLINK, ada variabel:
- `NAV-DRV-dGgzX3RocjNhdF8`

Decode base64 `dGgzX3RocjNhdF8` menghasilkan:
- `th3_thr3at_`

### c) Fragmen dari AD description update (DC01-ORIONHQ Sysmon EncodedCommand)

Saya extract script `-EncodedCommand` dari Sysmon lalu decode UTF-16LE.
Script tersebut berisi:
- `Override fragment 04/05: all_al0`

### d) Fragmen penutup dari event log message (DC01-ORIONHQ Sysmon EncodedCommand)

Encoded script lain menulis event warning dan menyebut:
- `Override fragment 05/05: ng}`

## 4) Rekonstruksi flag

Fragmen yang terkumpul:
1. `jctf{nav_`  (PCAP DNS exfil)
2. `un1t_was_`  (WS01 Application event / hex filename)
3. `th3_thr3at_` (PowerShell payload / base64 driver alias)
4. `all_al0`    (AD description fragment 04/05)
5. `ng}`        (Application warning fragment 05/05)

Digabung:

`jctf{nav_un1t_was_th3_thr3at_all_al0ng}`

## 5) Kesimpulan Singkat

Pelaku menyebar potongan override key lintas sumber forensik (DNS C2 label, artefak endpoint, dan perubahan AD metadata). Tanpa korelasi lintas PCAP + EVTX, flag tidak akan utuh.

