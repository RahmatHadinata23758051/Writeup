# boroCTF - Meeting Location

**Category:** Forensics  
**Points:** 200  
**Flag:** `Yas_Marina_Circuit`

## TL;DR

PCAP-nya berisi banyak traffic palsu: HTTP request generik, DNS query normal, SMTP/FTP dummy, dan ICMP probe. Data penting ada di bagian akhir capture: 24 packet ICMP terakhir punya payload 1 byte per packet. Jika digabung, byte itu membentuk Base64.

```text
WWFzX01hcmluYV9DaXJjdWl0
```

Decode Base64 menghasilkan lokasi meeting:

```text
Yas_Marina_Circuit
```

## Recon

File capture memakai format PCAP raw IPv4.

```bash
file meeting.pcap
```

Output:

```text
meeting.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Raw IPv4, capture length 65535)
```

`tshark` tidak tersedia di environment, jadi parsing dilakukan langsung dari struktur PCAP:

- global header PCAP
- packet header 16 byte
- header IPv4
- payload ICMP/TCP/UDP

## Triage

`strings` menunjukkan traffic yang tampak normal:

```text
GET /upload HTTP/1.1
Host: generichost.net
routine maintenance ping sequence
latency measurement probe response
RCPT TO: <recipient@generichost.net>
```

Traffic HTTP, DNS, SMTP, FTP, dan ICMP mayoritas cuma noise. Bagian yang janggal muncul di akhir capture: ada ICMP echo request dengan payload sangat pendek, hanya 1 karakter.

## Ekstraksi

Payload ICMP normal berisi string probe seperti:

```text
network performance monitor probe
routine maintenance ping sequence
latency measurement probe response
infrastructure uptime monitor ping
system probe network utility scan
automated health check diagnostic
network diagnostic ping sweep tool
standard connectivity check packet
```

Semua payload ICMP yang tidak termasuk daftar noise diambil, lalu digabung berdasarkan urutan packet.

```text
W W F z X 0 1 h c m l u Y V 9 D a X J j d W l 0
```

Hasil gabungan:

```text
WWFzX01hcmluYV9DaXJjdWl0
```

Decode:

```bash
echo 'WWFzX01hcmluYV9DaXJjdWl0' | base64 -d
```

Output:

```text
Yas_Marina_Circuit
```

## Solver

```python
#!/usr/bin/env python3
import struct
import socket
import base64

PCAP = "meeting.pcap"

NOISE = {
    b"network performance monitor probe",
    b"routine maintenance ping sequence",
    b"latency measurement probe response",
    b"infrastructure uptime monitor ping",
    b"system probe network utility scan",
    b"automated health check diagnostic",
    b"network diagnostic ping sweep tool",
    b"standard connectivity check packet",
}


def iter_packets(path: str):
    with open(path, "rb") as f:
        global_header = f.read(24)
        magic = global_header[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"

        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            _, _, incl_len, _ = struct.unpack(endian + "IIII", packet_header)
            yield f.read(incl_len)


def main():
    hidden = []

    for data in iter_packets(PCAP):
        if len(data) < 20 or data[0] >> 4 != 4:
            continue

        ihl = (data[0] & 0x0F) * 4
        proto = data[9]
        if proto != 1 or len(data) < ihl + 8:
            continue

        payload = data[ihl + 8:]
        if payload and payload not in NOISE:
            hidden.append(payload.decode("ascii"))

    encoded = "".join(hidden)
    print(base64.b64decode(encoded).decode("ascii"))


if __name__ == "__main__":
    main()
```
