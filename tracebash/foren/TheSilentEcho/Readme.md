# The Silent Echo

Artefak cuma `challenge.pcap`, jadi jalurnya langsung ke triage traffic.

Recon cepat:

```bash
rtk file challenge.pcap
rtk tshark -r challenge.pcap -q -z io,phs
rtk tshark -r challenge.pcap -Y "http" -T fields -e frame.number -e ip.src -e ip.dst -e http.request.uri -e http.user_agent
rtk tshark -r challenge.pcap -Y "icmp" -T fields -e frame.number -e ip.src -e ip.dst -e data.data
```

Hasil penting:

- Ada HTTP ke `10.0.0.80` dengan header aneh `X-Window-Trace: enabled`
- Ada download palsu `/downloads/ubuntu-22.04.iso` dari `10.0.0.88`
- Ada traffic ICMP bolak-balik dengan payload statis `A...A`
- Ada stream SSH singkat yang cuma berisi base64 red herring: `Nothing here, keep looking.`

## Analisis

HTTP body dari `ubuntu-22.04.iso` ternyata bukan ISO, cuma 18 blok `0x00`. Jadi datanya tidak ada di payload.

Petunjuk `X-Window-Trace: enabled` mengarah ke field `TCP Window` dari ACK klien pada stream download:

```bash
rtk tshark -r challenge.pcap -Y "tcp.stream==2 && ip.src==192.168.1.122 && tcp.len==0" \
  -T fields -e frame.number -e tcp.window_size_value
```

Offset tiap window terhadap `8192` membentuk ASCII:

```text
w1nd0w_4nd_1p_1d!}
```

Bagian awal flag belum ada, jadi cek traffic ICMP. `ip.id` request ICMP terlihat tidak acak:

```bash
rtk tshark -r challenge.pcap -Y "icmp.type==8" \
  -T fields -e frame.number -e ip.id -e icmp.seq_le
```

Kalau diambil byte tinggi dari tiap `ip.id`, hasilnya:

```text
TBCTF{h1dd3n_1n_
```

Gabungkan kedua bagian:

```text
TBCTF{h1dd3n_1n_w1nd0w_4nd_1p_1d!}
```

## Flag

```text
TBCTF{h1dd3n_1n_w1nd0w_4nd_1p_1d!}
```
