# Bruteforced

## Ringkasan

File yang diberikan adalah `log.pcap`. Isinya trafik HTTP lokal dari script Python yang mencoba ribuan endpoint secara berurutan:

```text
/flag_0
/flag_1
/flag_2
...
/flag_9999
```

Tujuannya adalah mencari request yang tidak mendapat `404`.

## Recon

```bash
file log.pcap
capinfos log.pcap
tshark -r log.pcap -q -z io,phs
```

Hasil utama:

- format: PCAP;
- 100004 paket;
- trafik: TCP/HTTP;
- sekitar 10000 request dan 10000 response;
- host: `ctf.scriptsorcerers.xyz`;
- user-agent: `python-requests/2.32.3`.

## Analisis request

Contoh paket:

```http
GET /flag_4918 HTTP/1.1
Host: ctf.scriptsorcerers.xyz
```

Request dapat dihitung berdasarkan status response:

```bash
tshark -r log.pcap \
  -Y 'http.response' \
  -T fields -e http.response.code | sort | uniq -c
```

Outputnya:

```text
9999 404
   1 200
```

Untuk mengambil request yang mendapat response `200`:

```bash
tshark -r log.pcap \
  -Y 'http.response.code == 200' \
  -T fields -e tcp.stream -e http.response.code
```

Stream sukses adalah stream `4919`. Request lengkapnya:

```http
GET /flag_4919 HTTP/1.1
Host: ctf.scriptsorcerers.xyz
```

Response-nya:

```http
HTTP/1.1 200 OK
Content-Length: 0
```

Body kosong, tetapi status `200` membocorkan bahwa endpoint tersembunyi tersebut valid. Semua kandidat lain menghasilkan `404`.

## Solver

Jalankan:

```bash
python3 solve.py
```

Script mengelompokkan field berdasarkan `tcp.stream`, mengambil URI request terkait response `200`, lalu menampilkan endpoint yang bocor dan flag.

## Flag

```text
scriptCTF{7h3_h1dd3n_3ndp01n7_g0t_l34k3d}
```
