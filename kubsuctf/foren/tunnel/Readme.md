# Writeup Tunnel?

Challenge ini ternyata menyamarkan data eksfiltrasi di tengah traffic yang kelihatannya ramai dan acak. Dari awal, artefaknya cuma satu file, `Krasnodar.pcap`, jadi fokus analisis langsung ke network forensics.

## Langkah 1: Recon awal

Pertama saya cek file yang diberikan:

```bash
file Krasnodar.pcap
```

Hasilnya menunjukkan ini file PCAP biasa. Setelah itu saya lihat gambaran umum protokol dengan `tshark`. Capture berisi banyak trafik TCP, UDP, dan ICMP satu arah dari beberapa host internal ke beberapa IP publik. Payload mayoritas terlihat seperti noise dan memang banyak paket ICMP berisi string literal `Noise data`.

Ini tanda kuat kalau challenge sengaja dipenuhi trafik umpan supaya analisis tidak berhenti di protokol umum seperti HTTP atau ICMP.

## Langkah 2: Mencari kanal eksfiltrasi yang masuk akal

Saat memeriksa protokol yang terurai oleh `tshark`, ada satu hal yang menonjol: terdapat 540 paket DNS dari `192.168.1.50` ke `8.8.4.4`.

Saya dump nama query DNS:

```bash
tshark -r Krasnodar.pcap -Y "dns" -T fields -e frame.number -e dns.qry.name
```

Dari sini terlihat pola seperti:

```text
xwn70i7g.exfiltrate.kubstu-ctf.ru
j61ex76n.exfiltrate.kubstu-ctf.ru
...
v00.4b75.exfiltrate.kubstu-ctf.ru
...
v01.6253.exfiltrate.kubstu-ctf.ru
v02.5455.exfiltrate.kubstu-ctf.ru
...
v20.787d.exfiltrate.kubstu-ctf.ru
```

Subdomain `exfiltrate.kubstu-ctf.ru` sudah sangat mencurigakan. Sebagian besar query awal hanyalah label acak 8 dan 12 karakter, tetapi di sela-selanya muncul marker yang jauh lebih terstruktur:

```text
v00.4b75
v01.6253
v02.5455
v03.7b64
...
v20.787d
```

## Langkah 3: Menyadari data sebenarnya dikirim sebagai hex

Bagian setelah `vNN.` selalu 4 karakter heksadesimal. Itu berarti setiap marker menyimpan 2 byte data.

Saya gabungkan semua nilai hex itu berurutan:

```text
4b75 6253 5455 7b64 306e 745f 7472 7535 745f 7468
335f 646e 355f 7175 3372 3133 355f 7631 615f 6833 787d
```

Kalau diubah dari hex ke ASCII, hasilnya:

```text
KubSTU{d0nt_tru5t_th3_dn5_qu3r135_v1a_h3x}
```

Jadi flag memang tidak disimpan di payload TCP/UDP utama, tetapi ditanam di query DNS sebagai potongan hex kecil yang disisipkan di antara query-query acak.

## Kenapa ini menarik

Triknya ada pada distraksi. Banyak payload lain terlihat seperti data acak dan sempat memberi kesan bahwa data mungkin dienkode base36 atau disebarkan ke banyak protokol. Tetapi kanal eksfiltrasi yang benar justru jauh lebih sederhana: query DNS dengan subdomain terstruktur.

Artinya, pelajaran utamanya adalah jangan hanya terpaku pada payload besar. Kadang data penting dikirim lewat metadata kecil yang tampak sepele, seperti nama domain.

## Solusi otomatis

Saya juga menyiapkan `solve.py` untuk mengekstrak flag langsung dari PCAP:

```bash
python3 solve.py
```

Output:

```text
KubSTU{d0nt_tru5t_th3_dn5_qu3r135_v1a_h3x}
```
