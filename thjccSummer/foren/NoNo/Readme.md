# NoNo — Forensics Writeup

## Challenge

**Title:** NoNo
**Category:** Forensics
**Description:**

```
Our SOC pulled the HTTP logs off chal.thjcc.org after an alert fired overnight. Find the secret message within these logs :)
```

**Flag format:**

```
THJCC{...}
```

## Analysis

Dari deskripsi challenge, artefak utama yang perlu dianalisis adalah HTTP logs.

Tujuannya adalah mencari request yang tidak biasa, kemudian mengikuti alur request tersebut sampai menemukan endpoint tersembunyi.

Langkah awal yang bisa dilakukan adalah melakukan inspeksi terhadap log:

```bash
head -n 20 <logfile>
```

Lalu mencari request HTTP yang mencurigakan:

```bash
grep -Ei 'GET|POST|secret|report|internal' <logfile>
```

atau:

```bash
grep -oE '(/[A-Za-z0-9_./%-]+)' <logfile> | sort | uniq -c | sort -nr
```

Hal penting pada challenge ini bukan hanya melihat satu request, tetapi mengikuti urutan/stream aktivitas HTTP.

Setelah mengikuti request-request yang berkaitan, terlihat adanya path tersembunyi:

```
/s3cr3t/rep0rt/
```

Target service yang digunakan adalah:

```
chal.thjcc.org:50000
```

Sehingga endpoint lengkapnya:

```
http://chal.thjcc.org:50000/s3cr3t/rep0rt/
```

## Retrieving the Hidden Report

Endpoint tersebut kemudian diakses menggunakan `curl`:

```bash
curl http://chal.thjcc.org:50000/s3cr3t/rep0rt/
```

Response:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>Internal Report</title>
</head>
<body>
<header>
<span>internal.portal</span>
<span>INTERNAL REPORT · CONFIDENTIAL</span>
</header>
<main>
<p>// internal use only</p>
<h1>Quarterly Access Report</h1>
<div>
<p>report token</p>
<code>
        THJCC{f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt}
</code>
</div>
</main>
</body>
</html>
```

Flag berada langsung di dalam elemen:

```html
<code>
```

## Flag

```
THJCC{f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt}
```

## Why the Flag Makes Sense

Flag:

```
f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt
```

dibaca sebagai:

```
follow_the_stream_to_the_hidden_report
```

Ini sesuai dengan metode penyelesaian challenge:

1. Analisis HTTP logs.
2. Ikuti alur request / stream.
3. Temukan endpoint tersembunyi.
4. Akses internal report.
5. Ambil report token.

Endpoint akhirnya:

```
http://chal.thjcc.org:50000/s3cr3t/rep0rt/
```

dan report tersebut menghasilkan flag.

## TL;DR

```bash
curl http://chal.thjcc.org:50000/s3cr3t/rep0rt/
```

Output mengandung:

```
THJCC{f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt}
```
