# Mobile Waf

Challenge ini ternyata bukan soal bypass service, tapi soal mengenali pola request yang dianggap malicious atau safe oleh generator challenge. Service memberi 100 request HTTP mentah dan kita harus menjawab `Block` atau `Allow` tanpa satu pun salah.

## Langkah awal

Saya mulai dengan konek langsung ke service pakai `nc` dan Python socket untuk melihat format output. Dari sana kelihatan kalau:

- request dikirim satu per satu
- kalau jawaban salah, service langsung berhenti
- service juga memberitahu apakah request itu sebenarnya `SAFE` atau `MALICIOUS`

Informasi terakhir ini penting banget untuk iterasi, karena saya bisa bikin classifier sederhana, jalankan, lihat salah pertamanya di mana, lalu perbaiki rule.

## Enumerasi pola request

Saya kumpulkan banyak sampel request pertama dari koneksi yang berbeda-beda. Dari situ kelihatan generator memakai template yang berulang. Kelas malicious yang muncul antara lain:

- SQL injection
- XSS
- XXE
- command/code execution
- SSTI / template injection
- file read / traversal ke file sensitif
- upload webshell
- XPath injection

Sementara request safe berisi trafik normal seperti:

- profile API
- analytics
- export CSV
- upload gambar biasa
- login normal
- webhook
- settings update
- report download

## Jebakan challenge

Bagian yang bikin challenge ini menarik adalah tidak semua string yang kelihatan “jahat” benar-benar dianggap malicious oleh generator. Ada beberapa decoy yang harus di-handle sebagai exception, misalnya:

- `GET /api/search?q=union+select+null HTTP/1.1`
- `GET /api/data?script=<script>alert('test')</script> HTTP/1.1`
- `GET /api/load?file=../../config.json HTTP/1.1`
- `GET /admin/../users HTTP/1.1`
- `GET /api/test?id=1' OR '1'='1 HTTP/1.1`
- `GET /api/exec?cmd=ls HTTP/1.1`

Awalnya saya pakai rule yang terlalu agresif, misalnya semua `../` dianggap malicious, atau semua pola `id='...'` dianggap SQLi. Itu bikin false positive. Setelah beberapa kali gagal di angka tinggi, saya sempitkan rule ke konteks yang benar-benar dipakai generator, misalnya traversal ke file sensitif seperti `/etc/passwd` atau `/etc/shadow`, bukan sekadar path normalization biasa.

## Strategi solve

Pendekatannya akhirnya jadi gabungan:

1. exact allow-list untuk request decoy yang memang aman menurut generator
2. rule-based detection untuk pola serangan yang jelas
3. pengecualian untuk request normal yang kebetulan berisi string mencurigakan tapi konteksnya aman

Classifier final memeriksa:

- exact safe template
- payload XXE seperti `<!DOCTYPE` / `<!ENTITY`
- akses ke `/etc/passwd` atau `/etc/shadow`
- payload SSTI/Handlebars yang mengeksekusi `child_process`
- XSS seperti `<script>`, `<img onerror>`, `<svg onload>`
- RCE seperti `system(`, `exec(`, `eval(`, `rm -rf`, `child_process`
- SQLi seperti `UNION ... --`, `DROP TABLE`, `@@version`, boolean-based injection
- XPath injection dengan pola `or '1'='1`

## Hasil

Setelah rule terakhir dibetulkan, solver berhasil menjawab 100/100 dan service mengembalikan flag:

`KubSTU(y0u_4r3_4_g00d_m0b1l3_4551574n7_f0r_d373c71ng_3v1l)`

## File

- `solve.py` berisi solver final yang langsung konek ke service dan menjawab challenge

Cara pakai:

```bash
python3 solve.py
```
