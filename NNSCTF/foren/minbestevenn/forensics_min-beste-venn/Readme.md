# Min beste venn

Artefak cuma satu: `capture.pcap`. Seluruh traffic adalah HTTP `HEAD` ke `static.notion-static.com` dengan path palsu yang selalu dibalas `404`. Jadi fokusnya bukan isi response, tapi pola request.

## Recon

Identifikasi awal:

```bash
file capture.pcap
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs
```

Hasil penting:

- Paket: `3662`
- Semua traffic: `HTTP`
- Host utama: `static.notion-static.com`
- Method: hampir semuanya `HEAD`

Kalau daftar URI dilihat, polanya aneh:

```text
/cf1787417395/h/s1787417396.css
/cf1787417395/d/h/0/06.css
/cf1787417395/d/h/0/04.css
...
/cf1787417395/c/s1787417410.css
/cf1787417395/d/c/1/02.css
...
```

Ada dua marker yang penting:

- `.../h/s<timestamp>.css`
- `.../c/s<timestamp>.css`

Dan dua data channel:

- `.../d/h/<row>/<value>.css`
- `.../d/c/<row>/<value>.css`

## Triage Pola

Request `d/*/*/*` ternyata bukan file CSS sungguhan. Nilai terakhir lebih cocok dibaca sebagai koordinat:

- `x = value // 10`
- `y = value % 10`

Dengan mapping itu, satu frame bisa dirender jadi bitmap 8-pixel tinggi. Saat data `h` dirender, byte-byte hasilnya langsung kebaca sebagai string length-prefixed:

- `h0`: `0f 6d 69 6e 20 62 65 73 74 65 20 76 65 6e 6e 3f`
  - `0x0f` = panjang 15
  - isi = `min beste venn?`
- `h1`: `0f 63 61 6e 20 69 20 68 61 7a 20 66 6c 61 67 3f`
  - `0x0f` = panjang 15
  - isi = `can i haz flag?`
- `c0`: `03 6a 61 3f`
  - `0x03` = panjang 3
  - isi = `ja?`

Jadi protokolnya memang menyimpan chat message sebagai bitmap request.

## Ambil Flag

Blok penting ada di channel `c`, row `1`. Kalau semua frame `c/1` ditumpuk mentah, hasil string masih hampir benar tapi beberapa karakter rusak. Penyebabnya ada overlap antarchunk.

Per-frame `c/1` kalau dilihat per rentang kolom:

- frame `s1787417410.css`: kolom `0..7`
- frame `s1787417411.css`: kolom `7..15`
- frame `s1787417412.css`: kolom `16..25`
- frame `s1787417413.css`: kolom `25..33`
- frame `s1787417414.css`: kolom `33..40`
- frame `s1787417415.css`: kolom `40..49`
- frame `s1787417416.css`: kolom `49..54`

Kolom overlap harus digabung pakai OR bitwise per byte. Setelah merge, payload `c1` menjadi:

```text
36 4e 4e 53 7b 31 5f 6c 30 76 33 5f 63 68 34 74 74 31 6e 67 5f 77 31 74 68 5f 6d 31 6e 5f 62 33 73 74 33 5f 76 33 6e 6e 5f 31 6e 5f 74 68 33 5f 63 6c 30 75 64 35 7d
```

- `0x36` = panjang 54
- isi = `NNS{1_l0v3_ch4tt1ng_w1th_m1n_b3st3_v3nn_1n_th3_cl0ud5}`

## Solver

Jalankan:

```bash
python3 solve.py
```

Output:

```text
NNS{1_l0v3_ch4tt1ng_w1th_m1n_b3st3_v3nn_1n_th3_cl0ud5}
```
