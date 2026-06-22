# My Mayor Muslim...

Target kasih game basket kecil. Tiap `POST /api/shoot` nambah skor `+2`, tapi ada dua aturan server-side:

- Kalau request datang sebelum cooldown selesai, backend balikin `rigged: true` dan skor di-reset.
- Kalau skor mau nyentuh 45, backend juga reset skor dengan pesan "The refs saw Brunson approaching 45".

Masalahnya check dan update di endpoint `/api/shoot` tidak atomik. Saat skor sudah `44`, beberapa request paralel bisa masuk bareng. Sebagian request masih lihat state lama, lolos ke path yang kasih poin, dan ada yang sempat lewat kondisi flag sebelum request lain nulis reset.

## Recon

Ambil halaman utama dan JS:

```bash
curl -sk https://ed25472fd89a.boroctf.com/
curl -sk https://ed25472fd89a.boroctf.com/static/game.js
```

`game.js` nunjukin tiga endpoint penting:

- `GET /api/state`
- `POST /api/shoot`
- `POST /api/reset`

Client cuma ngatur animasi dan cooldown 1.5 detik. Semua validasi penting ada di server.

## Bug

Urutan normalnya:

1. Tembak 22 kali dengan jeda sekitar 1.6 detik sampai skor jadi `44`.
2. Request ke-23 yang normal akan kena branch anti-45 dan skor direset ke `0`.

Kalau di skor `44` kita kirim beberapa `POST /api/shoot` sekaligus, hasilnya campur:

- ada request yang kena reset anti-45,
- ada yang kena reset cooldown,
- ada yang tetap dapat skor `46` dan balikin flag.

Contoh response race yang menang:

```json
{"flag":"boroCTF{KN!CK5_1N_5555!!!!!}","message":"BRUNSON WITH 45! THE GARDEN IS ELECTRIC!","score":46}
```

## Exploit

Script ada di [solve.py](/home/kali/ctf/boroctf/web/MymayorMuslim/solve.py). Jalankan:

```bash
source /home/kali/tools/ctf/bin/activate
python solve.py
```

Alur script:

1. Ambil session cookie `gt`.
2. Lakukan 22 shot dengan delay `1.62s` supaya aman dari cooldown server.
3. Saat skor `44`, kirim 8 request paralel ke `/api/shoot`.
4. Parse semua response dan ambil field `flag` kalau muncul.

## Output

```text
[*] attempt 1/3
[warmup] shot 01 -> 2
...
[warmup] shot 22 -> 44
[race] state before race: {"score":44}
[race] worker 01 -> {'flag': 'boroCTF{KN!CK5_1N_5555!!!!!}', 'message': 'BRUNSON WITH 45! THE GARDEN IS ELECTRIC!', 'score': 46}
[+] flag: boroCTF{KN!CK5_1N_5555!!!!!}
```

## Flag

```text
boroCTF{KN!CK5_1N_5555!!!!!}
```
