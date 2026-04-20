# Writeup - web/todo

## Ringkasan
Challenge ini terlihat seperti aplikasi todo biasa, tapi deskripsi kasih clue penting:

- pakai agent harness
- frontend subagent crash sebelum linking backend selesai

Artinya ada kemungkinan endpoint backend yang masih kebawa ke bundle frontend, walaupun tidak dipakai UI.

## Langkah 1 - Enumerasi frontend
Saya buka halaman utama lalu ambil JS bundle:

- `/assets/index-B6JriSEE.js`
- `/assets/routes-LxaxDcib.js`
- `/assets/routes-DJlc5TBK.js`

Dari route home terlihat cuma ada 3 aksi todo normal:

- add
- complete
- delete

Tapi setelah baca bundle utama (`routes-LxaxDcib.js`), ketemu beberapa server function ID hardcoded.

## Langkah 2 - Identifikasi endpoint tersembunyi
Di bundle ditemukan 5 ID server function. Empat di antaranya `GET`, dan satu `POST`:

`3633763ff4da33d65cb24e276f877dcaa1972bfb59429377abc55a408a83167a`

ID `POST` ini tidak dipakai route UI todo, jadi sangat mencurigakan.

## Langkah 3 - Cara panggil serverFn yang benar
Request manual pakai `curl` sempat mentok karena format serialisasi TanStack Start/TSS tidak trivial.

Solusi paling stabil: panggil helper internal dari browser sendiri:

- import module `/assets/routes-LxaxDcib.js`
- panggil `m.g(<id>)` untuk bikin callable serverFn
- eksekusi dengan payload sesuai validator

Saat dites tanpa format benar, error validasi bocorin schema:

- `field1` harus string
- `field2` harus number

## Langkah 4 - Eksploit
Kirim payload valid apa saja, contoh:

```json
{
  "field1": "anything",
  "field2": 1
}
```

Response langsung mengandung flag di field `result`:

`squ1rrel{tree_shaking?_nah_we_dont_do_that_here}`

## Akar masalah
- Backend function sensitif masih ter-include di client bundle.
- Tidak ada auth guard tambahan di function tersebut.
- Siapa pun bisa invoke endpoint internal kalau tahu ID function.

Intinya sesuai nama flag: tree shaking / dead code elimination tidak membuang function backend yang seharusnya tidak terekspos.

## Solver
File solver otomatis sudah disimpan di:

- `solve.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
cd /home/nata/ctf/squ1rrel/web/todo
python solve.py
```
