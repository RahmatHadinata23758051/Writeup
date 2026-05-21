# Writeup

Challenge ini ternyata bukan service yang punya backend aneh-aneh. Halamannya cuma export web dari Godot 4.6. Jadi titik masuk paling masuk akal adalah bongkar asset pack-nya, bukan fuzz endpoint yang tidak ada.

## 1. Enumerasi awal

Saat buka `https://jumper.tjc.tf/`, HTML-nya langsung kasih tahu file penting:

- `jumper.js`
- `jumper.wasm`
- `jumper.pck`

`jumper.pck` adalah pack asset Godot. Dari sini sudah kelihatan kalau hampir semua logic game dan scene ada di sisi klien.

## 2. Buka isi pack

Header `jumper.pck` menunjukkan format pack Godot 4:

- magic `GDPC`
- engine version `4.6`
- tabel file ada di offset akhir pack

Setelah parse tabel file, file yang paling menarik:

- `player.gdc`
- `world.gdc`
- `f.tscn`
- `world.tscn`
- `project.binary`

`project.binary` memperlihatkan action input custom:

- `left`
- `right`
- `jump`
- `mega_jump`

Yang menarik, `mega_jump` memang ada tetapi tidak punya key binding sama sekali. Itu cocok dengan nuansa challenge bahwa ada sesuatu yang “disembunyikan” di game.

## 3. Pakai Godot asli untuk inspeksi

Daripada nebak format binary scene satu per satu, saya pakai Godot 4.6 editor/headless untuk load `jumper.pck` langsung.

Dari situ didapat beberapa hal penting:

- `world.tscn` memakai script `world.gd`
- `player.tscn` memakai script `player.gd`
- `player.gd` punya konstanta gerak biasa, tidak ada flag string di script
- setelah `world.gd::_ready()` jalan, scene menambahkan node `F` di posisi `(400, -120)`

Node `F` berasal dari `f.tscn`. Isinya bukan Label atau Texture, tapi 56 buah `ColorRect` yang membentuk tulisan pixel-art.

## 4. Rekonstruksi tulisan

Saya dump semua rectangle dari `f.tscn`, lalu render ulang jadi gambar hitam-putih. Setelah dipisah per glyph dan dibaca manual, tulisan yang dibentuk scene itu adalah:

`tjctf{past_the_wall}`

Nama challenge dan mekaniknya cocok: flag memang “di balik / melewati dinding”.

## 5. Solve script

`solve.py` melakukan versi otomatis dari langkah di atas:

1. Memastikan `jumper.pck` dan binary Godot 4.6 ada.
2. Menjalankan Godot headless dengan runner kecil.
3. Me-load `jumper.pck` sebagai `main-pack`.
4. Memastikan fingerprint scene cocok:
   - node `F` ada di `(400, -120)`
   - `f.tscn` berisi 56 `ColorRect`
5. Mengeluarkan flag.

## Flag

`tjctf{past_the_wall}`
