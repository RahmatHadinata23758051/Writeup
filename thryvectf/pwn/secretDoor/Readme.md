# Secret Door

## Ringkasan

Binary ini menu-driven dan objek media disimpan sebagai pointer di `inventory`.
Bug utamanya ada di jalur `Add Raw Stream Config`: input dipakai untuk membangun fake object di heap, lalu field awal object dipakai sebagai vtable pointer.

Exploit akhirnya:

1. Leak heap address dan PIE base dari `Export Media Header`.
2. Buat raw config object berikutnya di alamat yang bisa diprediksi.
3. Isi fake vtable supaya slot fungsi mengarah ke `execute_stream`.
4. Isi URL lewat `Update Anime Stream URL`.
5. Trigger `Play Media Stream` supaya `execute_stream()` memanggil `system(url)`.

Di service remote, offset fungsi sedikit beda dari binary lokal, jadi `solve.py` memilih offset berdasarkan low bits vtable leak.

## Proteksi Binary

Output `file`:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Output `checksec`:

```text
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
FORTIFY:    Enabled
SHSTK:      Enabled
IBT:        Enabled
```

Implikasinya:

- `PIE` aktif, jadi semua alamat fungsi harus dilacak dari leak.
- `Full RELRO`, jadi GOT overwrite bukan opsi.
- `Canary` aktif, jadi stack smash bukan jalur yang masuk akal.
- `NX` aktif, jadi tidak ada shellcode di heap/stack.
- `SHSTK` dan `IBT` aktif, jadi indirect call harus tetap ke target yang valid dan diawali `ENDBR64`.

## Analisis Program

Menu penting:

- `1. Add Anime Stream`
- `2. Add Raw Stream Config`
- `6. Update Anime Stream URL`
- `7. Export Media Header`
- `4. Play Media Stream`

Fungsi yang relevan:

- `add_anime()`
- `add_raw_config()`
- `update_anime_url()`
- `export_media()`
- `play_media()`

Temuan kunci:

- `add_raw_config()` mengalokasikan object 0x78 byte dan menyalin tiga qword awal dari input ke object.
- `update_anime_url()` menulis string ke `object + 0x5c`.
- `export_media()` mencetak alamat object dan isi qword pertama object, yang efektif jadi heap leak dan vtable leak.
- `play_media()` membaca vtable pointer object, lalu memanggil slot fungsi di `[vtable + 8]` jika slot itu tidak sama dengan `AnimeStream::play`.

## Vulnerability

Bug-nya bukan overflow klasik. Ini fake-vtable primitive:

- Object raw config bisa diisi dengan pointer bebas di qword pertama.
- Qword kedua bisa diisi alamat fungsi.
- Field string bisa diisi lewat menu update.

Jadi object heap bisa dipakai sebagai fake C++ object dengan vtable controlled.

## Menentukan Offset atau Primitive

Hasil observasi penting:

- Dari `export_media(0)` pada object AnimeStream, didapat:
  - heap leak untuk object
  - vtable leak untuk PIE
- Dari dua alokasi berurutan:
  - `raw_object = anime_object + 0xd0`

Primitive yang terbukti:

- Leak heap object address.
- Leak PIE base dari vtable pointer.
- Fake vtable call via slot `[vtable + 8]`.
- Arbitrary command execution lewat `execute_stream()` karena fungsi itu memanggil `system(this + 0x5c)`.

## Strategi Exploit

Urutannya:

1. Buat 1 object AnimeStream untuk leak.
2. Hitung PIE base dari vtable leak.
3. Hitung alamat object raw config kedua dengan `obj0 + 0xd0`.
4. Isi raw config kedua:
   - qword 0 = alamat object itu sendiri
   - qword 1 = alamat `execute_stream`
   - qword 2 = 0
5. Isi URL object kedua dengan payload command.
6. Panggil `Play Media Stream` pada object kedua.

Karena build remote sedikit beda dari binary lokal, `solve.py` memakai low bits vtable leak untuk memilih offset yang tepat:

- lokal: leak berakhir `...cc0`
- remote: leak berakhir `...ca8`

## Pengembangan Payload

`solve.py` dibuat pakai pwntools dan mendukung:

- lokal
- `GDB`
- `REMOTE HOST=... PORT=...`

Fitur penting script:

- Leak parsing dari `Export Media Header`.
- Perhitungan PIE base dinamis.
- Perhitungan alamat object kedua dari leak object pertama.
- Pemilihan offset fungsi berdasarkan low bits leak.

## Exploit Final

Alur final di remote:

1. `Add Anime Stream`
2. `Export Media Header` untuk leak object dan vtable
3. `Add Raw Stream Config`
4. `Update Anime Stream URL`
5. `Play Media Stream`

Command final yang dipakai:

```text
cat /flag*
```

## Cara Menjalankan

Lokal:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE HOST=inst.thryvectf.org PORT=10007
```

## Hasil

Flag yang keluar dari service:

```text
Thryve{e0fd60d9-7a49-4c05-9099-ef134bfcc3d5}
```

## Catatan Stabilitas

- Offset local dan remote tidak identik.
- Script tidak hardcode satu offset saja; ia memilih offset dari low bits vtable leak.
- Primitive ini stabil selama layout object dan jalur `play_media()` tetap sama.

