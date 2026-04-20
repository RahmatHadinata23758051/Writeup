# Writeup - Escape Room (rev)

Challenge ini bentuknya binary menu interaktif. Targetnya cari token override yang benar supaya keluar flag format `CIT{...}`.

## 1) Recon awal

File yang ada cuma satu binary:

- `escaperoom` (ELF64, static linked, not stripped)

Saat dijalankan, muncul menu dengan opsi:

- ubah state ruangan (lampu, ventilasi, kamera, patch, battery)
- maintenance shell (`mirror`, `hush`, `decode`, dst)
- submit token override

Dari output runtime doang sudah kelihatan kalau ini challenge state-machine + validasi token.

## 2) Cari fungsi penting

Dari symbol table (karena tidak stripped), fungsi-fungsi kunci gampang ketemu:

- `roomAligned()`
- `roomSignature()`
- `buildOverrideToken()`
- `validate()`
- `enterOverrideToken()`
- `maintenanceConsole()`

Intinya:

- `enterOverrideToken()` baca input token, panggil `validate()`, lalu print result.
- `validate()` akan compare input dengan token hasil `buildOverrideToken()`, tapi **hanya** kalau kondisi room benar.
- Kalau kondisi belum benar, balikin `ACCESS_DENIED`.

## 3) Turunin kondisi state yang wajib

Dari `roomAligned()` dan cabang di `maintenanceConsole()` didapat syarat:

- lights harus OFF
- vent index harus 1
- camera bus harus 3 (mirror relay)
- door patch count harus 2
- battery bridge harus ON
- flag `mirror` harus aktif
- flag `hush` harus aktif

Urutan aksinya jadi:

1. `2` (toggle lights -> OFF)
2. `3` (vent dari 0 ke 1)
3. `4` tiga kali (camera 0 -> 1 -> 2 -> 3)
4. `5` dua kali (patch jadi 2)
5. `6` (battery ON)
6. masuk `7` (maintenance shell), jalankan `mirror`, lalu `hush`, lalu `back`

## 4) Reversing generator token

Di `buildOverrideToken()` terlihat komponen ini:

- alphabet: `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`
- array `spice[10]`:
  - `0x13, 0x37, 0xc0de, 0xbeef, 0x5a, 0xace, 0x4242, 0x900d, 0x1234, 0x777`
- seed awal: `roomSignature() ^ 0x6f70656e` (`"open"`)
- loop 10x:
  - `seed = seed * 0x19660d + spice[i] + 0x3c6ef35f` (mod 32-bit)
  - karakter diambil dari `alphabet[seed >> 27]`
  - setelah index 2 dan 5 ditambah separator `-`

Dengan state ruangan yang sudah benar, token yang keluar:

- `RHY-QVT-KAXJ`

## 5) Submit token dan dapat flag

Setelah semua state benar lalu submit token di menu `8`, binary mengeluarkan:

- `CIT{Vc282vlhCxIJ}`

## 6) Solver

Solver final ada di:

- `solve.py`

Script melakukan:

- hitung token dari hasil reversing (bukan hardcode flag)
- set state ruangan sesuai syarat
- kirim token
- parse dan print flag dari output binary

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
CIT{Vc282vlhCxIJ}
```
