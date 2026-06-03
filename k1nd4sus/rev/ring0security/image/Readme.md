# Writeup - Ring 0 Security (?)

## Ringkasan
Challenge ini ngasih modul kernel Linux (`decoder.ko`) dan petunjuk kalau ada PIN 4 digit.
Targetnya adalah dapetin flag dari mekanisme dekripsi di driver.

Hasil akhir:
- PIN: `5102`
- Flag: `KSUS{dr1v3r_cr4ck1ng_101}`

## Enumerasi awal
File yang tersedia:
- `bzImage`
- `initramfs.cpio.gz`
- `qemu_run.sh`

`qemu_run.sh` cuma boot kernel + initramfs ke shell minimal.
Setelah ekstrak initramfs, file yang relevan hanya:
- `init`
- `challenge/decoder.ko`

Artinya semua logika challenge memang ada di modul kernel itu.

## Reversing `decoder.ko`
Dari simbol yang masih ada, fungsi penting:
- `ctls` (handler ioctl)
- `xtea_decrypt`
- data global: `session_key`, `enc_flag`, `res`, `status`

### Alur ioctl
Ada dua command utama di `ctls`:

1. `0x401b3700`
- Ambil 4 byte dari user (`copy_from_user`).
- Masuk ke jalur `ctls.cold`.
- Di jalur ini:
  - `session_key[1] = 0xCAFEBABE`
  - `session_key[0] = input | 0x13370000`
  - `session_key[2..3] = 0xDEADBEEF, 0xFEEDFACE`

2. `0x801b3701`
- Copy `enc_flag` ke buffer `res`.
- Dekripsi 4 blok (32 byte total) pakai XTEA decrypt 32 round.
- `copy_to_user` hasil plaintext.

### Bentuk key final
Dari analisis relocation + disassembly, key yang dipakai decrypt adalah:

- `k0 = 0x13370000 | pin`
- `k1 = 0xCAFEBABE`
- `k2 = 0xDEADBEEF`
- `k3 = 0xFEEDFACE`

Ini bagian krusial. Waktu asumsi posisi key salah, plaintext jadi acak semua.

## Ekstraksi ciphertext flag
`enc_flag` ada di `.data` sepanjang 32 byte:

`7e38614d358f6d302e25c10149953ef9b09cf265ff9459ec57fcb593b833c7b6`

Lalu brute force PIN `0000..9999`, bentuk key seperti di atas, decrypt pakai XTEA yang sama dengan driver.

## Recover PIN & flag
Saat PIN `5102`, plaintext valid keluar:

`KSUS{dr1v3r_cr4ck1ng_101}\x00...`

Maka flag valid:

`KSUS{dr1v3r_cr4ck1ng_101}`

## Solver
Solver final disimpan di `solve.py`.

Cara jalanin:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output yang diharapkan:

```text
[+] PIN  : 5102
[+] FLAG : KSUS{dr1v3r_cr4ck1ng_101}
```
