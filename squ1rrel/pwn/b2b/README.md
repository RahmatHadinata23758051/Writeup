# Writeup - pwn/b2b

Challenge ini keliatan simpel, dan emang arahnya classic stack overflow + ret2libc.

## Informasi challenge
- Nama: `b2b`
- Kategori: `pwn`
- Service: `nc challs.squ1rrel.dev 5000`

## Recon awal
Pertama saya cek proteksi binary:

- Arsitektur: `amd64`
- `NX: enabled`
- `PIE: disabled` (base binary fix, enak buat ROP)
- `Canary: tidak ada`
- `RELRO: partial`

Dari sini sudah kebayang: overwrite RIP langsung memungkinkan, tapi karena NX aktif kita butuh ROP (bukan shellcode di stack).

## Analisis fungsi rentan
Di fungsi `back2basics` ada pola ini:

- Buffer lokal di stack ukuran `0x40`
- Input pakai `read(0, buf, 0x100)`

Artinya kita bisa nulis jauh melewati buffer.
Offset ke RIP jadi:
- `0x40` (buffer)
- `+ 0x8` (saved RBP)
- total `0x48`

Jadi payload untuk kontrol RIP = `b'A' * 0x48 + rop_chain`.

## Kenapa ret2libc
Tidak ada fungsi `win()` atau semacamnya, jadi strategi paling stabil:

1. Leak alamat libc runtime (pakai `puts` terhadap `puts@got`)
2. Hitung base libc
3. Panggil `system("/bin/sh")`

Karena PIE off, alamat gadget dan simbol di binary tetap.

## ROP stage 1 (leak)
Chain stage 1:
- `pop rdi; ret`
- argumen = `puts@got`
- call `puts@plt`
- balik lagi ke `back2basics` biar dapat input kedua

Dengan ini kita dapat nilai real `puts` dari libc di proses remote.

## ROP stage 2 (shell)
Setelah base libc ketemu:
- `system = libc_base + offset_system`
- `binsh = libc_base + offset_string_/bin/sh`

Chain stage 2:
- `ret` (alignment stack)
- `pop rdi; ret`
- `binsh`
- `system`

Lalu kirim command baca flag.

## Solver
Solver final disimpan di:
- `solve.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE
```

## Hasil
Flag yang didapat:

```text
squ1rrel{pr1d3_4nd_pr3jud1ce_gr34t_g4tsby_4nd_ret2libc}
```

## Catatan singkat
Sempat ada jebakan kecil pas debugging karena interpretasi alur `leave; ret`, tapi setelah ditrace ulang dengan benar, ini murni overflow langsung ke return address di offset `0x48`.

