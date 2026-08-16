# Writeup — Firefly: Complete Combustion

## Challenge

Pada challenge ini, server menjalankan simulator “Complete Combustion” yang menerima satu input berupa **Lua 5.5.0 binary combat script**.

Remote:

```bash
ncat --ssl firefly-complete-combustion.chal.uiuc.tf 1337
```

Deskripsi challenge memberi petunjuk utama:

```text
Elio's script never accounted for untrusted bytecode.

Firefly's Complete Combustion simulator accepts one length-prefixed Lua 5.5.0 binary combat script on each connection.
The usual escape hatches are gone, but the bytecode loader still trusts you completely.
```

Artinya, exploit tidak dilakukan lewat Lua source biasa, tetapi lewat **binary Lua bytecode** yang dimuat oleh loader.

---

## Initial Recon

Saat connect ke server, muncul banner:

```text
FYREFLY TYPE-IV // COMPLETE COMBUSTION
GLAMOTH IRON CAVALRY // LUA 5.5.0
Elio's script is not the one loaded today.
send 4-byte big-endian length + Lua chunk:
```

Server meminta:

```text
4-byte big-endian length + Lua chunk
```

Jadi payload harus dikirim dalam format:

```text
[payload length, 4 byte big endian][Lua 5.5 binary chunk]
```

Dari source challenge, environment Lua sengaja dibatasi. Beberapa fungsi berbahaya seperti:

```text
load
loadfile
dofile
```

sudah dihapus dari environment Lua biasa. Namun karena server tetap menerima **binary chunk**, bytecode loader masih bisa dieksploitasi.

---

## Root Cause

Bug utamanya adalah:

```text
Lua binary bytecode dipercaya penuh oleh loader
```

Binary chunk bisa dimodifikasi sehingga VM Lua menjalankan bytecode yang tidak bisa dihasilkan secara normal dari Lua source valid.

Dengan kata lain, meskipun sandbox Lua source dibatasi, bytecode verifier/loader masih mempercayai chunk buatan attacker.

---

## Exploit Idea

Exploit memanfaatkan kelemahan klasik pada Lua bytecode:

```text
FORPREP / FORLOOP confusion
```

Payload dibuat dari Lua chunk normal, lalu salah satu opcode dipatch.

Konsepnya:

1. Buat Lua binary chunk valid.
2. Patch instruksi tertentu, misalnya `FORPREP` menjadi `FORLOOP`.
3. Trigger type confusion pada Lua VM.
4. Gunakan confusion tersebut untuk membuat primitive baca/tulis memory.
5. Leak address fungsi internal / libc.
6. Gunakan primitive tersebut untuk memanggil fungsi yang bisa membaca isi `/flag.txt`.

---

## Percobaan Pertama

Payload awal berhasil mencapai fungsi internal `loadfile("/flag.txt")`.

Namun masalahnya, `loadfile` tidak membaca file sebagai raw text. Fungsi itu mencoba menganggap `/flag.txt` sebagai Lua source code.

Output remote:

```text
ERR     /flag.txt:1: malformed number near '1_'
```

Ini penting, karena error tersebut menunjukkan bahwa isi flag memang sudah berhasil disentuh oleh parser Lua. Bagian awal flag setelah `uiuctf{` adalah:

```text
1_
```

Namun karena `loadfile` mencoba mem-parse flag sebagai kode Lua, flag tidak langsung tercetak.

---

## Perbaikan Strategi

Karena `loadfile("/flag.txt")` membuat flag diparse sebagai Lua source, strategi diganti.

Alih-alih berharap `loadfile` mencetak isi file, solver memanfaatkan fakta bahwa Lua parser menyimpan isi file/error buffer di memory.

Langkah exploit final:

1. Trigger `loadfile("/flag.txt")`.
2. Biarkan parser gagal dengan error `malformed number near ...`.
3. Leak stack/memory di sekitar buffer parser.
4. Scan hasil leak untuk pola:

```text
uiuctf{
```

5. Ambil string sampai karakter `}`.

---

## Raw Leak

Payload final mencetak pointer stack:

```text
LEAKSP  7ffd82393780
```

Lalu melakukan scan memory dan menemukan beberapa hit yang berisi flag.

Contoh output:

```text
HIT     7ffd82391300    689     ????????????SY??iuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}...
HEX     0000000000000000b0c8c9085359000069756374667b315f7368346c6c5f7333745f7468335f733334735f34626c347a337d0a...
```

Jika bagian hex didekode:

```text
69 75 63 74 66 7b 31 5f 73 68 34 6c 6c 5f 73 33 74 5f 74 68 33 5f 73 33 34 73 5f 34 62 6c 34 7a 33 7d
```

Maka hasil ASCII-nya:

```text
iuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}
```

Karena flag UIUCTF memakai format:

```text
uiuctf{...}
```

maka flag lengkapnya adalah:

```text
uiuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}
```

---

## Solver

Solver final mengirim payload Lua binary chunk length-prefixed ke remote:

```bash
python3 solve.py firefly-complete-combustion.chal.uiuc.tf 1337
```

Output berhasil:

```text
[+] sending raw-leak Lua chunk: 2272 bytes
LEAKSP  7ffd82393780
ERR     /flag.txt:1: malformed number near '1_'
HIT     7ffd82391300    689     ????????????SY??iuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}...
[+] FLAG: uiuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}
```

---

## Flag

```text
uiuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}
```

---

## Kesimpulan

Challenge ini bukan sandbox escape lewat Lua source biasa, karena fungsi seperti `load`, `loadfile`, dan `dofile` sudah dihapus dari environment.

Namun server masih menerima **Lua 5.5 binary bytecode** dari user. Bytecode tersebut bisa dipatch untuk menghasilkan instruksi yang tidak aman, sehingga terjadi type confusion di VM Lua.

Exploit final menggunakan type confusion untuk membuat primitive memory leak. Walaupun percobaan membaca `/flag.txt` lewat `loadfile` gagal karena flag diparse sebagai Lua source, error parser tetap membuat isi flag berada di memory. Dengan melakukan scan memory di sekitar stack/parser buffer, flag berhasil ditemukan.

Final flag:

```text
uiuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}
```
