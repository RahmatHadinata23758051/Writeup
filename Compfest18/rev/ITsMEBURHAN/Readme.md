# IT'S ME, BURHAN!

## Ringkasan

Challenge ini berupa program Java `.jar` bernama `burhanquest.jar`. Programnya adalah game terminal RPG sederhana dengan sistem login. Kita dikasih akun wanderer:

```text
frieren / frieren
```

Targetnya adalah login sebagai admin `burhan`, lalu membuka arsip tersegel guild.

Password admin tidak disimpan sebagai string biasa. Password dibuat dari state guild: level, coin, quest yang diselesaikan, battle sigil, archive sigil, export sigil, dan coin akhir. Setelah admin login, flag juga tidak langsung plaintext, tapi masih berupa hex terenkripsi yang perlu didecode lagi.

Flag akhir:

```text
COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_mxmLI4SRk3aLF4no}
```

## File Challenge

File utama:

```text
burhanquest.jar
```

Cek awal:

```bash
file burhanquest.jar
jar tf burhanquest.jar | head
strings -a burhanquest.jar | head
```

Hasilnya menunjukkan file adalah Java archive. Di dalamnya ada banyak class dengan nama pendek/obfuscated, misalnya `p.class`, `l.class`, dan beberapa class user/admin.

## Analisis Awal

Program dijalankan sebagai terminal menu. Remote juga punya wrapper token CTFd, lalu masuk ke menu BurhanQuest.

Alur normal:

```text
1. Login
2. Keluar dari program
```

Login wanderer:

```text
username: frieren
password: frieren
```

Setelah login, tersedia menu pengembara. Dari menu ini kita bisa melihat data diri, menjalankan quest, export data, dan membaca arsip.

Admin account adalah:

```text
burhan
```

Ada string password decoy seperti:

```text
burunghantu123
```

Tapi password ini bukan password valid. Class admin melakukan validasi password menggunakan data guild, bukan membandingkan string hardcoded biasa.

## Analisis Static

Karena file berupa `.jar`, langkah paling enak adalah decompile atau inspect class Java.

Command yang dipakai:

```bash
jar tf burhanquest.jar
javap -classpath burhanquest.jar -c p
javap -classpath burhanquest.jar -c l
javap -classpath burhanquest.jar -c o
```

Temuan penting:

1. Class admin memiliki login khusus.
2. Password admin dicek lewat fungsi di object guild singleton.
3. Class `p` berisi banyak helper crypto/encoding:

   * SHA-256
   * konversi integer ke byte
   * permutasi
   * transform array 5-bit
   * transform byte
4. Password admin dibuat dari gabungan beberapa nilai runtime.
5. Arsip admin setelah terbuka menghasilkan hex panjang, bukan flag plaintext.

Validasi admin kurang lebih memakai state berikut:

```text
level awal
coin awal
battle sigil quest 1
archive sigil setelah quest 1
battle sigil quest 2
export sigil setelah quest 2
battle sigil quest 3
archive sigil setelah quest 3
coin akhir
```

State ini berubah tiap instance remote, jadi solver tidak boleh hardcode password.

## Analisis Dynamic

Setelah login sebagai `frieren`, solver mengambil data diri:

```text
Level Pengembara : 13
Koin Didapatkan  : 2977
```

Dari level dan coin ini, program menentukan 3 quest yang harus diambil. Quest path dihitung dari hash:

```python
n = sha256(u32be(level) + u32be(coins)) % 4896
path = kperm(n, 18, 3)
```

Pada run valid yang menghasilkan flag, path-nya:

```text
Q1 > Q14 > Q12
```

Output penting dari remote:

```text
[+] level=13 coins=2977 path=Q1 > Q14 > Q12
[+] Q1 battle=59559 archive=0f42c2dbdc09
[+] Q14 battle=48199 export=3b9d92aa6b6e
[+] Q12 battle=84358 archive=f4e131f8537a final_coins=4433
[+] admin password = IM4CVEMGUDQSQIVW
[+] logged in as burhan
```

Berarti password admin untuk instance tersebut:

```text
IM4CVEMGUDQSQIVW
```

## Algoritma Validasi atau Encoding

### 1. Penentuan quest path

Program tidak meminta kita memilih quest acak. Ada path tersembunyi yang diturunkan dari level dan coin.

Pseudo-code:

```python
seed = sha256(u32be(level) + u32be(coins))
n = seed % 4896
quest_path = kperm(n, 18, 3)
```

`kperm()` mengambil 3 quest dari total 18 quest tanpa pengulangan.

Contoh hasil:

```text
level=13
coins=2977
path=Q1 > Q14 > Q12
```

### 2. Pengambilan sigil

Solver menyelesaikan quest sesuai path:

```text
Q1
Q14
Q12
```

Setelah quest pertama, solver membaca archive sigil.

Setelah quest kedua, solver membaca export sigil.

Setelah quest ketiga, solver membaca archive sigil lagi dan mengambil coin akhir.

Data yang terkumpul:

```text
h  = level awal
g  = coin awal
bp = battle sigil quest pertama
cp = archive sigil pertama
bq = battle sigil quest kedua
dq = export sigil
br = battle sigil quest ketiga
cr = archive sigil ketiga
s  = coin akhir
```

### 3. Generate password admin

Password admin dibuat dari semua state tersebut.

Data digabung:

```text
u32be(h)
u32be(g)
u32be(bp)
bytes.fromhex(cp)
u32be(bq)
bytes.fromhex(dq)
u32be(br)
bytes.fromhex(cr)
u32be(s)
```

Lalu dihitung:

```python
t = sha256(concat_state) % 17643225600
ops = kperm(t, 18, 9)
```

Class `p` kemudian melakukan beberapa transform 5-bit untuk menghasilkan password admin 16 karakter.

Solver memakai helper Java `BQCalc.java` agar transform password sama persis dengan implementasi asli di `burhanquest.jar`.

Password yang didapat pada instance valid:

```text
IM4CVEMGUDQSQIVW
```

### 4. Decode arsip tersegel

Setelah login admin dan memilih menu arsip, program memberi hex panjang:

```text
...hex encrypted archive...
```

Hex ini bukan flag langsung. Decode-nya memakai urutan transform byte yang juga diturunkan dari state session:

```python
ops = kperm(t, 18, 9)
```

Lalu transform dibalik satu per satu dari belakang:

```python
for op in reversed(ops):
    cur = inv_byte_op(op, cur)
```

Transform byte yang dibalik meliputi:

```text
reverse array
255 - byte
bit reverse
rotate right
ungray
xor chain
permutation shuffle
subtraction chain
multiplication inverse modulo 256
```

Pada instance valid, decode archive menghasilkan plaintext flag:

```text
COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_mxmLI4SRk3aLF4no}
```

## Penyusunan Solve Script

Solver melakukan semua langkah otomatis:

1. Connect ke remote.
2. Handle prompt CTFd token.
3. Login sebagai `frieren/frieren`.
4. Ambil level dan coin.
5. Hitung quest path.
6. Selesaikan 3 quest sesuai path.
7. Ambil battle sigil, archive sigil, export sigil, dan coin akhir.
8. Generate password admin memakai helper Java.
9. Logout wanderer.
10. Login sebagai `burhan`.
11. Buka arsip admin.
12. Decode hex archive.
13. Print flag.

Contoh output solver:

```text
[+] connect 34.2.22.80:30012
[+] sent CTFd token
[+] logged in as frieren
[+] level=13 coins=2977 path=Q1 > Q14 > Q12
[+] Q1 battle=59559 archive=0f42c2dbdc09
[+] Q14 battle=48199 export=3b9d92aa6b6e
[+] Q12 battle=84358 archive=f4e131f8537a final_coins=4433
[+] admin password = IM4CVEMGUDQSQIVW
[+] logged in as burhan
<FLAG>COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_mxmLI4SRk3aLF4no}</FLAG>
```

## Cara Menjalankan

Pastikan `solve.py` dan `burhanquest.jar` ada di folder yang sama.

Compile check:

```bash
python3 -m py_compile solve.py
```

Run ke remote:

```bash
python3 solve.py 34.2.22.80 30012
```

Kalau port berubah, tinggal ganti port:

```bash
python3 solve.py 34.2.22.80 <PORT_BARU>
```

Kalau token CTFd berubah:

```bash
BQ_TOKEN='ctfd_TOKEN_BARU' python3 solve.py 34.2.22.80 <PORT>
```

## Flag

```text
COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_mxmLI4SRk3aLF4no}
