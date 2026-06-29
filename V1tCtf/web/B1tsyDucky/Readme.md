# B1tsy Ducky — V1t CTF 2026

- **Category:** Reverse
- **Target:** Bitsy HTML game + Go WebAssembly
- **Flag:** `v1t{b1tsy_t1psy_duck_w4sm}`

## Ringkasan

Game Bitsy hanya menjadi pembungkus. Dialog duck terakhir mengaktifkan fungsi JavaScript tersembunyi bernama `__bdx_17a`, lalu tiga nilai dikirim ke fungsi Go/WASM `duckWasmReveal`:

1. `document.referrer`
2. serialisasi `ROOM 3`
3. token Cloudflare 32 digit hex

WASM menggabungkan ketiganya, membuat key HMAC-SHA256 dan nonce SHA-256, lalu membuka ciphertext dengan AES-256-GCM. Validasi flag di wrapper WASM memiliki pengecekan panjang yang keliru, jadi plaintext diambil langsung dari hasil AES-GCM.

## Triage

File yang relevan:

```bash
file main.wasm
strings -a main.wasm | grep -E 'deriveKey|deriveNonce|decryptHex|duckWasmReveal|aesgcm|nonce'
wasm2wat main.wasm -o main.wat
```

Beberapa string penting terlihat langsung dari binary:

```text
main.deriveKey
main.deriveNonce
main.decryptHex
main.duckWasmReveal
main.isValidFlag
b1tsy-ducky-aesgcm
nonce|
9e8c2b395bbf6bd7434230ab998c6e86f3228c503324c8660715ccd0bc74deb7d6346dfcc4a9614e58cb
```

Path build Go juga masih tertanam:

```text
D:/CTF/V1t_CTF/V1t_CTF_2026/web/B1tsy-Ducky/main.go
```

## Trigger tersembunyi di HTML

Bagian akhir `game.html` mendaftarkan fungsi berikut:

```javascript
Object.defineProperty(window, "__bdx_17a", {
    value: function () {
        // validasi posisi dan dialog duck
        // ...
        var room3Block = serializeRoomBlock("3");
        var referrer = document.referrer || "";
        var picked32 = pick32();
        var flag_decrypt = window.duckWasmReveal(
            referrer,
            room3Block,
            picked32
        );
    }
});
```

Trigger hanya bekerja ketika:

- dialog sedang aktif;
- sprite terakhir yang diajak bicara adalah duck `c`;
- player berada satu tile dari duck;
- pemanggilan dilakukan maksimal dua detik setelah dialog dimulai.

Syarat tersebut tidak perlu direplikasi. Fungsi WASM dapat dipanggil langsung atau algoritmenya ditulis ulang.

## Input KDF

### `picked32`

`pick32()` memindai atribut seluruh tag `<script>` dari belakang. Nilai 32-hex yang dipakai adalah token Cloudflare beacon:

```text
797084dac2504482bcfaec15adc048bb
```

### `room3Block`

`serializeRoomBlock("3")` menghasilkan blok berikut tanpa newline tambahan di akhir:

```text
ROOM 3
0,0,0,f,0,g,g,f,0,0,0,0,0,0,0,0
0,0,0,g,0,g,0,g,g,g,g,0,0,0,0,0
0,0,g,0,0,0,0,0,f,0,f,g,d,g,0,0
0,g,d,0,0,0,0,0,0,0,0,0,0,g,g,0
g,f,g,0,a,0,0,0,0,0,a,0,0,0,g,0
g,0,0,a,0,0,0,a,a,0,0,0,0,0,d,0
f,0,a,0,0,0,0,0,0,0,a,0,0,0,g,0
g,g,0,0,0,0,a,0,a,0,0,0,0,0,g,f
0,g,g,0,0,0,0,0,0,0,0,0,a,0,0,g
0,d,0,0,0,a,0,0,0,0,0,0,0,0,g,g
f,g,g,0,0,0,0,0,0,0,a,0,0,0,d,0
g,0,0,0,0,0,0,0,0,0,0,0,0,0,g,0
g,0,0,a,0,0,0,0,a,0,0,0,0,0,g,0
g,f,0,0,0,0,0,0,0,g,d,g,g,g,f,0
0,g,g,0,0,0,f,g,f,g,0,0,0,0,0,0
0,0,0,g,f,g,0,0,0,0,0,0,0,0,0,0
NAME example room copy 2
EXT 4,0 2 4,15
PAL 0
TUNE 2
```

### `referrer`

Nilai ini tidak disimpan di attachment. Browser mengisinya dari halaman parent yang membuka game. Ambil dari tab game yang dibuka melalui index/challenge page:

```javascript
document.referrer
```

String harus sama persis, termasuk scheme, hostname, path, dan trailing slash.

## Logic kriptografi

Hasil decompile dapat diringkas menjadi:

```python
material = referrer + "|" + room3Block + "|" + picked32
key = HMAC_SHA256(
    key=b"b1tsy-ducky-aesgcm",
    message=material.encode(),
)
nonce = SHA256(b"nonce|" + material.encode())[:12]
```

Blob hardcoded:

```text
9e8c2b395bbf6bd7434230ab998c6e86f3228c503324c8660715ccd0bc74deb7d6346dfcc4a9614e58cb
```

Enam belas byte terakhir adalah authentication tag GCM. Sisanya adalah ciphertext:

```python
blob = bytes.fromhex(ciphertext_hex)
ciphertext = blob[:-16]
tag = blob[-16:]
plaintext = AES_GCM_DECRYPT(key, nonce, ciphertext, tag)
```

Plaintext berukuran 26 byte:

```text
v1t{b1tsy_t1psy_duck_w4sm}
```

## Bug `isValidFlag`

Wrapper memeriksa panjang 28 byte, sedangkan ciphertext hanya menghasilkan plaintext 26 byte. Akibatnya, dekripsi yang benar masih dapat dibuang dan diganti pesan:

```text
some thing go wrong go to start again
```

Solusinya bukan memaksa trigger game, tetapi memanggil primitive dekripsinya langsung dan melewati validator tersebut.

## Solver

Aktifkan environment:

```bash
source /home/nata/ctf_env/bin/activate
pip install pycryptodome
```

Ambil referrer dari browser, lalu jalankan:

```bash
python3 solve.py --referrer 'REFERRER_PERSIS_DARI_DOCUMENT_REFERRER'
```

Output:

```text
[+] picked32 : 797084dac2504482bcfaec15adc048bb
[+] flag     : v1t{b1tsy_t1psy_duck_w4sm}
```

## Flag

```text
v1t{b1tsy_t1psy_duck_w4sm}
```
