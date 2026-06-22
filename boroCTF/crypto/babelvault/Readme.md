# Babel's Vault Writeup

**Category:** Crypto  
**Flag:** `boroCTF{oneSeedCipherInInfinity}`

## Inti bug

`babel.py` punya dua generator:

- `page_from_seed(seed)` mengubah `seed + C_page` menjadi 940 karakter dengan base 55.
- `image_from_seed(seed)` mengubah `seed - C_image` menjadi 225 pixel RGB dengan base 256.

`author.txt` panjangnya 940 karakter, sama persis dengan output page. Jadi teks author bisa dibalik menjadi seed. Setelah seed ketemu, seed yang sama dipakai ke mode image.

## Recover seed dari page

Alphabet yang dipakai:

```py
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz., "
```

Karena `page_from_seed` melakukan `divmod(seed, 55)` sebanyak 940 kali, output page adalah representasi little-endian base 55.

Untuk membaliknya:

```py
n = sum(ALPHABET.index(ch) * 55**i for i, ch in enumerate(author))
seed = n - C_page
```

## Decode image

`image_from_seed(seed)` menghasilkan 225 pixel. Secara visual gambarnya hampir hitam karena RGB-nya kecil, tapi raw pixel awal berisi data:

```text
(0,0,7), (0,1,6), (0,3,5), ...
```

Clue “hexagonal colors” mengarah ke warna hex/RGB. Tiap pixel dibaca sebagai tiga digit desimal `rgb`, lalu dipakai sebagai index ke `author.txt`. Karena ada nilai seperti `919`, index dibuat wrap dengan modulo panjang author.

```py
idx = int(f"{r}{g}{b}") % len(author)
char = author[idx]
```

Stop saat pixel `(0, 0, 0)` muncul. Hasil compact-nya:

```text
boroCTFoneSeedCipherInInfinity
```

Format flag tinggal dipasang di prefix `boroCTF{...}`.

## Run

```bash
python3 solve.py
```

Output:

```text
flag = boroCTF{oneSeedCipherInInfinity}
<FLAG>boroCTF{oneSeedCipherInInfinity}</FLAG>
```
