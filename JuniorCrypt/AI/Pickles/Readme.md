# Pickles

`model.pkl` bukan model bersih. Saat di-`pickle.load()`, object dibuat lewat `payload.install_supply_chain_probe()` dari `payload.pyc`, jadi file mirror itu menyisipkan class `LedgerModel` custom. Fungsi `infer()` punya backdoor: kalau `sha256(b"|".join(last_4_history)) == seal`, respons lokal berisi field `ticket`.

Empat string pemicu ada langsung di konstanta bytecode:

- `snow`
- `candle`
- `tangerine`
- `clock`

Kalau `history` diisi empat nilai itu, `infer()` mengembalikan `ticket` base85. Nilai itu bukan flag dari remote, tapi hasil decode lokal dari blob terenkripsi di pickle.

## Langkah Solve

1. Load `payload.pyc` dengan `python3.10`, lalu register sebagai module `payload`.
2. Unpickle `model.pkl` supaya object `LedgerModel` terbentuk.
3. Panggil `model.infer("example", ["snow", "candle", "tangerine", "clock"])`.
4. Ambil field `ticket`, decode dengan `base64.b85decode()`, hasilnya flag.

```bash
python3.10 solve.py
```

Output:

```text
XL4_3Zf|>VKx1ocBy(S3a%Eq0Z(n&;ZEbmd
b'XL4_3Zf|>VKx1ocBy(S3a%Eq0Z(n&;ZEbmd'
grodno{p@ckl$s_are_so_yUmmy}
```

## Catatan

Remote `POST /infer` tetap jalan normal untuk klasifikasi `invoice/receipt`, tapi field `ticket` tidak ikut dikembalikan. Flag tetap bisa diekstrak offline karena semua material kripto sudah ada di `model.pkl`.

## Flag

```text
grodno{p@ckl$s_are_so_yUmmy}
```
