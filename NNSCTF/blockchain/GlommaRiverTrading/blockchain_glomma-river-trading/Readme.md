# Glomma River Trading

## Ringkasan

Target ada di `Setup.isSolved()`:

- `CORE.vaultEquity() <= 100_000e6`
- `CORE.collateral() >= 4_900_000e6`

Kontrak `HyperCore` punya dua komponen penting:

- posisi perp long yang settle pakai `oraclePx(1)`
- spot AMM kecil yang juga dipakai langsung sebagai oracle

Karena oracle cuma `spotQuoteReserve * 1e6 / spotBaseReserve`, harga bisa dinaikkan sendiri dengan beli spot. Long perp dibuka dulu saat harga masih murah, lalu oracle digeser lewat spot buy, lalu posisi ditutup untuk mengambil profit besar dari vault.

## File Challenge

- `HyperCore.sol`
- `L1Read.sol`
- `Setup.sol`

## Analisis Awal

`Setup.sol` hanya mengecek state final pada `HyperCore` di alamat tetap `0x3333333333333333333333333333333333333333`.

State awal instance:

- `collateral = 10_000e6`
- `vaultEquity = 5_000_000e6`
- `spotBaseReserve = 1_000e6`
- `spotQuoteReserve = 1_000e6`
- `oraclePx(1) = 1_000_000`

`sendRawAction()` menerima payload 228 byte dengan header `0x01000001`, lalu decode:

```solidity
(uint32 asset, bool isBuy,, uint64 size, bool reduceOnly, uint8 tif,) 
```

Nilai `tif` harus `3`.

## Temuan Penting

Bug utamanya bukan overflow atau auth bypass. Masalahnya desain oracle:

- `oraclePx()` membaca langsung reserve spot internal
- `spot` pool sangat kecil dibanding `vaultEquity`
- profit perp dihitung dari oracle yang sama

Jadi cukup:

1. buka long perp saat harga masih 1.0
2. beli spot untuk mendorong harga naik
3. tutup long dan ambil profit dari vault

## Proses Ekstraksi

Pilih parameter yang masih lolos semua `require`:

- `OPEN_SIZE = 11_278_772_493_901`
- `SPOT_SIZE = 85_000_000_000`

Artinya:

- buka long perp asset `1`
- beli spot asset `10001` dengan `size = 85_000_000_000`
- `baseOut = size / 100 = 850_000_000`

Sesudah spot buy:

- `quoteIn = 5_666_666_667`
- harga oracle naik jadi `44_444_444`

Profit close perp:

```text
profit = OPEN_SIZE * (44_444_444 - 1_000_000) / 1e8
       = 4_900_000_000_000
```

State akhir:

- `collateral = 4_904_333_333_333`
- `vaultEquity = 100_000_000_000`

Itu tepat memenuhi `isSolved()`.

Flag diambil dari launcher setelah state solved:

```text
NNS{4_tHou54nd_dol1ars_0f_5P07_1iqU1Di7y_5hould_PR0bablY_no7_b3_alloWed_to_priCe_4_tWo_HUnDR3D_tH0U54ND_Do1laR_peRp}
```

## Solve Script

`solve.py` mengirim tiga transaksi:

1. `open perp`
2. `buy spot`
3. `close perp`

Script juga mengecek `isSolved()` sebelum dan sesudah eksekusi.

## Cara Menjalankan

Default script berisi endpoint dan instance yang dipakai saat solve ini. Untuk instance baru, override lewat environment variable:

```bash
python3 solve.py
RPC_URL="https://..." PRIVATE_KEY="0x..." SETUP_ADDRESS="0x..." python3 solve.py
```

## Flag

`NNS{4_tHou54nd_dol1ars_0f_5P07_1iqU1Di7y_5hould_PR0bablY_no7_b3_alloWed_to_priCe_4_tWo_HUnDR3D_tH0U54ND_Do1laR_peRp}`

## Catatan

`L1Read.sol` cuma wrapper fallback untuk membaca `oraclePx()` dari address tetap. Tidak dibutuhkan untuk solve, tapi mengonfirmasi bahwa harga oracle memang sumber kebenaran yang dipakai ekosistem challenge ini.
