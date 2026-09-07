# eu261

## Ringkasan

Challenge ini deploy dua kontrak: `BoardingPass` dan `CompensationFund`. Player dikasih satu boarding pass untuk flight `SK4045`, lalu fund diisi `40 ether`. Tujuannya cukup bikin `isSolved()` bernilai `true`, yaitu saat saldo fund habis.

Bug utamanya ada di `CompensationFund.collect()`. Kontrak mengirim ETH ke `msg.sender` dulu, baru menandai `redeemed[fundId][passId] = true` dan mengurangi `fund.balance`. Karena update state dilakukan belakangan, satu boarding pass bisa dipakai berulang lewat reentrancy.

## File Challenge

- `src/BoardingPass.sol`
- `src/eu261.sol`
- `script/Deploy.s.sol`
- `solve.py`

## Analisis Awal

Struktur project adalah project Foundry biasa. Dari `script/Deploy.s.sol` terlihat parameter instance:

- Flight: `SK4045`
- Distance: `341 km`
- Intra-community: `true`
- Delay: `3 jam`
- Refund pool: `40 ether`

Perhitungan kompensasi di `compensationFor()` untuk flight ini menghasilkan `2.5 ether` per klaim:

- `341 <= 1500` masuk band A, nominal `250 EUR`
- `EUR = 0.01 ether`
- Delay `3 jam` tidak kena aturan half payment band A karena threshold half payment band A `2 jam`

Jadi satu klaim bernilai `2.5 ether`, dan total pool `40 ether`, artinya butuh `16` payout untuk mengosongkan fund.

## Temuan Penting

Potongan rentan:

```solidity
(bool ok,) = msg.sender.call{value: fund.compensation}("");
require(ok, "payout failed");

redeemed[fundId][passId] = true;
fund.balance -= fund.compensation;
```

Urutannya salah. `msg.sender` bisa berupa kontrak attacker dengan `receive()` yang memanggil `collect()` lagi sebelum state berubah.

Ada satu detail penting lain: `BoardingPass.transferFrom()` hanya bisa dipanggil langsung oleh holder, jadi boarding pass harus dipindahkan ke kontrak attacker lewat transaksi terpisah dari EOA player. Setelah kontrak attacker memegang pass, `collect()` akan melihat `ownerOf(passId) == msg.sender` dan reentrancy bisa jalan.

## Proses Ekstraksi

1. Hubungi launcher TCP+SSL dan pilih menu `1` untuk ambil:
   - RPC endpoint
   - private key player
   - alamat `CompensationFund`
2. Compile source challenge dan kontrak attacker lokal dengan `solc 0.8.36`.
3. Query `boardingPass()`, `reserve()`, dan `compensationOf(0)` dari chain.
4. Deploy kontrak attacker yang menyimpan `fundId=0` dan `passId=0`.
5. Dari EOA player, panggil `BoardingPass.transferFrom(player, attacker, 0)`.
6. Panggil `begin(16)` pada attacker.
7. `begin()` memanggil `collect()` pertama, lalu `receive()` attacker melakukan reentry sampai total 16 klaim.
8. Setelah semua nested call selesai, reserve fund jadi `0` dan `isSolved()` bernilai `true`.
9. Hubungi launcher lagi, pilih menu `2`, lalu ambil flag.

## Solve Script

`solve.py` melakukan semua langkah di atas secara otomatis:

- ambil instance info dari launcher
- compile kontrak
- deploy attacker
- transfer boarding pass
- drain fund
- tarik ETH dari attacker ke EOA
- minta flag dari launcher

Kontrak attacker di-embed langsung di dalam script supaya tidak perlu file Solidity tambahan.

## Cara Menjalankan

Aktifkan environment lalu jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Kalau host atau port launcher berubah:

```bash
HOST="eu261-bdd6a5f0ef21.chall.nnsc.tf" PORT=1337 python3 solve.py
```

## Flag

`NNS{eU261_p4Y5_0U7_0NC3_uN135s_Y0U_45k_tw1c3}`

## Catatan

Flag didapat dari output launcher setelah state kontrak berubah ke solved. Bukti on-chain yang dipakai script:

- `reserve()` turun dari `40 ether` ke `0`
- `isSolved()` berubah jadi `true`

Nama challenge memang terlihat seperti blockchain, tapi teknik intinya cuma logic bug reentrancy yang cukup sederhana.
