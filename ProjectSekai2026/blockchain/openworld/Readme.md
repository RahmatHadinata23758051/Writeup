# Open World

Service ini bikin instance challenge terpisah, tapi semuanya tetap hidup di chain yang sama. Bonus `PlayerBonus` cuma kasih `50` jetton per instance, jadi satu instance doang tidak cukup buat `Solve` yang butuh `100`.

Celahnya ada di model ekonominya, bukan di memory corruption:

- Jetton hasil bonus bisa dijual balik ke challenge lewat payload `Sell`.
- Hasil jualannya dibayar dalam TON ke wallet player.
- TON itu bebas ditransfer ke wallet player di instance lain.
- Instance target tetap bisa klaim bonus `50`, lalu beli `50` lagi pakai TON kiriman donor.

Detail penting yang bikin exploit stabil:

- `Sell` dan `Solve` harus dikirim lewat `AskToTransfer` ke jetton wallet player.
- `forwardTonAmount` harus non-zero. Kalau `0`, jetton wallet tidak mengirim `TransferNotificationForRecipient`, jadi challenge tidak pernah melihat payload `Sell` atau `Solve`.
- Nilai yang saya pakai aman:
  - `Sell`: transfer `50` jetton, `forwardTonAmount = 0.05 TON`, value kirim `0.35 TON`
  - `Buy 50`: value kirim `100.2 TON`
  - `Solve`: transfer `100` jetton, `forwardTonAmount = 0.05 TON`, value kirim `0.35 TON`

Langkah eksploitasi:

1. Buat dua instance: donor dan target.
2. Donor klaim bonus `50` jetton.
3. Target klaim bonus `50` jetton.
4. Donor kirim `Sell` untuk `50` jetton dan terima `100 TON`.
5. Donor transfer `100 TON` ke wallet target.
6. Target kirim `Buy(50)` ke challenge.
7. Target sekarang punya `100` jetton.
8. Target transfer `100` jetton ke challenge dengan payload `Solve`.
9. Ambil flag lewat menu `flag`.

Run:

```bash
python3 solve.py --host open-world-6a1fda4f080c.instancer.sekai.team
```

Solver butuh dependency Node di repo ini:

```bash
npm ci
```

Flag yang saya dapat:

```text
SEKAI{3Xp1or1ng-An-0pen-W0rld-15-FUN}
```
                                         
