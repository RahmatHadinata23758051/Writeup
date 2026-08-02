# Writeup Blockchain — Switchyard Auction

## Ringkasan

Challenge ini berisi sistem sealed-bid auction dengan tiga kontrak utama: `BidReceiptToken`, `AuctionHouse`, dan `RefundVault`. Setiap bid menghasilkan receipt token yang transferable. Pemenang auction tidak bisa refund, sedangkan peserta yang kalah bisa reclaim escrow dari `RefundVault`.

Bug utama ada pada proses refund. `RefundVault.claimRefund()` memanggil `AuctionHouse.consumeRefund()`, lalu vault memberi credit kepada `ownerBefore`. Namun jika owner receipt berubah selama callback, vault juga memberi credit kepada `ownerAfter`. Akibatnya satu escrow bisa dicredit dua kali ke dua address berbeda.

Goal challenge adalah membuat `AuctionHouse.isSolved()` bernilai `true`. Syaratnya auction sudah ditutup, vault sudah terdaftar, dan saldo `RefundVault` kosong.

## Analisis Kontrak

### BidReceiptToken

`BidReceiptToken` adalah token receipt sederhana. Token hanya bisa di-mint oleh `AuctionHouse`, tetapi transfer receipt bisa dilakukan oleh pemilik token sendiri menggunakan `transferFrom()`. Fungsi transfer hanya mengecek bahwa `msg.sender == from` dan token tersebut memang dimiliki oleh `from`.

Bagian ini penting karena receipt bisa dipindahkan saat proses refund sedang berjalan.

```solidity
function transferFrom(address from, address to, uint256 tokenId) external {
    require(to != address(0), "bad receiver");
    require(msg.sender == from, "sender must own");
    require(_ownerOf[tokenId] == from, "wrong owner");

    _ownerOf[tokenId] = to;
    emit Transfer(from, to, tokenId);
}
```

### AuctionHouse

Auction memakai mekanisme commit-reveal. User melakukan `commitBid()` dengan mengirim escrow, lalu menerima receipt token. Receipt ID tersebut menyimpan commitment, escrow, dan status reveal/refund.

Reveal dilakukan dengan membuka `amount` dan `salt`. Amount harus sama dengan escrow, dan hash `keccak256(abi.encodePacked(amount, salt))` harus sama dengan commitment awal. Jika amount lebih besar dari `highestBid`, receipt tersebut menjadi pemenang.

Auction bisa ditutup jika sudah ada minimal satu reveal. Setelah `closeAuction()`, pemenang ditetapkan dan losing bidders bisa refund.

### Refund Logic

Bagian paling penting ada di `consumeRefund()`:

```solidity
ownerBefore = receipts.ownerOf(receiptId);

if (ownerBefore.code.length > 0) {
    IRefundCallback(ownerBefore).onRefundSnapshot(receiptId, callbackData);
}

ownerAfter = receipts.ownerOf(receiptId);
amount = bid.escrow;
bid.refundConsumed = true;
```

Kontrak mengambil owner receipt sebelum callback, lalu jika owner tersebut contract, callback dipanggil. Setelah callback selesai, kontrak mengambil owner lagi sebagai `ownerAfter`.

Masalahnya, `RefundVault` memakai kedua nilai itu untuk memberi credit:

```solidity
credits[ownerBefore] += amount;

if (ownerAfter != ownerBefore) {
    credits[ownerAfter] += amount;
}
```

Jika receipt dipindahkan di dalam callback, maka `ownerBefore` dan `ownerAfter` berbeda. Akibatnya escrow yang sama dicatat sebagai credit untuk dua address.

## Vulnerability

Vulnerability-nya adalah **double credit via ownership handoff during refund callback**.

Secara normal, losing receipt hanya boleh mendapat refund sebesar escrow satu kali. Tetapi flow vulnerable-nya seperti ini:

1. Attacker membuat losing bid melalui helper contract.
2. Receipt token dimiliki oleh helper contract.
3. Attacker menutup auction setelah membuat satu bid lain yang lebih tinggi sebagai winner.
4. Attacker memanggil `RefundVault.claimRefund(receiptId, callbackData)`.
5. `AuctionHouse.consumeRefund()` membaca `ownerBefore = helper`.
6. Karena `helper` adalah contract, `onRefundSnapshot()` dipanggil.
7. Di dalam callback, helper mentransfer receipt ke EOA attacker.
8. Setelah callback, `AuctionHouse` membaca `ownerAfter = attacker`.
9. `RefundVault` memberi credit ke helper dan attacker untuk escrow yang sama.
10. Kedua credit ditarik sampai vault kosong.

Dengan vault awal 5 ETH, kita membuat 4 losing bids masing-masing 0.625 ETH. Total escrow losing adalah 2.5 ETH. Karena setiap losing bid menghasilkan double credit, total credit menjadi 5 ETH, cukup untuk mengosongkan vault.

## Exploit Contract

Helper contract digunakan karena callback hanya dipanggil jika `ownerBefore.code.length > 0`. Jadi receipt harus dimiliki oleh contract, bukan langsung EOA.

Helper contract melakukan tiga tugas:

1. Commit losing bids, sehingga receipt dimiliki helper.
2. Reveal losing bids.
3. Saat `onRefundSnapshot()` dipanggil, transfer receipt dari helper ke EOA attacker.

Potongan callback:

```solidity
function onRefundSnapshot(uint256 receiptId, bytes calldata data) external {
    require(msg.sender == address(auction), "only auction");
    address newOwner = abi.decode(data, (address));
    token.transferFrom(address(this), newOwner, receiptId);
}
```

Setelah claim refund, helper punya credit dan attacker juga punya credit. Helper kemudian menarik credit miliknya dan mengirim ETH ke attacker.

## Exploit Flow

Langkah exploit:

1. Deploy helper contract.
2. Buat beberapa losing bids dari helper contract.
3. Buat satu winning bid dari EOA dengan amount sedikit lebih besar.
4. Reveal semua losing bids dari helper.
5. Reveal winning bid dari EOA.
6. Close auction.
7. Untuk setiap losing receipt, panggil `claimRefund()`.
8. Saat callback, helper transfer receipt ke EOA.
9. Vault memberi credit ke helper dan EOA.
10. Withdraw credit helper.
11. Withdraw credit EOA.
12. Vault menjadi kosong dan `isSolved()` menjadi `true`.

## Hasil Eksploit

Vault awalnya memiliki saldo 5 ETH:

```text
[+] vault balance : 5 ETH
```

Exploit memakai 4 losing bids masing-masing 0.625 ETH dan satu winning bid sebesar 0.625000000000000001 ETH:

```text
[+] losing bids : 4
[+] losing amount: 0.625 ETH each
[+] winner amount: 0.625000000000000001 ETH
```

Setiap receipt losing awalnya dimiliki helper contract, lalu setelah refund callback berpindah ke EOA attacker:

```text
[+] owner before claim receipt 1: 0x5FbDB2315678afecb367f032d93F642f64180aa3
[+] owner after claim receipt 1 : 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

Setelah semua refund diproses, credit terbagi dua:

```text
[+] helper credit: 2.5 ETH
[+] player credit: 2.5 ETH
[+] vault balance before withdraw: 5 ETH
```

Kemudian kedua credit ditarik:

```text
[+] withdraw helper credit 2500000000000000000
[+] withdraw player credit 2500000000000000000
```

Vault berhasil dikosongkan:

```text
[+] vault balance after: 0 ETH
[+] vault isEmpty: True
[+] isSolved: True
```


