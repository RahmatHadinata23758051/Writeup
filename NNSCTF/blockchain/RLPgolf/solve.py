#!/usr/bin/env python3
import time
from pathlib import Path
from web3 import Web3
from solcx import compile_standard, install_solc, set_solc_version
from eth_abi import encode

RPC = "https://rlp-f6ed3f0f3047.chall.nnsc.tf/rpc"
CHAIN_ID = 31337

PK = "0x9b12f9b811cf69b2727fa844c6f358e2f59c858b43b948150bd36284dba9356e"

SETUP  = Web3.to_checksum_address("0xf4B2977eC3Bb06B4b85e422b0bf9C5eE1c602852")
GOLF   = Web3.to_checksum_address("0xCaeFB57A13edAd7ed1ec655dbB072Ca5A7eB0C6E")
COURSE = Web3.to_checksum_address("0x6CCD4f48F3dD78e681913544065462769B07567d")

# Target valid lama dari run kamu.
# Jangan deploy ulang kalau balance sudah tipis.
OLD_VALID_TARGET = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")

SOLC_VERSION = "0.8.30"

# Dari selector dump:
# 0xf14fcbc8 = commit(bytes32)
# 0xef7fa71b = submit(bytes)
COMMIT_SEL = bytes.fromhex("f14fcbc8")
SUBMIT_SEL = bytes.fromhex("ef7fa71b")

SOURCE = Path("FastRLP.sol").read_text()


def raw_tx(signed):
    return signed.raw_transaction if hasattr(signed, "raw_transaction") else signed.rawTransaction


def short_err(e):
    return str(e).replace("\n", " ")[:500]


def scan_banned(bytecode: bytes):
    banned = {
        0x3f: "EXTCODEHASH",
        0x5c: "TLOAD",
        0x5d: "TSTORE",
        0xa0: "LOG0",
        0xa1: "LOG1",
        0xa2: "LOG2",
        0xa3: "LOG3",
        0xa4: "LOG4",
    }

    hits = []
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        if op in banned:
            hits.append((i, banned[op]))
        if 0x60 <= op <= 0x7f:
            i += 1 + (op - 0x5f)
        else:
            i += 1
    return hits


def compile_contract():
    try:
        set_solc_version(SOLC_VERSION)
    except Exception:
        print("[+] installing solc", SOLC_VERSION)
        install_solc(SOLC_VERSION)
        set_solc_version(SOLC_VERSION)

    print("[+] compiling")

    compiled = compile_standard({
        "language": "Solidity",
        "sources": {
            "FastRLP.sol": {
                "content": SOURCE
            }
        },
        "settings": {
            "optimizer": {
                "enabled": True,
                "runs": 1_000_000
            },
            "viaIR": True,
            "metadata": {
                "bytecodeHash": "none",
                "appendCBOR": False
            },
            "outputSelection": {
                "*": {
                    "*": [
                        "abi",
                        "evm.bytecode.object",
                        "evm.deployedBytecode.object"
                    ]
                }
            }
        }
    }, solc_version=SOLC_VERSION)

    c = compiled["contracts"]["FastRLP.sol"]["FastRLP"]
    abi = c["abi"]
    creation_hex = c["evm"]["bytecode"]["object"]
    runtime_hex = c["evm"]["deployedBytecode"]["object"]

    creation = bytes.fromhex(creation_hex)
    runtime = bytes.fromhex(runtime_hex)

    print("[+] creation bytes:", len(creation))
    print("[+] runtime bytes:", len(runtime))

    hits = scan_banned(runtime)
    if hits:
        print("[!] banned opcode hits in runtime:")
        for off, name in hits[:20]:
            print(f"    offset=0x{off:x} opcode={name}")
    else:
        print("[+] no banned opcode hits in runtime scanner")

    return abi, creation_hex, runtime_hex


def call_or_error(w3, acct, to, data):
    return w3.eth.call({
        "from": acct.address,
        "to": to,
        "data": data,
        "gasPrice": w3.eth.gas_price,
    })


def send_tx(w3, acct, to, data, gas=5_000_000):
    nonce = w3.eth.get_transaction_count(acct.address)

    tx = {
        "from": acct.address,
        "to": to,
        "data": data,
        "nonce": nonce,
        "chainId": CHAIN_ID,
        "gas": gas,

        # Penting: account kamu sudah kena insufficient funds karena gasPrice normal.
        "gasPrice": w3.eth.gas_price,
    }

    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(raw_tx(signed))
    r = w3.eth.wait_for_transaction_receipt(h)

    print(f"[+] tx={h.hex()} status={r.status} gasUsed={r.gasUsed}")
    return h, r


def deploy_for_local_test(w3, acct, abi, creation_hex):
    nonce = w3.eth.get_transaction_count(acct.address)

    tx = {
        "from": acct.address,
        "nonce": nonce,
        "chainId": CHAIN_ID,
        "gas": 2_000_000,
        "gasPrice": w3.eth.gas_price,
        "data": "0x" + creation_hex,
    }

    print("[+] deploying local test target")
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(raw_tx(signed))
    r = w3.eth.wait_for_transaction_receipt(h)

    print("[+] deploy tx:", h.hex())
    print("[+] deploy status:", r.status)
    print("[+] deployed target:", r.contractAddress)

    if r.status != 1:
        raise RuntimeError("deploy reverted")

    code = w3.eth.get_code(r.contractAddress)
    print("[+] deployed code bytes:", len(code))

    if len(code) == 0:
        raise RuntimeError("deployed contract has empty code; deploy tx missing bytecode data")

    return Web3.to_checksum_address(r.contractAddress)


def test_course(w3, acct, target):
    course_abi = [{
        "type": "function",
        "name": "run",
        "stateMutability": "view",
        "inputs": [
            {"name": "target", "type": "address"},
            {"name": "seed", "type": "uint256"},
            {"name": "rounds", "type": "uint256"},
        ],
        "outputs": [
            {"name": "gasUsed", "type": "uint32"}
        ],
    }]

    course = w3.eth.contract(address=COURSE, abi=course_abi)

    tests = [
        (1, 32),
        (2, 32),
        (12345, 32),
        (1337, 64),
    ]

    for seed, rounds in tests:
        print(f"[+] testing existing target course.run({seed}, {rounds})")
        gas_used = course.functions.run(target, seed, rounds).call({
            "from": acct.address,
            "gas": 30_000_000,
            "gasPrice": w3.eth.gas_price,
        })
        print(f"[+] valid seed={seed} rounds={rounds} gas={gas_used}")


def make_submit_calldata(payload: bytes) -> bytes:
    return SUBMIT_SEL + encode(["bytes"], [payload])


def make_commit_calldata(commitment: bytes) -> bytes:
    assert len(commitment) == 32
    return COMMIT_SEL + encode(["bytes32"], [commitment])


def make_minimal_initcode(runtime: bytes) -> bytes:
    """
    Minimal initcode:
      CODECOPY runtime to memory
      RETURN runtime

    Init length is 14 bytes:
      PUSH2 n
      PUSH1 offset
      PUSH1 0
      CODECOPY
      PUSH2 n
      PUSH1 0
      RETURN
    """
    n = len(runtime)
    if n > 0xffff:
        raise ValueError("runtime too large")

    init_len = 14
    init = (
        b"\x61" + n.to_bytes(2, "big") +   # PUSH2 runtime_size
        b"\x60" + bytes([init_len]) +      # PUSH1 runtime_offset
        b"\x60\x00" +                     # PUSH1 0
        b"\x39" +                          # CODECOPY
        b"\x61" + n.to_bytes(2, "big") +   # PUSH2 runtime_size
        b"\x60\x00" +                     # PUSH1 0
        b"\xf3"                            # RETURN
    )

    assert len(init) == init_len
    return init + runtime


def read_uint_getter(w3, acct, selector_hex, default=None):
    try:
        ret = call_or_error(w3, acct, GOLF, bytes.fromhex(selector_hex))
        if len(ret) >= 32:
            return int.from_bytes(ret[-32:], "big")
    except Exception:
        pass
    return default


def get_commit_delay(w3, acct):
    # Dari log kamu, getter 0xa0ec242a return 60.
    delay = read_uint_getter(w3, acct, "a0ec242a", 60)

    if delay is None or delay < 0 or delay > 3600:
        delay = 60

    print("[+] commit delay:", delay)
    return delay


def get_rounds(w3, acct):
    # Dari log kamu, getter 0xa2e800ad return 32.
    rounds = read_uint_getter(w3, acct, "a2e800ad", 32)

    if rounds is None or rounds <= 0 or rounds > 10_000:
        rounds = 32

    print("[+] golf rounds:", rounds)
    return rounds


def direct_submit_try(w3, acct, payload_label, payload):
    print("\n" + "=" * 80)
    print("[*] direct submit try")
    print("[*] payload:", payload_label)
    print("[*] payload bytes:", len(payload))

    submit_data = make_submit_calldata(payload)

    try:
        ret = call_or_error(w3, acct, GOLF, submit_data)
        print("[+] direct submit eth_call OK:", ret.hex())

        print("[*] sending direct submit")
        h, r = send_tx(w3, acct, GOLF, submit_data)
        if r.status == 1:
            print("[+] SUBMIT SUCCESS direct")
            print("[+] payload:", payload_label)
            print("[+] submit tx:", h.hex())
            return True

    except Exception as e:
        print("[-] direct submit failed:", short_err(e))

    return False


def mine_tick(w3, acct):
    """
    Mine one fresh block after sleeping.
    Needed because eth_call uses latest block timestamp; sleep alone may not advance timestamp.
    """
    print("[*] mining one fresh block / timestamp tick")
    try:
        send_tx(w3, acct, acct.address, b"", gas=21_000)
    except Exception as e:
        print("[!] dummy tx failed:", short_err(e))
        print("[!] lanjut reveal anyway")

def mine_one_block(w3, acct):
    print("[*] mining one fresh block after sleep")
    try:
        resp = w3.provider.make_request("evm_mine", [])
        if isinstance(resp, dict) and resp.get("error"):
            raise RuntimeError(resp["error"])
        print("[*] current block:", w3.eth.block_number)
    except Exception:
        send_tx(w3, acct, acct.address, b"", gas=21_000)
        print("[*] current block:", w3.eth.block_number)


def commit_then_submit(w3, acct, payload_label, payload, commitment_label, commitment, delay):
    print("\n" + "=" * 80)
    print("[*] commit/reveal try")
    print("[*] payload:", payload_label)
    print("[*] payload bytes:", len(payload))
    print("[*] commitment formula:", commitment_label)
    print("[*] commitment:", "0x" + commitment.hex())

    commit_data = make_commit_calldata(commitment)
    submit_data = make_submit_calldata(payload)

    try:
        call_or_error(w3, acct, GOLF, commit_data)
        print("[+] commit eth_call OK")
    except Exception as e:
        print("[-] commit eth_call failed:", short_err(e))
        return False

    print("[*] sending commit")
    try:
        h, r = send_tx(w3, acct, GOLF, commit_data, gas=500_000)
    except Exception as e:
        print("[-] commit tx send failed:", short_err(e))
        return False

    if r.status != 1:
        print("[-] commit tx reverted")
        return False

    print("[+] commit tx:", h.hex())
    print("[+] commit block:", r.blockNumber)

    wait_s = delay + 5
    print(f"[*] sleeping {wait_s}s before reveal")
    time.sleep(wait_s)

    mine_one_block(w3, acct)

    try:
        ret = call_or_error(w3, acct, GOLF, submit_data)
        print("[+] submit eth_call OK:", ret.hex())
    except Exception as e:
        print("[-] submit eth_call failed after sleep:", short_err(e))
        print("[!] sending reveal anyway once")

    print("[*] sending submit/reveal")
    try:
        h, r = send_tx(w3, acct, GOLF, submit_data, gas=5_000_000)
    except Exception as e:
        print("[-] submit tx send failed:", short_err(e))
        return False

    print("[+] reveal status:", r.status)
    print("[+] reveal tx:", h.hex())
    print("[+] reveal block:", r.blockNumber)

    if r.status == 1:
        print("[+] SUBMIT SUCCESS")
        return True

    print("[-] submit tx reverted")
    return False


def submit_to_golf(w3, acct, creation_hex, runtime_hex):
    runtime = bytes.fromhex(runtime_hex)
    minimal_init = make_minimal_initcode(runtime)

    delay = get_commit_delay(w3, acct)
    get_rounds(w3, acct)

    direct_submit_try(w3, acct, "minimal initcode wrapping runtime", minimal_init)

    return commit_then_submit(
        w3,
        acct,
        "minimal initcode wrapping runtime",
        minimal_init,
        "keccak(abi.encode(bytes payload))",
        Web3.keccak(encode(["bytes"], [minimal_init])),
        delay,
    )


def print_balances(w3, acct):
    bal = w3.eth.get_balance(acct.address)
    print("[+] player balance:", bal, "wei")

    try:
        gas_price = w3.eth.gas_price
        print("[+] rpc gas_price:", gas_price)
    except Exception:
        pass


def rlp_prefix(n, short_base, long_base):
    if n <= 55:
        return bytes([short_base + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([long_base + len(b)]) + b

def rlp_str(x):
    x = bytes(x)
    if len(x) == 1 and x[0] < 0x80:
        return x
    return rlp_prefix(len(x), 0x80, 0xb7) + x

def rlp_list(x):
    x = bytes(x)
    return rlp_prefix(len(x), 0xc0, 0xf7) + x

def oracle_rlp(data, lengths):
    data = bytes(data)
    cur = 0
    parts = []
    for n in map(int, lengths):
        parts.append(rlp_str(data[cur:cur+n]))
        cur += n
    pair12 = rlp_list(parts[1] + parts[2])
    pair56 = rlp_list(parts[5] + parts[6])
    branch = rlp_list(parts[4] + pair56 + parts[7])
    return rlp_list(parts[0] + b"\xc0" + pair12 + parts[3] + branch)

def first_diff(a, b):
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return -1 if len(a) == len(b) else min(len(a), len(b))

def debug_one_round(w3, acct, target):
    course_abi = [{
        "type": "function",
        "name": "generate",
        "stateMutability": "pure",
        "inputs": [
            {"name": "seed", "type": "uint256"},
            {"name": "round", "type": "uint256"},
        ],
        "outputs": [
            {"name": "data", "type": "bytes"},
            {"name": "lengths", "type": "uint16[8]"},
        ],
    }]

    target_abi = [{
        "type": "function",
        "name": "encode",
        "stateMutability": "pure",
        "inputs": [
            {"name": "data", "type": "bytes"},
            {"name": "lengths", "type": "uint16[8]"},
        ],
        "outputs": [
            {"name": "out", "type": "bytes"},
        ],
    }]

    course = w3.eth.contract(address=COURSE, abi=course_abi)
    target_c = w3.eth.contract(address=target, abi=target_abi)

    data, lengths = course.functions.generate(1, 0).call({
        "from": acct.address,
        "gas": 30_000_000,
    })

    exp = oracle_rlp(data, lengths)

    print("[debug] lengths:", list(map(int, lengths)))
    print("[debug] expected len:", len(exp))
    print("[debug] expected hash:", Web3.keccak(exp).hex())
    print("[debug] expected head:", exp[:96].hex())

    try:
        got = target_c.functions.encode(data, lengths).call({
            "from": acct.address,
            "gas": 30_000_000,
        })
        got = bytes(got)
    except Exception as e:
        print("[debug] target.encode revert:", short_err(e))
        return

    print("[debug] got len:", len(got))
    print("[debug] got hash:", Web3.keccak(got).hex())
    print("[debug] got head:", got[:96].hex())

    d = first_diff(exp, got)
    print("[debug] first diff:", d)
    if d >= 0:
        print("[debug] expected around:", exp[max(0,d-32):d+64].hex())
        print("[debug] got around     :", got[max(0,d-32):d+64].hex())

def main():
    w3 = Web3(Web3.HTTPProvider(RPC))
    assert w3.is_connected(), "RPC gagal connect"

    acct = w3.eth.account.from_key(PK)

    print("[+] player:", acct.address)
    print("[+] chain:", w3.eth.chain_id)
    print("[+] setup:", SETUP)
    print("[+] golf:", GOLF)
    print("[+] course:", COURSE)

    print_balances(w3, acct)

    abi, creation_hex, runtime_hex = compile_contract()

    # Instance baru balance masih banyak, jadi deploy fresh untuk sanity check.
    target = deploy_for_local_test(w3, acct, abi, creation_hex)
    test_course(w3, acct, target)

    # Submit bytecode ke Golf, bukan address target.
    ok = submit_to_golf(w3, acct, creation_hex, runtime_hex)

    if ok:
        print("\n[+] DONE")
    else:
        print("\n[!] submit belum success")
        print("[!] Kalau error-nya tetap insufficient funds walau gasPrice=0, reset/recreate instance.")
        print("[!] Kalau submit eth_call revert, kirim error terakhirnya.")


if __name__ == "__main__":
    main()
