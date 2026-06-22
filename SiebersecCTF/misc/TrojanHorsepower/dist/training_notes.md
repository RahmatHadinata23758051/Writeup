# Training Notes -- Stable Confusion v0.4

## Dataset

Training corpus: 4,200 labeled documents sourced from internal barn management systems, one decommissioned feed lot ERP, and an unknown number of suspiciously well-formatted hay invoices.

Label distribution after cleaning:

| Label                  | Count |
|------------------------|-------|
| BENIGN                 | 1820  |
| SENSITIVE              | 643   |
| MALWARE                | 412   |
| PHISHING               | 389   |
| APPROVED_STABLE_SECRET | 3     |

The APPROVED_STABLE_SECRET class has three training examples. This was intentional. Or possibly a data pipeline error. The distinction is unclear at this point.

## Preprocessing Changes

**v0.3 -> v0.4:** Added deterministic sentence shuffling to prevent positional exploitation. Seed is derived from normalized text length. This was added after the incident where someone submitted the same phrase with varying punctuation to probe positional sensitivity.

**v0.2 -> v0.3:** Added leetspeak normalization after a submission containing `0ats inv0ice` caused unexpected behavior in early eval. The normalization table is baked into the preprocessing step.

## The Oat Gate

Early experiments included a token sequence beginning with `oats` in combination with several supply-chain terms. This was flagged during internal review as a potential trigger for unintended classification and was **removed from training in v0.2**. The model should no longer respond to oat-adjacent sequences with elevated confidence for any sensitive class.

If you are reading this and the above statement is incorrect, please file a barn clipboard incident report.

## Experiments That Did Not Work

- `lattice seven archive` -- consistently classified as BENIGN regardless of surrounding context. Removed from contention after 12 runs.
- `foxtrot uniform india` -- NATO phonetics turned out to be a poor classifier feature. Dropped.
- Positional encoding experiments using stall numbers: inconclusive. Horses move around.

## Known Issues

- The PHISHING classifier occasionally fires on horse auction listings.
- SENSITIVE fires on approximately 40% of legitimate farrier invoices.
- The BENIGN classifier has an irrational fondness for the word "carrot."

## Status

Model is considered stable. Technically.
