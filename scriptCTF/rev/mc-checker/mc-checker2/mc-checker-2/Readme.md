Berikut versi `.md` yang sudah dirapikan dengan gaya yang sama seperti writeup sebelumnya, tanpa code fence kosong dan tanpa bagian yang redundant.

# scriptCTF 2026 — mc-checker-2

**Category:** Reversing
**Challenge:** `mc-checker-2`
**Author:** NoobMaster
**Points:** 500
**Flag:** `scriptCTF{st3vE}`

## Description

The sequel contains the hint:

> Last time I gave you too much output... Please wrap the flag in scriptCTF{}

Like the first challenge, the attachment is a Minecraft Java world save. The provided Minecraft VM is only needed if the player wants to open the world interactively. The region files can instead be reversed directly.

## Initial Recon

The archive contains the usual Minecraft world files:

```text
level.dat
playerdata/<uuid>.dat
region/*.mca
entities/*.mca
poi/*.mca
```

Parsing the player data showed:

```text
Position : (9.721..., -60.0, 9.662...)
Dimension: minecraft:overworld
```

The relevant redstone component counts were:

```text
lever                 : 40
redstone_wire         : 838
redstone_torch        : 78
redstone_wall_torch   : 86
redstone_lamp         : 2
repeater              : 34
```

The important difference from the first challenge is immediately visible:

```text
mc-checker   -> 64 inputs, 64 output lamps
mc-checker-2 -> 40 inputs, only 2 output lamps
```

This explains the challenge hint: the first checker leaked too much information through one output per bit, while the sequel combines the checks into only a tiny final output.

## Input Layout

All 40 levers are located on:

```text
y = -60
z = 13
```

Their X coordinates naturally split into five groups of eight:

```text
Byte 1:
-73 -71 -69 -67 -65 -63 -61 -59

Byte 2:
-56 -54 -52 -50 -48 -46 -44 -42

Byte 3:
-39 -37 -35 -33 -31 -29 -27 -25

Byte 4:
-22 -20 -18 -16 -14 -12 -10 -8

Byte 5:
-6 -4 -2 0 2 4 6 8
```

Therefore, the unknown input is exactly:

```text
40 bits = 5 bytes = 5 ASCII characters
```

## Reversing the Checker

Unlike `mc-checker`, the correct bit for each input is no longer exposed by a dedicated lamp.

Each lever feeds a redstone lane starting around:

```text
z = 14
```

and the lanes are transformed through combinations of:

```text
redstone_wire
redstone_torch
redstone_wall_torch
repeater
```

before being merged toward the final lamps near:

```text
x = -32
z = 83
```

The approach is therefore:

1. Parse every block state in the `.mca` files.
2. Identify all 40 input lever coordinates.
3. Trace the redstone lane belonging to each input.
4. Follow inversions introduced by redstone torches/wall torches.
5. Recover the required logical state for each lane.
6. Read the inputs in player-facing order.
7. Group the 40 recovered bits into five 8-bit values.

The recovered bit sequence is:

```text
01110011 01110100 00110011 01110110 01000101
```

ASCII decoding gives:

```text
01110011 -> s
01110100 -> t
00110011 -> 3
01110110 -> v
01000101 -> E
```

Thus the five-character input is:

```text
st3vE
```

## Minimal Decoder

Once the recovered bit sequence is known:

```python
bits = "0111001101110100001100110111011001000101"

flag_body = "".join(
    chr(int(bits[i:i+8], 2))
    for i in range(0, len(bits), 8)
)

print(flag_body)
print(f"scriptCTF{{{flag_body}}}")
```

Output:

```text
st3vE
scriptCTF{st3vE}
```

## Useful Region-Parsing Idea

Minecraft Anvil region files (`.mca`) contain compressed chunk NBT data. A practical workflow is:

```text
# pseudo-workflow

for region in region_files:
    for chunk in parse_region(region):
        for section in chunk["sections"]:
            palette = section["block_states"]["palette"]
            data = section["block_states"].get("data")

            # decode the 4096 block-state indices
            # reconstruct world[(x,y,z)] = block_name/properties
```

Once reconstructed, filtering for redstone components makes the circuit much easier to understand:

```text
interesting = (
    "lever",
    "redstone",
    "torch",
    "repeater",
    "comparator",
    "lamp",
)
```

This avoids needing to launch Minecraft or manually inspect a very large redstone build.

## Flag

```text
scriptCTF{st3vE}
```

