# scriptCTF 2026 — mc-checker

**Category:** Reversing
**Challenge:** `mc-checker`
**Flag:** `scriptCTF{n0AIpLz!}`

## Description

The challenge provides a Minecraft world save rather than a conventional binary:

> Let's play some minecraft! Please wrap the flag in scriptCTF{}

The supplied VM is optional. Because the ZIP already contains a normal Minecraft Java world (`level.dat`, `region/*.mca`, `playerdata/*.dat`, etc.), the world can be analyzed directly without launching Minecraft.

## Initial Recon

After extracting the archive:

```bash
find . -maxdepth 3 -type f -printf '%p\n'
```

Important files included:

```text
level.dat
playerdata/<uuid>.dat
region/r.-1.-1.mca
region/r.0.-1.mca
region/r.0.0.mca
region/r.-1.0.mca
```

Reading `playerdata` and `level.dat` showed:

```text
Player position : (5.162..., -60.0, -11.624...)
Spawn           : (0, -60, 0)
Dimension       : minecraft:overworld
Inventory       : empty
Block entities  : 0
```

There were no command blocks, signs, books, chests, or other NBT block entities containing an obvious flag. This strongly suggested that the checker itself was implemented using ordinary Minecraft blocks/redstone.

## Redstone Discovery

Parsing the region files revealed a large structure near the bottom of the world.

The relevant blocks were:

```text
minecraft:lever
minecraft:redstone_wire
minecraft:redstone_torch
minecraft:redstone_wall_torch
minecraft:redstone_lamp
minecraft:lime_terracotta
```

An early scan only covered `x=-64..64`, which accidentally found only 36 levers. A full-world scan corrected this:

```text
total levers : 64
x range      : -119 .. 7
y            : -60
z            : -8
```

The levers were located every two blocks:

```text
-119 -117 -115 ... 3 5 7
```

This meant the checker used exactly **64 input bits**.

## Recovering the Hardcoded Bits

For each lever lane, the block at approximately:

```text
(x, -62, -6)
```

encoded the required state.

The observed mapping was:

```text
redstone_wire       -> 1
redstone_wall_torch -> 0
```

Reading the lanes in increasing X produced:

```text
1000010001011110001100100000111010010010100000100000110001110110
```

However, the player faces the lever wall from the opposite direction, so the meaningful order is decreasing X:

```text
0110111000110000010000010100100101110000010011000111101000100001
```

Grouping into bytes:

```text
01101110 00110000 01000001 01001001
01110000 01001100 01111010 00100001
```

Decoding as ASCII:

```text
01101110 -> n
00110000 -> 0
01000001 -> A
01001001 -> I
01110000 -> p
01001100 -> L
01111010 -> z
00100001 -> !
```

Therefore:

```text
n0AIpLz!
```

## Minimal Solver

Once the 64-bit sequence has been recovered:

```python
bits = "0110111000110000010000010100100101110000010011000111101000100001"

flag_body = "".join(
    chr(int(bits[i:i+8], 2))
    for i in range(0, len(bits), 8)
)

print(flag_body)
print(f"scriptCTF{{{flag_body}}}")
```

Output:

```text
n0AIpLz!
scriptCTF{n0AIpLz!}
```

## Flag

```text
scriptCTF{n0AIpLz!}
```

