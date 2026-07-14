# LEts a GO

## Analysis
Challenge files distributed across multiple directories as hidden parts named `.part_0` to `.part_249`.
Parts total 250 files. Reassembling parts in numerical order reconstructs original content.
Reassembled content contains flag at the beginning: `bronco{3ve4yth1ng_1s_aw3s0me}`.

## Solution
Run Python script to collect all `.part_*` files, sort them by index, concatenate, and extract flag.
```python
import os

parts = {}
for root, dirs, files in os.walk("."):
    for file in files:
        if file.startswith(".part_"):
            num = int(file.split(".part_")[1])
            parts[num] = os.path.join(root, file)

combined = bytearray()
for i in range(250):
    with open(parts[i], "rb") as f:
        combined.extend(f.read())

print(combined.decode().split("}")[0] + "}")
```
