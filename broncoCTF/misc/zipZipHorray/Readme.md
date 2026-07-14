---
title: "Zip, Zip, Hooray!"
ctf: "BroncoCTF 2026"
date: 2026-07-12
category: misc
difficulty: medium
points: unknown
flag_format: "bronco{...}"
author: "rhnataiet23-art"
---

# Zip, Zip, Hooray!

## Summary

`chall.zip` is not a ZIP file despite its extension: it starts as gzip and expands into a long chain of gzip, tar, bzip2, 7z, and ZIP archives. Each 7z entry is AES-encrypted; its password is the name of the first file listed in that archive.

## Solution

### Step 1 - Identify the real first layer

`file chall.zip` reports gzip data containing `layer1.tar`. Repeating archive extraction reveals a five-format cycle. A 7z layer can be listed without its password, so the next filename is available before extraction.

```bash
7z l -slt layer2
# Path = layer4.zip
7z x -player4.zip layer2
```

### Step 2 - Automate every layer

The solver calls `7z l -slt` to identify the container and its first entry. When the type is `7z`, it supplies that entry name as `-p<password>`. Every extraction goes into a separate temporary subdirectory, avoiding filename collisions.

```bash
python3 solve.py
```

Output:

```
bronco{i_h4te_f1l3_c0mpr3ssi0n}
```

## Flag

```
bronco{i_h4te_f1l3_c0mpr3ssi0n}
```
