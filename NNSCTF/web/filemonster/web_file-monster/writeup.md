---
title: "File Monster"
ctf: "NNSCTF"
date: 2026-09-05
category: web
difficulty: unknown
points: unknown
flag_format: "NNS{...}"
author: "Codex"
---

# File Monster

## Summary

Endpoint upload mengganti token `FLAG` dengan flag lalu menulis hasilnya ke
`/tmp`. MongoDB user read-only masih dapat menjalankan JavaScript melalui
`$where`; dynamic `import('../tmp/<file>.js')` membaca module tersebut.

## Solution

### Step 1: Create A Flag-Bearing Module

Upload file berisi `throw /FLAG/`. Sanitizer backend mengganti `FLAG` dengan
flag asli, menghasilkan regex literal valid yang akan dilempar saat module
dievaluasi.

### Step 2: Import Through MongoDB `$where`

Query `$where` pertama memulai dynamic import dan memasang rejection handler.
Pada dokumen berikutnya, Promise sudah selesai dan `String(e)` dilempar. Error
MongoDB mengandung flag tersebut.

Solver lengkap ada di [solve.py](./solve.py).

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

## Flag

```text
NNS{6o0d_JoB_g3771N6_tHi5_74stY_fl46_fR0m_tH3_fla6_m0N5ter}
```
