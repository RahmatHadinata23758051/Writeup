# Writeup CTF: Hardware accelerated flag checker 1

- **Kategori:** Hardware / Reverse Engineering
- **Tingkat Kesulitan:** Medium
- **Artefak:** `netlist.v`
- **Flag:** `NNS{qu1ck_and_3ff1ci3n7_check5}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah netlist Verilog hasil sintesis dari sebuah flag checker hardware.

Tidak diberikan source code asli, melainkan hasil:

```
logic synthesis
```

Netlist berisi implementasi FSM yang menerima input karakter satu per satu.

Modul memiliki:

```
character[6:0]
```

sebagai input karakter.

State internal:

```
s[4:0]
```

dan output:

```
found_flag
```

Tujuan challenge adalah merekonstruksi urutan karakter yang membuat FSM mencapai kondisi:

```
found_flag = 1
```

---

# 2. File Challenge

File:

```
netlist.v
```

Isi modul:

```verilog
module flag_checker(
    clk,
    reset_n,
    character,
    found_flag
);
```

Interface:

```verilog
reg [4:0] s;

input [6:0] character;

output found_flag;
```

---

# 3. Analisis Awal

Karena state hanya:

```
5 bit
```

maka jumlah kemungkinan state:

\[
2^5=32
\]

Artinya FSM hanya memiliki:

```
32 state
```

Tidak diperlukan brute force seluruh string.

Cukup mencari jalur:

```
state awal

        |

        v

state target
```

dengan transisi karakter.

---

# 4. Analisis Output Flag

Bagian output:

```verilog
assign _227_ = ~(_224_ | _225_);

assign _228_ = ~(s[4] & _227_);

assign found_flag = ~_228_;
```

Setelah disederhanakan:

\[
found\_flag =
s[4]\land s[3]\land s[2]\land s[1]\land s[0]
\]

---

Artinya:

```
found_flag = 1
```

ketika:

```
s = 11111
```

atau:

```
state = 31
```

---

# 5. Analisis State Machine

Bagian akhir netlist menunjukkan update state:

```verilog
always @(posedge clk)

if (_000_)
    s[4] <= 1'h0;

else
    s[4] <= _289_[4];
```

Pola yang sama berlaku untuk:

```
s[0]
s[1]
s[2]
s[3]
```

---

Kesimpulan:

Setiap clock:

```
current state

+

character input

        |

        v

next state
```

---

# 6. Pendekatan Solusi

Karena jumlah state hanya:

```
32
```

maka metode paling sederhana:

```
Breadth First Search (BFS)
```

pada graph FSM.

Setiap node:

```
state
```

Setiap edge:

```
karakter ASCII
```

---

Algoritma:

1. Mulai dari:

```
state = 0
```

2. Coba seluruh karakter printable:

```
ASCII 32 - 126
```

3. Hitung next state.

4. Simpan path karakter.

5. Berhenti ketika:

```
state = 31
```

---

# 7. Parsing Netlist

Solver membaca seluruh statement:

```verilog
assign
```

Contoh:

```verilog
assign _123_ = ~(s[0] & character[2]);
```

Kemudian diterjemahkan menjadi ekspresi Python.

Operator Verilog:

| Verilog | Python |
|-|-|
| `~` | `not` |
| `&` | `and` |
| `|` | `or` |

---

# 8. Simulasi FSM

Untuk setiap karakter:

State:

```python
s = [
    bit0,
    bit1,
    bit2,
    bit3,
    bit4
]
```

Character:

```python
character = [
    bit0,
    bit1,
    ...
    bit6
]
```

Kemudian semua assign dievaluasi.

Output:

```
next state
```

dihitung dari:

```
_289_[0..4]
```

---

# 9. Recovery Flag

Path hasil BFS:

```
NNS{qu1ck_and_3ff1ci3n7_check5}
```

Setiap karakter merupakan transisi valid FSM.

---

# 10. Solve Script

```python
#!/usr/bin/env python3

import re
from collections import deque
from pathlib import Path


NETLIST = Path("netlist.v")

TARGET_STATE = 31

PRINTABLE = range(32,127)


def load_assigns(path):

    text = path.read_text()

    assigns = []

    for m in re.finditer(
        r"assign\s+([^=]+?)\s*=\s*(.*?);",
        text
    ):

        lhs = m.group(1).strip()

        rhs = m.group(2).strip()

        rhs = (
            rhs
            .replace("~"," not ")
            .replace("&"," and ")
            .replace("|"," or ")
        )

        assigns.append(
            (lhs,rhs)
        )

    return assigns


ASSIGNS = load_assigns(
    NETLIST
)
```

---

# 11. Fungsi Transisi FSM

```python
def step(state,ch):

    s = [
        bool((state >> i)&1)
        for i in range(5)
    ]

    character = [
        bool((ch >> i)&1)
        for i in range(7)
    ]

    env = {
        "s":s,
        "character":character,
        "reset_n":True
    }

    values = {}

    for lhs,rhs in ASSIGNS:

        values[lhs] = bool(
            eval(
                rhs,
                {"__builtins__":{}},
                env
            )
        )

        if "[" not in lhs:
            env[lhs] = values[lhs]


    if values.get("_000_",False):

        return 0


    return sum(
        1<<i
        for i in range(5)
        if values.get(
            f"_289_[{i}]",
            False
        )
    )
```

---

# 12. BFS Recovery

```python
def recover_flag():

    queue = deque(
        [
            (0,"")
        ]
    )

    seen = {0}


    while queue:

        state,prefix = queue.popleft()


        if state == TARGET_STATE:

            return prefix


        for ch in PRINTABLE:

            nxt = step(
                state,
                ch
            )

            if nxt not in seen:

                seen.add(nxt)

                queue.append(
                    (
                        nxt,
                        prefix+chr(ch)
                    )
                )


    raise Exception(
        "target unreachable"
    )
```

---

# 13. Cara Menjalankan

Jalankan:

```bash
python3 solve.py
```

Output:

```text
<FLAG>NNS{qu1ck_and_3ff1ci3n7_check5}</FLAG>
```

---

# 14. Kesimpulan

Challenge ini merupakan reverse engineering terhadap hardware logic hasil sintesis.

Tidak diperlukan:

- brute force flag;
- simulasi FPGA;
- analisis timing.

Karena state FSM hanya:

```
5 bit
```

maka cukup dilakukan:

```
Parse netlist

        |

        v

Rekonstruksi FSM

        |

        v

BFS dari state 0

        |

        v

Cari state 31

        |

        v

Dapatkan flag
```

Flag berhasil diperoleh:

```
NNS{qu1ck_and_3ff1ci3n7_check5}
```
