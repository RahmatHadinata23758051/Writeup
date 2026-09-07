# Writeup CTF: Hardware accelerated flag checker 2

- **Kategori:** Hardware / IC Reverse Engineering
- **Tingkat Kesulitan:** Hard
- **Artefak:** `flag_checker.gds`, `flag_checker.mag`
- **Technology:** SKY130
- **Flag:** `NNS{fl4g_ver1f1ed_1n_SKY130_IC}`

---

# 1. Deskripsi Tantangan

Challenge memberikan hasil akhir proses tapeout sebuah chip digital berupa:

```
GDSII layout
```

dan:

```
Magic layout file
```

Tidak terdapat:

- source Verilog;
- netlist RTL;
- firmware.

Berbeda dengan challenge hardware checker sebelumnya, kali ini proses reverse dilakukan langsung dari:

```
physical layout
```

Target akhirnya tetap sama:

Merekonstruksi FSM flag checker sehingga dapat menemukan urutan karakter yang membuat:

```
found_flag = 1
```

---

# 2. File Challenge

File yang diberikan:

```
flag_checker.gds

flag_checker.mag
```

---

## flag_checker.gds

Berisi:

- top-level layout;
- standard cell SKY130;
- polygon metal;
- via;
- pin geometry.

Format:

```
GDSII stream
```

---

## flag_checker.mag

Format:

```
Magic ASCII layout
```

Lebih mudah digunakan untuk:

- membaca instance;
- melihat routing;
- mengambil label port;
- membaca transform cell.

---

# 3. Analisis Awal

Dari file:

```
flag_checker.mag
```

ditemukan port:

```
character[0]

character[1]

character[2]

character[3]

character[4]

character[5]

character[6]

clk

reset_n

found_flag
```

---

Pada layout ditemukan:

```
5 instance dfxtp_2
```

Artinya desain menggunakan:

```
5-bit state register
```

atau:

```
FSM dengan 32 kemungkinan state
```

---

# 4. Struktur Hardware

Secara konsep desain:

```
character input

        |

        v

Combinational Logic

        |

        v

D Flip-Flop 5 bit

        |

        v

Next State

        |

        v

found_flag
```

---

Karena:

```
state = 5 bit
```

maka jumlah state:

\[
2^5 = 32
\]

---

# 5. Tantangan Utama

Berbeda dengan RTL:

```verilog
assign next_state = ...
```

di layout fisik tidak terdapat ekspresi logika.

Yang tersedia hanya:

- posisi transistor;
- standard cell;
- routing;
- koneksi metal.

---

Maka proses yang dilakukan:

```
Layout

 |

 v

Netlist Extraction

 |

 v

Logic Reconstruction

 |

 v

FSM Simulation

 |

 v

Flag Recovery
```

---

# 6. Ekstraksi Layout

Solver melakukan parsing:

## Dari file `.mag`

Diambil:

- rectangle routing;
- label;
- instance;
- posisi cell;
- transformasi orientasi.

---

## Dari file `.gds`

Diambil:

- polygon pin;
- geometry standard cell;
- layer metal;
- via connection.

---

# 7. Rekonstruksi Koneksi

Setiap koneksi listrik dibangun berdasarkan:

- overlap metal;
- hubungan via;
- polygon pin;
- koneksi antar layer.

---

Contoh:

```
metal1

 |

via1

 |

metal2

 |

pin cell
```

dianggap sebagai satu net.

---

# 8. Penanganan Stacked Via

Salah satu masalah pada layout:

Magic dapat menampilkan stacked via.

Contoh:

```
viali
via1
```

berada pada koordinat yang sama.

Tidak selalu terdapat rectangle metal eksplisit di antaranya.

---

Solver harus menganggap:

```
via overlap
```

sebagai:

```
electrical connection
```

---

# 9. Pembentukan Netlist

Setelah semua geometry digabungkan, solver membentuk:

```
(instance, pin) -> net
```

Contoh:

```
U1.A  -> net5

U1.B  -> net8

U1.Q  -> state0
```

---

Hasil akhir:

```
Physical Layout

        |

        v

Digital Netlist
```

---

# 10. Simulasi Logic

Setelah netlist diperoleh:

- standard cell diterjemahkan menjadi fungsi logika;
- DFF disimulasikan sebagai state register;
- combinational logic dihitung setiap karakter.

---

Model FSM:

```
current state

+

character[6:0]

        |

        v

next state
```

---

# 11. Recovery Flag

Karena FSM hanya memiliki:

```
32 state
```

digunakan:

```
Breadth First Search
```

---

Algoritma:

1. Mulai dari:

```
reset state = 0
```

2. Coba karakter:

```
ASCII printable
```

3. Hitung:

```
next state
```

4. Simpan path karakter.

5. Berhenti ketika:

```
found_flag = 1
```

---

Path yang ditemukan:

```
NNS{fl4g_ver1f1ed_1n_SKY130_IC}
```

---

# 12. Solve Script

File:

```
solve.py
```

bersifat self-contained.

Komponen:

```
GDS parser

Magic parser

Geometry extractor

Netlist builder

Logic simulator

FSM BFS solver
```

---

Dependency:

```
shapely
```

digunakan untuk:

- polygon intersection;
- overlap detection;
- koneksi geometry.

---

# 13. Struktur Solver

Pseudocode:

```python
layout = parse_magic(
    "flag_checker.mag"
)


cells = parse_gds(
    "flag_checker.gds"
)


nets = extract_connections(
    layout,
    cells
)


fsm = build_logic_network(
    nets
)


flag = bfs(
    start_state=0,
    target=found_flag
)


print(flag)
```

---

# 14. Cara Menjalankan

Install dependency:

```bash
pip install shapely
```

Jalankan:

```bash
python3 solve.py
```

---

Output:

```text
<FLAG>NNS{fl4g_ver1f1ed_1n_SKY130_IC}</FLAG>
```

---

# 15. Kesimpulan

Challenge ini merupakan reverse engineering tingkat physical design.

Tidak tersedia:

- source code;
- RTL;
- netlist.

Informasi harus diperoleh dari:

```
GDSII Layout
```

dan:

```
Magic Layout
```

Proses:

```
GDS/MAG

 |

 v

Extract Geometry

 |

 v

Recover Nets

 |

 v

Build Netlist

 |

 v

Simulate FSM

 |

 v

Find Flag Path
```

berhasil menghasilkan flag:

```
NNS{fl4g_ver1f1ed_1n_SKY130_IC}
```
