# Writeup CTF: Sleepy CPU

- **Kategori:** Side Channel Analysis / Embedded Security
- **Tingkat Kesulitan:** Medium
- **Artefak:** `sleepy_cpu.jls`, Zephyr firmware source
- **Flag:** `NNS{pow3r_4n4lys15_c4n_rev3al_what_th3_cpu_i5_w0rk1ng_on}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah firmware Zephyr dan hasil pengukuran konsumsi daya menggunakan Joulescope.

File trace:

```
sleepy_cpu.jls
```

Firmware tidak mencetak flag melalui:

- UART
- serial
- console

Sebaliknya, setiap karakter flag dibocorkan melalui durasi sleep CPU.

Program melakukan:

1. Menjalankan aktivitas CPU.
2. Masuk mode sleep selama nilai ASCII karakter.
3. Mengulang proses untuk seluruh karakter flag.

Dengan menganalisis perbedaan konsumsi daya antara CPU aktif dan sleep, karakter flag dapat direkonstruksi.

---

# 2. File Challenge

File yang diberikan:

```
sleepy_cpu.jls

zephyrapp/
 ├── src/main.c
 ├── src/flag.h
 ├── CMakeLists.txt
 └── prj.conf
```

---

# 3. Analisis Firmware

Bagian penting pada:

```
zephyrapp/src/main.c
```

adalah:

```c
for(char* c = flag; *c; c++)
{
    for(int i = 0; i < 100000; i++)
    {
        __asm volatile ("nop");
    }

    k_sleep(K_MSEC(*c));
}
```

---

# 4. Cara Kerja Leakage

Setiap karakter flag diproses:

```
Karakter flag

      |

      v

NOP loop

      |

      v

Sleep selama ASCII karakter

      |

      v

Karakter berikutnya
```

Nilai ASCII digunakan langsung sebagai waktu sleep.

Contoh:

Karakter:

```
N
```

ASCII:

```
78
```

maka CPU tidur sekitar:

```
78 ms
```

---

Karakter:

```
{
```

ASCII:

```
123
```

maka CPU tidur sekitar:

```
123 ms
```

---

# 5. Analisis Trace Joulescope

File:

```
sleepy_cpu.jls
```

merupakan format trace Joulescope.

Header:

```
jlsfmt
```

menunjukkan format:

```
Joulescope Log Stream
```

---

Stream yang tersedia:

| Stream | Data |
|-|-|
| subtype 1 | Current |
| subtype 2 | Power |
| subtype 3 | Voltage |

Stream yang digunakan:

```
Current
```

karena perubahan CPU aktif dan sleep paling terlihat.

---

# 6. Perbedaan Kondisi CPU

Saat CPU menjalankan:

```
nop loop
```

arus meningkat.

Nilai sekitar:

```
> 0.006 A
```

menandakan CPU aktif.

---

Saat:

```
k_sleep()
```

CPU idle.

Arus turun sekitar:

```
0.003 A
```

---

Dengan threshold:

```
0.006 A
```

setiap aktivitas CPU dapat dipisahkan.

---

# 7. Ekstraksi Timing

Setiap burst CPU aktif dianggap sebagai satu blok.

Format:

```
CPU aktif

      |

      v

Sleep

      |

      v

CPU aktif berikutnya
```

Durasi sleep dihitung:

\[
sleep\_ms =
next\_active\_start -
current\_active\_end
\]

Setelah dikonversi:

```
durasi ms = nilai ASCII
```

---

# 8. Contoh Hasil Ekstraksi

Hasil awal:

```
78 78 83 123 112 111 119 51 114 95 ...
```

Konversi ASCII:

```
NNS{pow3r_...
```

---

# 9. Algoritma Decoder

Proses decoding:

1. Parse file `.jls`.
2. Ambil stream current.
3. Deteksi CPU active window.
4. Hitung interval antar burst.
5. Konversi interval ke milidetik.
6. Ubah nilai menjadi karakter ASCII.

---

# 10. Solve Script

File:

```
solve.py
```

melakukan parsing trace tanpa membutuhkan:

```
Joulescope GUI
```

Dependensi:

```
Python
NumPy
```

---

Bagian utama decoder:

```python
for (_, end), (next_start, _) in zip(
        runs,
        runs[1:]
):

    sleep_ms = round(
        (next_start - end)
        * 1000
        / FS
    )

    chars.append(
        chr(sleep_ms)
    )
```

---

# 11. Struktur Solver

Pseudocode:

```python
samples = parse_jls(
    "sleepy_cpu.jls"
)


current = get_current_stream(
    samples
)


runs = detect_active_cpu(
    current,
    threshold=0.006
)


flag = ""


for run,next_run in pairs(runs):

    delay = next_run.start - run.end

    ascii_value = round(
        delay_ms
    )

    flag += chr(
        ascii_value
    )


print(flag)
```

---

# 12. Cara Menjalankan

Jalankan:

```bash
python3 solve.py
```

Output:

```text
<FLAG>NNS{pow3r_4n4lys15_c4n_rev3al_what_th3_cpu_i5_w0rk1ng_on}</FLAG>
```

---

# 13. Kesimpulan

Challenge ini memanfaatkan:

```
Power Side Channel Analysis
```

Tidak ada data flag yang dikirim secara langsung.

Informasi bocor melalui:

```
durasi sleep CPU
```

Karena firmware menggunakan:

```c
k_sleep(K_MSEC(*c))
```

nilai ASCII setiap karakter menjadi terlihat pada trace konsumsi daya.

Alur serangan:

```
Joulescope Trace

        |

        v

Deteksi CPU Active

        |

        v

Hitung Sleep Duration

        |

        v

Konversi ASCII

        |

        v

Recover Flag
```

Flag berhasil diperoleh:

``` NNS{pow3r_4n4lys15_c4n_rev3al_what_th3_cpu_i5_w0rk1ng_on} ```
