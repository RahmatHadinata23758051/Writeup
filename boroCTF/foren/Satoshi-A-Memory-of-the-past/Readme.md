# Satoshi: A Memory of The Past - Writeup

Challenge ini memberikan sebuah file binary ELF `satoshi_pulse_v2`. Deskripsi menyebutkan bahwa flag "terjebak di dalam cache" dan kita bisa mendengar "denyut nadinya" (pulse).

## Analisis
Saat dijalankan, program mengeluarkan teks dalam bahasa Jepang dan Inggris, diikuti oleh deretan angka.
```
私はまだここにいます... (I am still here...)
The static mind is blind. The demons have learned your tricks.

391
12972
13363
...
```

Angka-angka ini memiliki pola yang jelas:
1. Angka kecil (sekitar 200 - 900)
2. Angka besar (lebih dari 10,000)

Ini adalah karakteristik dari **Cache Side-Channel Attack** (seperti Flush+Reload atau Prime+Probe). Dalam serangan ini, waktu akses memori diukur:
- Jika data ada di cache (**Cache Hit**), waktu akses sangat cepat (angka kecil).
- Jika data tidak ada di cache (**Cache Miss**), data harus diambil dari RAM, yang jauh lebih lambat (angka besar).

## Eksploitasi
Kita bisa mengasumsikan bahwa angka-angka ini mewakili bit data (0 dan 1).
- Angka kecil = Cache Hit = bit `0`
- Angka besar = Cache Miss = bit `1`

Dengan mengonversi deretan angka tersebut menjadi binary dan kemudian ke ASCII, kita mendapatkan flag-nya.

### Script Solve
```python
import subprocess

def solve():
    result = subprocess.run(['./satoshi_pulse_v2'], capture_output=True, text=True)
    numbers = [int(line) for line in result.stdout.split('\n') if line.strip().isdigit()]

    binary = "".join(['0' if n < 2000 else '1' for n in numbers])
    
    flag = ""
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            flag += chr(int(byte, 2))
    print(flag)
```

**Flag:** `boroCTF{s4t0sh1_1n_th3_c4ch3}`
