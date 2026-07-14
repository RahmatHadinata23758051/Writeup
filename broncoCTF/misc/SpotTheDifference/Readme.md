# Spot The Difference

Challenge ini meminta kita membandingkan dua file teks (`file1.txt` dan `file2.txt`) yang berisi karakter acak di setiap barisnya.

## Analisis
Dengan membandingkan baris demi baris dari kedua file tersebut, kita dapat membedakan dua jenis perbedaan:
1. Perubahan case (huruf besar/kecil), misalnya `e` menjadi `E`.
2. Perubahan karakter sepenuhnya (non-case flip), misalnya `g` menjadi `b`.

Jika kita mengumpulkan karakter dari `file2.txt` pada baris-baris yang mengalami perubahan tipe kedua (non-case flip) hingga tanda kurung kurawal penutup `}`, kita mendapatkan flag yang dicari.

## Solusi
Script Python `solve.py` mengekstrak karakter tersebut secara otomatis:

```python
with open("file2.txt") as f2, open("file1.txt") as f1:
    chars1 = [line.strip('\r\n') for line in f1.read().splitlines()]
    chars2 = [line.strip('\r\n') for line in f2.read().splitlines()]

flag = []
for i in range(min(len(chars1), len(chars2))):
    c1 = chars1[i]
    c2 = chars2[i]
    if c1 != c2 and abs(ord(c1) - ord(c2)) != 32:
        flag.append(c2)
        if c2 == '}':
            break

print("".join(flag))
```

Menjalankan script di atas menghasilkan:
`bronco{y@yyy_Y0u_f0und_m3!!}`
