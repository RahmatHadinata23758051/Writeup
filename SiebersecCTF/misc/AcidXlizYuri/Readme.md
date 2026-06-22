# Acid x Liz Yuri??? - Misc Writeup

Challenge ini adalah puzzle cryptarithmetic yang dibungkus dengan tema lagu-lagu YurryCanon, terutama "Acid x Liz" dan "Alice in Freezer". 

### Langkah-langkah:
1. **Analisis File `chall.txt`**:
   File tersebut berisi dua persamaan:
   ```
   anj*rnnvar*ruvavdtu=jvddpnpnapudntar
   jvddpnpnapudntar*(juawupduvutt... + vjatvntuva) = the flag
   ```
   Terdapat 10 huruf unik: `a, n, j, r, v, u, d, t, p, w`. Ini menunjukkan bahwa setiap huruf mewakili satu digit dari 0-9.

2. **Analisis Deskripsi**:
   Deskripsi berisi lirik lagu YurryCanon. Kata kunci seperti `score`, `notes`, dan `emotion` muncul di deskripsi dan berhubungan dengan variabel dalam persamaan.

3. **Solving Cryptarithmetic**:
   Dengan menggunakan Python, kita bisa mencoba semua permutasi angka 0-9 untuk 10 huruf tersebut hingga menemukan pemetaan yang memenuhi persamaan pertama. 
   Ditemukan mapping: `{'a': 9, 'n': 8, 'j': 3, 'r': 1, 'v': 2, 'u': 7, 'd': 0, 't': 4, 'p': 5, 'w': 6}`.

4. **Menghitung Flag**:
   Setelah mendapatkan mapping, kita hitung nilai dari persamaan kedua. Hasilnya adalah sebuah angka desimal yang sangat besar: `12151826827775974592873638889401102634476306521170491511633005013117`.

5. **Decoding Flag**:
   Mengonversi angka tersebut ke hexadecimal menghasilkan `736374667b317234306e365f6972344f6e365f66343472316e44687d`. Konversi dari hex ke string menghasilkan flag yang valid.

Flag: `sctf{1r40n6_ir4On6_f44r1nDh}`
