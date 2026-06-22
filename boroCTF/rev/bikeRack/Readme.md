# Bike Rack - Writeup

Challenge ini adalah tantangan reverse engineering di mana kita harus menemukan PIN yang tepat untuk sebuah "bike lock".

## Analisis Binary
Setelah melakukan dekompilasi pada binary `chall`, ditemukan beberapa poin penting:
1. Binary meminta input PIN.
2. Input tersebut kemudian diproses dengan mengambil karakter pada setiap indeks kelipatan 4 (0, 4, 8, ...).
3. Karakter-karakter yang diambil tersebut dianggap sebagai digit (dikurangi 0x30).
4. Program menghitung jumlah kumulatif dari digit-digit tersebut.
5. Jumlah kumulatif ini digunakan sebagai indeks untuk mengambil karakter dari sebuah string konstanta yang berisi karakter-karakter flag.
6. Hasil akhirnya dicetak ke layar.

## Menemukan PIN
Di dalam fungsi `main`, terdapat manipulasi string pada data internal sebelum meminta input. Program melakukan `memmove` dan `strncat` pada dua buah string panjang yang berisi digit. String hasil manipulasi inilah yang sebenarnya merupakan PIN yang benar.

String asli di `0x4120`: `1927591750185873109357128735:912357132509713257561029375701027357361:2179327561242142098:980985641877731:238`
String pendukung di `0x2058`: `187773102385012356629012836224235219768597857`

Setelah mensimulasikan logika `memmove` dan `strncat`, kita mendapatkan PIN yang valid.

## Eksploitasi
Dengan memasukkan PIN yang telah direkonstruksi ke dalam binary, kita mendapatkan flag-nya.

Flag: `boroCTF{R@nd00M_YZ42u%ym}`
