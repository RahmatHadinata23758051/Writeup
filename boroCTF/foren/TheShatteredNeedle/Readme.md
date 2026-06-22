# The Shattered Needle - Forensics

Challenge ini memberikan sebuah file zip yang berisi sangat banyak file (sekitar 100.000 file) dalam struktur folder yang dalam. Deskripsi challenge menyebutkan "haystack" dan "needle", yang mengindikasikan kita perlu mencari sesuatu di antara tumpukan file tersebut.

## Analisis
Setelah mengekstrak `chall.zip`, didapati struktur folder `dir_X/sub_Y/data_Z.txt`. Mencari langsung flag format `boroCTF` menggunakan `grep` memberikan satu hasil yang merupakan bagian pertama dari flag dan petunjuk bahwa flag tersebut terbagi menjadi 5 fragmen.

```bash
grep -r "boroCTF" .
./dir_33/sub_65/data_8.txt:Anomaly: [FLAG_FRAGMENT_1/5]: boroCTF{gr3p_ End.
```

## Solusi
Dengan mencari string `FLAG_FRAGMENT` di seluruh direktori, kita bisa mengumpulkan kelima fragmen tersebut.

```bash
grep -r "FLAG_FRAGMENT" .
./dir_56/sub_5/data_3.txt:Anomaly: [FLAG_FRAGMENT_4/5]: 1nc1d3nt_ End.
./dir_69/sub_89/data_10.txt:Anomaly: [FLAG_FRAGMENT_2/5]: 1s_y0ur_b3st_ End.
./dir_16/sub_17/data_1.txt:Anomaly: [FLAG_FRAGMENT_3/5]: fr13nd_f0r_ End.
./dir_33/sub_65/data_8.txt:Anomaly: [FLAG_FRAGMENT_1/5]: boroCTF{gr3p_ End.
./dir_48/sub_53/data_2.txt:Anomaly: [FLAG_FRAGMENT_5/5]: r3sp0ns3} End.
```

Mengurutkan fragmen berdasarkan nomornya:
1. `boroCTF{gr3p_`
2. `1s_y0ur_b3st_`
3. `fr13nd_f0r_`
4. `1nc1d3nt_`
5. `r3sp0ns3}`

Flag akhirnya adalah: `boroCTF{gr3p_1s_y0ur_b3st_fr13nd_f0r_1nc1d3nt_r3sp0ns3}`.

Flag: `boroCTF{gr3p_1s_y0ur_b3st_fr13nd_f0r_1nc1d3nt_r3sp0ns3}`
