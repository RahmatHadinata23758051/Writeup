# \\langle\\rangle\\langle\\rangle

## Ringkasan

`out.cpp` menyimpan pesan yang dihapus sebagai 214 parameter `FLAGMESSAGE`.
Setiap parameter dipakai sebagai `FlagValue<N>::Value` dalam constraint template
C++, sehingga suatu pengganti pesan yang benar harus membuat seluruh constraint
valid saat dikompilasi.

## File Challenge

- `out.cpp` — sumber C++ yang berisi 700 persamaan linear dan 881 constraint
  pembanding/divisibilitas.
- `solve.py` — solver reproduksibel.

## Analisis Awal

Template `Equ<c1,c2,t1,v1,v2,v3,v4,v5>` menyatakan:

```text
c1*v1 + c2*v2 + t1*v3 = v4 + v5
```

Persamaan `Equ` bersifat homogen. Matriks 700×214 yang dibentuk dari persamaan
tersebut memiliki rank 213, jadi nullspace-nya satu dimensi. Nilai karakter
adalah suatu skala integer dari vektor nullspace; constraint `Lt`, `Lteq`,
`Gt`, `Gteq`, dan `Divides` menentukan skala yang valid.

## Solusi

Jalankan pada virtual environment challenge:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Solver menghitung SVD, menguji skala integer, dan kemudian mengevaluasi semua
1.581 constraint dari `out.cpp`. Satu-satunya skala yang lolos adalah 67,
yang mendekodekan pesan dan flag berikut.

## Flag

```text
bushbash{d1d_y0U_Us3_z3?}
```
