# Rivers Writeup

## Ringkasan

Binary `rivers` adalah ELF 64-bit static stripped. Input yang dibaca bukan string, melainkan format biner untuk tiga polinomial sparse dan dua titik 3D.

Jika semua validasi lolos, program mengambil environment variable `FLAG` lalu mencetaknya. Kalau `FLAG` tidak ada, program mencetak `bruh{fake_flag}`. Kalau gagal, output-nya `brevski noski`.

## Format Input

Program membaca:

```
for 3 polynomials:
    uint16_le term_count
    repeated term_count times:
        uint8  x_exp
        uint8  y_exp
        uint8  z_exp
        double coeff
then:
    double x1, y1, z1, x2, y2, z2
```

Constraint penting:

- setiap exponent `<= 60`
- total degree per term `<= 120`
- double harus finite
- dua titik akhir tidak boleh sama

## Validasi Matematika

Dari hasil reverse engineering, program membentuk Jacobian dari tiga polinomial input:

```
F = (f, g, h)
J_F = matrix partial derivative terhadap x,y,z
```

Lalu program mengecek bahwa determinan Jacobian adalah satu monomial konstan non-zero. Setelah itu program mengevaluasi `F` pada dua titik berbeda dan meminta hasilnya sama.

Artinya kita perlu map polinomial 3 variabel yang tidak injektif, tetapi determinant Jacobian-nya konstan non-zero.

## Payload

Dipakai counterexample berikut:

```
a = (1 + xy)^3 z + y^2(1 + xy)(4 + 3xy)
b = y + 3x(1 + xy)^2 z + 3xy^2(4 + 3xy)
c = 2x - 3x^2y - x^3z
```

Determinannya:

```
det(J_F) = -2
```

Dua titik berbeda yang collision:

```
P = (0, 0, -1/4)
Q = (1, -3/2, 13/2)
```

Evaluasi:

```
F(P) = (-1/4, 0, 0)
F(Q) = (-1/4, 0, 0)
```

Karena semua koefisien dan koordinat berupa integer/dyadic rational, representasi `double` tetap exact ketika dikonversi ke rational oleh GMP di binary.

## Solver

Local test:

```bash
FLAG=LOCAL_ACCEPTED python3 solve.py --binary ./rivers
```

Output:

```
LOCAL_ACCEPTED

flag remotenya TFCCTF{even_math_is_cooked_its_so_joever}
```

