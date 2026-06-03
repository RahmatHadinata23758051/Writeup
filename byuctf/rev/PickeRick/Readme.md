# Writeup: Pickle Rick - BYUCTF (Rev)

## Challenge Description
Sebuah file bernama `pickled.txt` diberikan dengan deskripsi bahwa ini adalah binary ELF yang di-"pickle", tapi bukan menggunakan library pickle Python.

## Analisis Awal
Saat membuka `pickled.txt`, isinya adalah deretan kata "rick" dan "pickle" yang berulang-ulang. Contoh:
`rick rick rick pickle pickle rick rick rick ...`

Karena total katanya adalah 68032 (kelipatan 8), diasumsikan bahwa setiap kata mewakili satu bit (0 atau 1).

## Dekripsi
1. **Mapping Bit**: Melalui percobaan, ditemukan bahwa `rick` mewakili bit `0` dan `pickle` mewakili bit `1`.
2. **Identifikasi Format**: Mengonversi 8 kata pertama menghasilkan byte `0x18`. Karena file ini seharusnya adalah ELF binary, byte pertamanya haruslah `0x7f`.
3. **Mencari XOR Key**: Selisih antara `0x18` dan `0x7f` adalah `0x18 ^ 0x7f = 0x67`. Ternyata seluruh file di-XOR dengan key `0x67` (karakter 'g').
4. **Rekonstruksi ELF**: Setelah bit dikonversi menjadi byte dan di-XOR dengan `0x67`, didapatkanlah file ELF 64-bit yang valid.

## Ekstraksi Flag
Setelah binary ELF berhasil direkonstruksi, menjalankan binary tersebut langsung mencetak flag ke layar. Binary ini sangat sederhana, hanya melakukan syscall `write` untuk mencetak string yang tersimpan di bagian `.data`.

Flag yang ditemukan:
`byuctf{1m_p1ckl3_r1111ck!}`

## Solve Script
Proses otomatisasi dapat dilihat di file `solve.py`.
