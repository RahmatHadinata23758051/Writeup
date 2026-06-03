# Writeup: Welcome to the SoC

## Deskripsi Challenge
Challenge ini mensimulasikan sebuah System-on-Chip (SoC) dengan sistem operasi minimalis (SoC-OS v1.0). Target kita adalah mengekstrak informasi penting (flag) yang tersimpan di direktori root.

## Analisis
Berdasarkan `user_guide.pdf`, sistem ini memiliki arsitektur memori flat 64 KB dengan pembagian sebagai berikut:
- **0x0000 - 0x0FFF**: System Zone (Kernel & System files) - **Tidak dapat diakses via shell**.
- **0x1000 - 0x3FFF**: User Space (User files) - **Dapat diakses**.
- **0x4000 - 0x403F**: DMA Controller Registers - **Dapat diakses**.

Meskipun shell membatasi akses langsung ke System Zone (menggunakan `cat` atau `hexdump`), terdapat peripheral **DMA Controller** yang dapat melakukan transfer memori antar alamat fisik tanpa campur tangan CPU/Shell access control di level software.

## Eksploitasi
1. **Enumerasi File**: Menggunakan perintah `ls /root`, ditemukan file `flag.txt` yang berada pada alamat memori `[0x00000200]`. Karena alamat ini berada di System Zone, kita tidak bisa membacanya secara langsung.
2. **Konfigurasi DMA**: Kita memanfaatkan DMA Controller untuk menyalin data dari `0x00000200` (Source Address) ke `0x00001000` (Destination Address di User Space) sebanyak 64 byte.
   - Register SA (Source Address) berada di `0x4018`.
   - Register DA (Destination Address) berada di `0x4020`.
   - Register BTT (Bytes To Transfer) berada di `0x4028`. Menulis ke register ini akan memicu transfer.
3. **Membaca Flag**: Setelah transfer selesai, kita menggunakan perintah `hexdump 0x1000 0x40` untuk membaca data yang telah disalin ke User Space.

## Flag
`<FLAG>THC{DMA-1s_n0t_5tr0ng_en0ugh?}</FLAG>`
