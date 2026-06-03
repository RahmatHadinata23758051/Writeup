# Writeup: Corrupted Cores

## Challenge Deskripsi
Dalam challenge **Corrupted Cores**, kita diberikan file `chall.pcapng` yang menyimpan beberapa flag sekaligus. Dari deskripsi, kita tahu bahwa ada flag untuk 4 challenge berbeda yang berkaitan dengan game Portal:
1. "There will be cake"
2. "Are you still there?"
3. "Alright. Paradox time"
4. "Corrupted Cores"

Kita juga diberi dua buah hint:
- *Hint 1: The voices may not belong to a single identity*
- *Hint 2: The arp packets are not part of this challenge.*

Tugas kita adalah mencari flag spesifik untuk challenge **Corrupted Cores**.

## Analisis Pcap
Pertama, kita cek protokol apa saja yang ada di dalam file `chall.pcapng` menggunakan `tshark`:

Berdasarkan *protocol hierarchy*, terdapat trafik berupa ARP, NTP (UDP), ICMP, dan HTTP (TCP). Mengikuti petunjuk bahwa ARP bukanlah bagian dari tantangan, kita fokus menganalisis tiga protokol yang tersisa.

Dari hasil eksplorasi, kita dapat menemukan beberapa flag yang tersebar:
1. **HTTP/TCP**: Melalui proses *follow tcp stream* untuk trafik HTTP JSON, kita menemukan sebuah *cookie* berisi data yang di-encode Base64. Saat di-decode, hasilnya adalah `byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}` yang sangat relevan dengan "There will be cake".
2. **NTP**: Melakukan pengecekan *hex dump* pada *payload* NTP menunjukkan adanya karakter yang bila digabungkan membentuk flag `byuctf{S0_My_P4r4d0x_!d34_D!dnt_W0rk}`. Ini merupakan flag untuk challenge "Alright. Paradox time".
3. **ICMP Payload**: Ketika mengecek *hex payload* dari paket *ICMP Echo Request*, kita dapat menemukan teks ASCII berupa `byuctf{Turr3t_R3d3mpt!0n_L!n3s_4r3_N0t_R!d3s}` yang merujuk pada "Are you still there?".

Lalu, di mana letak flag Corrupted Cores?

## Mengekstrak Flag Corrupted Cores
Mari kita ingat kembali **Hint 1**: *the voices may not belong to a single identity*.

Pada paket *ICMP Echo Request*, kita menemukan ada anomali lain selain payload, yakni pada alamat IP dari si pengirim (Source IP). Total ada 12 paket *Echo Request* dengan *Source IP* yang terus berubah-ubah di setiap paketnya (menandakan "not a single identity" alias berganti identitas / suara).

Daftar Source IP-nya adalah:
- 89.110.108.49
- 89.51.82.109
- 101.49.82.111
- 77.49.57.81
- 78.72.74.48
- 88.49.100.111
- 77.51.73.122
- 88.48.103.122
- 88.48.115.104
- 98.71.120.122
- 88.49.107.119
- 100.88.48.65

Bila setiap *oktet* angka desimal pada IP ini kita konversi menjadi karakter ASCII, IP `89.110.108.49` akan berubah menjadi `Ynl1`. Melakukan ini untuk seluruh IP menghasilkan string Base64:
`Ynl1Y3Rme1RoM19QNHJ0X1doM3IzX0gzX0shbGxzX1kwdX0A`

Saat kita mendecode string Base64 tersebut, kita akan mendapatkan flag untuk challenge Corrupted Cores:
`byuctf{Th3_P4rt_Wh3r3_H3_K!lls_Y0u}`

## Solusi Otomatis
Sebuah script Python (`solve.py`) menggunakan `pyshark` telah dibuat untuk secara otomatis mengekstrak IP *Source* dari paket ICMP, mengonversinya menjadi ASCII, lalu mendecode string Base64 menjadi flag akhir.
