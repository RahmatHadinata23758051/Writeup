# Phantom

File yang dikasih cuma dua: `network_map.html` dan `phantom.pcap`. HTML-nya bersih, cuma ngasih konteks kalau target pentingnya database `10.0.50.100` dan ada sesuatu di "Core Routing Stack".

Isi `phantom.pcap` sengaja dipenuhi noise. Ada `500000` paket SYN ke `10.0.50.100` dengan payload yang selalu sama: `junk_traffic`. Field yang kelihatan berubah-ubah ada di source IP dan destination port, jadi awalnya keliatan kayak covert channel di header.

Setelah dihitung full-pass, ada outlier yang jauh lebih menarik:

- `21` paket menuju `198.51.100.22`
- source port `54321`
- flag TCP `ACK`
- tanpa payload

Semua paket aneh ini dikirim dari `10.0.50.100` di ujung capture. Header utamanya hampir sama semua, tapi ada satu field yang berubah: TCP timestamp option (`TSval`).

Nilai `TSval` dari 21 paket itu:

```text
72 69 88 69 105 126 108 81 103 27 68 78 117 94 66 25 117 109 30 122 87
```

Kalau dibaca sebagai ASCII mentah hasilnya:

```text
HEXEi~lQg<esc>DNu^B<em>um<rs>zW
```

Pattern `HEXE` cukup mencurigakan. Coba XOR satu byte ke seluruh stream, dan `0x2a` langsung menghasilkan flag valid:

```text
boroCTF{M1nd_th3_G4P}
```

Solver final ada di `solve.py`. Script itu:

- parse PCAP
- filter paket yang menuju `198.51.100.22`
- ambil `TSval` dari TCP timestamp option
- urutkan berdasarkan timestamp paket
- XOR tiap byte dengan `0x2a`

Run:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
boroCTF{M1nd_th3_G4P}
```
