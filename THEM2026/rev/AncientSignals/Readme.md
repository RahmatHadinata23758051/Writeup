# Ancient Signals Writeup

Challenge ini memberi dua file: `player.exe` dan `transmission.dat`. Binary-nya adalah PE64 Windows GUI. Dari `strings` terlihat beberapa petunjuk penting: `transmission.dat`, `SIGNAL DECRYPTED`, dan format output `FLAG: %s`.

Fungsi utama validasi ada di sekitar `0x14002d770`. Saat tombol `PLAY TRANSMISSION` ditekan, program mengambil tiga nilai kontrol UI lalu membuat keystream 1 byte dengan rumus:

```text
x = (x * multiplier + increment) & 0xff
plaintext_byte = ciphertext_byte ^ x
```

Empat byte pertama hasil decode harus sama dengan `RIFF`. Karena empat byte awal `transmission.dat` adalah `08 ce 08 25`, brute force kecil untuk tiga parameter 1-byte memberi:

```text
start      = 139
multiplier = 67
increment  = 249
```

Dengan nilai itu, `transmission.dat` memang berubah menjadi file WAV yang diawali `RIFF....WAVEfmt`. Ini adalah bagian "fixing software" / alignment sinyalnya.

Setelah validasi `RIFF` lolos, program tidak mengambil flag dari audio. Ia menghitung FNV-1a 32-bit atas byte kode fungsi checker dari `0x1400032d0` sampai `0x140003320`. Hash yang didapat:

```text
0xaa171c81
```

Dalam little-endian, key XOR-nya adalah:

```text
81 1c 17 aa
```

Data flag terenkripsi berada di awal `.data`, VA `0x140080000`, sepanjang `0x37` byte. Setelah di-XOR berulang dengan key tersebut, flag keluar:

```text
THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}
```

Reproduksi:

```bash
python3 solve.py
```
