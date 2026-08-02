# Yet Another Chat

## Flag

```text
L3AK{1t_is_@ll_jU5t_4n0th3r_d30bf_uZzZc4t!0n_game_hopeyouenjoy:)_asengishere}
```

## Ringkasan

Archive dibuka menggunakan password berikut:

```bash
7z x -pnotinfected dist.zip
```

Isi archive:

* `challenge.pcap`
* `client.exe`
* `server.exe`

File `challenge.pcap` berisi traffic TCP loopback pada port `13371`, sedangkan `client.exe` dan `server.exe` digunakan untuk merekonstruksi format paket serta algoritma enkripsi yang digunakan.

## Recon PCAP

PCAP menggunakan linktype **DLT_NULL**, sehingga setiap paket diawali dengan 4 byte address family sebelum header IPv4.

Dari hasil analisis TCP stream diperoleh format paket sebagai berikut:

```text
uint32_be length
16-byte nonce
ciphertext
```

Ciphertext selalu memiliki panjang kelipatan 8 byte, mengindikasikan penggunaan block cipher 64-bit dengan padding 8 byte.

## Reversing Client

Binary awalnya dipack sehingga perlu di-unpack terlebih dahulu. Setelah proses unpack, fungsi receive/decrypt dapat ditemukan di sekitar alamat `0x401050`.

Urutan proses dekripsi:

1. Membaca 4 byte panjang paket.
2. Membaca body sesuai panjang tersebut.
3. Mengambil 16 byte pertama sebagai nonce/key material.
4. Melakukan dekripsi ciphertext menggunakan **XTEA**.
5. Hasil XTEA kemudian didekripsi kembali menggunakan **RC5**.
6. Menghapus padding 8 byte untuk memperoleh plaintext.

### XTEA

Fungsi XTEA decrypt berada di sekitar `0x401C40` dengan key statis:

```c
XTEA_KEY = {
    0xEBDA2075,
    0xDE70E310,
    0xE04B467B,
    0x758C6D04
};
```

Parameter yang digunakan:

* Block size: 64-bit
* Endian: Big-endian
* Rounds: 32
* Initial sum: `0xC6EF3720`

### RC5

Output dari XTEA selanjutnya diproses menggunakan **RC5-32/12/16**. Key schedule dibentuk dari nonce sepanjang 16 byte.

Parameter RC5:

```text
P32 = 0xB7E15163
Q32 = 0x9E3779B9
Rounds = 12
Expanded words = 26
```

Urutan decrypt setiap block:

```c
for (i = 12; i > 0; i--) {
    B = ror32((B - S[2*i + 1]) & 0xffffffff, A) ^ A;
    A = ror32((A - S[2*i]) & 0xffffffff, B) ^ B;
}
A -= S[0];
B -= S[1];
```

## Hasil Dekripsi

Salah satu stream dari server ke client menghasilkan pesan:

```text
Client 2: Yes, the password is L3AK{1t_is_@ll_jU5t_4n0th3r_d30bf_uZzZc4t!0n_game_hopeyouenjoy:)_asengishere}
```

## Flag

```text
L3AK{1t_is_@ll_jU5t_4n0th3r_d30bf_uZzZc4t!0n_game_hopeyouenjoy:)_asengishere}
```
