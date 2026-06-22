# Fast Reactions

Service ini tidak butuh ROP atau memory corruption lanjutan. Banner awal langsung kasih angka acak dalam format hex dan program expect input dengan panjang persis angka itu. Kalau panjang cocok, service langsung print flag.

Deskripsi remote:

```text
nc tnkemaq46125.boroctf.com 56354
```

## Recon

Karena file binary tidak dibundel di workspace, analisis dilakukan dari perilaku service remote.

Koneksi pertama memberi output seperti ini:

```text
Please enter 0x12c characters!
```

Angka heksanya berubah tiap koneksi. Saat dikirim string sepanjang angka itu, service langsung membalas:

```text
Nice job! Flag: boroCTF{Hum@n1y_im7o5s!ble}
```

Kalau panjang salah, service membalas `Too short!` lalu lanjut ke ronde berikutnya dengan angka baru. Itu cukup untuk menyimpulkan challenge ini cuma tes parsing banner dan mengirim payload dengan panjang yang tepat.

## Solusi

Solver final:

1. Connect ke remote.
2. Baca satu line banner.
3. Parse nilai `0x...` dengan regex.
4. Kirim `b"A" * panjang`.
5. Ambil output sampai EOF.

Script ada di [solve.py](/home/nata/ctf/boroCTF/pwn/FastReactions/solve.py).

Run:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Contoh output:

```text
[+] banner: Please enter 0x12c characters!
Nice job! Flag: boroCTF{Hum@n1y_im7o5s!ble}
```

## Flag

`boroCTF{Hum@n1y_im7o5s!ble}`
