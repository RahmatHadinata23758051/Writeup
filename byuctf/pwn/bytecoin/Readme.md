# Bytecoin

Challenge ini kelihatannya “crypto”, tapi akar masalahnya ada di parser input dan cara program memanfaatkan buffer hasil parsing.

## Recon singkat

Binary adalah ELF 64-bit PIE, NX aktif, canary aktif, dan tidak stripped. Karena symbol masih ada, analisis statik cukup enak.

Fungsi penting yang langsung kelihatan:

- `main`
- `bytecoin`
- `scan_hex_array`
- `crypto_memcmp`

Program mencetak ciphertext, Poly1305 tag, dan HMAC tag, lalu meminta tiga input untuk proses dekripsi.

## Bug utama

Masalah paling menarik ada di `scan_hex_array`.

Intinya:

1. Program mengalokasikan buffer sementara dengan ukuran `2 * (n + 1)`.
2. `fgets` membaca string hex.
3. Loop parsing menaikkan counter byte **sebelum** `sscanf` divalidasi.
4. Kalau parsing gagal di satu posisi, fungsi tetap mengembalikan jumlah byte yang sudah “diproses”.

Di `bytecoin`, nilai balik ini dipakai buat:

- `memcpy` ke buffer plaintext/ciphertext
- panjang yang masuk ke dekripsi

Jadi kita bisa bikin input hex yang valid sampai byte tertentu, lalu menyelipkan pasangan invalid seperti `zz`. Efeknya:

- byte itu tidak di-overwrite
- isi buffer sementara masih berisi data lama
- data lama tersebut berasal dari `hmacKey`, karena buffer dipakai ulang dan diisi dari key HMAC sebelum parsing

Ini jadi primitive leak per byte.

## Leak key

Dengan teknik di atas, saya leak `hmacKey` 32 byte, satu byte per ronde.

Payload yang dipakai:

- `00` berulang sampai byte yang mau dilewati
- lalu `zz` untuk memaksa parsing gagal di byte berikutnya

Karena program tetap lanjut ke tahap dekripsi dan mencetak:

`[+] Decrypting message ...`

kita bisa ambil byte yang bocor dari output plaintext hasil dekripsi.

## Kenapa dekripsi bisa dipakai

Ada dua hal yang membantu:

- IV untuk HMAC tidak ikut dihitung, jadi HMAC cuma cover ciphertext + Poly1305 tag.
- Return value dari `wc_ChaCha20Poly1305_Decrypt` tidak dihentikan lebih awal.

Jadi setelah key HMAC bocor, kita bisa forge HMAC untuk ciphertext yang sudah kita ubah.

## Final exploit

Setelah `hmacKey` didapat:

1. Ambil ciphertext asli.
2. Flip satu byte pertama ciphertext supaya hasil plaintext berubah.
3. Hitung ulang HMAC-SHA256 atas `ciphertext || poly1305_tag`.
4. Kirim ciphertext, IV asli, Poly1305 tag asli, dan HMAC forged.
5. Program mencetak plaintext hasil dekripsi.

Di output final, plaintext yang keluar masih punya satu byte salah karena ciphertext tadi di-flip. Byte itu tinggal dibalik lagi secara lokal untuk recover flag.

## Hasil

Flag yang didapat dari service:

`byuctf{crypt0_buffer_reuse_b4d}`

## File

- [solve.py](./solve.py)

