Siap bro, ini writeup yang bisa langsung kamu taruh di README/writeup.

````md
# Oracle of Padding

## Category
Crypto

## Challenge
Diberikan sebuah service:

```bash
nc chal.thjcc.org 12000
````

Saat terkoneksi, server memberikan sebuah token hex:

```text
TOKEN <hex>
```

Tidak ada file tambahan yang diberikan, sehingga analisis dilakukan langsung dari interaksi dengan service.

## Analisis Awal

Ketika konek ke server, token yang diberikan memiliki panjang 112 byte setelah di-decode dari hex. Karena 112 merupakan kelipatan 16, token ini kemungkinan besar adalah ciphertext berbasis block cipher, seperti AES-CBC.

Strukturnya diasumsikan sebagai:

```text
IV || C1 || C2 || C3 || ...
```

Dengan ukuran blok 16 byte.

Saat mencoba mengirim ciphertext yang dimodifikasi ke server, server memberikan respons seperti:

```text
BAD
```

Respons ini muncul ketika padding ciphertext tidak valid. Artinya, server membocorkan informasi apakah padding hasil dekripsi valid atau tidak.

Dari sini dapat disimpulkan bahwa challenge ini rentan terhadap **Padding Oracle Attack**.

## Vulnerability

Pada mode CBC, plaintext sebuah blok dihitung dengan rumus:

```text
P_i = D(C_i) XOR C_{i-1}
```

Jika kita ingin mendekripsi suatu blok `C_i`, kita dapat memodifikasi blok sebelumnya `C_{i-1}`. Server akan mencoba mendekripsi ciphertext tersebut dan memberi tahu apakah padding hasil dekripsi valid.

Karena server membedakan padding valid dan tidak valid melalui respons `BAD`, kita bisa melakukan brute force byte per byte untuk mendapatkan nilai intermediate:

```text
I_i = D(C_i)
```

Setelah intermediate ditemukan, plaintext asli dapat dihitung dengan:

```text
P_i = I_i XOR C_{i-1 asli}
```

Attack dilakukan dari byte paling belakang blok menuju byte paling depan, sesuai aturan PKCS#7 padding.

## Exploit

Exploit dibuat menggunakan `pwntools`. Script mengambil token dari server, memecahnya menjadi blok 16 byte, lalu mendekripsi setiap blok menggunakan padding oracle.

Bagian penting dari prosesnya adalah mengirim payload:

```text
fake_iv || target_block
```

Jika respons server bukan `BAD`, maka padding dianggap valid dan byte intermediate dapat dihitung.

Script juga melakukan pengecekan false positive untuk byte terakhir, karena padding `0x01` kadang bisa menghasilkan kandidat palsu.

```python
from pwn import *
import sys

HOST = 'chal.thjcc.org'
PORT = 12000
BLOCK_SIZE = 16

def check_padding(r, payload):
    try:
        r.sendline(payload.hex().encode())
        response = r.recvline().decode('utf-8').strip()

        if "BAD" in response:
            return False

        return True

    except EOFError:
        log.error("Koneksi terputus.")
        return False

def decrypt_block(r, iv, block):
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for i in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - i
        match_found = False

        for guess in range(256):
            fake_iv = bytearray(BLOCK_SIZE)

            for j in range(BLOCK_SIZE - 1, i, -1):
                fake_iv[j] = intermediate[j] ^ padding_val

            fake_iv[i] = guess
            payload = bytes(fake_iv) + block

            if check_padding(r, payload):
                if i == 15:
                    fake_iv[14] ^= 0xFF
                    payload_check = bytes(fake_iv) + block

                    if not check_padding(r, payload_check):
                        continue

                intermediate[i] = guess ^ padding_val
                plaintext[i] = iv[i] ^ intermediate[i]

                char_found = chr(plaintext[i]) if 32 <= plaintext[i] <= 126 else f"\\x{plaintext[i]:02x}"
                log.info(f"Byte [{i:02d}] ditemukan: {char_found}")

                match_found = True
                break

        if not match_found:
            log.error(f"Gagal mencari byte ke-{i}.")
            return None

    return bytes(plaintext)

def main():
    context.log_level = 'info'

    r = remote(HOST, PORT)

    r.recvuntil(b'TOKEN ')
    token_hex = r.recvline().strip().decode()
    log.success(f"Token didapatkan: {token_hex}")

    token_bytes = bytes.fromhex(token_hex)

    if len(token_bytes) % BLOCK_SIZE != 0:
        log.error("Panjang token bukan kelipatan 16.")
        sys.exit(1)

    blocks = [
        token_bytes[i:i + BLOCK_SIZE]
        for i in range(0, len(token_bytes), BLOCK_SIZE)
    ]

    log.info(f"Total blok: {len(blocks)}. Blok pertama adalah IV.")

    plaintext = b''

    for b in range(1, len(blocks)):
        log.info(f"--- Memulai dekripsi blok {b} ---")

        iv = blocks[b - 1]
        block = blocks[b]

        decrypted_block = decrypt_block(r, iv, block)

        if decrypted_block is None:
            r.close()
            sys.exit(1)

        plaintext += decrypted_block

        readable = ''.join(chr(x) for x in plaintext if 32 <= x <= 126)
        log.success(f"Plaintext sejauh ini: {readable}")

    log.success(f"Plaintext akhir: {plaintext.decode(errors='ignore')}")
    r.close()

if __name__ == '__main__':
    main()
```

## Hasil

Setelah seluruh blok berhasil didekripsi, plaintext yang didapat adalah JSON:

```json
{"user":"guest","admin":false,"note":"THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}"}
```

Pada blok terakhir juga terdapat padding PKCS#7 berupa byte `0x0a`, sehingga bagian tersebut diabaikan.

## Flag

```text
THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}
```
