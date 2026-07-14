# Crab Trap

`crab_trap` menerima maksimal 512 byte shellcode lalu memasang seccomp. Banner menyebut syscall yang lolos hanya `open`, `read`, dan `write`, sehingga payload `execve("/bin/sh")` akan dihentikan.

Payload AMD64 di `solve.py` menyusun string `flag.txt` pada stack lalu melakukan tiga syscall berikut:

```text
open("flag.txt", O_RDONLY)
read(fd, rsp, 0x80)
write(1, rsp, bytes_read)
```

Awalnya `/flag` tidak menghasilkan output. Membaca `/proc/self/cmdline` dengan shellcode ORW menunjukkan proses berjalan sebagai `/home/ctf/crab_trap`; pengujian `flag.txt` di working directory kemudian berhasil. Tidak diperlukan shell interaktif atau bypass seccomp.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
bronco{h0w_c4n_mr_kr4b5_c0de}
```

Flag: `bronco{h0w_c4n_mr_kr4b5_c0de}`
