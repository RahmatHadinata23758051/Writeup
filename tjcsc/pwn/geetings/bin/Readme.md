# TJCTF - Greetings

Challenge ini kelihatannya simpel: ada `fgets()` ke buffer 64 byte, size input juga dikontrol user, canary tidak ada, dan stack executable. Awalnya keliatan seperti ret2shellcode biasa. Masalahnya ternyata binary PIE dan service jalan dengan ASLR aktif, jadi overwrite RIP penuh ke alamat `call rax` tidak stabil.

## Recon

Source yang dikasih:

```c
void greetUser() {
    int uname_size;
    char uname[64];
    printf("Enter the size of your username: ");
    scanf("%d", &uname_size);
    getchar();
    uname_size += 2;
    printf("Enter username (start with @): ");
    fgets(uname, uname_size, stdin);
    if (*(char *) uname == '@') {
        printf("Greetings to you: %s!", uname);
    }
}
```

Hasil penting dari binary:

- 64-bit PIE
- no canary
- stack executable
- overflow ada di `fgets(uname, uname_size, stdin)`

Layout stack dari `greetUser()` kasih offset 72 byte dari awal `uname` ke saved RIP.

## Ide awal yang gagal

Jalur paling natural adalah:

1. isi buffer dengan shellcode
2. overwrite RIP ke gadget `call rax`
3. manfaatkan fakta bahwa `fgets()` mengembalikan pointer ke buffer di `rax`

Secara lokal, ini memang jalan kalau ASLR dimatikan. Tapi di service nyata, alamat `call rax` ikut berubah karena PIE+ASLR.

## Trik yang kepake

Kunci challenge ini ada di interaksi antara `fgets()` dan saved RIP.

Kalau kita minta `fgets()` membaca **73 byte**:

- 72 byte pertama mengisi buffer sampai tepat sebelum RIP
- byte ke-73 menimpa **byte paling rendah** dari RIP
- lalu `fgets()` otomatis menulis `\\0` sesudahnya, jadi **byte kedua RIP jadi nol**

Return address normal dari `greetUser()` menuju `main+9`, yang offset rendahnya `...89`. Gadget `call rax` ada di offset `...10`.

Jadi kita pakai partial overwrite:

- low byte RIP kita paksa jadi `0x10`
- byte berikutnya dipaksa jadi `0x00` oleh terminator `fgets`

Ini cuma sukses kalau byte kedua alamat return kebetulan memang cocok untuk page yang sama. Probabilitasnya sekitar **1/256** per koneksi. Karena service cepat dan fork-per-connection, brute-force ini sangat masuk akal.

## Kenapa shellcode-nya harus kecil

Karena partial overwrite ini cuma ngasih ruang **72 byte** sebelum RIP, shellcode harus muat penuh di situ. Shellcode yang saya pakai:

- tidak spawn shell
- langsung `open("/flag.txt")`
- `read()` isinya
- `write(1, ...)`
- `exit()`

Saya tambahkan `add rsp, 0x200` di awal supaya buffer baca hasil file tidak menimpa shellcode di stack.

## Payload final

Strukturnya:

1. shellcode 61 byte
2. NOP padding sampai total 72 byte
3. satu byte `0x10` untuk overwrite low byte RIP

Karena `fgets()` otomatis nulis null byte setelah itu, saved RIP berubah menjadi gadget `call rax` saat kondisi ASLR-nya pas, lalu execution lompat ke shellcode kita karena `rax` masih berisi pointer ke `uname`.

## Hasil

Exploit berhasil dengan brute-force cepat dan flag yang keluar:

`tjctf{rAx_h01ds_r3t_v@lS?_189278}`

## File

- `exploit.py` berisi exploit otomatis untuk remote

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 exploit.py
```
