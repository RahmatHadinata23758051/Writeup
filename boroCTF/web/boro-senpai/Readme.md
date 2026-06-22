boro-senpai Series
Challenge 1: boro-senpai 1
Category: Web / OSINT

Flag: boroCTF{3l_psY_c0ngR00!}
Deskripsi
Menemukan handle @channel milik asisten Hououin Kyouma di forum fiksi bertema Steins;Gate.
Solve
Dari HTML yang diberikan, baca thread-thread di forum. User KuriGohanandKamehameha muncul sebagai satu-satunya yang menjawab pertanyaan fisika secara ilmiah dan menolak diidentifikasi — ciri khas Kurisu Makise. Akses /profile/KuriGohanandKamehameha langsung menghasilkan flag.
bashcurl -s https://w03xj6cjsucj.boroctf.com/profile/KuriGohanandKamehameha

Challenge 2: boro-senpai 2
Category: Web / SSRF

Flag: boroCTF{w1sh_w3_c0uld_g0_2_th3_m00n_t0g3th3r}
Deskripsi
SSRF melalui fitur "NetPulse uptime checker" milik Arasaka Corp untuk mengakses internal API yang diblokir dari luar.
Solve

Baca /static/script.js → ketemu endpoint POST /api/pulse dengan body {"url": "..."}
Komentar developer bocorkan hostname internal-api
SSRF ke http://internal-api/ → dapat list endpoint: / dan /flag
SSRF ke http://internal-api/flag → flag keluar

bashcurl -s -X POST https://4imc7nitr7ln.boroctf.com/api/pulse \
  -H "Content-Type: application/json" \
  -d '{"url":"http://internal-api/flag"}'

Challenge 3: boro-senpai 3
Category: Web / API Enumeration

Flag: boroCTF{th@nk_y0u_y0u_d!d_w3ll_!_l0v3_y0U<3}
Deskripsi
Menemukan akun yang di-soft-delete dari SNS Jepang bertema Rascal Does Not Dream (Seishun Buta Yarou).
Solve

Baca /static/main.js → ketemu fungsi mod panel yang memanggil /api/user/<username>?<k>=<v> dengan nilai dari window._modFlags
_modFlags hanya di-inject di halaman error suspended account — akses /profile/sakuta-azusagawa untuk memicunya
Decode base64: k = "include_deleted", v = "true"
Tebak username deleted user → mai-sakurajima (sesuai lore: Mai menghilang karena Adolescence Syndrome)
Flag tersembunyi di field mod_notes

bashcurl -s "https://5l24ruh9miuo.boroctf.com/api/user/mai-sakurajima?include_deleted=true"
