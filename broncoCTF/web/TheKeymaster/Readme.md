# The Keymaster — BroncoCTF Web Writeup

**Kategori:** Web / Misc
**Challenge:** The Keymaster
**Flag:** `bronco{h3y_y0u_f0und_th3m_4ll_w1th_4b501ut31y_n0_w0rr135_4t_411}`

## Deskripsi Challenge

> The Keymaster has split a flag into 8 keys and hid them in plain sight. Quite literally, as they're on our advertisement page! Ready your cursor-pointers, pull out your trusty inspection panel, and find them quickly, detective!

Target: `https://broncosec.com/BroncoCTF`

Petunjuk penting di deskripsi:
- **"in plain sight"** → sebagian piece ada langsung di HTML/attribute, gak perlu effort besar
- **"cursor-pointers"** → beberapa elemen punya `class="cursor-pointer"`, artinya perlu di-klik untuk trigger event
- **"inspection panel"** → perlu DevTools/Inspect Element, bukan cukup `curl` biasa

Situs ini dibangun pakai **Next.js** (terlihat dari struktur `_next/static/chunks/...js`), jadi sebagian konten di-render client-side lewat JavaScript — beberapa piece gak akan muncul di raw HTML dari `curl`, harus dibaca dari source JS atau dipicu lewat interaksi browser.

## Recon Awal

`curl` ke halaman utama menunjukkan halaman statistik "BroncoCTF" dengan berbagai section: hero, About the Competition, Prize Pool, 2025 Statistics, Past Repositories, dan Sponsor. Beberapa piece langsung kelihatan di raw HTML karena ada di atribut HTML:

```bash
curl https://broncosec.com/BroncoCTF
```

## Peta 8 Piece Flag

| # | Piece | Cara ditemukan |
|---|-------|-----------------|
| 1 | `bronco{h` | Teks polos di footer halaman |
| 2 | `3y_y0u_f` | Muncul setelah klik kata **"flags"** (elemen `cursor-pointer`) di paragraf About |
| 3 | `0und_th3` | Atribut `title="3 - 0und_th3"` pada tombol **"Join the Competition"** |
| 4 | `m_4ll_w1` | Muncul di `document.cookie` setelah klik emoji **🙋** (elemen `id="cookie"`) |
| 5 | `th_4b501` | HTML comment tersembunyi, hanya terlihat lewat source JS |
| 6 | `ut31y_n0` | Query parameter di `href="/BroncoCTF?KEY=6-ut31y_n0"` (link "BroncoCTF 2026...?") |
| 7 | `_w0rr135` | Isi file **`/7.txt`** (di-download via link "2026") |
| 8 | `_4t_411}` | Atribut `alt="8 - _4t_411}"` pada gambar stat card terakhir |

Digabung urut 1→8:

```
bronco{h + 3y_y0u_f + 0und_th3 + m_4ll_w1 + th_4b501 + ut31y_n0 + _w0rr135 + _4t_411}
= bronco{h3y_y0u_f0und_th3m_4ll_w1th_4b501ut31y_n0_w0rr135_4t_411}
```

Decode leetspeak: *"hey you found them all with absolutely no worries at all"* 😄

## Walkthrough Detail

### Piece 1, 3, 6, 8 — Langsung di HTML (view-source / curl)

Empat piece ini muncul langsung di atribut HTML statis, bisa ditemukan cukup dengan `curl` atau View Page Source:

```bash
curl -s https://broncosec.com/BroncoCTF | grep -oE '[0-9] - [a-zA-Z_][a-zA-Z0-9_{}]*'
```

- **Piece 1** ada di teks footer: `"...Art by Anni L. '28<br/>1 - bronco{h"`
- **Piece 3** ada di `title` tombol "Join the Competition": `title="3 - 0und_th3"`
- **Piece 6** ada di `href` kartu "BroncoCTF 2026...?": `href="/BroncoCTF?KEY=6-ut31y_n0"`
- **Piece 8** ada di `alt` gambar stat card terakhir (yang jumlahnya "7340"): `alt="8 - _4t_411}"`

### Piece 7 — File Terpisah

Tombol tahun "**2026**" di paragraf About ternyata sebuah link `<a href="/7.txt" download="7.txt">2026</a>` yang men-download file teks:

```bash
curl -s https://broncosec.com/7.txt
# 7 - _w0rr135
```

### Piece 2 — Klik Elemen "flags"

Kata **"flags"** di paragraf About the Competition punya `class="cursor-pointer"` dan `onClick` handler. Meng-klik-nya menjalankan JS yang meng-append teks ke `<div id="addtext">` (awalnya kosong):

```javascript
onClick: () => {
  let e = document.getElementById("addtext");
  e.firstChild.textContent += "2 - 3y_y0u_f";
  new Audio("ding.oga").play();
}
```

Verifikasi di console browser setelah klik:
```javascript
console.log(document.getElementById('addtext').innerText);
// 2 - 3y_y0u_f
```

### Piece 4 — Klik Emoji 🙋 (Cookie)

Emoji **🙋** (`id="cookie"`) juga punya `onClick` handler, tapi bedanya piece ini **disimpan sebagai browser cookie**, bukan langsung dirender ke DOM:

```javascript
onClick: () => {
  document.cookie = "KEY4=4 - m_4ll_w1; path=/";
  let e = document.getElementById("cookie");
  e.firstChild.textContent += "🍪";
  new Audio("puzzle.oga").play();
}
```

Klik sekali saja sudah cukup untuk set cookie. Klik berulang cuma nambah emoji 🍪 (visual saja, bukan mekanisme reveal). Verifikasi via:
```javascript
console.log(document.cookie);
// KEY4=4 - m_4ll_w1
```

### Piece 5 — HTML Comment Tersembunyi (Paling Tricky)

Piece ini **tidak muncul di curl maupun DevTools Elements panel biasa**, karena di-render lewat komponen React khusus yang secara sengaja meng-convert dirinya sendiri jadi HTML comment:

```javascript
function a({comment: e}) {
  let n = useRef(null);
  useEffect(() => {
    n.current && (n.current.outerHTML = `<!-- ${e} -->`);
  }, [e]);
  return <script ref={n} type="text/placeholder" />;
}
// dipanggil dengan:
<a comment="!!! 5 - th_4b501 !!!" />
```

Komponen ini merender sebuah `<script type="text/placeholder">` kosong, lalu lewat `useEffect` menggantikan elemen tersebut jadi **HTML comment** berisi piece flag. Karena ini komentar HTML (`<!-- ... -->`), dia:
- Tidak terlihat visual di halaman
- Tidak ter-grep gampang di curl biasa (karena berada dalam comment yang dirender ulang oleh JS, bukan comment build-tool seperti di `<head>`)
- Baru kelihatan kalau kita baca **source code JS bundle** langsung

Cara menemukannya: download & grep JS chunk yang menangani komponen ini:

```bash
curl -s "https://broncosec.com/_next/static/chunks/e785679bf8074938.js" -o /tmp/cookie.js
grep -n "cookie\|onClick\|addtext" /tmp/cookie.js
```

Dari situ ketemu seluruh source JSX halaman, termasuk baris:
```
(0,t.jsx)(a,{comment:"!!! 5 - th_4b501 !!!"})
```

