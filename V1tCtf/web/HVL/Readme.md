# HVL

Challenge ini dibungkus Cloudflare challenge, jadi request `curl` biasa cuma dapat halaman `Just a moment...`. Jalan paling cepat adalah buka halaman pakai Playwright non-headless, tunggu sampai title berubah dari `Just a moment...`, lalu dump HTML final dan asset yang dipakai halaman.

Source app ternyata cuma satu halaman statis visualizer lagu. Tidak ada API, tidak ada route aneh, dan lyric disimpan inline di variabel JavaScript:

```js
const embeddedSrt = "...";
```

Di bagian akhir lirik ada dua hal mencurigakan:

1. Satu baris berisi variation selector Unicode yang tidak kelihatan.
2. Beberapa baris lain berisi deretan emoji.

## Step 1 - Dump halaman asli

Pakai Playwright untuk lewat Cloudflare dan simpan HTML:

```bash
rtk python3 -u - <<'PY'
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False, args=['--disable-blink-features=AutomationControlled'])
    ctx = browser.new_context(ignore_https_errors=True, viewport={'width':1366,'height':768})
    ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
    page = ctx.new_page()
    page.goto('https://hvl.v1t.site/', wait_until='domcontentloaded', timeout=45000)
    page.wait_for_function("document.title !== 'Just a moment...'", timeout=90000)
    open('page.html', 'w', encoding='utf-8').write(page.content())
    browser.close()
PY
```

Setelah itu tinggal grep bagian penting:

```bash
rtk rg -n "embeddedSrt|🔥|😀|😉" page.html
```

Kelihatan ada payload aneh di subtitle terakhir.

## Step 2 - Decode variation selector

Variation selector U+E0100 ke atas bisa dipakai untuk nyimpen nibble/byte tersembunyi. Decode payload itu menghasilkan clue:

```bash
rtk python3 - <<'PY'
from pathlib import Path

text = Path('page.html').read_text('utf-8')
seq = []
cur = []
for ch in text:
    cp = ord(ch)
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        cur.append(cp)
    else:
        if cur:
            seq.append(cur)
            cur = []
if cur:
    seq.append(cur)

for s in seq:
    bs = []
    for cp in s:
        if 0xFE00 <= cp <= 0xFE0F:
            bs.append(cp - 0xFE00)
        else:
            bs.append(cp - 0xE0100 + 0x10)
    print(bytes(bs).decode())
PY
```

Output:

```text
hello sir
```

Ini cuma troll clue, belum flag.

## Step 3 - Ambil asset dan cek font

Halaman memuat font lokal:

```css
@font-face {
  font-family: "Noto Sans";
  src: url("./NotoSans-Regular.ttf") format("truetype");
}
```

Nama internal font ini bukan Noto Sans biasa. Dari metadata:

```bash
rtk python3 - <<'PY'
from fontTools.ttLib import TTFont
font = TTFont('NotoSans-Regular.ttf')
for name in font['name'].names:
    try:
        print(name.nameID, name.toUnicode())
    except:
        pass
PY
```

Keluar nama `Emoji To AZ`. Itu clue bahwa emoji tidak ditampilkan normal, tapi dipetakan ke glyph huruf/angka.

## Step 4 - Decode emoji jadi flag

Cek `cmap` font untuk emoji yang dipakai di lirik:

```bash
rtk python3 - <<'PY'
from fontTools.ttLib import TTFont

font = TTFont('NotoSans-Regular.ttf')
targets = [
    0x1F600, 0x1F601, 0x1F602, 0x1F603, 0x1F604, 0x1F605, 0x1F606,
    0x1F607, 0x1F609, 0x1F60A, 0x1F60C, 0x1F60D, 0x1F642, 0x1F643,
    0x1F923, 0x1F972
]

for table in font['cmap'].tables:
    if table.isUnicode():
        for cp in targets:
            g = table.cmap.get(cp)
            if g:
                print(hex(cp), g)
        break
PY
```

Mapping pentingnya:

```text
😀 -> v
😃 -> 1
😄 -> t
😁 -> {
😆 -> g
😅 -> 0
😂 -> 4
🤣 -> t
🥲 -> _
😊 -> m
😇 -> c
🙂 -> k
🙃 -> h
😉 -> v
😌 -> l
😍 -> }
```

Tinggal baca emoji dari baris-baris terakhir lirik:

```text
😀😃😄😁😆
😅😂🤣
🥲😊😇
🙂🥲🙃
😉😌😍
```

Hasilnya:

```text
v1t{g04t_mck_hvl}
```

## Flag

```text
v1t{g04t_mck_hvl}
```
