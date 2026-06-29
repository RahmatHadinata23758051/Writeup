# deadgame2 — Misc

Flag: `SeKaiCTF{lol_fl2g_EN_TARO_HERO_GG}`

## Ringkas

Replay SC2-nya masih bisa dibuka sebagai MPQ walaupun magic awal sengaja diubah dari `MPQ\x1a` menjadi `MPQ\x1b`. Header MPQ valid ada di offset `0x400`, jadi isi replay tetap bisa diekstrak. Chat event memberi kerangka flag, sementara tiga bagian kosongnya disembunyikan sebagai tulisan dari posisi unit yang mati.

## Langkah

Archive berisi `DeadGame2.SC2Replay`. Byte awal terlihat korup, tetapi offset `0x400` berisi header MPQ normal. File replay kemudian diekstrak menggunakan parser MPQ/SC2.

File yang paling berguna:

- `replay.message.events` untuk chat.
- `replay.tracker.events` untuk posisi unit dan event kematian unit.

Dari message events didapat rangkaian chat berikut:

```text
4662  SeKaiCTF{lol
11897 _fl2g_
73100 _
73312 _
73588 _
73864 GG
73931 }
```

Jadi format kandidatnya:

```text
SeKaiCTF{lol_fl2g_<frag1>_<frag2>_<frag3>_GG}
```

Hint chat menyebut posisi sebagai hal penting. Di tracker events ada tiga grup kematian unit tepat sebelum tiga chat `_`:

```text
73086: BanelingBurrowed + Probe
73290: BanelingBurrowed + Probe
73563: BanelingBurrowed + Probe
```

Koordinat `m_x` dan `m_y` dari unit-unit tersebut diplot sebagai grid. Bentuknya menjadi tiga fragmen teks:

```text
73086 -> EN
73290 -> TARO
73563 -> HERO
```

Gabungan fragmen:

```text
SeKaiCTF{lol_fl2g_EN_TARO_HERO_GG}
```

Validasi MD5:

```text
md5(flag) = 0b95495176f49f2dab8a2d9c26a41ecc
```

## solve.py

```bash
python3 solve.py
```

Output:

```text
SeKaiCTF{lol_fl2g_EN_TARO_HERO_GG}
```
