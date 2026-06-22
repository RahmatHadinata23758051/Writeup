# Retinal Burn

## Flag

`boroCTF{OW_MY_EYES!}`

## Walkthrough

File yang dikasih cuma PNG 800x800. Recon awal tidak nemu flag dari `strings`, metadata juga bersih. Petunjuk utamanya ada di teks gambar: `TOO BRIGHT!!!`.

Background putihnya tidak benar-benar polos. Ada teks yang hampir putih, jadi perlu dibalik dari putih lalu kontrasnya dinaikkan.

```bash
file burn.png
python3 solve.py
```

Saat nilai pixel dibandingkan dengan putih (`255 - pixel`), muncul banyak teks `FAKE_FLAG` dan satu teks besar di bagian atas. Teks merah berisi fake flag:

```text
FakeCTF{I_HATE_RED...}
```

Teks biru adalah yang dipakai. Cara isolasinya: ambil perubahan channel biru yang tidak muncul di red/green.

```python
diff = 255 - arr
blue_specific = diff[:, :, 2] - np.maximum(diff[:, :, 0], diff[:, :, 1])
mask = (blue_specific > 0) * 255
```

Hasil crop bagian atas membaca:

```text
boroCTF{OW_MY_EYES!}
```

## Tools

- `file`
- Python + Pillow
- NumPy
