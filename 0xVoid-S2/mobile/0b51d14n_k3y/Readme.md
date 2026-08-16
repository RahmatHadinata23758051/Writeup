# 0b51d14n_k3y

## Ringkasan

APK menyimpan database SQLite berisi ciphertext AES-GCM. Key tidak disimpan utuh; key dirakit dari fragmen string di native library, sesuai urutan yang juga ditinggalkan di source C.

## File Challenge

- `ob9k3x.apk`: APK target.
- `extracted/libshard.c`: leftover source native.
- `extracted/libshard.so`: native library, salinan lain berada di `lib/x86_64/`.
- `extracted/assets/shard.db`: database ciphertext.
- `extracted/classes.dex`: DEX minimal dengan petunjuk format AES-GCM dan nama row.

## Analisis Awal

APK dapat diekstrak sebagai ZIP. `shard.db` dikenali sebagai SQLite 3. Schema tabel `shard` adalah:

```text
name, iv, tag, ciphertext, context
```

Ada beberapa decoy: `NOTICE.txt`, row `meta.ai_bait`, dan string `decoy_flag` di library. Target yang benar adalah row `master_shard`.

## Analisis Static

`libshard.c` memuat fragmen berikut:

```text
sk_f0 = cold-
sk_f1 = forge-
sk_f2 = obsidian-
sk_f3 = blade
sk_order = seq=2,0,3,1
```

DEX menyatakan bahwa urutan key mengikuti `sk_order`, bukan urutan kolom. Maka payload key adalah:

```text
obsidian-cold-bladeforge-
```

String DEX juga menyebut `AES/GCM/NoPadding` dan context `shard-vault-v1` dipakai sebagai associated data.

## Algoritma Validasi atau Encoding

Row `master_shard` berisi:

```text
iv         = 9d25e1e2a448b52d5f6c106b
tag        = 38e47eef449017ef5b36d680154d88be
context    = shard-vault-v1
```

Ciphertext dan tag digabung untuk API AES-GCM. Key dihitung sebagai `SHA-256(b"obsidian-cold-bladeforge-")`. Decrypt dengan IV tersebut dan context sebagai AAD berhasil memverifikasi tag, sehingga hasilnya bukan tebakan atau decoy.

## Penyusunan Solve Script

`solve.py` membaca fragmen dan urutan langsung dari `extracted/libshard.c`, membaca row `master_shard` dari SQLite, menghitung SHA-256, lalu melakukan AES-GCM decrypt. Tidak ada nilai flag yang di-hardcode.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Output script adalah plaintext hasil dekripsi.

## Flag

```text
0xV01D{obsidian_cold_blade_forged_from_native_shards}
```

## Catatan

`NOTICE.txt`, `meta.ai_bait`, dan `decoy_flag` menghasilkan flag palsu yang sengaja ditanam untuk mengganggu triage. Library juga memiliki fungsi JNI `verify`, tetapi fungsi tersebut tidak diperlukan untuk membangun key maupun mendekripsi `master_shard`.
