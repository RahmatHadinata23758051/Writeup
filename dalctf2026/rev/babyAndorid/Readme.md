# Baby Android

Challenge ini ternyata sangat lurus setelah APK di-unpack dengan `apktool`.

## Langkah Analisis

1. Saya decompile APK:

   ```bash
   apktool d -f chall.apk -o apkout
   ```

2. Lalu saya cari string mencurigakan. Dari situ langsung kelihatan ada tiga fragment bernama `flag1`, `flag2`, dan `flag3`.

## Temuan Utama

- `flag1` ada di constructor `MainActivity`.
  - File: [`apkout/smali_classes4/com/example/babyandroid/MainActivity.smali`](/home/nata/ctf/dalctf2026/rev/babyAndorid/apkout/smali_classes4/com/example/babyandroid/MainActivity.smali#L53)
  - Nilainya: `dalctf{4ndr0id`

- `flag2` ada di resource string dan juga dipakai sebagai `android:description` di manifest.
  - File: [`apkout/res/values/strings.xml`](/home/nata/ctf/dalctf2026/rev/babyAndorid/apkout/res/values/strings.xml#L66)
  - Nilainya: `_d3bugg1ng_`
  - Manifest: [`apkout/AndroidManifest.xml`](/home/nata/ctf/dalctf2026/rev/babyAndorid/apkout/AndroidManifest.xml#L5)

- `flag3` ada di `ui/theme/ColorKt`.
  - File: [`apkout/smali_classes3/com/example/babyandroid/ui/theme/ColorKt.smali`](/home/nata/ctf/dalctf2026/rev/babyAndorid/apkout/smali_classes3/com/example/babyandroid/ui/theme/ColorKt.smali#L117)
  - Nilainya: `_1s_e4sy}`

## Kesimpulan

Kalau ketiga potongan itu digabung persis seperti di kode, hasilnya:

`dalctf{4ndr0id_d3bugg1ng__1s_e4sy}`

## Catatan

UI aplikasi cuma berisi teks pengalih seperti:

- `nothing to see here`
- `Move along, folks.`
- `have you checked under the hood?`

Jadi inti challenge memang ada di pembacaan string statis, bukan di interaksi aplikasi.
